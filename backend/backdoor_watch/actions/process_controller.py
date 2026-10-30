import os

import psutil

from backdoor_watch.domain.errors import ActionFailedError, ActionRefusedError, NotFoundError

_SYSTEM32 = os.path.normcase(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32"))


class ProcessKillPolicy:
    """Blocks actions that would crash Windows.

    A protected name only counts when the binary really lives in System32: malware
    commonly names itself svchost.exe or lsass.exe from another folder, and those
    impostors must stay killable.
    """

    def __init__(self, protected_names: frozenset[str]) -> None:
        self._protected = protected_names
        self._own_pid = os.getpid()

    def ensure_allowed(self, process: psutil.Process) -> None:
        if process.pid in (0, 4) or process.pid == self._own_pid:
            raise ActionRefusedError(f"PID {process.pid} is a core system process or this monitor")
        try:
            name, exe = process.name().lower(), process.exe()
        except psutil.AccessDenied:
            name, exe = process.name().lower(), None
        in_system32 = exe is None or os.path.normcase(os.path.dirname(exe)) == _SYSTEM32
        if name in self._protected and in_system32:
            raise ActionRefusedError(f"{name} (PID {process.pid}) is a critical Windows process")


class ProcessController:
    def __init__(self, policy: ProcessKillPolicy) -> None:
        self._policy = policy

    def kill(self, pid: int, include_children: bool) -> list[int]:
        process = self._allowed_process(pid)
        targets = (process.children(recursive=True) if include_children else []) + [process]
        for target in targets:
            self._run(target.kill)
        psutil.wait_procs(targets, timeout=3)
        return [t.pid for t in targets]

    def suspend(self, pid: int) -> None:
        self._run(self._allowed_process(pid).suspend)

    def resume(self, pid: int) -> None:
        self._run(self._allowed_process(pid).resume)

    def suspend_tree(self, pid: int) -> list[int]:
        """Freezes the process and everything it started. Critical Windows processes in the tree are skipped."""
        root = self._allowed_process(pid)
        frozen = []
        for target in [root, *root.children(recursive=True)]:
            try:
                self._policy.ensure_allowed(target)
                self._run(target.suspend)
                frozen.append(target.pid)
            except ActionRefusedError:
                continue
        return frozen

    def resume_pids(self, pids: list[int]) -> list[int]:
        resumed = []
        for pid in pids:
            try:
                self.resume(pid)
                resumed.append(pid)
            except (NotFoundError, ActionRefusedError):
                continue
        return resumed

    def executable(self, pid: int) -> str:
        process = self._get(pid)
        try:
            return process.exe()
        except psutil.AccessDenied as exc:
            raise ActionFailedError("Access denied reading the executable path — run as administrator") from exc

    def _allowed_process(self, pid: int) -> psutil.Process:
        process = self._get(pid)
        self._policy.ensure_allowed(process)
        return process

    @staticmethod
    def _get(pid: int) -> psutil.Process:
        try:
            return psutil.Process(pid)
        except psutil.NoSuchProcess as exc:
            raise NotFoundError(f"Process {pid} no longer exists") from exc

    @staticmethod
    def _run(operation) -> None:
        try:
            operation()
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied as exc:
            raise ActionFailedError("Access denied — run Backdoor Watch as administrator") from exc
