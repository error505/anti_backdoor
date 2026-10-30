from pydantic import BaseModel

from backdoor_watch.domain.errors import NotFoundError
from backdoor_watch.domain.findings import Finding, FindingTargetKind
from backdoor_watch.domain.network import Connection
from backdoor_watch.domain.process import ProcessInfo
from backdoor_watch.monitoring.system_state import SystemState


class ProcessDetail(BaseModel):
    process: ProcessInfo
    ancestors: list[ProcessInfo]
    children: list[ProcessInfo]
    connections: list[Connection]
    findings: list[Finding]


class ProcessQueries:
    def __init__(self, state: SystemState) -> None:
        self._state = state

    def detail(self, pid: int) -> ProcessDetail:
        snapshot = self._state.current
        process = snapshot.processes.get(pid)
        if process is None:
            raise NotFoundError(f"Process {pid} is not running")
        return ProcessDetail(
            process=process,
            ancestors=self._ancestors(process, snapshot.processes),
            children=[p for p in snapshot.processes.values() if p.ppid == pid],
            connections=[c for c in snapshot.connections if c.pid == pid],
            findings=[f for f in snapshot.findings
                      if any(t.kind == FindingTargetKind.PROCESS and t.ref == str(pid) for t in f.targets)],
        )

    @staticmethod
    def _ancestors(process: ProcessInfo, processes: dict[int, ProcessInfo]) -> list[ProcessInfo]:
        """Parent chain (e.g. Code.exe → cmd.exe → node.exe) shows who launched a process."""
        chain: list[ProcessInfo] = []
        current = process
        while current.ppid and current.ppid in processes and len(chain) < 15:
            parent = processes[current.ppid]
            if parent.create_time and current.create_time and parent.create_time > current.create_time:
                break  # PID reused by a newer process; not the real parent
            chain.append(parent)
            current = parent
        return chain
