"""Recognises Backdoor Watch's own processes so they are labelled, not reported.

Ours = this server, every helper it spawns (PowerShell queries), and any process
whose executable or command line lives in the install folder: the start.ps1
PowerShell window, the venv launcher, `npm run dev`. Trade-off: malware copied
into the install folder would also be trusted. That folder is user-owned, so
keep it somewhere you control.
"""

import os
from collections.abc import Mapping
from pathlib import Path

import psutil

from backdoor_watch.domain.process import ProcessInfo


class SelfIdentity:
    def __init__(self, install_root: Path) -> None:
        self._root = os.path.normcase(str(install_root.resolve()))

    def own_pids(self, processes: Mapping[int, ProcessInfo]) -> frozenset[int]:
        own = set(self._own_process_tree())
        own.update(pid for pid, process in processes.items() if self._lives_in_install_root(process))
        return frozenset(own)

    def _lives_in_install_root(self, process: ProcessInfo) -> bool:
        return self._root in os.path.normcase(process.exe or "") or self._root in os.path.normcase(process.cmdline)

    @staticmethod
    def _own_process_tree() -> set[int]:
        me = psutil.Process(os.getpid())
        try:
            return {me.pid, *(child.pid for child in me.children(recursive=True))}
        except psutil.Error:
            return {me.pid}
