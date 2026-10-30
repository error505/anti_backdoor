import os
from pathlib import Path

from backdoor_watch.domain.process import ProcessInfo
from backdoor_watch.monitoring.self_identity import SelfIdentity

ROOT = Path(__file__).resolve().parents[2]


def _process(pid: int, exe: str, cmdline: str) -> ProcessInfo:
    return ProcessInfo(pid=pid, ppid=1, name=os.path.basename(exe), exe=exe, cmdline=cmdline, username=None,
                       create_time=None, cpu_percent=None, memory_mb=None)


def test_launcher_powershell_running_start_script_is_ours():
    launcher = _process(500, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        rf"powershell.exe -NoExit -File {ROOT}\start.ps1")
    assert 500 in SelfIdentity(ROOT).own_pids({500: launcher})


def test_unrelated_node_process_is_not_ours():
    other = _process(600, r"C:\Program Files\nodejs\node.exe", r"node C:\Users\me\Downloads\repo\server.js")
    assert 600 not in SelfIdentity(ROOT).own_pids({600: other})


def test_current_process_is_always_ours():
    assert os.getpid() in SelfIdentity(ROOT).own_pids({})
