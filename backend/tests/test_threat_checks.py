import os

from backdoor_watch.analysis.checks.network_checks import check_suspicious_ports
from backdoor_watch.analysis.checks.persistence_checks import check_persistence
from backdoor_watch.analysis.checks.process_checks import check_command_lines
from backdoor_watch.analysis.ioc_rules import load_rules
from backdoor_watch.analysis.path_classifier import PathClassifier
from backdoor_watch.analysis.scan_context import ScanContext
from backdoor_watch.domain.findings import Severity
from backdoor_watch.domain.network import Connection
from backdoor_watch.domain.persistence import PersistenceEntry, PersistenceKind
from backdoor_watch.domain.process import ProcessInfo, SignatureInfo
from backdoor_watch.settings import Settings

RULES = load_rules(Settings(port=0, token="").rules_path)


def _context(processes=(), connections=(), persistence=(), own_pids=frozenset()) -> ScanContext:
    return ScanContext(processes=list(processes), connections=list(connections), persistence=list(persistence),
                       defender_threats=[], rules=RULES, paths=PathClassifier(RULES), own_pids=own_pids)


def _process(pid: int, name: str, cmdline: str) -> ProcessInfo:
    return ProcessInfo(pid=pid, ppid=1, name=name, exe=None, cmdline=cmdline, username=None,
                       create_time=None, cpu_percent=None, memory_mb=None)


def test_flags_invisibleferret_module_in_command_line():
    process = _process(10, "python.exe", r"python.exe C:\Users\me\.n2\pay")
    findings = check_command_lines(_context(processes=[process]))
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_ignores_own_processes():
    process = _process(10, "python.exe", r"python.exe C:\Users\me\.n2\pay")
    assert check_command_lines(_context(processes=[process], own_pids=frozenset({10}))) == []


def test_flags_external_connection_to_beavertail_port():
    conn = Connection(protocol="tcp", family="ipv4", local_ip="10.0.0.5", local_port=50000,
                      remote_ip="95.164.17.24", remote_port=1224, state="ESTABLISHED", pid=10,
                      process_name="node.exe", is_external=True)
    findings = check_suspicious_ports(_context(connections=[conn]))
    assert findings and findings[0].severity == Severity.HIGH


def test_run_key_launching_node_from_appdata_is_high():
    loader = os.path.join(os.environ["APPDATA"], "x", "loader.js")
    entry = PersistenceEntry(id="1", kind=PersistenceKind.RUN_KEY, name="updater", location="HKCU\\Run",
                             command=rf'"C:\Program Files\nodejs\node.exe" {loader}',
                             image_path=r"C:\Program Files\nodejs\node.exe",
                             signature=SignatureInfo(status="Valid", subject="CN=OpenJS Foundation"))
    findings = check_persistence(_context(persistence=[entry]))
    assert findings and findings[0].severity == Severity.HIGH


def test_microsoft_signed_entries_are_not_reported():
    entry = PersistenceEntry(id="2", kind=PersistenceKind.SERVICE, name="wuauserv", location="HKLM",
                             command="svchost.exe -k netsvcs", image_path=None, is_microsoft=True)
    assert check_persistence(_context(persistence=[entry])) == []
