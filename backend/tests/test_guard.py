import os
from pathlib import Path

import pytest

from backdoor_watch.domain.activity import ActivityEvent
from backdoor_watch.domain.errors import ActionFailedError
from backdoor_watch.domain.guard import GuardAlertKind, GuardConfig, GuardMode, TrustEntry, TrustKind
from backdoor_watch.domain.network import Connection
from backdoor_watch.domain.process import ProcessInfo, SignatureInfo
from backdoor_watch.guard.alert_log import AlertLog
from backdoor_watch.guard.guard_config_store import GuardConfigStore
from backdoor_watch.guard.guard_engine import GuardEngine
from backdoor_watch.guard.guard_rules import load_guard_rules
from backdoor_watch.guard.guard_service import GuardService
from backdoor_watch.guard.install_chain import Phase, classify_command
from backdoor_watch.guard.trust_policy import ProgramHasher, TrustPolicy
from backdoor_watch.monitoring.system_state import Snapshot, SystemState

RULES = load_guard_rules()
NPM = r'"C:\Program Files\nodejs\node.exe" "C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js"'
SIGNED = SignatureInfo(status="Valid", subject='CN="Some Vendor Ltd"')
UNSIGNED = SignatureInfo(status="NotSigned")
MICROSOFT = SignatureInfo(status="Valid", subject='CN="Microsoft Corporation"')


@pytest.mark.parametrize("cmdline, phase", [
    (f"{NPM} install", Phase.INSTALL),
    (f"{NPM} i --no-audit", Phase.INSTALL),
    (f"{NPM} --prefix app ci", Phase.INSTALL),
    (f"{NPM} run dev", Phase.RUN),
    (f"{NPM} start", Phase.RUN),
    (f"{NPM} view lodash", None),
    ("node server.js", None),
    ('cmd.exe /d /s /c "vite build"', None),
    (r"C:\tools\yarn.cmd", Phase.INSTALL),
    (r"C:\tools\yarn.cmd dev", Phase.RUN),
    ("npx create-react-app demo", Phase.RUN),
    ("pnpm dlx cowsay", Phase.RUN),
    ("npx @playwright/mcp@latest", Phase.RUN),
    ("python -m pip install requests", Phase.INSTALL),
])
def test_package_manager_commands_are_classified(cmdline, phase):
    assert classify_command(cmdline, RULES) is phase


def process(pid, ppid, name, cmdline="", signature=SIGNED, exe=None):
    return ProcessInfo(pid=pid, ppid=ppid, name=name, exe=exe or rf"C:\bin\{name}", cmdline=cmdline, username=None,
                       create_time=None, cpu_percent=None, memory_mb=None, signature=signature)


def connection(pid, ip="203.0.113.9", port=443, host=None):
    return Connection(protocol="tcp", family="ipv4", local_ip="10.0.0.2", local_port=50000 + pid, remote_ip=ip,
                      remote_port=port, state="ESTABLISHED", pid=pid, process_name="x", remote_host=host,
                      is_external=True)


def snapshot(processes, connections, own=frozenset()):
    return Snapshot(processes={p.pid: p for p in processes}, connections=connections, own_pids=own)


INSTALL_TREE = [
    process(10, 1, "cmd.exe", signature=MICROSOFT),
    process(11, 10, "node.exe", f"{NPM} install"),
    process(12, 11, "cmd.exe", 'cmd /c "node setup.js"', signature=MICROSOFT),
    process(13, 12, "node.exe", "node setup.js"),
]


def engine():
    return GuardEngine(RULES, TrustPolicy(ProgramHasher(lambda path: None)), frozenset({1224, 4444}))


def test_install_script_contacting_unknown_server_is_a_leak():
    config = GuardConfig(install_watch=GuardMode.CONTAIN)
    [violation] = engine().find(snapshot(INSTALL_TREE, [connection(13)]), config)
    assert violation.kind is GuardAlertKind.INSTALL_LEAK
    assert violation.containment_root == 11
    assert violation.chain == ["node.exe", "cmd.exe", "node.exe"]


def test_the_package_manager_itself_may_download_from_any_host():
    assert engine().find(snapshot(INSTALL_TREE, [connection(11)]), GuardConfig()) == []


def test_known_registries_and_user_allowed_hosts_are_not_leaks():
    registry = connection(13, host="registry.npmjs.org")
    assert engine().find(snapshot(INSTALL_TREE, [registry]), GuardConfig()) == []
    custom = connection(13, host="files.example.org")
    assert engine().find(snapshot(INSTALL_TREE, [custom]), GuardConfig(allowed_hosts=["example.org"])) == []
    by_ip = connection(13, ip="203.0.113.9")
    assert engine().find(snapshot(INSTALL_TREE, [by_ip]), GuardConfig(allowed_hosts=["203.0.113.9"])) == []


def test_running_a_project_only_matters_on_attacker_ports():
    run_tree = [process(11, 1, "node.exe", f"{NPM} run dev"), process(13, 11, "node.exe", "node server.js")]
    assert engine().find(snapshot(run_tree, [connection(13, port=443)]), GuardConfig()) == []
    [violation] = engine().find(snapshot(run_tree, [connection(13, port=1224)]), GuardConfig())
    assert violation.kind is GuardAlertKind.INSTALL_LEAK


def test_nothing_is_watched_when_the_install_watch_is_off():
    config = GuardConfig(install_watch=GuardMode.OFF)
    assert engine().find(snapshot(INSTALL_TREE, [connection(13)]), config) == []


def test_own_processes_are_never_reported():
    assert engine().find(snapshot(INSTALL_TREE, [connection(13)], own=frozenset({13})), GuardConfig()) == []


def test_lockdown_flags_only_untrusted_programs():
    tools = [process(20, 1, "stealer.exe", signature=UNSIGNED), process(21, 1, "vendor.exe"),
             process(22, 1, "svc.exe", signature=MICROSOFT), process(23, 1, "pending.exe", signature=None)]
    conns = [connection(p.pid) for p in tools]
    config = GuardConfig(install_watch=GuardMode.OFF, lockdown=GuardMode.CONTAIN)
    names = {v.process.name for v in engine().find(snapshot(tools, conns), config)}
    assert names == {"stealer.exe", "vendor.exe"}


def test_trusted_publisher_and_pinned_program_pass_lockdown(tmp_path: Path):
    exe = tmp_path / "tool.exe"
    exe.write_bytes(b"original")
    hasher = ProgramHasher(lambda path: (__import__("hashlib").sha256(Path(path).read_bytes()).hexdigest(), 1))
    policy = TrustPolicy(hasher)
    pinned = TrustEntry(id="a", kind=TrustKind.PROGRAM, value=str(exe), sha256=hasher.sha256(str(exe)), added_at=0)
    publisher = TrustEntry(id="b", kind=TrustKind.PUBLISHER, value="some vendor ltd", added_at=0)
    tool = process(30, 1, "tool.exe", signature=UNSIGNED, exe=str(exe))
    assert policy.assess(tool, [pinned]).value == "trusted"
    assert policy.assess(process(31, 1, "v.exe"), [publisher]).value == "trusted"
    exe.write_bytes(b"replaced by malware!")
    os.utime(exe, (1, 1))  # a changed file must be re-hashed, whatever the clock says
    assert policy.assess(tool, [pinned]).value == "untrusted"


class FakeResponse:
    def __init__(self, fail_suspend: bool = False) -> None:
        self.suspended, self.blocked_ips, self.blocked_programs, self.resumed = [], [], [], []
        self._fail = fail_suspend

    def suspend_tree(self, pid):
        if self._fail:
            raise ActionFailedError("Access denied")
        self.suspended.append(pid)
        return [pid, pid + 1]

    def block_ip(self, ip):
        self.blocked_ips.append(ip)

    def block_process_program(self, pid):
        self.blocked_programs.append(pid)

    def resume_processes(self, pids):
        self.resumed.extend(pids)
        return "resumed"

    def unblock_program(self, path):
        return 0


class FakeEvents:
    def __init__(self) -> None:
        self.items: list[ActivityEvent] = []

    def append(self, event):
        self.items.append(event)


def make_service(tmp_path, response, sirens):
    store = GuardConfigStore(tmp_path / "guard.json")
    hasher = ProgramHasher(lambda path: None)
    policy = TrustPolicy(hasher)
    service = GuardService(store, GuardEngine(RULES, policy, frozenset({1224})), policy, hasher, response,
                           SystemState(), FakeEvents(), AlertLog(), lambda: sirens.append("alarm"),
                           lambda: sirens.append("test"), RULES.allowed_host_suffixes)
    return service, store


def test_a_leak_sounds_the_alarm_suspends_the_tree_and_blocks_the_server(tmp_path):
    response, sirens = FakeResponse(), []
    service, _ = make_service(tmp_path, response, sirens)
    service.check(snapshot(INSTALL_TREE, [connection(13)]))
    [alert] = service.status().alerts
    assert (alert.action, response.suspended, response.blocked_ips) == ("suspended", [11], ["203.0.113.9"])
    assert sirens == ["alarm"]
    assert alert.contained_pids == [11, 12]


def test_the_same_leak_is_reported_once(tmp_path):
    response, sirens = FakeResponse(), []
    service, _ = make_service(tmp_path, response, sirens)
    for _ in range(3):
        service.check(snapshot(INSTALL_TREE, [connection(13)]))
    assert len(service.status().alerts) == 1


def test_alert_mode_warns_without_stopping_anything(tmp_path):
    response, sirens = FakeResponse(), []
    service, _ = make_service(tmp_path, response, sirens)
    service.set_modes(GuardMode.ALERT, GuardMode.OFF, True)
    service.check(snapshot(INSTALL_TREE, [connection(13)]))
    assert service.status().alerts[0].action == "alerted"
    assert response.suspended == [] and sirens == ["alarm"]


def test_a_failed_suspend_still_raises_the_alert(tmp_path):
    service, _ = make_service(tmp_path, FakeResponse(fail_suspend=True), [])
    service.check(snapshot(INSTALL_TREE, [connection(13)]))
    alert = service.status().alerts[0]
    assert alert.action == "alerted" and "Access denied" in alert.detail


def test_sound_can_be_switched_off(tmp_path):
    sirens = []
    service, _ = make_service(tmp_path, FakeResponse(), sirens)
    service.set_modes(GuardMode.CONTAIN, GuardMode.OFF, False)
    service.check(snapshot(INSTALL_TREE, [connection(13)]))
    assert sirens == []


def test_resume_unfreezes_what_the_guard_froze_and_acknowledges(tmp_path):
    response = FakeResponse()
    service, _ = make_service(tmp_path, response, [])
    service.check(snapshot(INSTALL_TREE, [connection(13)]))
    alert = service.status().alerts[0]
    service.resume(alert.id)
    assert response.resumed == [11, 12]
    assert service.status().unacknowledged == 0


def test_config_store_validates_and_persists(tmp_path):
    store = GuardConfigStore(tmp_path / "guard.json")
    store.allow_host(" Example.ORG ")
    assert GuardConfigStore(tmp_path / "guard.json").read().allowed_hosts == ["example.org"]
    with pytest.raises(Exception):
        store.allow_host("http://bad host/")


def test_a_child_detached_from_a_finished_install_is_still_watched():
    guard_engine = engine()
    guard_engine.find(snapshot(INSTALL_TREE, []), GuardConfig())
    orphan = [process(13, 12, "node.exe", "node setup.js")]  # npm and its shell have exited
    [violation] = guard_engine.find(snapshot(orphan, [connection(13)]), GuardConfig())
    assert violation.chain == ["npm (exited)", "node.exe"]
    assert violation.containment_root == 13


def test_an_install_inside_a_dev_command_keeps_the_strict_rule():
    nested = [process(11, 1, "node.exe", f"{NPM} run dev"), process(12, 11, "node.exe", f"{NPM} install"),
              process(13, 12, "node.exe", "node setup.js")]
    [violation] = engine().find(snapshot(nested, [connection(13)]), GuardConfig())
    assert violation.containment_root == 11 and "install" in violation.title
