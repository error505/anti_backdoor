"""Fictional guard alerts for demo mode."""

import os
import time
import uuid

from backdoor_watch.domain.guard import GuardAlert, GuardAlertKind, GuardMode
from backdoor_watch.demo.demo_processes import C2_IP, SECOND_IP


def _alert(kind: GuardAlertKind, title: str, age: float, acknowledged: bool, **fields) -> GuardAlert:
    return GuardAlert(id=uuid.uuid4().hex, created_at=time.time() - age, kind=kind, title=title,
                      acknowledged=acknowledged, **fields)


def demo_guard_alerts() -> list[GuardAlert]:
    # BW_DEMO_ALARM=1 leaves them unacknowledged so the alarm banner can be shown (documentation screenshots).
    open_alerts = bool(os.environ.get("BW_DEMO_ALARM"))
    return [
        _alert(GuardAlertKind.INSTALL_LEAK,
               f"node.exe sent data to {C2_IP}:1224 during `npm` (install)", 40, not open_alerts,
               pid=2301, process_name="node.exe", exe=r"C:\Program Files\nodejs\node.exe",
               chain=["node.exe", "cmd.exe", "node.exe"], remote_ip=C2_IP, remote_port=1224, remote_host=None,
               action="suspended", detail="Suspended 3 process(es). Firewall block added.",
               contained_pids=[2290, 2299, 2301]),
        _alert(GuardAlertKind.UNTRUSTED_OUTBOUND,
               f"Untrusted program updater.exe connected to {SECOND_IP}:8080", 900, True,
               pid=3412, process_name="updater.exe", exe=r"C:\Users\demo\AppData\Local\Temp\updater.exe",
               chain=["updater.exe"], remote_ip=SECOND_IP, remote_port=8080, remote_host=None,
               action="suspended", detail="Suspended 1 process(es). Firewall block added.", contained_pids=[3412]),
    ]


DEMO_MODES = (GuardMode.CONTAIN, GuardMode.ALERT, True)
