"""Loads fictional data into a freshly built service graph (demo mode only)."""

import time
from typing import TYPE_CHECKING

from backdoor_watch.demo.demo_findings import demo_findings, demo_persistence
from backdoor_watch.demo.demo_processes import C2_IP, DEMO_OWN_PIDS, demo_connections, demo_processes
from backdoor_watch.domain.activity import ActivityEvent, ActivityKind
from backdoor_watch.domain.ai import AiAnalysis, AiProvider, AiVerdict, AnalysisTrigger
from backdoor_watch.domain.ai_schedule import AiScheduleState
from backdoor_watch.domain.security_tools import DefenderStatus

if TYPE_CHECKING:
    from backdoor_watch.container import AppServices

_SAMPLE_ANALYSIS = """\
VERDICT: COMPROMISE

> **Sample output from demo mode.** The data analysed here is fictional.

## Verdict
**Signs of compromise.** A Python interpreter running from `.pyp` executes `.n2\\pay` and holds an
outbound connection to `203.0.113.45:1224`, a combination that matches the InvisibleFerret backdoor
delivered after a malicious Node.js "interview task".

## Items to act on
- **python.exe (PID 3377)**: launched by `node.exe` (PID 2301), which Code.exe started from the
  `interview-task` folder. Action: *Kill tree*, then quarantine `.pyp` and `.n2`.
- **203.0.113.45:1224**: raw IP on a port reported for this campaign. Action: *Block IP*.
- **Run key `SystemUpdateCheck`**: relaunches the same interpreter at every logon. Action: *Remove autostart*.
- **AnyDesk.exe**: installed from the user profile in the same time window. Action: kill and uninstall.

## Likely false positives
- `postgres.exe` and `node.exe` on 5173: normal development servers, unsigned or user-installed.

## Blind spots
TLS content is not visible, and credentials stolen in the first seconds cannot be seen here.

## Next steps
1. Rotate passwords, tokens and SSH keys from a clean device. 2. Move wallet funds to a new wallet.
3. Back up documents and reinstall Windows if you want certainty.
"""


def _events() -> list[ActivityEvent]:
    return [
        ActivityEvent(kind=ActivityKind.MONITORING_STARTED, summary="Monitoring started: 148 processes, 71 sockets"),
        ActivityEvent(kind=ActivityKind.PROCESS_STARTED, pid=2301, process_name="node.exe",
                      summary="Started node.exe (PID 2301)",
                      details={"cmdline": r"node C:\Users\demo\Downloads\interview-task\server\index.js", "ppid": "2290"}),
        ActivityEvent(kind=ActivityKind.PROCESS_STARTED, pid=3377, process_name="python.exe",
                      summary="Started python.exe (PID 3377)",
                      details={"cmdline": r"C:\Users\demo\.pyp\python.exe C:\Users\demo\.n2\pay", "ppid": "2301"}),
        ActivityEvent(kind=ActivityKind.CONNECTION_OPENED, pid=3377, process_name="python.exe",
                      summary=f"python.exe: Connected to {C2_IP}:1224", details={"remote_ip": C2_IP, "remote_port": "1224"}),
        ActivityEvent(kind=ActivityKind.PERSISTENCE_ADDED,
                      summary="NEW autostart entry: run_key 'SystemUpdateCheck'",
                      details={"command": r"C:\Users\demo\.pyp\pythonw.exe C:\Users\demo\.npl"}),
        ActivityEvent(kind=ActivityKind.LISTENER_OPENED, pid=3412, process_name="AnyDesk.exe",
                      summary="AnyDesk.exe: Opened listening port 0.0.0.0:7070"),
        ActivityEvent(kind=ActivityKind.ACTION_TAKEN, summary="AI Watch started: every 30 min for 8 h (at most 14 analyses, skip unchanged=True)"),
    ]


def _seed_traffic(services: "AppServices", connections: list) -> None:
    """Two samples one second apart, so the ledger shows totals plus plausible live rates (about 0.2 % per second)."""
    earlier = [c.model_copy(update={"bytes_out": int((c.bytes_out or 0) * 0.998), "bytes_in": int((c.bytes_in or 0) * 0.998)})
               if c.bytes_out is not None else c for c in connections]
    services.ledger.record(earlier)
    time.sleep(1.0)
    services.ledger.record(connections)


def seed_demo(services: "AppServices") -> None:
    now = time.time()
    connections = demo_connections()
    services.state.update(
        processes=demo_processes(), connections=connections, persistence=demo_persistence(),
        findings=demo_findings(), persistence_scanned=True, own_pids=DEMO_OWN_PIDS,
        defender_status=DefenderStatus(available=True, antivirus_enabled=True, real_time_protection=False,
                                       running_mode="Passive Mode", active_antivirus=["McAfee"], tamper_protected=True,
                                       signatures_updated="2026-10-29T23:54:17+01:00"),
    )
    _seed_traffic(services, connections)
    services.events.extend(_events())
    services.analysis_archive.store(AiAnalysis(
        provider=AiProvider.ANTHROPIC, model="claude-opus-5-5", effort="high", question=None,
        markdown=_SAMPLE_ANALYSIS, created_at=now - 600, context_chars=58_400,
        trigger=AnalysisTrigger.SCHEDULED, verdict=AiVerdict.COMPROMISE))
    services.ai_scheduler._store.replace(AiScheduleState(
        enabled=True, interval_minutes=30, skip_unchanged=True, started_at=now - 3 * 1800, ends_at=now + 5 * 3600,
        last_check_at=now - 600, last_run_at=now - 600, runs=3, skipped=5, last_status="Analysed: verdict compromise"))
