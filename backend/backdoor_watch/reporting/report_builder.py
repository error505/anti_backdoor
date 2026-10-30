"""Assembles a point-in-time security report from the live monitoring state."""

import socket
from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import datetime, timezone

from backdoor_watch.domain.activity import ActivityKind
from backdoor_watch.domain.ai import AiAnalysis
from backdoor_watch.domain.ip_intel import IpIntel
from backdoor_watch.domain.network import Connection
from backdoor_watch.domain.process import ProcessInfo
from backdoor_watch.monitoring.event_log import EventLog
from backdoor_watch.monitoring.system_state import Snapshot, SystemState
from backdoor_watch.monitoring.traffic_ledger import TrafficLedger
from backdoor_watch.platform.privileges import is_admin
from backdoor_watch.reporting.redaction import Redactor
from backdoor_watch.reporting.report_model import ConnectionSummary, ProcessGroup, SecurityReport

_NOTABLE_EVENTS = {ActivityKind.PERSISTENCE_ADDED, ActivityKind.PERSISTENCE_REMOVED, ActivityKind.LISTENER_OPENED,
                   ActivityKind.ACTION_TAKEN, ActivityKind.MONITORING_STARTED}
_MAX_EVENTS = 300
_TOP_TRAFFIC = 40
_CMDLINE_LIMIT = 600


def _group_processes(snapshot: Snapshot) -> list[ProcessGroup]:
    grouped: dict[str, list[ProcessInfo]] = defaultdict(list)
    for process in snapshot.processes.values():
        if process.pid in snapshot.own_pids or (process.signature and process.signature.is_microsoft):
            continue
        grouped[(process.exe or process.name).lower()].append(process)
    return [_to_group(members, snapshot.processes) for members in grouped.values()]


def _to_group(members: list[ProcessInfo], processes: dict[int, ProcessInfo]) -> ProcessGroup:
    first = members[0]
    parent = processes.get(first.ppid or -1)
    return ProcessGroup(
        name=first.name, exe=first.exe, signer=first.signature.signer if first.signature else None,
        signature_status=first.signature.status if first.signature else None, instances=len(members),
        pids=[m.pid for m in members][:10], sample_cmdline=first.cmdline[:_CMDLINE_LIMIT],
        parent=f"{parent.name} ({parent.pid})" if parent else None,
    )


def _summarize(conn: Connection) -> ConnectionSummary:
    return ConnectionSummary(
        process=conn.process_name or "unknown", pid=conn.pid, local=f"{conn.local_ip}:{conn.local_port}",
        remote=f"{conn.remote_ip}:{conn.remote_port}" if conn.remote_ip else "", remote_host=conn.remote_host,
        state=conn.state, exposure=conn.exposure, bytes_out=conn.bytes_out, bytes_in=conn.bytes_in,
    )


class ReportBuilder:
    def __init__(self, state: SystemState, ledger: TrafficLedger, events: EventLog,
                 last_analysis: Callable[[], AiAnalysis | None],
                 server_intel: Callable[[list[str]], list[IpIntel]] = lambda ips: []) -> None:
        self._state = state
        self._ledger = ledger
        self._events = events
        self._last_analysis = last_analysis
        self._server_intel = server_intel

    def build(self, redact: bool, include_ai_analysis: bool = True) -> SecurityReport:
        snapshot = self._state.current
        own = snapshot.own_pids
        external = [c for c in snapshot.connections if c.is_external and c.state == "ESTABLISHED" and c.pid not in own]
        listeners = [c for c in snapshot.connections
                     if c.state == "LISTEN" and c.exposure == "network" and c.pid not in own]
        report = SecurityReport(
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            hostname=socket.gethostname(), is_admin=is_admin(), redacted=redact,
            summary={"processes": len(snapshot.processes), "external_connections": len(external),
                     "network_listeners": len(listeners), "autostart_entries": len(snapshot.persistence),
                     **{f"findings_{k}": v for k, v in Counter(f.severity.value for f in snapshot.findings).items()}},
            findings=snapshot.findings, defender=snapshot.defender_status, defender_threats=snapshot.defender_threats,
            non_microsoft_processes=_group_processes(snapshot),
            external_connections=[_summarize(c) for c in external],
            network_listeners=[_summarize(c) for c in listeners],
            autostart_non_microsoft=[e for e in snapshot.persistence if not e.is_microsoft],
            traffic_by_process=self._ledger.by_process()[:_TOP_TRAFFIC],
            traffic_by_remote=self._ledger.by_remote()[:_TOP_TRAFFIC],
            remote_server_intel=self._server_intel([c.remote_ip for c in external if c.remote_ip]),
            notable_events=[e for e in self._events.since(0, 10_000) if e.kind in _NOTABLE_EVENTS][-_MAX_EVENTS:],
            ai_analysis=self._last_analysis() if include_ai_analysis else None,
        )
        if not redact:
            return report
        return SecurityReport.model_validate(Redactor().value(report.model_dump(mode="json")))
