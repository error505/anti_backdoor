"""Background refresh steps. Each one reads a part of the system and publishes it to SystemState."""

import logging
from collections.abc import Callable

from backdoor_watch.analysis.ioc_rules import IocRules
from backdoor_watch.analysis.path_classifier import PathClassifier
from backdoor_watch.analysis.scan_context import ScanContext
from backdoor_watch.analysis.threat_scanner import ThreatScanner
from backdoor_watch.collectors.connection_collector import ConnectionCollector
from backdoor_watch.collectors.defender_client import DefenderClient
from backdoor_watch.collectors.persistence.persistence_scanner import PersistenceScanner
from backdoor_watch.collectors.process_collector import ProcessCollector
from backdoor_watch.domain.activity import ActivityEvent, ActivityKind
from backdoor_watch.monitoring.event_log import EventLog
from backdoor_watch.monitoring.self_identity import SelfIdentity
from backdoor_watch.monitoring.snapshot_diff import diff_connections, diff_persistence, diff_processes
from backdoor_watch.monitoring.system_state import Snapshot, SystemState
from backdoor_watch.monitoring.traffic_ledger import TrafficLedger

logger = logging.getLogger(__name__)


class SnapshotRefresher:
    def __init__(self, processes: ProcessCollector, connections: ConnectionCollector, ledger: TrafficLedger,
                 state: SystemState, events: EventLog, self_identity: SelfIdentity,
                 on_refresh: Callable[[Snapshot], None] = lambda snapshot: None) -> None:
        self._on_refresh = on_refresh
        self._processes = processes
        self._connections = connections
        self._ledger = ledger
        self._state = state
        self._events = events
        self._self_identity = self_identity
        self._has_baseline = False

    def refresh(self) -> None:
        processes = {p.pid: p for p in self._processes.snapshot()}
        connections = self._connections.snapshot({pid: p.name for pid, p in processes.items()})
        self._ledger.record(connections)
        previous = self._state.current
        own_pids = self._self_identity.own_pids(processes)
        if self._has_baseline:
            ours = own_pids | previous.own_pids
            events = (diff_processes(previous.processes, processes)
                      + diff_connections({c.key(): c for c in previous.connections}, {c.key(): c for c in connections}))
            self._events.extend(e for e in events if e.pid not in ours)
        else:
            self._events.append(ActivityEvent(kind=ActivityKind.MONITORING_STARTED,
                                              summary=f"Monitoring started: {len(processes)} processes, "
                                                      f"{len(connections)} sockets"))
            self._has_baseline = True
        self._state.update(processes=processes, connections=connections, own_pids=own_pids)
        self._notify(self._state.current)

    def _notify(self, snapshot: Snapshot) -> None:
        try:
            self._on_refresh(snapshot)
        except Exception:  # a guard fault must never stop monitoring
            logger.exception("snapshot listener failed")


class PersistenceRefresher:
    def __init__(self, scanner: PersistenceScanner, state: SystemState, events: EventLog) -> None:
        self._scanner = scanner
        self._state = state
        self._events = events

    def refresh(self) -> None:
        entries = self._scanner.scan()
        previous = self._state.current
        if previous.persistence_scanned:
            self._events.extend(diff_persistence({e.id: e for e in previous.persistence},
                                                 {e.id: e for e in entries}))
        self._state.update(persistence=entries, persistence_scanned=True)


class DefenderRefresher:
    def __init__(self, defender: DefenderClient, state: SystemState) -> None:
        self._defender = defender
        self._state = state

    def refresh(self) -> None:
        self._state.update(defender_threats=self._defender.threats(), defender_status=self._defender.status())


class FindingsRefresher:
    def __init__(self, scanner: ThreatScanner, rules: IocRules, state: SystemState) -> None:
        self._scanner = scanner
        self._rules = rules
        self._paths = PathClassifier(rules)
        self._state = state

    def refresh(self) -> None:
        snapshot = self._state.current
        context = ScanContext(processes=list(snapshot.processes.values()), connections=snapshot.connections,
                              persistence=snapshot.persistence, defender_threats=snapshot.defender_threats,
                              defender_status=snapshot.defender_status, malware_hits=snapshot.malware_hits,
                              rules=self._rules, paths=self._paths, own_pids=snapshot.own_pids)
        self._state.update(findings=self._scanner.scan(context))
