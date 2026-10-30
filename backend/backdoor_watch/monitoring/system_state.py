"""Latest snapshots shared between background jobs and API requests."""

import threading
from dataclasses import dataclass, field, replace

from backdoor_watch.domain.findings import Finding
from backdoor_watch.domain.malware import MalwareHit
from backdoor_watch.domain.network import Connection
from backdoor_watch.domain.persistence import PersistenceEntry
from backdoor_watch.domain.process import ProcessInfo
from backdoor_watch.domain.security_tools import DefenderStatus, DefenderThreat


@dataclass(frozen=True)
class Snapshot:
    processes: dict[int, ProcessInfo] = field(default_factory=dict)
    connections: list[Connection] = field(default_factory=list)
    persistence: list[PersistenceEntry] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    defender_threats: list[DefenderThreat] = field(default_factory=list)
    defender_status: DefenderStatus | None = None
    own_pids: frozenset[int] = frozenset()
    malware_hits: list[MalwareHit] = field(default_factory=list)
    persistence_scanned: bool = False


class SystemState:
    def __init__(self) -> None:
        self._snapshot = Snapshot()
        self._endpoint_owners: dict[tuple[str, int], tuple[int, str]] = {}
        self._lock = threading.Lock()

    @property
    def current(self) -> Snapshot:
        with self._lock:
            return self._snapshot

    def update(self, **changes) -> None:
        with self._lock:
            self._snapshot = replace(self._snapshot, **changes)
            if "connections" in changes:
                self._endpoint_owners = {(c.protocol, c.local_port): (c.pid, c.process_name or "?")
                                         for c in changes["connections"] if c.pid}

    def endpoint_owner(self, protocol: str, local_port: int) -> tuple[int, str] | None:
        with self._lock:
            return self._endpoint_owners.get((protocol, local_port))

    def persistence_entry(self, entry_id: str) -> PersistenceEntry | None:
        return next((e for e in self.current.persistence if e.id == entry_id), None)
