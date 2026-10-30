from collections.abc import Callable, Sequence
from dataclasses import dataclass

from backdoor_watch.analysis.ioc_rules import IocRules
from backdoor_watch.analysis.path_classifier import PathClassifier
from backdoor_watch.domain.findings import Finding, FindingTarget, FindingTargetKind
from backdoor_watch.domain.network import Connection
from backdoor_watch.domain.persistence import PersistenceEntry
from backdoor_watch.domain.process import ProcessInfo
from backdoor_watch.domain.security_tools import DefenderStatus, DefenderThreat


@dataclass(frozen=True)
class ScanContext:
    processes: Sequence[ProcessInfo]
    connections: Sequence[Connection]
    persistence: Sequence[PersistenceEntry]
    defender_threats: Sequence[DefenderThreat]
    rules: IocRules
    paths: PathClassifier
    # The monitor spawns PowerShell helpers; they must not be reported as threats.
    own_pids: frozenset[int]
    defender_status: DefenderStatus | None = None


ThreatCheck = Callable[[ScanContext], list[Finding]]


def process_target(process: ProcessInfo) -> FindingTarget:
    return FindingTarget(kind=FindingTargetKind.PROCESS, ref=str(process.pid),
                         label=f"{process.name} (PID {process.pid})")


def file_target(path: str) -> FindingTarget:
    return FindingTarget(kind=FindingTargetKind.FILE, ref=path, label=path)


def remote_target(ip: str, host: str | None) -> FindingTarget:
    return FindingTarget(kind=FindingTargetKind.REMOTE_IP, ref=ip, label=host or ip)


def persistence_target(entry: PersistenceEntry) -> FindingTarget:
    return FindingTarget(kind=FindingTargetKind.PERSISTENCE, ref=entry.id,
                         label=f"{entry.kind.value}: {entry.name}")
