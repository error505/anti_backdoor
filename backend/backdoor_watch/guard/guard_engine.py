"""Decides which live connections break the guard's rules. Reads a snapshot, changes nothing."""

from collections.abc import Mapping
from dataclasses import dataclass

from backdoor_watch.domain.guard import GuardAlertKind, GuardConfig, GuardMode
from backdoor_watch.domain.network import Connection
from backdoor_watch.domain.process import ProcessInfo
from backdoor_watch.guard.guard_rules import GuardRules
from backdoor_watch.guard.install_chain import (Lineage, Phase, chain_names, find_package_manager_runs,
                                                update_lineage)
from backdoor_watch.guard.trust_policy import Trust, TrustPolicy
from backdoor_watch.monitoring.system_state import Snapshot

_LIVE_STATES = frozenset({"ESTABLISHED", "SYN_SENT"})


@dataclass(frozen=True)
class Violation:
    kind: GuardAlertKind
    process: ProcessInfo
    connection: Connection
    chain: list[str]
    containment_root: int
    title: str


def host_allowed(connection: Connection, allowed: list[str]) -> bool:
    host = (connection.remote_host or "").lower().rstrip(".")
    for entry in allowed:
        if connection.remote_ip == entry or (host and (host == entry or host.endswith(f".{entry}"))):
            return True
    return False


def _destination(connection: Connection) -> str:
    return f"{connection.remote_host or connection.remote_ip}:{connection.remote_port}"


class GuardEngine:
    def __init__(self, rules: GuardRules, policy: TrustPolicy, command_and_control_ports: frozenset[int]) -> None:
        self._rules = rules
        self._policy = policy
        self._c2_ports = command_and_control_ports
        self._lineage: dict[int, Lineage] = {}  # only touched from the snapshot thread

    def find(self, snapshot: Snapshot, config: GuardConfig) -> list[Violation]:
        processes = snapshot.processes
        watching = config.install_watch is not GuardMode.OFF
        self._lineage = update_lineage(self._lineage, processes, find_package_manager_runs(processes, self._rules)
                                       if watching else {})
        allowed = [*config.allowed_hosts, *self._rules.allowed_host_suffixes]
        found = []
        for connection in snapshot.connections:
            process = processes.get(connection.pid) if connection.pid else None
            if process is None or process.pid in snapshot.own_pids or not self._is_outbound(connection):
                continue
            violation = (self._install_leak(process, connection, processes, allowed)
                         or self._untrusted_outbound(process, connection, config, processes))
            if violation:
                found.append(violation)
        return found

    @staticmethod
    def _is_outbound(connection: Connection) -> bool:
        return bool(connection.is_external and connection.remote_ip and not connection.is_listener
                    and connection.state in _LIVE_STATES)

    def _install_leak(self, process: ProcessInfo, connection: Connection, processes: Mapping[int, ProcessInfo],
                      allowed: list[str]) -> Violation | None:
        lineage = self._lineage.get(process.pid)
        if lineage is None or lineage.root_pid == process.pid or host_allowed(connection, allowed):
            return None  # not from a package manager, or the package manager's own registry download
        if lineage.phase is Phase.RUN and connection.remote_port not in self._c2_ports:
            return None  # a dev server talks to many hosts; only known attacker ports count while running
        title = (f"{process.name} sent data to {_destination(connection)} "
                 f"during `{lineage.root_name}` ({lineage.phase.value})")
        root = lineage.root_pid if lineage.root_pid in processes else process.pid
        return Violation(GuardAlertKind.INSTALL_LEAK, process, connection,
                         chain_names(process.pid, lineage, processes), root, title)

    def _untrusted_outbound(self, process: ProcessInfo, connection: Connection, config: GuardConfig,
                            processes: Mapping[int, ProcessInfo]) -> Violation | None:
        if config.lockdown is GuardMode.OFF or self._policy.assess(process, config.trusted) is not Trust.UNTRUSTED:
            return None
        title = f"Untrusted program {process.name} connected to {_destination(connection)}"
        return Violation(GuardAlertKind.UNTRUSTED_OUTBOUND, process, connection,
                         [process.name], process.pid, title)
