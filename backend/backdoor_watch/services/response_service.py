"""Response actions with an audit trail: every action taken lands in the activity log."""

from backdoor_watch.actions.firewall_controller import FirewallController
from backdoor_watch.actions.persistence_remover import PersistenceRemover, describe_entry
from backdoor_watch.actions.process_controller import ProcessController
from backdoor_watch.actions.quarantine_vault import QuarantineVault
from backdoor_watch.collectors.defender_client import DefenderClient, ScanType
from backdoor_watch.domain.activity import ActivityEvent, ActivityKind
from backdoor_watch.domain.errors import NotFoundError
from backdoor_watch.monitoring.event_log import EventLog
from backdoor_watch.monitoring.system_state import SystemState


class ResponseService:
    def __init__(self, processes: ProcessController, vault: QuarantineVault, firewall: FirewallController,
                 remover: PersistenceRemover, defender: DefenderClient, state: SystemState,
                 events: EventLog) -> None:
        self._processes = processes
        self._vault = vault
        self._firewall = firewall
        self._remover = remover
        self._defender = defender
        self._state = state
        self._events = events

    def kill_process(self, pid: int, include_children: bool) -> str:
        name = self._process_name(pid)
        killed = self._processes.kill(pid, include_children)
        return self._audit(f"Killed {name} (PIDs {', '.join(map(str, killed))})", pid=pid, process_name=name)

    def suspend_process(self, pid: int) -> str:
        self._processes.suspend(pid)
        return self._audit(f"Suspended {self._process_name(pid)} (PID {pid})", pid=pid)

    def resume_process(self, pid: int) -> str:
        self._processes.resume(pid)
        return self._audit(f"Resumed {self._process_name(pid)} (PID {pid})", pid=pid)

    def suspend_tree(self, pid: int) -> list[int]:
        frozen = self._processes.suspend_tree(pid)
        self._audit(f"Suspended {self._process_name(pid)} and its children (PIDs {', '.join(map(str, frozen))})", pid=pid)
        return frozen

    def resume_processes(self, pids: list[int]) -> str:
        resumed = self._processes.resume_pids(pids)
        return self._audit(f"Resumed PIDs {', '.join(map(str, resumed)) or 'none (already gone)'}")

    def unblock_program(self, path: str) -> int:
        """Removes this tool's firewall blocks for a program the user has just decided to trust."""
        rules = [r for r in self._firewall.list_rules() if r.target.lower() == path.lower()]
        for rule in rules:
            self._firewall.remove_rule(rule.id)
        return len(rules)

    def quarantine_path(self, path: str, reason: str) -> str:
        item = self._vault.quarantine(path, reason)
        return self._audit(f"Quarantined {item.original_path}", sha256=item.sha256 or "", item_id=item.id)

    def quarantine_process_executable(self, pid: int) -> str:
        exe = self._processes.executable(pid)
        self._processes.kill(pid, include_children=True)
        return self.quarantine_path(exe, reason=f"Executable of PID {pid}")

    def restore_quarantined(self, item_id: str) -> str:
        return self._audit(f"Restored {self._vault.restore(item_id).original_path} from quarantine")

    def purge_quarantined(self, item_id: str) -> str:
        return self._audit(f"Permanently deleted quarantined {self._vault.purge(item_id).original_path}")

    def block_ip(self, ip: str) -> str:
        self._firewall.block_remote_ip(ip)
        return self._audit(f"Firewall: blocked all traffic to/from {ip}")

    def block_process_program(self, pid: int) -> str:
        return self.block_program(self._processes.executable(pid))

    def block_program(self, path: str) -> str:
        self._firewall.block_program(path)
        return self._audit(f"Firewall: blocked network access for {path}")

    def remove_firewall_rule(self, rule_id: str) -> str:
        self._firewall.remove_rule(rule_id)
        return self._audit(f"Firewall: removed rule {rule_id}")

    def remove_persistence(self, entry_id: str) -> str:
        entry = self._state.persistence_entry(entry_id)
        if entry is None:
            raise NotFoundError("Autostart entry not found; rescan and try again")
        message = self._remover.remove(entry)
        self._state.update(persistence=[e for e in self._state.current.persistence if e.id != entry_id])
        return self._audit(message, **describe_entry(entry))

    def enable_realtime_protection(self) -> str:
        self._defender.enable_realtime_protection()
        return self._audit("Turned on Microsoft Defender real-time protection")

    def start_defender_scan(self, scan_type: ScanType, path: str | None) -> str:
        self._defender.start_scan(scan_type, path)
        return self._audit(f"Started Microsoft Defender {scan_type}" + (f" of {path}" if path else ""))

    def _process_name(self, pid: int) -> str:
        process = self._state.current.processes.get(pid)
        return process.name if process else f"PID {pid}"

    def _audit(self, summary: str, pid: int | None = None, process_name: str | None = None,
               **details: str) -> str:
        self._events.append(ActivityEvent(kind=ActivityKind.ACTION_TAKEN, summary=summary, pid=pid,
                                          process_name=process_name, details=details))
        return summary
