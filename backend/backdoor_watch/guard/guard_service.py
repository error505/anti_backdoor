"""Turns guard violations into alerts, an audible alarm and (when the user chose it) containment.

Containment suspends instead of killing: a false alarm can be resumed, a real one killed after a look.
"""

import os
import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Callable

from backdoor_watch.domain.activity import ActivityEvent, ActivityKind
from backdoor_watch.domain.errors import ActionRefusedError, BackdoorWatchError
from backdoor_watch.domain.guard import (GuardAlert, GuardAlertKind, GuardConfig, GuardMode, GuardStatus,
                                         SeenProgram, TrustKind)
from backdoor_watch.guard.alert_log import AlertLog
from backdoor_watch.guard.guard_config_store import GuardConfigStore
from backdoor_watch.guard.guard_engine import GuardEngine, Violation
from backdoor_watch.guard.trust_policy import ProgramHasher, Trust, TrustPolicy
from backdoor_watch.monitoring.event_log import EventLog
from backdoor_watch.monitoring.system_state import Snapshot, SystemState
from backdoor_watch.services.response_service import ResponseService

_SEEN_REMOTES = 3


class GuardService:
    def __init__(self, store: GuardConfigStore, engine: GuardEngine, policy: TrustPolicy, hasher: ProgramHasher,
                 response: ResponseService, state: SystemState, events: EventLog, alerts: AlertLog,
                 sound_alarm: Callable[[], None], test_alarm: Callable[[], None],
                 default_allowed_hosts: tuple[str, ...]) -> None:
        self._test_alarm = test_alarm
        self._store = store
        self._engine = engine
        self._policy = policy
        self._hasher = hasher
        self._response = response
        self._state = state
        self._events = events
        self._alerts = alerts
        self._sound_alarm = sound_alarm
        self.default_allowed_hosts = default_allowed_hosts
        self._handled: set[tuple] = set()
        self._lock = threading.Lock()

    # --- called after every snapshot refresh ---------------------------------------------------------------

    def check(self, snapshot: Snapshot) -> None:
        config = self._store.read()
        if config.install_watch is GuardMode.OFF and config.lockdown is GuardMode.OFF:
            return
        for violation in self._engine.find(snapshot, config):
            key = (violation.kind, violation.process.pid, violation.connection.remote_ip)
            with self._lock:
                if key in self._handled:
                    continue
                self._handled.add(key)
            self._raise(violation, config)
        self._forget_finished(snapshot)

    def _raise(self, violation: Violation, config: GuardConfig) -> None:
        mode = config.install_watch if violation.kind is GuardAlertKind.INSTALL_LEAK else config.lockdown
        action, detail, pids = ("alerted", "Alert only: nothing was stopped.", [])
        if mode is GuardMode.CONTAIN:
            action, detail, pids = self._contain(violation)
        alert = self._to_alert(violation, action, detail, pids)
        self._alerts.add(alert)
        self._events.append(ActivityEvent(kind=ActivityKind.ACTION_TAKEN, summary=f"GUARD: {alert.title}. {detail}",
                                          pid=alert.pid, process_name=alert.process_name,
                                          details={"remote": f"{alert.remote_ip}:{alert.remote_port}",
                                                   "action": action}))
        if config.sound:
            self._sound_alarm()

    def _contain(self, violation: Violation) -> tuple[str, str, list[int]]:
        try:
            frozen = self._response.suspend_tree(violation.containment_root)
        except BackdoorWatchError as exc:
            return "alerted", f"Could not stop it: {exc}", []
        return "suspended", f"Suspended {len(frozen)} process(es). {self._block(violation)}", frozen

    def _block(self, violation: Violation) -> str:
        try:
            if violation.kind is GuardAlertKind.INSTALL_LEAK:
                self._response.block_ip(violation.connection.remote_ip or "")
            else:
                self._response.block_process_program(violation.process.pid)
            return "Firewall block added."
        except BackdoorWatchError:
            return "Firewall block not added (needs administrator)."

    @staticmethod
    def _to_alert(violation: Violation, action: str, detail: str, pids: list[int]) -> GuardAlert:
        process, conn = violation.process, violation.connection
        return GuardAlert(id=uuid.uuid4().hex, created_at=time.time(), kind=violation.kind, title=violation.title,
                          pid=process.pid, process_name=process.name, exe=process.exe, chain=violation.chain,
                          remote_ip=conn.remote_ip or "", remote_port=conn.remote_port, remote_host=conn.remote_host,
                          action=action, detail=detail, contained_pids=pids)

    def _forget_finished(self, snapshot: Snapshot) -> None:
        with self._lock:
            self._handled = {key for key in self._handled if key[1] in snapshot.processes}

    # --- queries ---------------------------------------------------------------------------------------------

    def status(self) -> GuardStatus:
        config = self._store.read()
        alerts = self._alerts.all()
        return GuardStatus(config=config, default_allowed_hosts=list(self.default_allowed_hosts), alerts=alerts,
                           unacknowledged=sum(not a.acknowledged for a in alerts),
                           seen_programs=self._seen_programs(self._state.current, config))

    def _seen_programs(self, snapshot: Snapshot, config: GuardConfig) -> list[SeenProgram]:
        grouped: dict[str, list] = defaultdict(list)
        for conn in snapshot.connections:
            process = snapshot.processes.get(conn.pid) if conn.pid else None
            if (process and process.pid not in snapshot.own_pids and conn.is_external and conn.state == "ESTABLISHED"
                    and self._policy.assess(process, config.trusted) is Trust.UNTRUSTED):
                grouped[(process.exe or process.name).lower()].append((process, conn))
        return sorted((self._seen(rows) for rows in grouped.values()), key=lambda s: -s.connections)

    @staticmethod
    def _seen(rows: list) -> SeenProgram:
        process = rows[0][0]
        remotes = list(dict.fromkeys(c.remote_host or c.remote_ip or "?" for _, c in rows))[:_SEEN_REMOTES]
        return SeenProgram(name=process.name, exe=process.exe,
                           signer=process.signature.signer if process.signature else None,
                           validly_signed=bool(process.signature and process.signature.is_valid),
                           connections=len(rows), remotes=remotes)

    # --- user decisions --------------------------------------------------------------------------------------

    def set_modes(self, install_watch: GuardMode, lockdown: GuardMode, sound: bool) -> GuardConfig:
        return self._store.set_modes(install_watch, lockdown, sound)

    def trust_program(self, path: str) -> GuardConfig:
        if not os.path.isfile(path):
            raise ActionRefusedError(f"{path} is not a file on this PC")
        config = self._store.add_trust(TrustKind.PROGRAM, path, self._hasher.sha256(path))
        self._lift_block(path)
        return config

    def trust_publisher(self, name: str) -> GuardConfig:
        return self._store.add_trust(TrustKind.PUBLISHER, name, None)

    def trust_signed_programs_seen(self) -> int:
        snapshot, config = self._state.current, self._store.read()
        publishers = {s.signer for s in self._seen_programs(snapshot, config) if s.validly_signed and s.signer}
        for publisher in publishers:
            self._store.add_trust(TrustKind.PUBLISHER, publisher, None)
        return len(publishers)

    def untrust(self, entry_id: str) -> GuardConfig:
        return self._store.remove_trust(entry_id)

    def allow_host(self, host: str) -> GuardConfig:
        return self._store.allow_host(host)

    def disallow_host(self, host: str) -> GuardConfig:
        return self._store.disallow_host(host)

    def acknowledge(self, alert_id: str | None) -> None:
        self._alerts.acknowledge(alert_id)

    def resume(self, alert_id: str) -> str:
        """The user judged it a false alarm: unfreeze what the guard froze."""
        alert = self._alerts.get(alert_id)
        message = self._response.resume_processes(alert.contained_pids)
        self._alerts.acknowledge(alert_id)
        return message

    def load_alerts(self, alerts: list[GuardAlert]) -> None:
        """Demo mode only: shows fictional alerts without running any detection."""
        for alert in reversed(alerts):
            self._alerts.add(alert)

    def test_alarm(self) -> None:
        self._test_alarm()

    def _lift_block(self, path: str) -> None:
        try:
            self._response.unblock_program(path)
        except BackdoorWatchError:
            pass  # no admin rights, or the rule is already gone
