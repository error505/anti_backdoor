import threading

from backdoor_watch.domain.errors import NotFoundError
from backdoor_watch.domain.guard import GuardAlert

_CAPACITY = 100


class AlertLog:
    """Recent guard alerts, newest first. The permanent record is the activity log."""

    def __init__(self) -> None:
        self._alerts: list[GuardAlert] = []
        self._lock = threading.Lock()

    def add(self, alert: GuardAlert) -> None:
        with self._lock:
            self._alerts = [alert, *self._alerts][:_CAPACITY]

    def all(self) -> list[GuardAlert]:
        with self._lock:
            return list(self._alerts)

    def get(self, alert_id: str) -> GuardAlert:
        with self._lock:
            found = next((a for a in self._alerts if a.id == alert_id), None)
        if found is None:
            raise NotFoundError("That alert is no longer in the list")
        return found

    def acknowledge(self, alert_id: str | None = None) -> None:
        with self._lock:
            for alert in self._alerts:
                if alert_id is None or alert.id == alert_id:
                    alert.acknowledged = True
