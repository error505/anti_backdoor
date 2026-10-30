import logging
import threading
from collections.abc import Callable

logger = logging.getLogger(__name__)


class PeriodicJob:
    """Runs a callable on its own daemon thread at a fixed interval."""

    def __init__(self, name: str, interval: float, action: Callable[[], None]) -> None:
        self.name = name
        self._interval = interval
        self._action = action
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name=f"job-{name}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._action()
            except Exception:  # keep monitoring alive; the error is logged with its traceback
                logger.exception("periodic_job_failed", extra={"job": self.name})
            self._stop.wait(self._interval)
