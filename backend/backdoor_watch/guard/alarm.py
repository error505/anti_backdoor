import threading
import time

_PATTERN_HZ = (1100, 700, 1100, 700, 1100, 700)
_TONE_MS = 220


class AlarmSounder:
    """Plays a siren on the PC's speakers, so the alert is heard even when the dashboard tab is hidden."""

    def __init__(self, min_gap_seconds: float = 8.0) -> None:
        self._min_gap = min_gap_seconds
        self._last = 0.0
        self._lock = threading.Lock()

    def alarm(self) -> None:
        """Debounced: a burst of alerts sounds one siren."""
        with self._lock:
            if time.monotonic() - self._last < self._min_gap:
                return
            self._last = time.monotonic()
        self.test()

    def test(self) -> None:
        threading.Thread(target=self._play, name="guard-alarm", daemon=True).start()

    @staticmethod
    def _play() -> None:
        try:
            import winsound
            for frequency in _PATTERN_HZ:
                winsound.Beep(frequency, _TONE_MS)
        except (ImportError, RuntimeError):
            pass  # not Windows, or no audio device: the dashboard banner still shows the alert
