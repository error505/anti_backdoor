"""In-memory ring buffer of activity events, mirrored to a daily JSONL file.

The file is the forensic record: it survives restarts and can be handed to an
incident responder.
"""

import threading
import time
from collections import deque
from collections.abc import Iterable
from pathlib import Path

from backdoor_watch.domain.activity import ActivityEvent


class EventLog:
    def __init__(self, log_dir: Path, capacity: int = 10_000) -> None:
        self._log_dir = log_dir
        self._events: deque[ActivityEvent] = deque(maxlen=capacity)
        self._next_seq = 1
        self._lock = threading.Lock()
        log_dir.mkdir(parents=True, exist_ok=True)

    def append(self, event: ActivityEvent) -> None:
        self.extend([event])

    def extend(self, events: Iterable[ActivityEvent]) -> None:
        lines = []
        with self._lock:
            for event in events:
                event.seq, event.timestamp = self._next_seq, time.time()
                self._next_seq += 1
                self._events.append(event)
                lines.append(event.model_dump_json())
        if lines:
            self._write(lines)

    def since(self, seq: int, limit: int) -> list[ActivityEvent]:
        with self._lock:
            newer = [e for e in self._events if e.seq > seq]
        return newer[-limit:]

    def _write(self, lines: list[str]) -> None:
        path = self._log_dir / f"activity-{time.strftime('%Y%m%d')}.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
