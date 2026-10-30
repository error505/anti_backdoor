import threading
import time
from collections import deque

from backdoor_watch.domain.security_tools import CaptureRecord


class CaptureLog:
    def __init__(self, capacity: int = 5000) -> None:
        self._records: deque[CaptureRecord] = deque(maxlen=capacity)
        self._next_seq = 1
        self._lock = threading.Lock()

    def append(self, record: CaptureRecord) -> None:
        with self._lock:
            record.seq, record.timestamp = self._next_seq, time.time()
            self._next_seq += 1
            self._records.append(record)

    def since(self, seq: int, limit: int) -> list[CaptureRecord]:
        with self._lock:
            newer = [r for r in self._records if r.seq > seq]
        return newer[-limit:]
