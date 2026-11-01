"""Keeps the last half hour of machine-wide readings so charts have a time axis."""

import threading
import time
from collections import Counter, deque

from backdoor_watch.domain.metrics import MetricSample
from backdoor_watch.monitoring.system_state import SystemState
from backdoor_watch.monitoring.traffic_ledger import TrafficLedger

SAMPLE_INTERVAL_SECONDS = 2.0
_CAPACITY = 900  # 30 minutes at one sample every 2 seconds


class MetricsRecorder:
    def __init__(self, state: SystemState, ledger: TrafficLedger) -> None:
        self._state = state
        self._ledger = ledger
        self._samples: deque[MetricSample] = deque(maxlen=_CAPACITY)
        self._lock = threading.Lock()

    def sample(self) -> None:
        snapshot = self._state.current
        traffic = self._ledger.by_process()
        severities = Counter(f.severity.value for f in snapshot.findings)
        external = sum(1 for c in snapshot.connections if c.is_external and c.state == "ESTABLISHED")
        listeners = sum(1 for c in snapshot.connections if c.state == "LISTEN" and c.exposure == "network")
        self.add(MetricSample(
            t=time.time(), rate_out=sum(r.rate_out for r in traffic), rate_in=sum(r.rate_in for r in traffic),
            external_connections=external, network_listeners=listeners, processes=len(snapshot.processes),
            critical=severities["critical"], high=severities["high"], medium=severities["medium"]))

    def add(self, sample: MetricSample) -> None:
        with self._lock:
            self._samples.append(sample)

    def samples(self) -> list[MetricSample]:
        with self._lock:
            return list(self._samples)
