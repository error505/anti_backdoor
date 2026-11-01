"""Fictional 15-minute history for demo mode: steady browsing traffic plus a burst out to the fake C2 server."""

import math
import random
import time

from backdoor_watch.domain.activity import ActivityEvent, ActivityKind
from backdoor_watch.domain.metrics import MetricSample
from backdoor_watch.monitoring.metrics_recorder import SAMPLE_INTERVAL_SECONDS

_POINTS = 450
_BURST = range(300, 330)  # about 10 minutes in, for a minute


def demo_metric_samples() -> list[MetricSample]:
    rng, now = random.Random(7), time.time()
    samples = []
    for i in range(_POINTS):
        wave = 1 + 0.5 * math.sin(i / 14)
        burst = 1 + (28 * math.sin((i - _BURST.start) / len(_BURST) * math.pi) if i in _BURST else 0)
        samples.append(MetricSample(
            t=now - (_POINTS - i) * SAMPLE_INTERVAL_SECONDS,
            rate_out=max(0.0, 9_000 * wave * burst * rng.uniform(0.6, 1.4)),
            rate_in=max(0.0, 62_000 * wave * rng.uniform(0.5, 1.5)),
            external_connections=7 + int(2 * math.sin(i / 20)) + (1 if i > _BURST.start else 0),
            network_listeners=4, processes=140 + int(5 * math.sin(i / 30)) + i // 90,
            critical=2 if i > _BURST.start else 0, high=2, medium=1))
    return samples


_KINDS = [(ActivityKind.PROCESS_STARTED, 5), (ActivityKind.PROCESS_EXITED, 4), (ActivityKind.CONNECTION_OPENED, 6),
          (ActivityKind.CONNECTION_CLOSED, 5), (ActivityKind.LISTENER_OPENED, 1), (ActivityKind.PERSISTENCE_ADDED, 1)]


def _summary(rng: random.Random) -> str:
    return rng.choice(["Started helper.exe", "Started node.exe", "Connected to 142.250.185.14:443", "Connected to 52.112.0.5:443"])


def demo_history_events() -> list[ActivityEvent]:
    """Background noise over the last 30 minutes, with a cluster of suspicious activity around the burst."""
    rng, now = random.Random(11), time.time()
    kinds = [kind for kind, weight in _KINDS for _ in range(weight)]
    events = [ActivityEvent(kind=rng.choice(kinds), summary=_summary(rng), timestamp=now - rng.uniform(30, 1780))
              for _ in range(170)]
    burst_at = now - (_POINTS - _BURST.start) * SAMPLE_INTERVAL_SECONDS
    events += [ActivityEvent(kind=rng.choice(kinds[:12]), summary=_summary(rng), timestamp=burst_at + rng.uniform(-40, 60))
               for _ in range(40)]
    return events
