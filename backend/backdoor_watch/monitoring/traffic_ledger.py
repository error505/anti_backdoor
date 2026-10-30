"""Accumulates bytes sent/received per process and per remote address.

Totals include connections that have already closed, so a short burst of
exfiltration stays visible after the socket disappears.
"""

import threading
import time
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from backdoor_watch.domain.network import Connection, ConnectionKey, ProcessTraffic, RemoteTraffic


@dataclass
class _Totals:
    bytes_out: int = 0
    bytes_in: int = 0
    recent_out: int = 0
    recent_in: int = 0
    peers: set[str] = field(default_factory=set)
    label: str = ""

    def add(self, sent: int, received: int, peer: str) -> None:
        self.bytes_out += sent
        self.bytes_in += received
        self.recent_out += sent
        self.recent_in += received
        self.peers.add(peer)


class TrafficLedger:
    def __init__(self) -> None:
        self._last_counts: dict[ConnectionKey, tuple[int, int]] = {}
        self._by_process: dict[int, _Totals] = defaultdict(_Totals)
        self._by_remote: dict[str, _Totals] = defaultdict(_Totals)
        self._last_tick = time.monotonic()
        self._interval = 1.0
        self._lock = threading.Lock()

    def record(self, connections: Iterable[Connection]) -> None:
        with self._lock:
            now = time.monotonic()
            self._interval, self._last_tick = max(now - self._last_tick, 0.001), now
            for totals in (*self._by_process.values(), *self._by_remote.values()):
                totals.recent_out = totals.recent_in = 0
            seen = {}
            for conn in connections:
                if conn.bytes_out is None or conn.remote_ip is None:
                    continue
                key = conn.key()
                seen[key] = (conn.bytes_out, conn.bytes_in or 0)
                self._accumulate(conn, *self._delta(key, seen[key]))
            self._last_counts = seen

    def by_process(self) -> list[ProcessTraffic]:
        with self._lock:
            rows = [ProcessTraffic(pid=pid, process_name=t.label, bytes_out=t.bytes_out, bytes_in=t.bytes_in,
                                   rate_out=t.recent_out / self._interval, rate_in=t.recent_in / self._interval,
                                   remotes=sorted(t.peers)[:50])
                    for pid, t in self._by_process.items()]
        return sorted(rows, key=lambda r: r.bytes_out, reverse=True)

    def by_remote(self) -> list[RemoteTraffic]:
        with self._lock:
            rows = [RemoteTraffic(remote_ip=ip, remote_host=t.label or None, bytes_out=t.bytes_out,
                                  bytes_in=t.bytes_in, processes=sorted(t.peers))
                    for ip, t in self._by_remote.items()]
        return sorted(rows, key=lambda r: r.bytes_out, reverse=True)

    def _delta(self, key: ConnectionKey, counts: tuple[int, int]) -> tuple[int, int]:
        previous_out, previous_in = self._last_counts.get(key, (0, 0))
        sent, received = counts
        if sent < previous_out or received < previous_in:  # counters reset for a reused 4-tuple
            return sent, received
        return sent - previous_out, received - previous_in

    def _accumulate(self, conn: Connection, sent: int, received: int) -> None:
        remote = conn.remote_host or conn.remote_ip
        process = self._by_process[conn.pid or 0]
        process.label = conn.process_name or "unknown"
        process.add(sent, received, remote)
        peer = self._by_remote[conn.remote_ip]
        peer.label = conn.remote_host or peer.label
        peer.add(sent, received, f"{conn.process_name or 'unknown'} ({conn.pid})")
