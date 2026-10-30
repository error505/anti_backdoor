"""Decides which addresses may be looked up, serves them from cache and records the user's opt-in.

Off by default: looking up an address tells the provider you are talking to it.
"""

import json
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Protocol

from backdoor_watch.domain.addresses import is_public_address, strip_scope
from backdoor_watch.domain.errors import BackdoorWatchError
from backdoor_watch.domain.ip_intel import IpIntel, IpIntelSettingsView
from backdoor_watch.ip_intel.ip_intel_store import IpIntelStore
from backdoor_watch.ip_intel.reverse_dns import reverse_dns

MAX_ADDRESSES_PER_CALL = 50
_WORKERS = 4


class IpProvider(Protocol):
    name: str

    def lookup(self, ip: str) -> IpIntel: ...


class IpIntelService:
    def __init__(self, provider: IpProvider, store: IpIntelStore, settings_path: Path,
                 may_look_up: Callable[[str], bool] = is_public_address,
                 resolve_reverse: Callable[[str], str | None] = reverse_dns) -> None:
        self._provider = provider
        self._store = store
        self._settings_path = settings_path
        self._may_look_up = may_look_up
        self._resolve_reverse = resolve_reverse
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        try:
            return bool(json.loads(self._settings_path.read_text(encoding="utf-8")).get("enabled"))
        except (OSError, ValueError):
            return False

    def set_enabled(self, enabled: bool) -> None:
        with self._lock:
            self._settings_path.parent.mkdir(parents=True, exist_ok=True)
            self._settings_path.write_text(json.dumps({"enabled": enabled}), encoding="utf-8")

    def view(self) -> IpIntelSettingsView:
        return IpIntelSettingsView(enabled=self.enabled, provider=self._provider.name,
                                   cached_addresses=self._store.count())

    def lookup(self, ips: list[str]) -> list[IpIntel]:
        """Cached answers always; new addresses are fetched only when the user has opted in."""
        wanted = self._eligible(ips)
        known = {ip: hit for ip in wanted if (hit := self._store.get(ip))}
        missing = [ip for ip in wanted if ip not in known]
        if missing and self.enabled:
            with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
                known.update(zip(missing, pool.map(self._fetch, missing)))
        return [known[ip] for ip in wanted if ip in known]

    def _eligible(self, ips: list[str]) -> list[str]:
        unique = dict.fromkeys(strip_scope(ip) for ip in ips)
        return [ip for ip in unique if self._may_look_up(ip)][:MAX_ADDRESSES_PER_CALL]

    def _fetch(self, ip: str) -> IpIntel:
        try:
            intel = self._provider.lookup(ip)
        except BackdoorWatchError as exc:
            return IpIntel(ip=ip, error=str(exc))  # not cached: a rate limit or outage should be retried
        intel.reverse_dns = self._resolve_reverse(ip)
        self._store.put(intel)
        return intel
