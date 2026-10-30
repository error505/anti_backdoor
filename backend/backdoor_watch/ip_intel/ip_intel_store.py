"""Remembers lookups on disk so an address is only sent to the provider once a month."""

import json
import threading
import time
from pathlib import Path

from backdoor_watch.domain.ip_intel import IpIntel

_TTL_SECONDS = 30 * 24 * 3600


class IpIntelStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._entries: dict[str, dict] = self._load()

    def get(self, ip: str) -> IpIntel | None:
        with self._lock:
            entry = self._entries.get(ip)
        if not entry or time.time() - entry["at"] > _TTL_SECONDS:
            return None
        return IpIntel.model_validate(entry["intel"])

    def put(self, intel: IpIntel) -> None:
        with self._lock:
            self._entries[intel.ip] = {"at": time.time(), "intel": intel.model_dump(mode="json")}
            self._save()

    def count(self) -> int:
        with self._lock:
            return len(self._entries)

    def _load(self) -> dict[str, dict]:
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._entries), encoding="utf-8")
