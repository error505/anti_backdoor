"""Persists the guard's modes, trusted programs and extra allowed hosts."""

import json
import threading
import time
import uuid
from pathlib import Path

from backdoor_watch.domain.errors import ActionRefusedError, NotFoundError
from backdoor_watch.domain.guard import GuardConfig, GuardMode, TrustEntry, TrustKind


class GuardConfigStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def read(self) -> GuardConfig:
        with self._lock:
            return self._load()

    def set_modes(self, install_watch: GuardMode, lockdown: GuardMode, sound: bool) -> GuardConfig:
        return self._change(lambda c: c.model_copy(update={"install_watch": install_watch, "lockdown": lockdown,
                                                           "sound": sound}))

    def add_trust(self, kind: TrustKind, value: str, sha256: str | None) -> GuardConfig:
        value = value.strip()
        if not value:
            raise ActionRefusedError("Nothing to trust: the name or path is empty")

        def add(config: GuardConfig) -> GuardConfig:
            kept = [t for t in config.trusted if not (t.kind is kind and t.value.lower() == value.lower())]
            entry = TrustEntry(id=uuid.uuid4().hex, kind=kind, value=value, sha256=sha256, added_at=time.time())
            return config.model_copy(update={"trusted": [*kept, entry]})
        return self._change(add)

    def remove_trust(self, entry_id: str) -> GuardConfig:
        def remove(config: GuardConfig) -> GuardConfig:
            kept = [t for t in config.trusted if t.id != entry_id]
            if len(kept) == len(config.trusted):
                raise NotFoundError("That trust entry no longer exists")
            return config.model_copy(update={"trusted": kept})
        return self._change(remove)

    def allow_host(self, host: str) -> GuardConfig:
        host = host.strip().lower().lstrip(".")
        if not host or "/" in host or " " in host:
            raise ActionRefusedError("Enter a host name such as example.com, or an IP address")
        return self._change(lambda c: c.model_copy(update={"allowed_hosts": sorted({*c.allowed_hosts, host})}))

    def disallow_host(self, host: str) -> GuardConfig:
        return self._change(lambda c: c.model_copy(update={"allowed_hosts": [h for h in c.allowed_hosts if h != host]}))

    def _change(self, edit) -> GuardConfig:
        with self._lock:
            updated = edit(self._load())
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(updated.model_dump_json(), encoding="utf-8")
            return updated

    def _load(self) -> GuardConfig:
        try:
            return GuardConfig.model_validate(json.loads(self._path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return GuardConfig()
