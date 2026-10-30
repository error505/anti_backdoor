"""Stores the Flockion connection. The flk_ runtime key is DPAPI-encrypted and never returned to the UI."""

import base64
import json
import threading
from dataclasses import dataclass
from pathlib import Path

from backdoor_watch.domain.errors import ActionFailedError, ActionRefusedError
from backdoor_watch.domain.flockion import (DEFAULT_ENDPOINT, KEY_PATTERN, FlockionEndpoint, FlockionSettingsView,
                                            parse_endpoint)
from backdoor_watch.platform import dpapi


@dataclass(frozen=True)
class FlockionConnection:
    endpoint: str
    api_key: str | None

    def parsed(self) -> FlockionEndpoint:
        return parse_endpoint(self.endpoint)

    def require_key(self) -> str:
        if not self.api_key:
            raise ActionRefusedError("Save the Flockion runtime key (starts with flk_) first")
        return self.api_key


class FlockionSettingsStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def connection(self) -> FlockionConnection:
        raw = self._read()
        encrypted = raw.get("key")
        api_key = dpapi.unprotect(base64.b64decode(encrypted)).decode("utf-8") if encrypted else None
        return FlockionConnection(endpoint=raw.get("endpoint", DEFAULT_ENDPOINT), api_key=api_key)

    def view(self) -> FlockionSettingsView:
        c = self.connection()
        return FlockionSettingsView(endpoint=c.endpoint, has_stored_key=c.api_key is not None,
                                    key_hint=f"…{c.api_key[-4:]}" if c.api_key else None)

    def save(self, endpoint: str, api_key: str | None) -> None:
        """api_key None keeps the stored key; an empty string deletes it."""
        parse_endpoint(endpoint)
        if api_key and not KEY_PATTERN.match(api_key.strip()):
            raise ActionRefusedError("Enter a Flockion runtime API key. It starts with flk_")
        with self._lock:
            raw = self._read()
            raw["endpoint"] = endpoint.strip()
            if api_key == "":
                raw.pop("key", None)
            elif api_key is not None:
                raw["key"] = self._encrypt(api_key.strip())
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(raw, indent=2), encoding="utf-8")

    def _read(self) -> dict:
        return json.loads(self._path.read_text(encoding="utf-8")) if self._path.is_file() else {}

    @staticmethod
    def _encrypt(api_key: str) -> str:
        try:
            return base64.b64encode(dpapi.protect(api_key.encode("utf-8"))).decode("ascii")
        except OSError as exc:
            raise ActionFailedError(f"Could not encrypt the key with Windows DPAPI: {exc}") from exc
