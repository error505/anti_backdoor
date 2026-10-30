"""Stores the Flockion connection. The flk_ runtime key is DPAPI-encrypted and never returned to the UI."""

import base64
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from backdoor_watch.domain.errors import ActionFailedError, ActionRefusedError
from backdoor_watch.domain.flockion import (AGENT_ID_PATTERN, BODY_FIELD_PATTERN, DEFAULT_AUTH_HEADER,
                                            DEFAULT_AUTH_SCHEME, DEFAULT_BASE_URL, DEFAULT_BODY_FIELD,
                                            HEADER_NAME_PATTERN, FlockionSettingsView)
from backdoor_watch.platform import dpapi


@dataclass(frozen=True)
class FlockionConnection:
    agent_id: str
    base_url: str
    auth_header: str
    auth_scheme: str
    body_field: str
    api_key: str | None

    def run_url(self) -> str:
        if not self.agent_id:
            raise ActionRefusedError("Enter the Flockion agent ID first")
        return f"{self.base_url}/api/v1/api-access/agent/{self.agent_id}/run"


def _validated_base_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.query or parsed.fragment:
        raise ActionRefusedError("The Flockion API URL must be a plain https:// address")
    return f"https://{parsed.netloc}"


def _require(pattern, value: str, what: str) -> str:
    if not pattern.match(value):
        raise ActionRefusedError(f"Invalid {what}")
    return value


class FlockionSettingsStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def connection(self) -> FlockionConnection:
        raw = self._read()
        encrypted = raw.get("key")
        return FlockionConnection(
            agent_id=raw.get("agent_id", ""), base_url=raw.get("base_url", DEFAULT_BASE_URL),
            auth_header=raw.get("auth_header", DEFAULT_AUTH_HEADER), auth_scheme=raw.get("auth_scheme", DEFAULT_AUTH_SCHEME),
            body_field=raw.get("body_field", DEFAULT_BODY_FIELD),
            api_key=dpapi.unprotect(base64.b64decode(encrypted)).decode("utf-8") if encrypted else None)

    def view(self) -> FlockionSettingsView:
        c = self.connection()
        return FlockionSettingsView(agent_id=c.agent_id, base_url=c.base_url, auth_header=c.auth_header,
                                    auth_scheme=c.auth_scheme, body_field=c.body_field,
                                    has_stored_key=c.api_key is not None,
                                    key_hint=f"…{c.api_key[-4:]}" if c.api_key else None)

    def save(self, agent_id: str, base_url: str, auth_header: str, auth_scheme: str, body_field: str,
             api_key: str | None) -> None:
        """api_key None keeps the stored key; an empty string deletes it."""
        record = {
            "agent_id": _require(AGENT_ID_PATTERN, agent_id.strip(), "agent ID") if agent_id.strip() else "",
            "base_url": _validated_base_url(base_url or DEFAULT_BASE_URL),
            "auth_header": _require(HEADER_NAME_PATTERN, auth_header.strip(), "auth header name"),
            "auth_scheme": auth_scheme.strip(),
            "body_field": _require(BODY_FIELD_PATTERN, body_field.strip(), "request field name"),
        }
        with self._lock:
            raw = self._read()
            raw.update(record)
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
