"""Persists the AI provider choice. API keys are DPAPI-encrypted at rest and never returned to the UI."""

import base64
import json
import threading
from dataclasses import dataclass
from pathlib import Path

from backdoor_watch.domain.ai import PROVIDER_OPTIONS, AiProvider, AiSettingsView
from backdoor_watch.domain.errors import ActionFailedError, ActionRefusedError
from backdoor_watch.platform import dpapi


@dataclass(frozen=True)
class AiCredentials:
    provider: AiProvider
    model: str
    effort: str
    api_key: str | None


def validated_effort(provider: AiProvider, effort: str | None) -> str:
    options = PROVIDER_OPTIONS[provider]
    if not effort:
        return options.default_effort
    if effort not in options.effort_levels:
        raise ActionRefusedError(f"Effort '{effort}' is not valid for {provider.value}; "
                                 f"choose one of {', '.join(options.effort_levels)}")
    return effort


class AiSettingsStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def credentials(self) -> AiCredentials:
        raw = self._read()
        provider = AiProvider(raw.get("provider", AiProvider.ANTHROPIC.value))
        options = PROVIDER_OPTIONS[provider]
        encrypted = raw.get("keys", {}).get(provider.value)
        api_key = dpapi.unprotect(base64.b64decode(encrypted)).decode("utf-8") if encrypted else None
        return AiCredentials(
            provider=provider,
            model=raw.get("models", {}).get(provider.value) or options.default_model,
            effort=raw.get("efforts", {}).get(provider.value) or options.default_effort,
            api_key=api_key,
        )

    def view(self) -> AiSettingsView:
        credentials = self.credentials()
        hint = f"…{credentials.api_key[-4:]}" if credentials.api_key else None
        return AiSettingsView(provider=credentials.provider, model=credentials.model, effort=credentials.effort,
                              has_stored_key=credentials.api_key is not None, key_hint=hint)

    def save(self, provider: AiProvider, model: str | None, effort: str | None, api_key: str | None) -> None:
        """api_key None keeps the stored key; an empty string deletes it."""
        effort = validated_effort(provider, effort)
        with self._lock:
            raw = self._read()
            raw["provider"] = provider.value
            raw.setdefault("models", {})[provider.value] = (model or "").strip() or PROVIDER_OPTIONS[provider].default_model
            raw.setdefault("efforts", {})[provider.value] = effort
            keys = raw.setdefault("keys", {})
            if api_key == "":
                keys.pop(provider.value, None)
            elif api_key is not None:
                keys[provider.value] = self._encrypt(api_key.strip())
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(raw, indent=2), encoding="utf-8")

    def _read(self) -> dict:
        if not self._path.is_file():
            return {}
        return json.loads(self._path.read_text(encoding="utf-8"))

    @staticmethod
    def _encrypt(api_key: str) -> str:
        try:
            return base64.b64encode(dpapi.protect(api_key.encode("utf-8"))).decode("ascii")
        except OSError as exc:
            raise ActionFailedError(f"Could not encrypt the API key with Windows DPAPI: {exc}") from exc
