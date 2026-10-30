"""Removes secrets and personal identifiers before data leaves the machine (AI providers, uploads).

Command lines often carry tokens (`--token=…`, `Authorization: Bearer …`); those
must never be sent to a third party. Encoded payloads are shortened rather than
removed because their presence is evidence.
"""

import os
import re
import socket
from typing import Any

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(\b[\w-]*(?:token|secret|passw(?:or)?d|pwd|api[_-]?key|apikey|auth|credential|session|cookie)[\w-]*"
    r"\s*[=:]\s*|--?[\w-]*(?:token|secret|password|api-?key|auth)[\w-]*\s+)(\"[^\"]*\"|'[^']*'|[^\s\"',;&]+)")
_KNOWN_TOKEN = re.compile(
    r"\b(?:sk-(?:ant-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"
    r"|npm_[A-Za-z0-9]{30,})")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}")
_LONG_BLOB = re.compile(r"[A-Za-z0-9+/=_-]{120,}")


def _shorten_blob(match: re.Match[str]) -> str:
    blob = match.group(0)
    return f"{blob[:48]}…[{len(blob)} chars]"


class Redactor:
    def __init__(self, anonymize_identity: bool = True) -> None:
        self._identity: list[tuple[re.Pattern[str], str]] = []
        if anonymize_identity:
            # Very short names would also mangle unrelated words, so they are left alone.
            for name, placeholder in ((os.environ.get("USERNAME", ""), "<user>"), (socket.gethostname(), "<host>")):
                if len(name) >= 3:
                    self._identity.append((re.compile(re.escape(name), re.IGNORECASE), placeholder))

    def text(self, value: str) -> str:
        redacted = _KNOWN_TOKEN.sub("[REDACTED-TOKEN]", value)
        redacted = _BEARER.sub(r"\1 [REDACTED]", redacted)
        redacted = _SECRET_ASSIGNMENT.sub(lambda m: f"{m.group(1)}[REDACTED]", redacted)
        redacted = _LONG_BLOB.sub(_shorten_blob, redacted)
        for pattern, replacement in self._identity:
            redacted = pattern.sub(replacement, redacted)
        return redacted

    def value(self, data: Any) -> Any:
        """Recursively redacts every string in a JSON-like structure."""
        if isinstance(data, str):
            return self.text(data)
        if isinstance(data, list):
            return [self.value(item) for item in data]
        if isinstance(data, dict):
            return {key: self.value(item) for key, item in data.items()}
        return data
