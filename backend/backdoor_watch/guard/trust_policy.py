"""Who may send data out: Microsoft-signed software, publishers the user accepted, and pinned programs."""

import os
import threading
from collections.abc import Callable
from enum import Enum

from backdoor_watch.domain.guard import TrustEntry, TrustKind
from backdoor_watch.domain.process import ProcessInfo


class Trust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"  # signature not read yet, or unreadable: not evidence either way


class ProgramHasher:
    """SHA-256 of an executable, remembered until the file changes."""

    def __init__(self, hash_file: Callable[[str], tuple[str, int] | None]) -> None:
        self._hash_file = hash_file
        self._cache: dict[tuple[str, int, int], str | None] = {}
        self._lock = threading.Lock()

    def sha256(self, path: str) -> str | None:
        try:
            stat = os.stat(path)
        except OSError:
            return None
        key = (os.path.normcase(path), stat.st_mtime_ns, stat.st_size)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        result = self._hash_file(path)
        with self._lock:
            self._cache[key] = result[0] if result else None
            return self._cache[key]


class TrustPolicy:
    def __init__(self, hasher: ProgramHasher) -> None:
        self._hasher = hasher

    def assess(self, process: ProcessInfo, trusted: list[TrustEntry]) -> Trust:
        signature = process.signature
        if signature is None or not (signature.is_valid or signature.is_untrusted):
            return Trust.UNKNOWN
        if signature.is_microsoft or any(self._matches(process, entry) for entry in trusted):
            return Trust.TRUSTED
        return Trust.UNTRUSTED

    def _matches(self, process: ProcessInfo, entry: TrustEntry) -> bool:
        if entry.kind is TrustKind.PUBLISHER:
            signer = process.signature.signer if process.signature else None
            return bool(process.signature and process.signature.is_valid and signer
                        and signer.lower() == entry.value.lower())
        if not process.exe or os.path.normcase(process.exe) != os.path.normcase(entry.value):
            return False
        current = self._hasher.sha256(process.exe)
        return entry.sha256 is None or current is None or current == entry.sha256
