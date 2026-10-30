import logging
import os
from collections.abc import Sequence
from typing import Protocol

from backdoor_watch.collectors.signature_verifier import SignatureVerifier
from backdoor_watch.domain.persistence import PersistenceEntry, PersistenceKind

logger = logging.getLogger(__name__)


class PersistenceSource(Protocol):
    def collect(self) -> list[PersistenceEntry]: ...


class PersistenceScanner:
    """Collects every autostart location and attaches signature verdicts."""

    def __init__(self, sources: Sequence[PersistenceSource], signatures: SignatureVerifier) -> None:
        self._sources = sources
        self._signatures = signatures

    def scan(self) -> list[PersistenceEntry]:
        entries: list[PersistenceEntry] = []
        for source in self._sources:
            try:
                entries.extend(source.collect())
            except Exception as exc:  # one broken source must not hide the others
                logger.warning("persistence_source_failed",
                               extra={"source": type(source).__name__, "error": str(exc)})
        return self._with_signatures(entries)

    def _with_signatures(self, entries: list[PersistenceEntry]) -> list[PersistenceEntry]:
        existing = {e.image_path for e in entries if e.image_path and os.path.isfile(e.image_path)}
        verdicts = self._signatures.verify_now(existing)
        for entry in entries:
            entry.image_exists = entry.image_path in existing
            entry.signature = verdicts.get(entry.image_path) if entry.image_path else None
            entry.is_microsoft = self._is_microsoft(entry)
        return entries

    @staticmethod
    def _is_microsoft(entry: PersistenceEntry) -> bool:
        if entry.signature is not None:
            return entry.signature.is_microsoft
        # COM-handler tasks have no executable to verify; trust only Microsoft's own task folder.
        return (entry.kind == PersistenceKind.SCHEDULED_TASK and entry.image_path is None
                and entry.location.lower().startswith("\\microsoft\\"))
