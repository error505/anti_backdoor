"""Moves suspicious files/folders out of the way instead of deleting them.

Keeping a copy preserves evidence (hashes for VirusTotal, samples for an
incident responder) and allows restoring a false positive. Payloads lose
their extension so they cannot be launched by double-click.
"""

import hashlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path

from backdoor_watch.domain.errors import ActionFailedError, ActionRefusedError, NotFoundError
from backdoor_watch.domain.security_tools import QuarantineItem

_SYSTEM_ROOT = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
_MANIFEST = "manifest.json"
_PAYLOAD = "payload.quarantined"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class QuarantineVault:
    def __init__(self, directory: Path) -> None:
        self._directory = directory
        directory.mkdir(parents=True, exist_ok=True)

    def quarantine(self, path: str, reason: str) -> QuarantineItem:
        source = Path(path)
        self._ensure_movable(source)
        item = QuarantineItem(id=uuid.uuid4().hex, original_path=str(source), is_directory=source.is_dir(),
                              sha256=None if source.is_dir() else _sha256(source), reason=reason,
                              quarantined_at=time.time())
        slot = self._directory / item.id
        slot.mkdir()
        try:
            shutil.move(str(source), str(slot / _PAYLOAD))
        except (PermissionError, OSError) as exc:
            shutil.rmtree(slot, ignore_errors=True)
            raise ActionFailedError(f"Cannot move {source}: {exc}. Kill the process using it first.") from exc
        (slot / _MANIFEST).write_text(item.model_dump_json(indent=2), encoding="utf-8")
        return item

    def list_items(self) -> list[QuarantineItem]:
        items = [QuarantineItem(**json.loads(m.read_text(encoding="utf-8")))
                 for m in self._directory.glob(f"*/{_MANIFEST}")]
        return sorted(items, key=lambda i: i.quarantined_at, reverse=True)

    def restore(self, item_id: str) -> QuarantineItem:
        item, slot = self._find(item_id)
        if os.path.exists(item.original_path):
            raise ActionRefusedError(f"{item.original_path} already exists; not overwriting it")
        shutil.move(str(slot / _PAYLOAD), item.original_path)
        shutil.rmtree(slot)
        return item

    def purge(self, item_id: str) -> QuarantineItem:
        item, slot = self._find(item_id)
        shutil.rmtree(slot)
        return item

    def _find(self, item_id: str) -> tuple[QuarantineItem, Path]:
        slot = self._directory / item_id
        if not item_id.isalnum() or not (slot / _MANIFEST).is_file():
            raise NotFoundError(f"Quarantine item {item_id} not found")
        return QuarantineItem(**json.loads((slot / _MANIFEST).read_text(encoding="utf-8"))), slot

    @staticmethod
    def _ensure_movable(source: Path) -> None:
        if not source.exists():
            raise NotFoundError(f"{source} does not exist")
        resolved = os.path.normcase(str(source.resolve()))
        if resolved.startswith(_SYSTEM_ROOT + os.sep) or resolved == _SYSTEM_ROOT:
            raise ActionRefusedError("Refusing to move files inside the Windows folder; use Defender for those")
        if len(source.resolve().parts) <= 2:
            raise ActionRefusedError("Refusing to quarantine a drive root or top-level folder")
        home = os.path.normcase(str(Path.home().resolve()))
        if home == resolved or home.startswith(resolved + os.sep):
            raise ActionRefusedError("Refusing to quarantine your user profile folder")
