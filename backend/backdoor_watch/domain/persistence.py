import hashlib
from enum import Enum

from pydantic import BaseModel

from backdoor_watch.domain.process import SignatureInfo


class PersistenceKind(str, Enum):
    RUN_KEY = "run_key"
    STARTUP_FOLDER = "startup_folder"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    WMI_CONSUMER = "wmi_consumer"


class PersistenceEntry(BaseModel):
    id: str
    kind: PersistenceKind
    name: str
    location: str
    command: str
    image_path: str | None
    enabled: bool = True
    is_microsoft: bool = False
    image_exists: bool = True
    signature: SignatureInfo | None = None
    details: dict[str, str] = {}


def make_entry_id(kind: PersistenceKind, location: str, name: str) -> str:
    raw = f"{kind.value}|{location}|{name}".lower().encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:16]
