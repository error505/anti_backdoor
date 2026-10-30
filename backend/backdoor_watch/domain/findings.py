import hashlib
from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class FindingTargetKind(str, Enum):
    PROCESS = "process"
    FILE = "file"
    PERSISTENCE = "persistence"
    REMOTE_IP = "remote_ip"
    DEFENDER = "defender"


class FindingTarget(BaseModel, frozen=True):
    kind: FindingTargetKind
    ref: str
    label: str


class Finding(BaseModel):
    id: str
    severity: Severity
    category: str
    title: str
    detail: str
    remediation: str
    targets: list[FindingTarget] = []


def make_finding_id(category: str, key: str) -> str:
    return hashlib.sha1(f"{category}|{key}".lower().encode("utf-8")).hexdigest()[:16]
