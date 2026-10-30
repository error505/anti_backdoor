"""Models for response tooling: quarantine, firewall rules, Defender, capture, source scan."""

from enum import Enum

from pydantic import BaseModel


class QuarantineItem(BaseModel):
    id: str
    original_path: str
    is_directory: bool
    sha256: str | None
    reason: str
    quarantined_at: float


class FirewallRule(BaseModel):
    id: str
    display_name: str
    direction: str
    target: str
    enabled: bool


class DefenderThreat(BaseModel):
    threat_id: str
    name: str
    severity: str
    detected_at: str | None
    resources: list[str]
    process_name: str | None
    action_success: bool | None


class DefenderStatus(BaseModel):
    available: bool
    antivirus_enabled: bool | None = None
    real_time_protection: bool | None = None
    running_mode: str | None = None
    # Third-party antivirus products Windows Security Center reports as ON (e.g. McAfee).
    active_antivirus: list[str] = []
    tamper_protected: bool | None = None
    signatures_updated: str | None = None
    last_quick_scan: str | None = None
    last_full_scan: str | None = None
    error: str | None = None


class CaptureProtocol(str, Enum):
    DNS = "dns"
    TLS = "tls"
    HTTP = "http"
    PAYLOAD = "payload"


class CaptureRecord(BaseModel):
    protocol: CaptureProtocol
    summary: str
    local: str
    remote: str
    remote_host: str | None = None
    pid: int | None = None
    process_name: str | None = None
    preview: str = ""
    seq: int = 0
    timestamp: float = 0.0


class CaptureStatus(BaseModel):
    running: bool
    available: bool
    message: str


class SourceHit(BaseModel):
    file: str
    line: int
    rule_id: str
    severity: str
    description: str
    snippet: str
