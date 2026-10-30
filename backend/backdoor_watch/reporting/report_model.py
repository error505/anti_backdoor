from pydantic import BaseModel

from backdoor_watch.domain.activity import ActivityEvent
from backdoor_watch.domain.ai import AiAnalysis
from backdoor_watch.domain.findings import Finding
from backdoor_watch.domain.ip_intel import IpIntel
from backdoor_watch.domain.network import ProcessTraffic, RemoteTraffic
from backdoor_watch.domain.persistence import PersistenceEntry
from backdoor_watch.domain.security_tools import DefenderStatus, DefenderThreat


class ProcessGroup(BaseModel):
    """Processes sharing one executable (e.g. 30 chrome.exe) collapsed into one row."""
    name: str
    exe: str | None
    signer: str | None
    signature_status: str | None
    instances: int
    pids: list[int]
    sample_cmdline: str
    parent: str | None


class ConnectionSummary(BaseModel):
    process: str
    pid: int | None
    local: str
    remote: str
    remote_host: str | None
    state: str
    exposure: str
    bytes_out: int | None
    bytes_in: int | None


class SecurityReport(BaseModel):
    generated_at: str
    hostname: str
    is_admin: bool
    redacted: bool
    summary: dict[str, int]
    findings: list[Finding]
    defender: DefenderStatus | None
    defender_threats: list[DefenderThreat]
    non_microsoft_processes: list[ProcessGroup]
    external_connections: list[ConnectionSummary]
    network_listeners: list[ConnectionSummary]
    autostart_non_microsoft: list[PersistenceEntry]
    traffic_by_process: list[ProcessTraffic]
    traffic_by_remote: list[RemoteTraffic]
    notable_events: list[ActivityEvent]
    remote_server_intel: list[IpIntel] = []
    ai_analysis: AiAnalysis | None = None
