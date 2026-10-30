import socket
from collections import Counter

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backdoor_watch.api.deps import get_services
from backdoor_watch.container import AppServices
from backdoor_watch.domain.security_tools import CaptureStatus
from backdoor_watch.platform.privileges import is_admin

router = APIRouter(prefix="/api")


class SystemStatus(BaseModel):
    hostname: str
    is_admin: bool
    traffic_metering: bool
    capture: CaptureStatus
    process_count: int
    connection_count: int
    external_connection_count: int
    network_listener_count: int
    persistence_scanned: bool
    persistence_count: int
    findings_by_severity: dict[str, int]
    self_pids: list[int]
    demo: bool


@router.get("/status")
def get_status(services: AppServices = Depends(get_services)) -> SystemStatus:
    snapshot = services.state.current
    connections = snapshot.connections
    return SystemStatus(
        hostname="DEMO-WORKSTATION" if services.settings.demo else socket.gethostname(),
        is_admin=services.settings.demo or is_admin(),
        traffic_metering=services.settings.demo or services.meter.available,
        capture=services.sniffer.status(),
        process_count=len(snapshot.processes),
        connection_count=len(connections),
        external_connection_count=sum(1 for c in connections if c.is_external and c.state == "ESTABLISHED"),
        network_listener_count=sum(1 for c in connections if c.state == "LISTEN" and c.exposure == "network"),
        persistence_scanned=snapshot.persistence_scanned,
        persistence_count=len(snapshot.persistence),
        findings_by_severity=dict(Counter(f.severity.value for f in snapshot.findings)),
        self_pids=sorted(snapshot.own_pids),
        demo=services.settings.demo,
    )
