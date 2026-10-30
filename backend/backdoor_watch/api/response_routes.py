"""Quarantine, Defender, packet capture and source-folder scanning."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backdoor_watch.analysis.source_scanner import default_sweep_roots
from backdoor_watch.api.deps import ActionResult, get_services
from backdoor_watch.collectors.defender_client import ScanType
from backdoor_watch.container import AppServices
from backdoor_watch.domain.security_tools import (CaptureRecord, CaptureStatus, DefenderStatus,
                                                  DefenderThreat, QuarantineItem, SourceHit)

router = APIRouter(prefix="/api")


class QuarantineRequest(BaseModel):
    path: str
    reason: str = "Manual quarantine"


class DefenderScanRequest(BaseModel):
    scan_type: ScanType
    path: str | None = None


class DefenderOverview(BaseModel):
    status: DefenderStatus
    threats: list[DefenderThreat]


class SourceScanRequest(BaseModel):
    path: str
    include_node_modules: bool = False


@router.get("/quarantine")
def list_quarantine(services: AppServices = Depends(get_services)) -> list[QuarantineItem]:
    return services.quarantine.list_items()


@router.post("/quarantine")
def quarantine_path(body: QuarantineRequest, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.quarantine_path(body.path, body.reason))


@router.post("/quarantine/{item_id}/restore")
def restore_item(item_id: str, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.restore_quarantined(item_id))


@router.post("/quarantine/{item_id}/purge")
def purge_item(item_id: str, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.purge_quarantined(item_id))


@router.get("/defender")
def defender_overview(services: AppServices = Depends(get_services)) -> DefenderOverview:
    return DefenderOverview(status=services.defender.status(), threats=services.defender.threats())


@router.post("/defender/scan")
def defender_scan(body: DefenderScanRequest, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.start_defender_scan(body.scan_type, body.path))


@router.post("/defender/enable-realtime")
def defender_enable_realtime(services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.enable_realtime_protection())


@router.post("/defender/open")
def defender_open(services: AppServices = Depends(get_services)) -> ActionResult:
    services.defender.open_security_settings()
    return ActionResult(message="Opened Windows Security on this PC")


@router.get("/capture/status")
def capture_status(services: AppServices = Depends(get_services)) -> CaptureStatus:
    return services.sniffer.status()


@router.post("/capture/start")
def capture_start(services: AppServices = Depends(get_services)) -> CaptureStatus:
    services.sniffer.start()
    return services.sniffer.status()


@router.post("/capture/stop")
def capture_stop(services: AppServices = Depends(get_services)) -> CaptureStatus:
    services.sniffer.stop()
    return services.sniffer.status()


@router.get("/capture/records")
def capture_records(since: int = 0, limit: int = 1000,
                    services: AppServices = Depends(get_services)) -> list[CaptureRecord]:
    return services.capture_log.since(since, min(limit, 5000))


@router.post("/source-scan")
def source_scan(body: SourceScanRequest, services: AppServices = Depends(get_services)) -> list[SourceHit]:
    return services.source_scanner.scan(body.path, body.include_node_modules)


@router.get("/source-scan/sweep-roots")
def sweep_roots() -> list[str]:
    return default_sweep_roots()


@router.post("/source-scan/sweep")
def source_sweep(services: AppServices = Depends(get_services)) -> list[SourceHit]:
    return services.source_scanner.sweep(default_sweep_roots())
