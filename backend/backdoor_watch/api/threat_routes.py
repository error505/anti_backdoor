"""Findings, autostart entries and the activity timeline."""

from fastapi import APIRouter, Depends

from backdoor_watch.api.deps import ActionResult, get_services
from backdoor_watch.container import AppServices
from backdoor_watch.domain.activity import ActivityEvent
from backdoor_watch.domain.findings import Finding
from backdoor_watch.domain.persistence import PersistenceEntry

router = APIRouter(prefix="/api")


@router.get("/findings")
def list_findings(services: AppServices = Depends(get_services)) -> list[Finding]:
    return services.state.current.findings


@router.post("/findings/rescan")
def rescan_findings(services: AppServices = Depends(get_services)) -> ActionResult:
    services.findings_refresher.refresh()
    return ActionResult(message=f"{len(services.state.current.findings)} findings")


@router.get("/persistence")
def list_persistence(services: AppServices = Depends(get_services)) -> list[PersistenceEntry]:
    return services.state.current.persistence


@router.post("/persistence/rescan")
def rescan_persistence(services: AppServices = Depends(get_services)) -> ActionResult:
    services.persistence_refresher.refresh()
    services.findings_refresher.refresh()
    return ActionResult(message=f"{len(services.state.current.persistence)} autostart entries scanned")


@router.post("/persistence/{entry_id}/remove")
def remove_persistence(entry_id: str, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.response.remove_persistence(entry_id))


@router.get("/events")
def list_events(since: int = 0, limit: int = 1000,
                services: AppServices = Depends(get_services)) -> list[ActivityEvent]:
    return services.events.since(since, min(limit, 5000))
