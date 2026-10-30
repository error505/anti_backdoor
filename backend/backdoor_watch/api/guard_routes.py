"""Install tripwire and trusted-app list. Thin handlers: the rules live in GuardService."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backdoor_watch.api.deps import ActionResult, get_services
from backdoor_watch.container import AppServices
from backdoor_watch.domain.guard import GuardConfig, GuardMode, GuardStatus

router = APIRouter(prefix="/api/guard")


class ModesRequest(BaseModel):
    install_watch: GuardMode
    lockdown: GuardMode
    sound: bool


class TrustRequest(BaseModel):
    value: str


class HostRequest(BaseModel):
    host: str


class AcknowledgeRequest(BaseModel):
    alert_id: str | None = None


@router.get("")
def status(services: AppServices = Depends(get_services)) -> GuardStatus:
    return services.guard.status()


@router.post("/modes")
def set_modes(body: ModesRequest, services: AppServices = Depends(get_services)) -> GuardConfig:
    return services.guard.set_modes(body.install_watch, body.lockdown, body.sound)


@router.post("/trust-program")
def trust_program(body: TrustRequest, services: AppServices = Depends(get_services)) -> GuardConfig:
    return services.guard.trust_program(body.value)


@router.post("/trust-publisher")
def trust_publisher(body: TrustRequest, services: AppServices = Depends(get_services)) -> GuardConfig:
    return services.guard.trust_publisher(body.value)


@router.post("/trust-signed-seen")
def trust_signed_seen(services: AppServices = Depends(get_services)) -> ActionResult:
    count = services.guard.trust_signed_programs_seen()
    return ActionResult(message=f"Trusted {count} signed publisher(s) that are connecting now")


@router.post("/untrust")
def untrust(body: TrustRequest, services: AppServices = Depends(get_services)) -> GuardConfig:
    return services.guard.untrust(body.value)


@router.post("/allow-host")
def allow_host(body: HostRequest, services: AppServices = Depends(get_services)) -> GuardConfig:
    return services.guard.allow_host(body.host)


@router.post("/disallow-host")
def disallow_host(body: HostRequest, services: AppServices = Depends(get_services)) -> GuardConfig:
    return services.guard.disallow_host(body.host)


@router.post("/acknowledge")
def acknowledge(body: AcknowledgeRequest, services: AppServices = Depends(get_services)) -> ActionResult:
    services.guard.acknowledge(body.alert_id)
    return ActionResult(message="Acknowledged")


@router.post("/alerts/{alert_id}/resume")
def resume(alert_id: str, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.guard.resume(alert_id))


@router.post("/test-alarm")
def test_alarm(services: AppServices = Depends(get_services)) -> ActionResult:
    services.guard.test_alarm()
    return ActionResult(message="Alarm played")
