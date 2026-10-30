from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backdoor_watch.api.deps import ActionResult, get_services
from backdoor_watch.container import AppServices
from backdoor_watch.domain.flockion import FlockionCheck, FlockionResult, FlockionSettingsView, SendMode

router = APIRouter(prefix="/api/flockion")


class FlockionSettingsRequest(BaseModel):
    endpoint: str
    # None keeps the stored key, "" deletes it.
    api_key: str | None = None


class SendRequest(BaseModel):
    mode: SendMode = "findings"


class PreviewResponse(BaseModel):
    characters: int
    content: str


@router.get("/settings")
def get_settings(services: AppServices = Depends(get_services)) -> FlockionSettingsView:
    return services.flockion_settings.view()


@router.post("/settings")
def save_settings(body: FlockionSettingsRequest, services: AppServices = Depends(get_services)) -> FlockionSettingsView:
    services.flockion_settings.save(body.endpoint, body.api_key)
    return services.flockion_settings.view()


@router.post("/clear-key")
def clear_key(services: AppServices = Depends(get_services)) -> ActionResult:
    services.flockion_settings.save(services.flockion_settings.view().endpoint, "")
    return ActionResult(message="Removed the stored Flockion key")


@router.post("/preview")
def preview(body: SendRequest, services: AppServices = Depends(get_services)) -> PreviewResponse:
    content = services.flockion.preview(body.mode)
    return PreviewResponse(characters=len(content), content=content)


@router.post("/test")
def test_connection(services: AppServices = Depends(get_services)) -> FlockionCheck:
    return services.flockion.test()


@router.post("/send")
def send_snapshot(body: SendRequest, services: AppServices = Depends(get_services)) -> FlockionResult:
    return services.flockion.send(body.mode)
