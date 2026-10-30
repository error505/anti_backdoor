from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backdoor_watch.api.deps import ActionResult, get_services
from backdoor_watch.container import AppServices
from backdoor_watch.domain.ai import PROVIDER_OPTIONS, AiAnalysis, AiProvider, AiSettingsView, ProviderOptions
from backdoor_watch.domain.ai_schedule import AiScheduleConfig, AiScheduleState

router = APIRouter(prefix="/api/ai")


class AiSettingsRequest(BaseModel):
    provider: AiProvider
    model: str | None = None
    effort: str | None = None
    # None keeps the stored key, "" deletes it.
    api_key: str | None = None


class AnalyzeRequest(BaseModel):
    question: str | None = None


class ContextPreview(BaseModel):
    characters: int
    content: str


@router.get("/options")
def provider_options() -> dict[AiProvider, ProviderOptions]:
    return PROVIDER_OPTIONS


@router.get("/settings")
def get_settings(services: AppServices = Depends(get_services)) -> AiSettingsView:
    return services.ai_settings.view()


@router.post("/settings")
def save_settings(body: AiSettingsRequest, services: AppServices = Depends(get_services)) -> AiSettingsView:
    services.ai_settings.save(body.provider, body.model, body.effort, body.api_key)
    return services.ai_settings.view()


@router.get("/context")
def preview_context(services: AppServices = Depends(get_services)) -> ContextPreview:
    content = services.ai_analysis.preview_context()
    return ContextPreview(characters=len(content), content=content)


@router.post("/analyze")
def analyze(body: AnalyzeRequest, services: AppServices = Depends(get_services)) -> AiAnalysis:
    return services.ai_analysis.analyze(body.question)


@router.get("/history")
def analysis_history(services: AppServices = Depends(get_services)) -> list[AiAnalysis]:
    return services.analysis_archive.history()


@router.get("/schedule")
def schedule_state(services: AppServices = Depends(get_services)) -> AiScheduleState:
    return services.ai_scheduler.state()


@router.post("/schedule/start")
def start_schedule(body: AiScheduleConfig, services: AppServices = Depends(get_services)) -> AiScheduleState:
    return services.ai_scheduler.start(body)


@router.post("/schedule/stop")
def stop_schedule(services: AppServices = Depends(get_services)) -> AiScheduleState:
    return services.ai_scheduler.stop()


@router.post("/settings/clear-key")
def clear_key(services: AppServices = Depends(get_services)) -> ActionResult:
    current = services.ai_settings.view()
    services.ai_settings.save(current.provider, current.model, current.effort, "")
    return ActionResult(message=f"Removed the stored {current.provider.value} API key")
