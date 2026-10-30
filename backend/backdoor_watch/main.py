from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backdoor_watch.ai.analyst import AiProviderError
from backdoor_watch.api import (ai_routes, flockion_routes, malware_routes, network_routes, process_routes, report_routes, response_routes,
                                system_routes, threat_routes)
from backdoor_watch.api.local_access_guard import LocalAccessGuard
from backdoor_watch.container import AppServices
from backdoor_watch.domain.errors import (ActionFailedError, ActionRefusedError, BackdoorWatchError,
                                          CaptureUnavailableError, NotFoundError)

_STATUS_BY_ERROR = {NotFoundError: 404, ActionRefusedError: 409, ActionFailedError: 500,
                    CaptureUnavailableError: 503, AiProviderError: 502}


async def _domain_error_handler(_: Request, exc: BackdoorWatchError) -> JSONResponse:
    status = next((code for kind, code in _STATUS_BY_ERROR.items() if isinstance(exc, kind)), 400)
    return JSONResponse({"detail": str(exc)}, status_code=status)


def create_app(services: AppServices) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        services.start()
        yield
        services.stop()

    app = FastAPI(title="Flockion Backdoor Watch", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.services = services
    app.add_middleware(LocalAccessGuard, token=services.settings.token, port=services.settings.port,
                       read_only=services.settings.demo)
    app.add_exception_handler(BackdoorWatchError, _domain_error_handler)
    for module in (system_routes, process_routes, network_routes, threat_routes, response_routes, ai_routes,
                   report_routes, flockion_routes, malware_routes):
        app.include_router(module.router)
    if services.settings.frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=services.settings.frontend_dist, html=True), name="ui")
    return app
