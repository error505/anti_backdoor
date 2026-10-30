from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel

from backdoor_watch.api.deps import ActionResult, get_services
from backdoor_watch.container import AppServices
from backdoor_watch.reporting.report_renderers import ReportFormat
from backdoor_watch.reporting.report_uploader import UploadMethod

router = APIRouter(prefix="/api/report")


class UploadRequest(BaseModel):
    url: str
    method: UploadMethod = "PUT"
    format: ReportFormat = "json"
    redact: bool = True


@router.get("")
def download_report(report_format: ReportFormat = Query("html", alias="format"), redact: bool = False,
                    services: AppServices = Depends(get_services)) -> Response:
    rendered = services.reports.render(report_format, redact)
    return Response(content=rendered.body, media_type=rendered.content_type,
                    headers={"Content-Disposition": f'attachment; filename="{rendered.filename}"'})


@router.post("/upload")
def upload_report(body: UploadRequest, services: AppServices = Depends(get_services)) -> ActionResult:
    return ActionResult(message=services.reports.upload(body.url, body.method, body.format, body.redact))
