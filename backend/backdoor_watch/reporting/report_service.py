from backdoor_watch.domain.activity import ActivityEvent, ActivityKind
from backdoor_watch.monitoring.event_log import EventLog
from backdoor_watch.reporting.report_builder import ReportBuilder
from backdoor_watch.reporting.report_renderers import ReportFormat, render
from backdoor_watch.reporting.report_uploader import ReportUploader, UploadMethod, host_of


class RenderedReport:
    def __init__(self, body: bytes, content_type: str, filename: str) -> None:
        self.body = body
        self.content_type = content_type
        self.filename = filename


class ReportService:
    def __init__(self, builder: ReportBuilder, uploader: ReportUploader, events: EventLog) -> None:
        self._builder = builder
        self._uploader = uploader
        self._events = events

    def render(self, report_format: ReportFormat, redact: bool) -> RenderedReport:
        report = self._builder.build(redact=redact)
        body, content_type, extension = render(report, report_format)
        stamp = report.generated_at.replace(":", "").replace("-", "")[:15]
        return RenderedReport(body, content_type, f"backdoor-watch-report-{stamp}.{extension}")

    def upload(self, url: str, method: UploadMethod, report_format: ReportFormat, redact: bool) -> str:
        rendered = self.render(report_format, redact)
        status = self._uploader.upload(url, method, rendered.body, rendered.content_type)
        summary = f"Uploaded {report_format} report ({len(rendered.body)} bytes, redacted={redact}) to {host_of(url)}"
        self._events.append(ActivityEvent(kind=ActivityKind.ACTION_TAKEN, summary=summary,
                                          details={"http_status": str(status)}))
        return f"{summary}: HTTP {status}"
