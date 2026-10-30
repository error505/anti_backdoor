import threading
import time
from collections.abc import Callable

from backdoor_watch.ai.analysis_archive import AnalysisArchive
from backdoor_watch.ai.analyst import SecurityAnalyst
from backdoor_watch.ai.anthropic_analyst import AnthropicAnalyst
from backdoor_watch.ai.change_fingerprint import state_fingerprint
from backdoor_watch.ai.openai_analyst import OpenAiAnalyst
from backdoor_watch.ai.prompts import SYSTEM_PROMPT, build_user_content
from backdoor_watch.ai.settings_store import AiSettingsStore
from backdoor_watch.ai.verdict import parse_verdict
from backdoor_watch.domain.activity import ActivityEvent, ActivityKind
from backdoor_watch.domain.ai import AiAnalysis, AiProvider, AnalysisTrigger
from backdoor_watch.domain.errors import ActionRefusedError
from backdoor_watch.monitoring.event_log import EventLog
from backdoor_watch.reporting.report_builder import ReportBuilder
from backdoor_watch.reporting.report_model import SecurityReport

AnalystFactory = Callable[[str, str, str | None], SecurityAnalyst]  # (model, effort, api_key)

ANALYSTS: dict[AiProvider, AnalystFactory] = {
    AiProvider.ANTHROPIC: AnthropicAnalyst,
    AiProvider.OPENAI: OpenAiAnalyst,
}


class AiAnalysisService:
    def __init__(self, settings: AiSettingsStore, reports: ReportBuilder, archive: AnalysisArchive,
                 events: EventLog) -> None:
        self._settings = settings
        self._reports = reports
        self._archive = archive
        self._events = events
        self._busy = threading.Lock()

    def preview_context(self) -> str:
        """Exactly what would be sent to the provider (always redacted)."""
        return self._snapshot().model_dump_json(exclude_none=True)

    def current_fingerprint(self) -> str:
        return state_fingerprint(self._snapshot())

    def analyze(self, question: str | None, trigger: AnalysisTrigger = AnalysisTrigger.MANUAL) -> AiAnalysis:
        if not self._busy.acquire(blocking=False):
            raise ActionRefusedError("An analysis is already running")
        try:
            return self._run(question, trigger)
        finally:
            self._busy.release()

    def _snapshot(self) -> SecurityReport:
        return self._reports.build(redact=True, include_ai_analysis=False)

    def _run(self, question: str | None, trigger: AnalysisTrigger) -> AiAnalysis:
        credentials = self._settings.credentials()
        snapshot = self._snapshot()
        context = snapshot.model_dump_json(exclude_none=True)
        analyst = ANALYSTS[credentials.provider](credentials.model, credentials.effort, credentials.api_key)
        markdown = analyst.analyze(SYSTEM_PROMPT, build_user_content(context, question))
        analysis = AiAnalysis(
            provider=credentials.provider, model=credentials.model, effort=credentials.effort, question=question,
            markdown=markdown, created_at=time.time(), context_chars=len(context), trigger=trigger,
            verdict=parse_verdict(markdown), fingerprint=state_fingerprint(snapshot),
        )
        self._archive.store(analysis)
        self._events.append(ActivityEvent(
            kind=ActivityKind.ACTION_TAKEN,
            summary=f"{trigger.value.capitalize()} AI analysis by {credentials.provider.value}/{credentials.model} "
                    f"(effort {credentials.effort}, {len(context)} chars sent, redacted): verdict {analysis.verdict.value}"))
        return analysis
