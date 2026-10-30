"""AI Watch: re-runs the AI analysis on an interval, for a limited time, only when something changed."""

import time
from collections.abc import Callable
from typing import Protocol

from backdoor_watch.ai.analysis_archive import AnalysisArchive
from backdoor_watch.ai.schedule_store import AiScheduleStore
from backdoor_watch.domain.activity import ActivityEvent, ActivityKind
from backdoor_watch.domain.ai import AiAnalysis, AnalysisTrigger
from backdoor_watch.domain.ai_schedule import MAX_CONSECUTIVE_FAILURES, AiScheduleConfig, AiScheduleState
from backdoor_watch.domain.errors import ActionRefusedError, BackdoorWatchError
from backdoor_watch.monitoring.event_log import EventLog


class ScheduledAnalysis(Protocol):
    def analyze(self, question: str | None, trigger: AnalysisTrigger) -> AiAnalysis: ...

    def current_fingerprint(self) -> str: ...


class AiAnalysisScheduler:
    def __init__(self, store: AiScheduleStore, analysis: ScheduledAnalysis, archive: AnalysisArchive,
                 events: EventLog, now: Callable[[], float] = time.time) -> None:
        self._store = store
        self._analysis = analysis
        self._archive = archive
        self._events = events
        self._now = now

    def state(self) -> AiScheduleState:
        return self._store.load()

    def start(self, config: AiScheduleConfig) -> AiScheduleState:
        now = self._now()
        fresh = AiScheduleState(enabled=True, interval_minutes=config.interval_minutes,
                                skip_unchanged=config.skip_unchanged, started_at=now,
                                ends_at=now + config.duration_hours * 3600, last_status="Scheduled")
        state = self._store.replace(fresh)
        self._audit(f"AI Watch started: every {config.interval_minutes} min for {config.duration_hours:g} h "
                    f"(at most {state.max_runs} analyses, skip unchanged={config.skip_unchanged})")
        return state

    def stop(self, reason: str = "Stopped by user") -> AiScheduleState:
        state = self._store.update(lambda s: self._disable(s, reason))
        self._audit(f"AI Watch stopped: {reason}")
        return state

    def tick(self) -> None:
        """Called every ~30 s by a background job; does nothing unless a check is due."""
        state = self._store.load()
        now = self._now()
        if not state.enabled or state.started_at is None:
            return
        if state.ends_at is not None and now >= state.ends_at:
            self.stop("Schedule finished")
            return
        if state.last_check_at is not None and now - state.last_check_at < state.interval_minutes * 60:
            return
        self._store.update(lambda s: setattr(s, "last_check_at", now))
        if state.skip_unchanged and self._nothing_changed():
            self._record(state.started_at, lambda s: self._mark_skipped(s, "Skipped: nothing security-relevant changed"))
            return
        self._run(state.started_at, now)

    def _nothing_changed(self) -> bool:
        latest = self._archive.latest
        return latest is not None and latest.fingerprint == self._analysis.current_fingerprint()

    def _run(self, started_at: float, now: float) -> None:
        try:
            analysis = self._analysis.analyze(None, AnalysisTrigger.SCHEDULED)
        except ActionRefusedError:
            self._record(started_at, lambda s: self._mark_skipped(s, "Skipped: another analysis was running"))
            return
        except BackdoorWatchError as exc:
            self._record(started_at, lambda s: self._mark_failed(s, str(exc)))
            return
        self._record(started_at, lambda s: self._mark_ran(s, now, analysis))

    def _record(self, started_at: float, change: Callable[[AiScheduleState], None]) -> None:
        # The analysis can take minutes; ignore the result if the user restarted the schedule meanwhile.
        def apply(state: AiScheduleState) -> None:
            if state.started_at == started_at:
                change(state)
        state = self._store.update(apply)
        if state.started_at == started_at and state.consecutive_failures >= MAX_CONSECUTIVE_FAILURES and state.enabled:
            self.stop(f"Paused after {MAX_CONSECUTIVE_FAILURES} failures in a row: {state.last_error}")

    @staticmethod
    def _mark_ran(state: AiScheduleState, now: float, analysis: AiAnalysis) -> None:
        state.runs += 1
        state.last_run_at = now
        state.consecutive_failures = 0
        state.last_error = None
        state.last_status = f"Analysed: verdict {analysis.verdict.value}"

    @staticmethod
    def _mark_skipped(state: AiScheduleState, status: str) -> None:
        state.skipped += 1
        state.last_status = status

    @staticmethod
    def _mark_failed(state: AiScheduleState, error: str) -> None:
        state.consecutive_failures += 1
        state.last_error = error
        state.last_status = "Failed"

    @staticmethod
    def _disable(state: AiScheduleState, reason: str) -> None:
        state.enabled = False
        state.last_status = reason

    def _audit(self, summary: str) -> None:
        self._events.append(ActivityEvent(kind=ActivityKind.ACTION_TAKEN, summary=summary))
