import time

from backdoor_watch.ai.analysis_archive import AnalysisArchive
from backdoor_watch.ai.analysis_scheduler import AiAnalysisScheduler
from backdoor_watch.ai.analyst import AiProviderError
from backdoor_watch.ai.schedule_store import AiScheduleStore
from backdoor_watch.domain.ai import AiAnalysis, AiProvider, AiVerdict, AnalysisTrigger
from backdoor_watch.domain.ai_schedule import AiScheduleConfig
from backdoor_watch.monitoring.event_log import EventLog


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance_minutes(self, minutes: float) -> None:
        self.now += minutes * 60


class FakeAnalysis:
    def __init__(self, archive: AnalysisArchive) -> None:
        self.archive = archive
        self.fingerprint = "state-1"
        self.calls = 0
        self.error: Exception | None = None

    def current_fingerprint(self) -> str:
        return self.fingerprint

    def analyze(self, question, trigger):
        self.calls += 1
        if self.error:
            raise self.error
        analysis = AiAnalysis(provider=AiProvider.ANTHROPIC, model="m", effort="high", question=question,
                              markdown="VERDICT: CLEAR", created_at=time.time(), context_chars=1, trigger=trigger,
                              verdict=AiVerdict.CLEAR, fingerprint=self.fingerprint)
        self.archive.store(analysis)
        return analysis


def _scheduler(tmp_path):
    clock = FakeClock()
    archive = AnalysisArchive(tmp_path / "history.jsonl")
    analysis = FakeAnalysis(archive)
    scheduler = AiAnalysisScheduler(AiScheduleStore(tmp_path / "schedule.json"), analysis, archive,
                                    EventLog(tmp_path / "logs"), now=clock)
    return scheduler, analysis, clock


def test_runs_immediately_then_waits_for_the_interval(tmp_path):
    scheduler, analysis, clock = _scheduler(tmp_path)
    scheduler.start(AiScheduleConfig(interval_minutes=15, duration_hours=2, skip_unchanged=False))
    scheduler.tick()
    clock.advance_minutes(10)
    scheduler.tick()
    assert analysis.calls == 1
    clock.advance_minutes(6)
    scheduler.tick()
    assert analysis.calls == 2


def test_skips_when_nothing_security_relevant_changed(tmp_path):
    scheduler, analysis, clock = _scheduler(tmp_path)
    scheduler.start(AiScheduleConfig(interval_minutes=5, duration_hours=1))
    scheduler.tick()
    clock.advance_minutes(5)
    scheduler.tick()
    assert (analysis.calls, scheduler.state().skipped) == (1, 1)
    analysis.fingerprint = "state-2"
    clock.advance_minutes(5)
    scheduler.tick()
    assert analysis.calls == 2


def test_stops_by_itself_when_the_duration_ends(tmp_path):
    scheduler, analysis, clock = _scheduler(tmp_path)
    state = scheduler.start(AiScheduleConfig(interval_minutes=30, duration_hours=1, skip_unchanged=False))
    assert state.max_runs == 3
    clock.advance_minutes(61)
    scheduler.tick()
    assert scheduler.state().enabled is False
    assert analysis.calls == 0


def test_pauses_after_repeated_failures(tmp_path):
    scheduler, analysis, clock = _scheduler(tmp_path)
    analysis.error = AiProviderError("Anthropic rejected the API key")
    scheduler.start(AiScheduleConfig(interval_minutes=5, duration_hours=5, skip_unchanged=False))
    for _ in range(3):
        scheduler.tick()
        clock.advance_minutes(5)
    state = scheduler.state()
    assert state.enabled is False and "rejected the API key" in (state.last_status or "")
