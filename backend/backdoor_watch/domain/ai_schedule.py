"""Periodic AI analysis ("AI Watch"): how often, for how long, and what happened so far."""

import math

from pydantic import BaseModel, Field, computed_field, field_validator

INTERVAL_CHOICES_MINUTES = (5, 10, 15, 30, 60, 120, 360, 720)
MAX_DURATION_HOURS = 24 * 30
MAX_CONSECUTIVE_FAILURES = 3


class AiScheduleConfig(BaseModel):
    interval_minutes: int = 30
    duration_hours: float = Field(default=8, gt=0, le=MAX_DURATION_HOURS)
    skip_unchanged: bool = True

    @field_validator("interval_minutes")
    @classmethod
    def _known_interval(cls, value: int) -> int:
        if value not in INTERVAL_CHOICES_MINUTES:
            raise ValueError(f"interval must be one of {INTERVAL_CHOICES_MINUTES} minutes")
        return value


class AiScheduleState(BaseModel):
    enabled: bool = False
    interval_minutes: int = 30
    skip_unchanged: bool = True
    started_at: float | None = None
    ends_at: float | None = None
    last_check_at: float | None = None
    last_run_at: float | None = None
    runs: int = 0
    skipped: int = 0
    consecutive_failures: int = 0
    last_status: str | None = None
    last_error: str | None = None

    @computed_field
    @property
    def next_check_at(self) -> float | None:
        if not self.enabled or self.started_at is None:
            return None
        if self.last_check_at is None:
            return self.started_at
        return min(self.last_check_at + self.interval_minutes * 60, self.ends_at or math.inf)

    @computed_field
    @property
    def max_runs(self) -> int | None:
        """Upper bound on analyses (and therefore token spend) for the whole schedule."""
        if self.started_at is None or self.ends_at is None:
            return None
        return math.floor((self.ends_at - self.started_at) / (self.interval_minutes * 60)) + 1
