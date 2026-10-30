"""Persists the AI Watch schedule so it resumes after a restart until its end time."""

import threading
from collections.abc import Callable
from pathlib import Path

from backdoor_watch.domain.ai_schedule import AiScheduleState


class AiScheduleStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def load(self) -> AiScheduleState:
        with self._lock:
            return self._read()

    def update(self, change: Callable[[AiScheduleState], None]) -> AiScheduleState:
        """Read-modify-write under one lock, so API calls and the background job don't overwrite each other."""
        with self._lock:
            state = self._read()
            change(state)
            self._write(state)
            return state

    def replace(self, state: AiScheduleState) -> AiScheduleState:
        with self._lock:
            self._write(state)
            return state

    def _write(self, state: AiScheduleState) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(state.model_dump_json(indent=2, exclude={"next_check_at", "max_runs"}), encoding="utf-8")

    def _read(self) -> AiScheduleState:
        if not self._path.is_file():
            return AiScheduleState()
        return AiScheduleState.model_validate_json(self._path.read_text(encoding="utf-8"))
