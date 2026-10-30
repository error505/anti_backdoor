"""Keeps past analyses (newest last) in memory and in data/ai_history.jsonl so they survive restarts."""

import threading
from collections import deque
from pathlib import Path

from pydantic import ValidationError

from backdoor_watch.domain.ai import AiAnalysis

_KEEP = 50


class AnalysisArchive:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._items: deque[AiAnalysis] = deque(self._load(), maxlen=_KEEP)

    @property
    def latest(self) -> AiAnalysis | None:
        with self._lock:
            return self._items[-1] if self._items else None

    def history(self) -> list[AiAnalysis]:
        with self._lock:
            return list(reversed(self._items))

    def store(self, analysis: AiAnalysis) -> None:
        with self._lock:
            self._items.append(analysis)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(analysis.model_dump_json() + "\n")

    def _load(self) -> list[AiAnalysis]:
        if not self._path.is_file():
            return []
        items = []
        for line in self._path.read_text(encoding="utf-8").splitlines()[-_KEEP:]:
            try:
                items.append(AiAnalysis.model_validate_json(line))
            except ValidationError:
                continue
        return items
