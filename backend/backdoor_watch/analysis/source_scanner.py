"""Static scan of a source folder (e.g. the interview repo) for loader / stealer patterns."""

import os
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from backdoor_watch.analysis.ioc_rules import PatternRule
from backdoor_watch.domain.errors import NotFoundError
from backdoor_watch.domain.findings import Severity
from backdoor_watch.domain.security_tools import SourceHit

_EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json", ".py", ".sh", ".ps1", ".bat",
               ".cmd", ".vbs", ".env", ".yml", ".yaml"}
_SKIPPED_DIRS = {".git", ".venv", "venv", "__pycache__", "dist", "build", ".next", ".nuxt", ".turbo", "coverage",
                 ".cache", "site-packages", "target", "obj", ".gradle", ".idea"}
_MAX_FILE_BYTES = 3 * 1024 * 1024
_MAX_HITS = 3000
_OBFUSCATION_LINE_LENGTH = 1500
_SCRIPT_SUFFIXES = {".js", ".mjs", ".cjs", ".ts"}
_SWEEP_FOLDERS = ("Downloads", "Desktop", "Documents", "source", "repos", "projects", "code", "dev", "git")


def default_sweep_roots() -> list[str]:
    """Where interview take-home repos usually end up."""
    home = Path.home()
    return [str(home / name) for name in _SWEEP_FOLDERS if (home / name).is_dir()]


@dataclass(frozen=True)
class _RuleSet:
    rules: tuple[PatternRule, ...]
    # One combined regex rejects most files in a single pass before per-line matching.
    prefilter: re.Pattern[str]
    flag_long_lines: bool


def _rule_set(patterns: Sequence[PatternRule], minimum: Severity) -> _RuleSet:
    rules = tuple(p for p in patterns if p.severity.rank >= minimum.rank)
    combined = "|".join(f"(?:{p.pattern.pattern})" for p in rules) or r"(?!)"
    return _RuleSet(rules, re.compile(combined, re.IGNORECASE), Severity.MEDIUM.rank >= minimum.rank)


class SourceScanner:
    def __init__(self, patterns: Sequence[PatternRule], excluded_roots: Sequence[Path] = ()) -> None:
        self._patterns = patterns
        # Backdoor Watch's own folder contains every pattern (in ioc_rules.json) and would match itself.
        self._excluded = tuple(os.path.normcase(str(p.resolve())) for p in excluded_roots)

    def scan(self, root: str, include_node_modules: bool, minimum: Severity = Severity.INFO) -> list[SourceHit]:
        if not os.path.isdir(root):
            raise NotFoundError(f"Folder not found: {root}")
        rule_set = _rule_set(self._patterns, minimum)
        hits: list[SourceHit] = []
        for path in self._candidate_files(Path(root), include_node_modules):
            hits.extend(self._scan_file(path, rule_set))
            if len(hits) >= _MAX_HITS:
                break
        return hits[:_MAX_HITS]

    def sweep(self, roots: Sequence[str]) -> list[SourceHit]:
        """Broad search across user folders; only high-confidence patterns, to keep noise manageable."""
        hits: list[SourceHit] = []
        for root in roots:
            hits.extend(self.scan(root, include_node_modules=False, minimum=Severity.HIGH))
        return hits[:_MAX_HITS]

    def _candidate_files(self, root: Path, include_node_modules: bool) -> Iterator[Path]:
        skipped = _SKIPPED_DIRS if include_node_modules else _SKIPPED_DIRS | {"node_modules"}
        for directory, subdirs, files in os.walk(root):
            if self._excluded and os.path.normcase(directory).startswith(self._excluded):
                subdirs[:] = []
                continue
            subdirs[:] = [d for d in subdirs if d not in skipped and not d.startswith(".next")]
            for name in files:
                path = Path(directory, name)
                if path.suffix.lower() in _EXTENSIONS or name.startswith(".env"):
                    yield path

    def _scan_file(self, path: Path, rule_set: _RuleSet) -> list[SourceHit]:
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                return []
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        check_long = rule_set.flag_long_lines and path.suffix.lower() in _SCRIPT_SUFFIXES
        if not rule_set.prefilter.search(text) and not check_long:
            return []
        hits = []
        for number, line in enumerate(text.splitlines(), start=1):
            hits.extend(self._scan_line(path, number, line, rule_set, check_long))
        return hits

    @staticmethod
    def _scan_line(path: Path, number: int, line: str, rule_set: _RuleSet, check_long: bool) -> list[SourceHit]:
        hits = []
        for rule in rule_set.rules:
            match = rule.pattern.search(line)
            if match:
                hits.append(SourceHit(file=str(path), line=number, rule_id=rule.id,
                                      severity=rule.severity.value, description=rule.title,
                                      snippet=_snippet(line, match.start())))
        if check_long and len(line) > _OBFUSCATION_LINE_LENGTH:
            hits.append(SourceHit(file=str(path), line=number, rule_id="long-line", severity="medium",
                                  description=f"Very long line ({len(line)} chars): possible obfuscated payload",
                                  snippet=line[:200]))
        return hits


def _snippet(line: str, position: int, radius: int = 120) -> str:
    start = max(0, position - radius)
    return line[start:position + radius].strip()
