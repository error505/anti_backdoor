import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from backdoor_watch.domain.findings import Severity


@dataclass(frozen=True)
class PortRule:
    port: int
    severity: Severity
    reason: str


@dataclass(frozen=True)
class PatternRule:
    id: str
    severity: Severity
    pattern: re.Pattern[str]
    title: str


@dataclass(frozen=True)
class PathRule:
    path: str
    severity: Severity
    reason: str


@dataclass(frozen=True)
class IocRules:
    suspicious_ports: dict[int, PortRule]
    cmdline_rules: list[PatternRule]
    ioc_paths: list[PathRule]
    script_hosts: frozenset[str]
    user_writable_dirs: list[str]
    remote_access_tools: list[str]
    protected_processes: frozenset[str]
    source_patterns: list[PatternRule]


def _pattern_rules(items: list[dict], title_key: str) -> list[PatternRule]:
    return [PatternRule(item["id"], Severity(item["severity"]),
                        re.compile(item["pattern"], re.IGNORECASE), item[title_key])
            for item in items]


def _expanded_dir(path: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.expandvars(path))).rstrip("\\") + "\\"


def load_rules(path: Path) -> IocRules:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return IocRules(
        suspicious_ports={item["port"]: PortRule(item["port"], Severity(item["severity"]), item["reason"])
                          for item in raw["suspicious_remote_ports"]},
        cmdline_rules=_pattern_rules(raw["cmdline_rules"], "title"),
        ioc_paths=[PathRule(os.path.expandvars(item["path"]), Severity(item["severity"]), item["reason"])
                   for item in raw["ioc_paths"]],
        script_hosts=frozenset(name.lower() for name in raw["script_hosts"]),
        user_writable_dirs=[_expanded_dir(d) for d in raw["user_writable_dirs"]],
        remote_access_tools=[name.lower() for name in raw["remote_access_tools"]],
        protected_processes=frozenset(name.lower() for name in raw["protected_processes"]),
        source_patterns=_pattern_rules(raw["source_patterns"], "description"),
    )
