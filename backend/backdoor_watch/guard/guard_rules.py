"""Declarative guard rules: which tools count as package managers and which hosts install scripts may reach."""

import json
import re
from dataclasses import dataclass
from pathlib import Path

DEFAULTS_PATH = Path(__file__).with_name("guard_defaults.json")


@dataclass(frozen=True)
class PackageTool:
    label: str
    pattern: re.Pattern[str]
    install_verbs: frozenset[str]
    run_verbs: frozenset[str]
    bare_is_install: bool


@dataclass(frozen=True)
class GuardRules:
    tools: tuple[PackageTool, ...]
    allowed_host_suffixes: tuple[str, ...]


def _tool(raw: dict) -> PackageTool:
    names = "|".join(re.escape(name) for name in raw["names"])
    # The tool name must be a whole path segment or argument; what follows is scanned for its sub-command.
    boundary_before = r"""(?:^|[\\/\s"'])"""
    boundary_after = r"""(?=["'\s]|$)"""
    pattern = re.compile(boundary_before + f"(?:{names})" + boundary_after + r"(?P<rest>[^\r\n]*)", re.IGNORECASE)
    return PackageTool(raw["label"], pattern, frozenset(raw["install"]), frozenset(raw["run"]), raw.get("bare_is_install", False))


def load_guard_rules(path: Path = DEFAULTS_PATH) -> GuardRules:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return GuardRules(tools=tuple(_tool(t) for t in raw["tools"]),
                      allowed_host_suffixes=tuple(raw["allowed_host_suffixes"]))
