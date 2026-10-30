"""Finds package-manager runs (npm i, yarn, pnpm add ...) in the process list and who they spawned.

Pure functions over a process snapshot, so the rules are easy to test.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from backdoor_watch.domain.process import ProcessInfo
from backdoor_watch.guard.guard_rules import GuardRules

_MAX_DEPTH = 32
_SUBCOMMAND_WINDOW = 3


class Phase(str, Enum):
    INSTALL = "install"
    RUN = "run"


class Detected(NamedTuple):
    phase: Phase
    tool: str


@dataclass(frozen=True)
class Lineage:
    """Where a process came from. Remembered, because a malicious install script can detach a child and let npm exit."""
    root_pid: int
    root_name: str  # the tool, e.g. npm, not the process that happens to host it
    phase: Phase
    started: float | None  # the process's own start time, to notice a reused PID


def classify_run(cmdline: str, rules: GuardRules) -> Detected | None:
    for tool in rules.tools:
        for match in tool.pattern.finditer(cmdline):
            # Flags can carry a value (--prefix app ci), so look at the first few words that are not flags.
            words = [w for w in (w.strip("\"'").lower() for w in match.group("rest").split()) if w and not w.startswith("-")]
            if not words and tool.bare_is_install:
                return Detected(Phase.INSTALL, tool.label)
            for word in words[:_SUBCOMMAND_WINDOW]:
                if word in tool.install_verbs:
                    return Detected(Phase.INSTALL, tool.label)
                if word in tool.run_verbs:
                    return Detected(Phase.RUN, tool.label)
            if "*" in tool.run_verbs:
                return Detected(Phase.RUN, tool.label)
    return None


def classify_command(cmdline: str, rules: GuardRules) -> Phase | None:
    detected = classify_run(cmdline, rules)
    return detected.phase if detected else None


def find_package_manager_runs(processes: Mapping[int, ProcessInfo], rules: GuardRules) -> dict[int, Detected]:
    runs: dict[int, Detected] = {}
    for pid, process in processes.items():
        detected = classify_run(process.cmdline, rules) if process.cmdline else None
        if detected:
            runs[pid] = detected
    return runs


def _trace_to_runs(pid: int, processes: Mapping[int, ProcessInfo], runs: Mapping[int, Detected]) -> Lineage | None:
    """Walks up the parents. Root = the outermost package manager (suspending from there stops the whole run);
    phase = the strictest one on the way, so an install inside a dev command still counts as an install."""
    root, tool, phase, current, seen = None, "", None, processes.get(pid), set()
    for _ in range(_MAX_DEPTH):
        if current is None or current.pid in seen:
            break
        seen.add(current.pid)
        if current.pid in runs:
            root, tool = current, runs[current.pid].tool
            phase = Phase.INSTALL if Phase.INSTALL in (phase, runs[current.pid].phase) else Phase.RUN
        current = processes.get(current.ppid) if current.ppid else None
    started = processes[pid].create_time
    return Lineage(root.pid, tool, phase, started) if root and phase else None


def update_lineage(previous: Mapping[int, Lineage], processes: Mapping[int, ProcessInfo],
                   runs: Mapping[int, Detected]) -> dict[int, Lineage]:
    current: dict[int, Lineage] = {}
    for pid, process in processes.items():
        known = previous.get(pid)
        if known and known.started == process.create_time:
            current[pid] = known
            continue
        traced = _trace_to_runs(pid, processes, runs)
        if traced:
            current[pid] = traced
    return current


def chain_names(pid: int, lineage: Lineage, processes: Mapping[int, ProcessInfo]) -> list[str]:
    """Names from the package manager down to the process, e.g. ['node.exe', 'cmd.exe', 'node.exe']."""
    names, current = [], processes.get(pid)
    for _ in range(_MAX_DEPTH):
        if current is None:
            break
        names.append(current.name)
        if current.pid == lineage.root_pid:
            return list(reversed(names))
        current = processes.get(current.ppid) if current.ppid else None
    return [f"{lineage.root_name} (exited)", *reversed(names)]
