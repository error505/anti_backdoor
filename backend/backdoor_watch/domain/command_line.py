"""Extracts the executable from Windows command strings (Run keys, services, tasks)."""

import os
import re
import shutil

_EXECUTABLE_SUFFIXES = (".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
                        ".wsf", ".hta", ".dll", ".scr", ".sys", ".py", ".pyw", ".lnk")
_SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")


def normalize_windows_path(path: str) -> str:
    """Resolves the NT-style prefixes used in service image paths."""
    expanded = os.path.expandvars(path.strip().strip('"'))
    if expanded.startswith("\\??\\"):
        expanded = expanded[4:]
    if expanded.lower().startswith("\\systemroot\\"):
        expanded = _SYSTEM_ROOT + expanded[len("\\systemroot"):]
    if expanded.lower().startswith("system32\\"):
        expanded = os.path.join(_SYSTEM_ROOT, expanded)
    return expanded


def resolve_bare_executable(path: str) -> str:
    """Scheduled tasks often name just 'sc.exe'; Windows resolves those via System32 / PATH."""
    if os.path.isabs(path) or not path:
        return path
    candidate = os.path.join(_SYSTEM_ROOT, "System32", path)
    return candidate if os.path.isfile(candidate) else (shutil.which(path) or path)


def _end_of_first_executable(lowered: str) -> int | None:
    best: int | None = None
    for suffix in _EXECUTABLE_SUFFIXES:
        for match in re.finditer(re.escape(suffix) + r"(?=$|[\s,])", lowered):
            if best is None or match.end() < best:
                best = match.end()
            break
    return best


def extract_image_path(command: str) -> str | None:
    text = os.path.expandvars(command.strip())
    if not text:
        return None
    if text.startswith('"'):
        closing = text.find('"', 1)
        image = text[1:closing] if closing > 0 else text[1:]
    else:
        end = _end_of_first_executable(text.lower())
        image = text[:end] if end else text.split(" ", 1)[0]
    return resolve_bare_executable(normalize_windows_path(image))
