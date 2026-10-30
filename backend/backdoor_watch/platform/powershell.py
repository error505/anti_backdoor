"""Runs PowerShell scripts and parses their JSON output.

Arguments travel through an environment variable as JSON and are read back
with ConvertFrom-Json, never interpolated into script text, so paths or names
containing quotes cannot inject commands.
"""

import base64
import json
import os
import subprocess
from typing import Any

_CREATE_NO_WINDOW = 0x08000000
_UTF8_PREAMBLE = "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n"


class PowerShellError(RuntimeError):
    pass


def _command(script: str) -> list[str]:
    encoded = base64.b64encode((_UTF8_PREAMBLE + script).encode("utf-16-le")).decode("ascii")
    return ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-EncodedCommand", encoded]


def _environment(args: Any) -> dict[str, str]:
    return {**os.environ, "BW_ARGS": json.dumps(args if args is not None else [])}


def run_powershell(script: str, args: Any = None, timeout: float = 90) -> str:
    try:
        completed = subprocess.run(
            _command(script), capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=_environment(args), creationflags=_CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired as exc:
        raise PowerShellError(f"PowerShell timed out after {timeout}s") from exc
    if completed.returncode != 0:
        raise PowerShellError(completed.stderr.strip() or f"exit code {completed.returncode}")
    return completed.stdout


def run_powershell_json(script: str, args: Any = None, timeout: float = 90) -> list[dict]:
    output = run_powershell(script, args, timeout).strip()
    if not output:
        return []
    parsed = json.loads(output)
    return parsed if isinstance(parsed, list) else [parsed]


def start_powershell_detached(script: str, args: Any = None) -> None:
    """Fire-and-forget for long operations such as antivirus scans."""
    subprocess.Popen(_command(script), env=_environment(args), creationflags=_CREATE_NO_WINDOW,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
