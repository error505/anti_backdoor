import os
from pathlib import Path

from backdoor_watch.domain.command_line import extract_image_path
from backdoor_watch.domain.persistence import PersistenceEntry, PersistenceKind, make_entry_id
from backdoor_watch.platform.powershell import PowerShellError, run_powershell_json

_RESOLVE_SHORTCUTS = r"""
$shell = New-Object -ComObject WScript.Shell
$out = foreach ($p in ($env:BW_ARGS | ConvertFrom-Json)) {
  $l = $shell.CreateShortcut($p)
  [pscustomobject]@{ path = $p; target = $l.TargetPath; arguments = $l.Arguments }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


def _startup_folders() -> list[Path]:
    return [
        Path(os.environ["APPDATA"]) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        Path(os.environ["PROGRAMDATA"]) / r"Microsoft\Windows\Start Menu\Programs\StartUp",
    ]


def _resolve_shortcuts(shortcuts: list[Path]) -> dict[str, str]:
    if not shortcuts:
        return {}
    try:
        rows = run_powershell_json(_RESOLVE_SHORTCUTS, [str(s) for s in shortcuts], timeout=30)
    except (PowerShellError, ValueError):
        return {}
    return {row["path"]: f'"{(row.get("target") or "").strip(chr(34))}" {row.get("arguments") or ""}'.strip()
            for row in rows if row.get("target")}


class StartupFolderCollector:
    def collect(self) -> list[PersistenceEntry]:
        files = [item for folder in _startup_folders() if folder.is_dir()
                 for item in folder.iterdir()
                 if item.is_file() and item.name.lower() != "desktop.ini"]
        shortcut_commands = _resolve_shortcuts([f for f in files if f.suffix.lower() == ".lnk"])
        return [self._to_entry(item, shortcut_commands.get(str(item))) for item in files]

    @staticmethod
    def _to_entry(item: Path, shortcut_command: str | None) -> PersistenceEntry:
        command = shortcut_command or f'"{item}"'
        return PersistenceEntry(
            id=make_entry_id(PersistenceKind.STARTUP_FOLDER, str(item.parent), item.name),
            kind=PersistenceKind.STARTUP_FOLDER, name=item.name, location=str(item.parent),
            command=command, image_path=extract_image_path(command),
            details={"file": str(item)},
        )
