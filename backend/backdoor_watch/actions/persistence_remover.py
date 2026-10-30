"""Removes or disables autostart entries, keeping a backup of what was removed."""

import json
import time
import winreg
from collections.abc import Callable
from pathlib import Path

from backdoor_watch.actions.quarantine_vault import QuarantineVault
from backdoor_watch.collectors.persistence.run_keys import HIVES
from backdoor_watch.domain.errors import ActionFailedError
from backdoor_watch.domain.persistence import PersistenceEntry, PersistenceKind
from backdoor_watch.platform.powershell import PowerShellError, run_powershell

_REMOVE_TASK = r"""
$a = $env:BW_ARGS | ConvertFrom-Json
$xml = Export-ScheduledTask -TaskPath $a.task_path -TaskName $a.task_name -ErrorAction Stop
Unregister-ScheduledTask -TaskPath $a.task_path -TaskName $a.task_name -Confirm:$false -ErrorAction Stop
$xml
"""

_DISABLE_SERVICE = r"""
$a = $env:BW_ARGS | ConvertFrom-Json
Stop-Service -Name $a.service_name -Force -ErrorAction SilentlyContinue
Set-Service -Name $a.service_name -StartupType Disabled -ErrorAction Stop
"""

_REMOVE_WMI = r"""
$a = $env:BW_ARGS | ConvertFrom-Json
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding |
  Where-Object { $_.Consumer.Name -eq $a.consumer_name } | Remove-CimInstance -ErrorAction Stop
Get-CimInstance -Namespace root/subscription -ClassName $a.consumer_class |
  Where-Object { $_.Name -eq $a.consumer_name } | Remove-CimInstance -ErrorAction Stop
"""


class PersistenceRemover:
    def __init__(self, vault: QuarantineVault, backup_dir: Path) -> None:
        self._vault = vault
        self._backup_dir = backup_dir
        backup_dir.mkdir(parents=True, exist_ok=True)
        self._handlers: dict[PersistenceKind, Callable[[PersistenceEntry], str]] = {
            PersistenceKind.RUN_KEY: self._delete_run_value,
            PersistenceKind.STARTUP_FOLDER: self._quarantine_startup_file,
            PersistenceKind.SCHEDULED_TASK: self._unregister_task,
            PersistenceKind.SERVICE: self._disable_service,
            PersistenceKind.WMI_CONSUMER: self._remove_wmi_consumer,
        }

    def remove(self, entry: PersistenceEntry) -> str:
        self._write_backup(entry, suffix="json", content=entry.model_dump_json(indent=2))
        return self._handlers[entry.kind](entry)

    def _delete_run_value(self, entry: PersistenceEntry) -> str:
        details = entry.details
        try:
            with winreg.OpenKey(HIVES[details["hive"]], details["subkey"], 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, details["value_name"])
        except OSError as exc:
            raise ActionFailedError(f"Could not delete registry value: {exc}") from exc
        return f"Deleted Run value '{entry.name}' from {entry.location}"

    def _quarantine_startup_file(self, entry: PersistenceEntry) -> str:
        item = self._vault.quarantine(entry.details["file"], reason=f"Startup entry {entry.name}")
        return f"Moved startup item to quarantine ({item.id})"

    def _unregister_task(self, entry: PersistenceEntry) -> str:
        xml = self._powershell(_REMOVE_TASK, entry.details)
        backup = self._write_backup(entry, suffix="xml", content=xml)
        return f"Deleted scheduled task {entry.location}{entry.name} (XML backup: {backup})"

    def _disable_service(self, entry: PersistenceEntry) -> str:
        self._powershell(_DISABLE_SERVICE, entry.details)
        return f"Stopped and disabled service {entry.name}; quarantine its binary if malicious"

    def _remove_wmi_consumer(self, entry: PersistenceEntry) -> str:
        self._powershell(_REMOVE_WMI, entry.details)
        return f"Removed WMI consumer {entry.name} and its bindings"

    def _write_backup(self, entry: PersistenceEntry, suffix: str, content: str) -> Path:
        path = self._backup_dir / f"{int(time.time())}-{entry.kind.value}-{entry.id}.{suffix}"
        path.write_text(content, encoding="utf-8")
        return path

    @staticmethod
    def _powershell(script: str, details: dict[str, str]) -> str:
        try:
            return run_powershell(script, details, timeout=60)
        except PowerShellError as exc:
            raise ActionFailedError(f"Removal failed (administrator required?): {exc}") from exc


def describe_entry(entry: PersistenceEntry) -> dict[str, str]:
    """Flat audit-log details for an entry."""
    return {"kind": entry.kind.value, "name": entry.name, "location": entry.location,
            "command": entry.command[:500], "details": json.dumps(entry.details)[:500]}
