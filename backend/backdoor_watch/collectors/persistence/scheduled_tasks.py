from backdoor_watch.domain.command_line import extract_image_path
from backdoor_watch.domain.persistence import PersistenceEntry, PersistenceKind, make_entry_id
from backdoor_watch.platform.powershell import run_powershell_json

_LIST_TASKS = r"""
$out = Get-ScheduledTask | ForEach-Object {
  $exec = @($_.Actions | Where-Object { $_.Execute })
  [pscustomobject]@{
    path = $_.TaskPath; name = $_.TaskName; state = [string]$_.State; author = $_.Author
    execute = $(if ($exec.Count) { $exec[0].Execute } else { $null })
    arguments = $(if ($exec.Count) { $exec[0].Arguments } else { $null })
  }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


class ScheduledTaskCollector:
    def collect(self) -> list[PersistenceEntry]:
        return [self._to_entry(row) for row in run_powershell_json(_LIST_TASKS, timeout=120)]

    @staticmethod
    def _to_entry(row: dict) -> PersistenceEntry:
        execute = (row.get("execute") or "").strip().strip('"')
        command = f'"{execute}" {row.get("arguments") or ""}'.strip() if execute else "(COM handler)"
        return PersistenceEntry(
            id=make_entry_id(PersistenceKind.SCHEDULED_TASK, row["path"], row["name"]),
            kind=PersistenceKind.SCHEDULED_TASK, name=row["name"], location=row["path"],
            command=command, image_path=extract_image_path(execute) if execute else None,
            enabled=row.get("state") != "Disabled",
            details={"task_path": row["path"], "task_name": row["name"],
                     "author": row.get("author") or "", "state": row.get("state") or ""},
        )
