"""WMI event consumers that run commands or scripts: a stealthy, fileless persistence trick."""

from backdoor_watch.domain.command_line import extract_image_path
from backdoor_watch.domain.persistence import PersistenceEntry, PersistenceKind, make_entry_id
from backdoor_watch.platform.powershell import PowerShellError, run_powershell_json

_LOCATION = r"root\subscription"
_LIST_CONSUMERS = r"""
$consumers = @(Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue) +
             @(Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue)
$out = foreach ($c in $consumers) {
  [pscustomobject]@{ name = $c.Name; class = $c.CimClass.CimClassName
    command = $(if ($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif ($c.ExecutablePath) { $c.ExecutablePath } else { [string]$c.ScriptText }) }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


class WmiConsumerCollector:
    def collect(self) -> list[PersistenceEntry]:
        try:
            rows = run_powershell_json(_LIST_CONSUMERS, timeout=60)
        except (PowerShellError, ValueError):
            return []
        return [self._to_entry(row) for row in rows if row.get("name")]

    @staticmethod
    def _to_entry(row: dict) -> PersistenceEntry:
        command = row.get("command") or ""
        is_script = row.get("class") == "ActiveScriptEventConsumer"
        return PersistenceEntry(
            id=make_entry_id(PersistenceKind.WMI_CONSUMER, _LOCATION, row["name"]),
            kind=PersistenceKind.WMI_CONSUMER, name=row["name"], location=_LOCATION,
            command=command[:2000], image_path=None if is_script else extract_image_path(command),
            details={"consumer_class": row.get("class") or "", "consumer_name": row["name"]},
        )
