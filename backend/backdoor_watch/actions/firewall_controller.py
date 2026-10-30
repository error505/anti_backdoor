import ipaddress
import os

from backdoor_watch.domain.errors import ActionFailedError, ActionRefusedError, NotFoundError
from backdoor_watch.domain.security_tools import FirewallRule
from backdoor_watch.platform.powershell import PowerShellError, run_powershell, run_powershell_json

RULE_GROUP = "BackdoorWatch"

_ADD_RULES = r"""
$a = $env:BW_ARGS | ConvertFrom-Json
foreach ($dir in 'Outbound', 'Inbound') {
  $p = @{ DisplayName = "$($a.name) ($dir)"; Direction = $dir; Action = 'Block'; Group = 'BackdoorWatch'; Description = $a.target }
  if ($a.ip) { $p.RemoteAddress = $a.ip } else { $p.Program = $a.program }
  New-NetFirewallRule @p | Out-Null
}
"""

_LIST_RULES = r"""
$out = Get-NetFirewallRule -Group 'BackdoorWatch' -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ id = $_.Name; display_name = $_.DisplayName; direction = [string]$_.Direction
    target = $_.Description; enabled = ([string]$_.Enabled -eq 'True') }
}
ConvertTo-Json -InputObject @($out) -Compress
"""

_REMOVE_RULE = r"""
$a = $env:BW_ARGS | ConvertFrom-Json
Get-NetFirewallRule -Name $a.id -ErrorAction Stop | Where-Object { $_.Group -eq 'BackdoorWatch' } | Remove-NetFirewallRule
"""


class FirewallController:
    """Only creates, lists and deletes rules in its own group, never the user's other rules."""

    def block_remote_ip(self, ip: str) -> None:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ActionRefusedError(f"'{ip}' is not an IP address") from exc
        if address.is_loopback or address.is_unspecified:
            raise ActionRefusedError("Blocking loopback or unspecified addresses would break Windows")
        self._add({"name": f"BackdoorWatch block {address}", "ip": str(address), "target": str(address)})

    def block_program(self, program_path: str) -> None:
        if not os.path.isfile(program_path):
            raise NotFoundError(f"{program_path} does not exist")
        name = os.path.basename(program_path)
        self._add({"name": f"BackdoorWatch block {name}", "program": program_path, "target": program_path})

    def list_rules(self) -> list[FirewallRule]:
        return [FirewallRule(**row) for row in run_powershell_json(_LIST_RULES, timeout=60)]

    def remove_rule(self, rule_id: str) -> None:
        self._run(_REMOVE_RULE, {"id": rule_id})

    def _add(self, args: dict) -> None:
        self._run(_ADD_RULES, args)

    @staticmethod
    def _run(script: str, args: dict) -> None:
        try:
            run_powershell(script, args, timeout=60)
        except PowerShellError as exc:
            raise ActionFailedError(f"Firewall change failed (administrator required): {exc}") from exc
