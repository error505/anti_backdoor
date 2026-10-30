import os
from typing import Literal

from backdoor_watch.domain.errors import ActionFailedError
from backdoor_watch.domain.security_tools import DefenderStatus, DefenderThreat
from backdoor_watch.platform.powershell import (PowerShellError, run_powershell, run_powershell_json,
                                                start_powershell_detached)

# productState bits 8-15 hold the scanner state: 0x10 / 0x11 mean "on".
_STATUS = r"""
$s = Get-MpComputerStatus -ErrorAction Stop
function iso($d) { if ($d) { $d.ToString('o') } else { $null } }
$others = [string[]]@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
  Where-Object { $_.displayName -notmatch 'Defender' -and ((($_.productState -shr 8) -band 0xFF) -in 0x10, 0x11) } |
  ForEach-Object { $_.displayName })
$o = [pscustomobject]@{ antivirus_enabled = $s.AntivirusEnabled; real_time_protection = $s.RealTimeProtectionEnabled
  running_mode = [string]$s.AMRunningMode; active_antivirus = $others
  tamper_protected = $s.IsTamperProtected; signatures_updated = iso $s.AntivirusSignatureLastUpdated
  last_quick_scan = iso $s.QuickScanEndTime; last_full_scan = iso $s.FullScanEndTime }
ConvertTo-Json -InputObject @($o) -Compress
"""

_ENABLE_REALTIME = "Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop"
_SECURITY_SETTINGS_URI = "windowsdefender://threatsettings"

_THREATS = r"""
$names = @{}
Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $names[[string]$_.ThreatID] = $_ }
$out = Get-MpThreatDetection -ErrorAction SilentlyContinue | ForEach-Object {
  $t = $names[[string]$_.ThreatID]
  [pscustomobject]@{ threat_id = [string]$_.ThreatID
    name = $(if ($t) { $t.ThreatName } else { 'Unknown' })
    severity = $(if ($t) { [string]$t.SeverityID } else { '' })
    detected_at = $(if ($_.InitialDetectionTime) { $_.InitialDetectionTime.ToString('o') } else { $null })
    resources = @($_.Resources); process_name = $_.ProcessName; action_success = $_.ActionSuccess }
}
ConvertTo-Json -InputObject @($out) -Compress -Depth 3
"""

_SCAN = r"""
$a = $env:BW_ARGS | ConvertFrom-Json
if ($a.path) { Start-MpScan -ScanType CustomScan -ScanPath $a.path } else { Start-MpScan -ScanType $a.type }
"""

ScanType = Literal["QuickScan", "FullScan", "CustomScan"]


class DefenderClient:
    def status(self) -> DefenderStatus:
        try:
            rows = run_powershell_json(_STATUS, timeout=30)
        except (PowerShellError, ValueError) as exc:
            return DefenderStatus(available=False, error=str(exc)[:300])
        return DefenderStatus(available=True, **rows[0]) if rows else DefenderStatus(available=False)

    def threats(self) -> list[DefenderThreat]:
        try:
            rows = run_powershell_json(_THREATS, timeout=60)
        except (PowerShellError, ValueError):
            return []
        return [DefenderThreat(**{**row, "resources": [r for r in row.get("resources") or [] if r]})
                for row in rows]

    def enable_realtime_protection(self) -> None:
        try:
            run_powershell(_ENABLE_REALTIME, timeout=60)
        except PowerShellError as exc:
            raise ActionFailedError(f"Defender refused the change: {exc}") from exc
        status = self.status()
        if status.real_time_protection:
            return
        if status.active_antivirus:
            raise ActionFailedError(
                f"Defender stays passive while {', '.join(status.active_antivirus)} is the active antivirus. "
                "That is expected; make sure that product's real-time protection is on instead.")
        raise ActionFailedError("Real-time protection is still off (Tamper Protection only allows changing it "
                                "in Windows Security). Use 'Open Windows Security' and switch it on there.")

    @staticmethod
    def open_security_settings() -> None:
        os.startfile(_SECURITY_SETTINGS_URI)

    def start_scan(self, scan_type: ScanType, path: str | None) -> None:
        if scan_type == "CustomScan" and not path:
            raise ActionFailedError("A custom scan needs a path")
        start_powershell_detached(_SCAN, {"type": scan_type, "path": path})
