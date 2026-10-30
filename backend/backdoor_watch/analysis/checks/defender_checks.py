import os

from backdoor_watch.analysis.scan_context import ScanContext, file_target
from backdoor_watch.domain.findings import (Finding, FindingTarget, FindingTargetKind, Severity,
                                            make_finding_id)


def _file_path(resource: str) -> str | None:
    """Defender resources look like 'file:_C:\\path\\x.js'."""
    path = resource.split("_", 1)[1] if resource.startswith("file:_") else None
    return path if path and os.path.exists(path) else None


_DEFENDER_TARGET = FindingTarget(kind=FindingTargetKind.DEFENDER, ref="realtime", label="Microsoft Defender")


def check_defender_protection(ctx: ScanContext) -> list[Finding]:
    """Malware commonly switches off real-time protection before dropping later stages.

    Defender legitimately goes passive when another antivirus is registered and
    active (McAfee, Norton…), so that case is informational only.
    """
    status = ctx.defender_status
    if status is None or not status.available or status.real_time_protection is not False:
        return []
    scans = f"Last quick scan: {status.last_quick_scan or 'never'}. Last full scan: {status.last_full_scan or 'never'}."
    if status.active_antivirus:
        others = ", ".join(status.active_antivirus)
        return [Finding(
            id=make_finding_id("defender-passive", others), severity=Severity.INFO,
            category="Microsoft Defender", title=f"{others} is the active antivirus; Defender is in {status.running_mode}",
            detail=f"Windows Security Center reports {others} as enabled, so Defender is not scanning in real time. {scans}",
            remediation=f"Expected. Make sure {others} is up to date with real-time scanning on, and run a full scan with it.",
            targets=[_DEFENDER_TARGET],
        )]
    return [Finding(
        id=make_finding_id("defender-off", "real-time"), severity=Severity.HIGH,
        category="Microsoft Defender", title="No antivirus is protecting this PC in real time",
        detail=f"Defender real-time protection is OFF (mode: {status.running_mode}) and no other antivirus is active. {scans}",
        remediation="Turn real-time protection back on. If it switches itself off again, treat the PC as compromised.",
        targets=[_DEFENDER_TARGET],
    )]


def check_defender_detections(ctx: ScanContext) -> list[Finding]:
    findings = []
    for threat in ctx.defender_threats:
        failed = threat.action_success is False
        files = [p for p in (_file_path(r) for r in threat.resources) if p]
        findings.append(Finding(
            id=make_finding_id("defender", f"{threat.threat_id}|{threat.detected_at}"),
            severity=Severity.CRITICAL if failed else Severity.HIGH,
            category="Microsoft Defender detection",
            title=f"{threat.name}" + (" (remediation FAILED)" if failed else ""),
            detail=f"Detected {threat.detected_at or 'unknown time'}. Process: {threat.process_name or '-'}. "
                   f"Resources: {'; '.join(threat.resources[:8]) or '-'}",
            remediation="Even if Defender cleaned the file, earlier stages may have run. "
                        "Rotate credentials and review the other findings.",
            targets=[file_target(p) for p in files],
        ))
    return findings
