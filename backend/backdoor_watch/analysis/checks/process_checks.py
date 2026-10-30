from collections.abc import Iterator

from backdoor_watch.analysis.scan_context import ScanContext, file_target, process_target
from backdoor_watch.domain.findings import Finding, FindingTarget, Severity, make_finding_id
from backdoor_watch.domain.process import ProcessInfo

_KILL_ADVICE = "Kill the process tree, quarantine its executable/script, then block its remote addresses."


def foreign_processes(ctx: ScanContext) -> Iterator[ProcessInfo]:
    return (p for p in ctx.processes if p.pid not in ctx.own_pids)


def _targets(process: ProcessInfo) -> list[FindingTarget]:
    targets = [process_target(process)]
    if process.exe:
        targets.append(file_target(process.exe))
    return targets


def check_command_lines(ctx: ScanContext) -> list[Finding]:
    findings = []
    for process in foreign_processes(ctx):
        text = f"{process.exe or ''} {process.cmdline}"
        for rule in ctx.rules.cmdline_rules:
            if not rule.pattern.search(text):
                continue
            findings.append(Finding(
                id=make_finding_id("cmdline", f"{rule.id}|{process.pid}"), severity=rule.severity,
                category="Malicious command line", title=f"{rule.title}: {process.name}",
                detail=f"PID {process.pid} matched rule '{rule.id}'. Command: {process.cmdline[:800]}",
                remediation=_KILL_ADVICE, targets=_targets(process),
            ))
    return findings


def check_script_host_locations(ctx: ScanContext) -> list[Finding]:
    findings = []
    for process in foreign_processes(ctx):
        if not ctx.paths.is_script_host(process.exe or process.name):
            continue
        if ctx.paths.is_suspicious_location(process.exe):
            severity, reason = Severity.HIGH, f"interpreter itself lives in {process.exe}"
        elif ctx.paths.references_user_writable(process.cmdline):
            severity, reason = Severity.MEDIUM, "runs code from a user folder (Downloads/Desktop/Temp/AppData)"
        else:
            continue
        findings.append(Finding(
            id=make_finding_id("script-host-location", str(process.pid)), severity=severity,
            category="Script interpreter", title=f"{process.name} {reason}",
            detail=f"PID {process.pid}. Command: {process.cmdline[:800]}",
            remediation="Confirm you started this. If not: " + _KILL_ADVICE, targets=_targets(process),
        ))
    return findings


def check_unsigned_in_user_dirs(ctx: ScanContext) -> list[Finding]:
    findings = []
    for process in foreign_processes(ctx):
        signature = process.signature
        if signature is None or not signature.is_untrusted or not ctx.paths.is_suspicious_location(process.exe):
            continue
        findings.append(Finding(
            id=make_finding_id("unsigned-user-dir", f"{process.exe}"), severity=Severity.MEDIUM,
            category="Unverified executable", title=f"Unsigned program running from user folder: {process.name}",
            detail=f"{process.exe} (signature: {signature.status}). PID {process.pid}.",
            remediation="Check the file on virustotal.com (upload the SHA-256, not the file). " + _KILL_ADVICE,
            targets=_targets(process),
        ))
    return findings


def check_remote_access_tools(ctx: ScanContext) -> list[Finding]:
    findings = []
    for process in foreign_processes(ctx):
        tool = ctx.paths.remote_access_tool(process.exe or process.name)
        if not tool:
            continue
        findings.append(Finding(
            id=make_finding_id("remote-access", f"{tool}|{process.pid}"), severity=Severity.MEDIUM,
            category="Remote access tool", title=f"Remote access tool running: {process.name}",
            detail=f"InvisibleFerret installs AnyDesk for hands-on access. PID {process.pid}, {process.exe}.",
            remediation="If you did not install it yourself: kill it, uninstall it, and remove its persistence.",
            targets=_targets(process),
        ))
    return findings
