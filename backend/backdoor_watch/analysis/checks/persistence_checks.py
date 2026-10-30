from backdoor_watch.analysis.scan_context import ScanContext, file_target, persistence_target
from backdoor_watch.domain.findings import Finding, Severity, make_finding_id
from backdoor_watch.domain.persistence import PersistenceEntry, PersistenceKind

_AUTOSTART_KINDS = {PersistenceKind.RUN_KEY, PersistenceKind.STARTUP_FOLDER, PersistenceKind.SCHEDULED_TASK}

Reason = tuple[Severity, str]


def _reasons(entry: PersistenceEntry, ctx: ScanContext) -> list[Reason]:
    reasons: list[Reason] = []
    paths = ctx.paths
    if entry.kind == PersistenceKind.WMI_CONSUMER:
        reasons.append((Severity.HIGH, "WMI event consumer that runs commands (rarely legitimate)"))
    signed = entry.signature is not None and entry.signature.is_valid
    script_host = paths.is_script_host(entry.image_path)
    # Signed vendor apps (Zoom, Teams…) legitimately install per-user; interpreters do not get that pass.
    if paths.is_suspicious_location(entry.image_path) and (not signed or script_host):
        reasons.append((Severity.HIGH, "starts a program from a user-writable or hidden folder"))
    if script_host:
        refs_user_dir = paths.references_user_writable(entry.command)
        reasons.append((Severity.HIGH if refs_user_dir else Severity.MEDIUM,
                        "launches a script interpreter" + (" on a file in a user folder" if refs_user_dir else "")))
    if entry.signature is not None and entry.signature.is_untrusted:
        protected = paths.is_admin_protected_install(entry.image_path)
        reasons.append((Severity.LOW if protected else Severity.MEDIUM,
                        f"executable signature: {entry.signature.status}"))
    if entry.image_path and not entry.image_exists and entry.enabled and entry.kind in _AUTOSTART_KINDS:
        reasons.append((Severity.LOW, "points to a file that no longer exists"))
    if paths.remote_access_tool(entry.image_path):
        reasons.append((Severity.MEDIUM, "remote access tool set to auto-start"))
    for rule in ctx.rules.cmdline_rules:
        if rule.pattern.search(entry.command):
            reasons.append((rule.severity, rule.title))
    return reasons


def check_persistence(ctx: ScanContext) -> list[Finding]:
    findings = []
    for entry in ctx.persistence:
        if entry.is_microsoft:
            continue
        reasons = _reasons(entry, ctx)
        if not reasons:
            continue
        severity = max((s for s, _ in reasons), key=lambda s: s.rank)
        targets = [persistence_target(entry)]
        if entry.image_path and entry.image_exists:
            targets.append(file_target(entry.image_path))
        findings.append(Finding(
            id=make_finding_id("persistence", entry.id), severity=severity,
            category="Autostart / persistence", title=f"{entry.kind.value.replace('_', ' ')}: {entry.name}",
            detail="; ".join(text for _, text in reasons) + f". Command: {entry.command[:600]}",
            remediation="If you don't recognize it: remove the entry (a backup is kept), then quarantine the file.",
            targets=targets,
        ))
    return findings
