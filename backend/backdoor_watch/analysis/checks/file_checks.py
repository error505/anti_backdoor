import os

from backdoor_watch.analysis.scan_context import ScanContext, file_target
from backdoor_watch.domain.findings import Finding, make_finding_id

_MAX_LISTED = 15


def _describe_contents(path: str) -> str:
    if not os.path.isdir(path):
        return f"File size: {os.path.getsize(path)} bytes"
    names = sorted(os.listdir(path))
    listed = ", ".join(names[:_MAX_LISTED])
    more = f" (+{len(names) - _MAX_LISTED} more)" if len(names) > _MAX_LISTED else ""
    return f"Folder contents: {listed or '(empty)'}{more}"


def check_ioc_paths(ctx: ScanContext) -> list[Finding]:
    findings = []
    for rule in ctx.rules.ioc_paths:
        if not os.path.exists(rule.path):
            continue
        findings.append(Finding(
            id=make_finding_id("ioc-path", rule.path), severity=rule.severity,
            category="Known malware artifact", title=f"Found {rule.path}",
            detail=f"{rule.reason}. {_describe_contents(rule.path)}",
            remediation="Kill any python/node process using it, quarantine the path, check Run keys "
                        "and scheduled tasks for references, then rotate all credentials.",
            targets=[file_target(rule.path)],
        ))
    return findings
