from collections import defaultdict

from backdoor_watch.analysis.checks.process_checks import foreign_processes
from backdoor_watch.analysis.scan_context import ScanContext, process_target, remote_target
from backdoor_watch.domain.findings import Finding, Severity, make_finding_id
from backdoor_watch.domain.network import Connection
from backdoor_watch.domain.process import ProcessInfo

_WEB_PORTS = frozenset({80, 443})
_BLOCK_ADVICE = "Block the remote IP in the firewall, kill the owning process, then investigate its files."


def _external_by_pid(ctx: ScanContext) -> dict[int, list[Connection]]:
    grouped: dict[int, list[Connection]] = defaultdict(list)
    for conn in ctx.connections:
        if conn.pid and conn.is_external and conn.state == "ESTABLISHED":
            grouped[conn.pid].append(conn)
    return grouped


def _endpoint(conn: Connection) -> str:
    return f"{conn.remote_host or conn.remote_ip}:{conn.remote_port}"


def check_suspicious_ports(ctx: ScanContext) -> list[Finding]:
    findings = []
    processes = {p.pid: p for p in ctx.processes}
    for conn in ctx.connections:
        rule = ctx.rules.suspicious_ports.get(conn.remote_port or -1)
        if rule is None or not conn.is_external or conn.pid in ctx.own_pids:
            continue
        owner = processes.get(conn.pid or -1)
        findings.append(Finding(
            id=make_finding_id("port", f"{conn.remote_ip}|{conn.remote_port}|{conn.pid}"),
            severity=rule.severity, category="Suspicious remote port",
            title=f"{conn.process_name or 'unknown'} → {_endpoint(conn)}",
            detail=f"{rule.reason}. State {conn.state}, PID {conn.pid}.",
            remediation=_BLOCK_ADVICE,
            targets=[remote_target(conn.remote_ip, conn.remote_host)]
            + ([process_target(owner)] if owner else []),
        ))
    return findings


def _risky_process_finding(process: ProcessInfo, conns: list[Connection], severity: Severity,
                           title: str, detail: str) -> Finding:
    endpoints = ", ".join(sorted({_endpoint(c) for c in conns})[:10])
    return Finding(
        id=make_finding_id("outbound", f"{title}|{process.pid}"), severity=severity,
        category="Outbound connection", title=f"{title}: {process.name}",
        detail=f"{detail} PID {process.pid} → {endpoints}. Command: {process.cmdline[:400]}",
        remediation=_BLOCK_ADVICE,
        targets=[process_target(process)] + [remote_target(c.remote_ip, c.remote_host) for c in conns[:5]],
    )


def check_outbound_by_risky_processes(ctx: ScanContext) -> list[Finding]:
    findings = []
    by_pid = _external_by_pid(ctx)
    running = {p.pid for p in ctx.processes}
    for process in foreign_processes(ctx):
        conns = by_pid.get(process.pid)
        if not conns:
            continue
        if ctx.paths.is_script_host(process.exe or process.name):
            raw_ip_odd_port = [c for c in conns if not c.remote_host and c.remote_port not in _WEB_PORTS]
            severity = Severity.HIGH if raw_ip_odd_port else Severity.MEDIUM
            # BeaverTail starts its Python stage detached, so the launcher is gone by the time we look.
            detached = " Its parent process has exited (detached background process)." \
                if process.ppid not in running else ""
            findings.append(_risky_process_finding(
                process, conns, severity, "Script interpreter talking to the internet",
                "Node/Python/PowerShell with live external connections; BeaverTail-style loaders "
                "connect to raw IPs on non-web ports." + detached))
        elif process.signature is not None and process.signature.is_untrusted:
            findings.append(_risky_process_finding(
                process, conns, Severity.MEDIUM, "Unsigned program talking to the internet",
                f"Signature status: {process.signature.status}."))
    return findings


def check_exposed_listeners(ctx: ScanContext) -> list[Finding]:
    findings = []
    processes = {p.pid: p for p in foreign_processes(ctx)}
    for conn in ctx.connections:
        process = processes.get(conn.pid or -1)
        if not (conn.state == "LISTEN" and conn.exposure == "network" and process):
            continue
        unverified = process.signature is not None and process.signature.is_untrusted
        if not (ctx.paths.is_script_host(process.exe or process.name) or unverified):
            continue
        findings.append(Finding(
            id=make_finding_id("listener", f"{process.pid}|{conn.local_port}"), severity=Severity.MEDIUM,
            category="Open port", title=f"{process.name} accepts connections from the network on port {conn.local_port}",
            detail=f"Bound to {conn.local_ip}:{conn.local_port}. Command: {process.cmdline[:400]}",
            remediation="If this is not a dev server you started, kill it and block the program in the firewall.",
            targets=[process_target(process)],
        ))
    return findings
