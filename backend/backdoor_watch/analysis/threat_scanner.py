import logging
from collections.abc import Sequence

from backdoor_watch.analysis.checks.defender_checks import (check_defender_detections,
                                                            check_defender_protection)
from backdoor_watch.analysis.checks.file_checks import check_ioc_paths
from backdoor_watch.analysis.checks.malware_checks import check_malware_hits
from backdoor_watch.analysis.checks.network_checks import (check_exposed_listeners,
                                                           check_outbound_by_risky_processes,
                                                           check_suspicious_ports)
from backdoor_watch.analysis.checks.persistence_checks import check_persistence
from backdoor_watch.analysis.checks.process_checks import (check_command_lines,
                                                           check_remote_access_tools,
                                                           check_script_host_locations,
                                                           check_unsigned_in_user_dirs)
from backdoor_watch.analysis.scan_context import ScanContext, ThreatCheck
from backdoor_watch.domain.findings import Finding

logger = logging.getLogger(__name__)

DEFAULT_CHECKS: tuple[ThreatCheck, ...] = (
    check_ioc_paths,
    check_command_lines,
    check_script_host_locations,
    check_unsigned_in_user_dirs,
    check_remote_access_tools,
    check_suspicious_ports,
    check_outbound_by_risky_processes,
    check_exposed_listeners,
    check_persistence,
    check_defender_detections,
    check_defender_protection,
    check_malware_hits,
)


class ThreatScanner:
    def __init__(self, checks: Sequence[ThreatCheck] = DEFAULT_CHECKS) -> None:
        self._checks = checks

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: dict[str, Finding] = {}
        for check in self._checks:
            try:
                for finding in check(ctx):
                    findings.setdefault(finding.id, finding)
            except Exception as exc:  # a faulty check must not hide the others' results
                logger.exception("threat_check_failed", extra={"check": check.__name__, "error": str(exc)})
        return sorted(findings.values(), key=lambda f: f.severity.rank, reverse=True)
