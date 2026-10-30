"""Hashes the security-relevant part of a report so unchanged states are not re-analysed.

Deliberately excluded: ordinary internet connections, traffic counters and
timestamps. Browsers open new connections every second, so including them
would make every check look "changed" and burn tokens. Suspicious connections
still count, because they surface as findings.
"""

import hashlib
import json

from backdoor_watch.reporting.report_model import SecurityReport


def state_fingerprint(report: SecurityReport) -> str:
    relevant = {
        "findings": sorted(f"{f.id}:{f.severity.value}" for f in report.findings),
        "programs": sorted({(p.exe or p.name).lower() for p in report.non_microsoft_processes}),
        "listeners": sorted({f"{c.process}|{c.local}" for c in report.network_listeners}),
        "autostart": sorted(e.id for e in report.autostart_non_microsoft),
        "defender": sorted(t.threat_id for t in report.defender_threats),
    }
    return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode("utf-8")).hexdigest()
