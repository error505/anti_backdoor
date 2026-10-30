from backdoor_watch.analysis.checks.defender_checks import check_defender_protection
from backdoor_watch.analysis.ioc_rules import load_rules
from backdoor_watch.analysis.path_classifier import PathClassifier
from backdoor_watch.analysis.scan_context import ScanContext
from backdoor_watch.domain.findings import Severity
from backdoor_watch.domain.security_tools import DefenderStatus
from backdoor_watch.settings import Settings

RULES = load_rules(Settings(port=0, token="").rules_path)


def _context(status: DefenderStatus) -> ScanContext:
    return ScanContext(processes=[], connections=[], persistence=[], defender_threats=[], rules=RULES,
                       paths=PathClassifier(RULES), own_pids=frozenset(), defender_status=status)


def test_passive_defender_with_other_active_antivirus_is_informational():
    status = DefenderStatus(available=True, real_time_protection=False, running_mode="Passive Mode",
                            active_antivirus=["McAfee"])
    findings = check_defender_protection(_context(status))
    assert [f.severity for f in findings] == [Severity.INFO]


def test_no_realtime_antivirus_at_all_is_high():
    status = DefenderStatus(available=True, real_time_protection=False, running_mode="Normal")
    findings = check_defender_protection(_context(status))
    assert findings[0].severity == Severity.HIGH
    assert findings[0].targets[0].kind.value == "defender"


def test_realtime_on_reports_nothing():
    assert check_defender_protection(_context(DefenderStatus(available=True, real_time_protection=True))) == []
