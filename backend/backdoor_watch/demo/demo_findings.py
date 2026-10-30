"""Fictional persistence entries and findings that mirror what a Contagious Interview infection looks like."""

from backdoor_watch.demo.demo_processes import C2_IP, USER
from backdoor_watch.domain.findings import Finding, FindingTarget, FindingTargetKind, Severity
from backdoor_watch.domain.persistence import PersistenceEntry, PersistenceKind, make_entry_id
from backdoor_watch.domain.process import SignatureInfo


def _entry(kind: PersistenceKind, name: str, location: str, command: str, image: str | None,
           sig: SignatureInfo | None, microsoft: bool = False) -> PersistenceEntry:
    return PersistenceEntry(id=make_entry_id(kind, location, name), kind=kind, name=name, location=location,
                            command=command, image_path=image, is_microsoft=microsoft, signature=sig,
                            details={"value_name": name})


_RUN = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
_OK = SignatureInfo(status="Valid", subject="CN=Microsoft Corporation, O=Microsoft Corporation")
EVIL_RUN = _entry(PersistenceKind.RUN_KEY, "SystemUpdateCheck", _RUN,
                  rf'"{USER}\.pyp\pythonw.exe" {USER}\.npl', rf"{USER}\.pyp\pythonw.exe", None)


def demo_persistence() -> list[PersistenceEntry]:
    return [
        EVIL_RUN,
        _entry(PersistenceKind.RUN_KEY, "OneDrive", _RUN, rf"{USER}\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background",
               rf"{USER}\AppData\Local\Microsoft\OneDrive\OneDrive.exe", _OK, True),
        _entry(PersistenceKind.RUN_KEY, "Slack", _RUN, rf"{USER}\AppData\Local\slack\slack.exe --startup",
               rf"{USER}\AppData\Local\slack\slack.exe", SignatureInfo(status="Valid", subject="CN=Slack Technologies")),
        _entry(PersistenceKind.SCHEDULED_TASK, "AnyDeskUpdate", "\\", rf"{USER}\AppData\Roaming\AnyDesk\AnyDesk.exe --update",
               rf"{USER}\AppData\Roaming\AnyDesk\AnyDesk.exe", SignatureInfo(status="Valid", subject="CN=philandro Software GmbH")),
        _entry(PersistenceKind.SERVICE, "postgresql-x64-18", r"HKLM\SYSTEM\CurrentControlSet\Services",
               r'"C:\Program Files\PostgreSQL\18\bin\pg_ctl.exe" runservice -N postgresql-x64-18',
               r"C:\Program Files\PostgreSQL\18\bin\pg_ctl.exe", SignatureInfo(status="NotSigned")),
        _entry(PersistenceKind.SERVICE, "Spooler", r"HKLM\SYSTEM\CurrentControlSet\Services",
               r"C:\Windows\System32\spoolsv.exe", r"C:\Windows\System32\spoolsv.exe", _OK, True),
        _entry(PersistenceKind.SCHEDULED_TASK, "ScheduledDefrag", "\\Microsoft\\Windows\\Defrag\\",
               r"C:\Windows\System32\defrag.exe -c -h", r"C:\Windows\System32\defrag.exe", _OK, True),
    ]


def _target(kind: FindingTargetKind, ref: str, label: str) -> FindingTarget:
    return FindingTarget(kind=kind, ref=ref, label=label)


def _finding(fid: str, severity: Severity, category: str, title: str, detail: str, fix: str,
             targets: list[FindingTarget]) -> Finding:
    return Finding(id=fid, severity=severity, category=category, title=title, detail=detail, remediation=fix,
                   targets=targets)


def demo_findings() -> list[Finding]:
    kill = "Kill the process tree, quarantine its executable/script, then block its remote addresses."
    return [
        _finding("d1", Severity.CRITICAL, "Known malware artifact", rf"Found {USER}\.n2",
                 "InvisibleFerret drop folder (pay / bow / mlip modules). Folder contents: pay, bow, mlip",
                 "Kill any python/node process using it, quarantine the path, check Run keys and scheduled tasks for "
                 "references, then rotate all credentials.", [_target(FindingTargetKind.FILE, rf"{USER}\.n2", rf"{USER}\.n2")]),
        _finding("d2", Severity.CRITICAL, "Malicious command line", "InvisibleFerret module path in command line: python.exe",
                 rf"PID 3377 matched rule 'invisibleferret-paths'. Command: {USER}\.pyp\python.exe {USER}\.n2\pay",
                 kill, [_target(FindingTargetKind.PROCESS, "3377", "python.exe (PID 3377)"),
                        _target(FindingTargetKind.FILE, rf"{USER}\.pyp\python.exe", rf"{USER}\.pyp\python.exe")]),
        _finding("d3", Severity.HIGH, "Suspicious remote port", f"python.exe → {C2_IP}:1224",
                 "BeaverTail / InvisibleFerret C2 port reported in Contagious Interview campaigns. State ESTABLISHED, PID 3377.",
                 "Block the remote IP in the firewall, kill the owning process, then investigate its files.",
                 [_target(FindingTargetKind.REMOTE_IP, C2_IP, C2_IP), _target(FindingTargetKind.PROCESS, "3377", "python.exe (PID 3377)")]),
        _finding("d4", Severity.HIGH, "Autostart / persistence", "run key: SystemUpdateCheck",
                 rf"starts a program from a user-writable or hidden folder; launches a script interpreter. Command: {USER}\.pyp\pythonw.exe {USER}\.npl",
                 "If you don't recognize it: remove the entry (a backup is kept), then quarantine the file.",
                 [_target(FindingTargetKind.PERSISTENCE, EVIL_RUN.id, "run_key: SystemUpdateCheck")]),
        _finding("d5", Severity.MEDIUM, "Remote access tool", "Remote access tool running: AnyDesk.exe",
                 "InvisibleFerret installs AnyDesk for hands-on access. PID 3412.",
                 "If you did not install it yourself: kill it, uninstall it, and remove its persistence.",
                 [_target(FindingTargetKind.PROCESS, "3412", "AnyDesk.exe (PID 3412)")]),
        _finding("d6", Severity.INFO, "Microsoft Defender", "McAfee is the active antivirus; Defender is in Passive Mode",
                 "Windows Security Center reports McAfee as enabled, so Defender is not scanning in real time.",
                 "Expected. Make sure McAfee is up to date with real-time scanning on.",
                 [_target(FindingTargetKind.DEFENDER, "realtime", "Microsoft Defender")]),
    ]
