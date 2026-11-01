"""Builds the object graph once; nothing else constructs infrastructure."""

from dataclasses import dataclass

from backdoor_watch.actions.firewall_controller import FirewallController
from backdoor_watch.actions.persistence_remover import PersistenceRemover
from backdoor_watch.actions.process_controller import ProcessController, ProcessKillPolicy
from backdoor_watch.actions.quarantine_vault import QuarantineVault
from backdoor_watch.ai.analysis_archive import AnalysisArchive
from backdoor_watch.ai.analysis_scheduler import AiAnalysisScheduler
from backdoor_watch.ai.analysis_service import AiAnalysisService
from backdoor_watch.ai.schedule_store import AiScheduleStore
from backdoor_watch.ai.settings_store import AiSettingsStore
from backdoor_watch.analysis.ioc_rules import IocRules, load_rules
from backdoor_watch.analysis.source_scanner import SourceScanner
from backdoor_watch.analysis.threat_scanner import ThreatScanner
from backdoor_watch.capture.capture_log import CaptureLog
from backdoor_watch.capture.packet_sniffer import PacketSniffer
from backdoor_watch.collectors.connection_collector import ConnectionCollector
from backdoor_watch.collectors.defender_client import DefenderClient
from backdoor_watch.collectors.dns_names import DnsNameResolver
from backdoor_watch.collectors.persistence.persistence_scanner import PersistenceScanner
from backdoor_watch.collectors.persistence.run_keys import RunKeyCollector
from backdoor_watch.collectors.persistence.scheduled_tasks import ScheduledTaskCollector
from backdoor_watch.collectors.persistence.services import ServiceCollector
from backdoor_watch.collectors.persistence.startup_folders import StartupFolderCollector
from backdoor_watch.collectors.persistence.wmi_consumers import WmiConsumerCollector
from backdoor_watch.collectors.process_collector import ProcessCollector
from backdoor_watch.collectors.signature_verifier import SignatureVerifier
from backdoor_watch.collectors.tcp_traffic_meter import TcpTrafficMeter
from backdoor_watch.demo.demo_seed import seed_demo
from backdoor_watch.domain.activity import ActivityEvent, ActivityKind
from backdoor_watch.domain.malware import MalwareHit
from backdoor_watch.malware.hash_intel import LocalHashList, VirusTotalLookup
from backdoor_watch.malware.intel_settings import IntelSettingsStore
from backdoor_watch.malware.scanner import MalwareScanner
from backdoor_watch.demo.demo_ip_intel import DemoIpProvider
from backdoor_watch.flockion.client import FlockionClient
from backdoor_watch.guard.alarm import AlarmSounder
from backdoor_watch.guard.alert_log import AlertLog
from backdoor_watch.guard.guard_config_store import GuardConfigStore
from backdoor_watch.guard.guard_engine import GuardEngine
from backdoor_watch.guard.guard_rules import load_guard_rules
from backdoor_watch.guard.guard_service import GuardService
from backdoor_watch.guard.trust_policy import ProgramHasher, TrustPolicy
from backdoor_watch.malware.hasher import sha256_of
from backdoor_watch.ip_intel.ip_intel_service import IpIntelService
from backdoor_watch.ip_intel.ip_intel_store import IpIntelStore
from backdoor_watch.ip_intel.ip_providers import IpWhoIsProvider
from backdoor_watch.flockion.service import FlockionService
from backdoor_watch.flockion.settings_store import FlockionSettingsStore
from backdoor_watch.monitoring.event_log import EventLog
from backdoor_watch.monitoring.metrics_recorder import SAMPLE_INTERVAL_SECONDS, MetricsRecorder
from backdoor_watch.monitoring.periodic_job import PeriodicJob
from backdoor_watch.monitoring.refreshers import (DefenderRefresher, FindingsRefresher,
                                                  PersistenceRefresher, SnapshotRefresher)
from backdoor_watch.monitoring.self_identity import SelfIdentity
from backdoor_watch.monitoring.system_state import SystemState
from backdoor_watch.monitoring.traffic_ledger import TrafficLedger
from backdoor_watch.reporting.report_builder import ReportBuilder
from backdoor_watch.reporting.report_service import ReportService
from backdoor_watch.reporting.report_uploader import ReportUploader
from backdoor_watch.services.process_queries import ProcessQueries
from backdoor_watch.services.response_service import ResponseService
from backdoor_watch.settings import Settings


@dataclass
class AppServices:
    settings: Settings
    rules: IocRules
    state: SystemState
    events: EventLog
    ledger: TrafficLedger
    meter: TcpTrafficMeter
    capture_log: CaptureLog
    sniffer: PacketSniffer
    quarantine: QuarantineVault
    firewall: FirewallController
    defender: DefenderClient
    source_scanner: SourceScanner
    response: ResponseService
    process_queries: ProcessQueries
    persistence_refresher: PersistenceRefresher
    findings_refresher: FindingsRefresher
    reports: ReportService
    ai_settings: AiSettingsStore
    ai_analysis: AiAnalysisService
    analysis_archive: AnalysisArchive
    ai_scheduler: AiAnalysisScheduler
    flockion_settings: FlockionSettingsStore
    flockion: FlockionService
    malware_scanner: MalwareScanner
    intel_settings: IntelSettingsStore
    ip_intel: IpIntelService
    guard: GuardService
    metrics: MetricsRecorder
    jobs: list[PeriodicJob]

    def start(self) -> None:
        for job in self.jobs:
            job.start()

    def stop(self) -> None:
        self.sniffer.stop()
        for job in self.jobs:
            job.stop()


def _persistence_scanner(signatures: SignatureVerifier) -> PersistenceScanner:
    sources = [RunKeyCollector(), StartupFolderCollector(), ScheduledTaskCollector(), ServiceCollector(),
               WmiConsumerCollector()]
    return PersistenceScanner(sources, signatures)


@dataclass(frozen=True)
class _Insights:
    reports: ReportService
    ai_settings: AiSettingsStore
    ai_analysis: AiAnalysisService
    archive: AnalysisArchive
    scheduler: AiAnalysisScheduler
    flockion_settings: FlockionSettingsStore
    flockion: FlockionService


def _insights(settings: Settings, state: SystemState, ledger: TrafficLedger, events: EventLog,
              ip_intel: IpIntelService, alerts: AlertLog) -> _Insights:
    archive = AnalysisArchive(settings.ai_history_path)
    builder = ReportBuilder(state, ledger, events, lambda: archive.latest, ip_intel.lookup, alerts.all)
    ai_settings = AiSettingsStore(settings.ai_settings_path)
    analysis = AiAnalysisService(ai_settings, builder, archive, events)
    scheduler = AiAnalysisScheduler(AiScheduleStore(settings.ai_schedule_path), analysis, archive, events)
    flockion_settings = FlockionSettingsStore(settings.flockion_settings_path)
    return _Insights(reports=ReportService(builder, ReportUploader(), events), ai_settings=ai_settings,
                     ai_analysis=analysis, archive=archive, scheduler=scheduler,
                     flockion_settings=flockion_settings,
                     flockion=FlockionService(flockion_settings, builder, FlockionClient(), events))


def _malware_scanner(settings: Settings, state: SystemState, events: EventLog) -> tuple[MalwareScanner, IntelSettingsStore]:
    intel = IntelSettingsStore(settings.intel_settings_path)

    def publish(hits: list[MalwareHit]) -> None:
        state.update(malware_hits=hits)
        events.append(ActivityEvent(kind=ActivityKind.ACTION_TAKEN,
                                    summary=f"Malware scan finished: {len(hits)} flagged file(s)"))

    scanner = MalwareScanner(LocalHashList(settings.known_bad_hashes_path), VirusTotalLookup(settings.virustotal_cache_path),
                             intel.virustotal_key, lambda: state.current, publish, [settings.install_root])
    return scanner, intel


def _ip_intel(settings: Settings) -> IpIntelService:
    store = IpIntelStore(settings.ip_intel_cache_path)
    if settings.demo:  # fictional provider; documentation-range addresses are normally not lookup-eligible
        return IpIntelService(DemoIpProvider(), store, settings.ip_intel_settings_path, lambda ip: True,
                              lambda ip: None)
    return IpIntelService(IpWhoIsProvider(), store, settings.ip_intel_settings_path)


def _guard(settings: Settings, rules: IocRules, state: SystemState, events: EventLog,
           response: ResponseService, alerts: AlertLog) -> GuardService:
    guard_rules = load_guard_rules()
    hasher = ProgramHasher(sha256_of)
    policy = TrustPolicy(hasher)
    attacker_ports = frozenset(p for p, rule in rules.suspicious_ports.items() if rule.severity.value == "high")
    siren = AlarmSounder()
    return GuardService(GuardConfigStore(settings.guard_config_path), GuardEngine(guard_rules, policy, attacker_ports),
                        policy, hasher, response, state, events, alerts, siren.alarm, siren.test,
                        guard_rules.allowed_host_suffixes)


def build_services(settings: Settings) -> AppServices:
    rules = load_rules(settings.rules_path)
    state, events, ledger = SystemState(), EventLog(settings.log_dir), TrafficLedger()
    signatures, dns, meter = SignatureVerifier(), DnsNameResolver(), TcpTrafficMeter()
    defender, vault = DefenderClient(), QuarantineVault(settings.quarantine_dir)
    firewall, capture_log = FirewallController(), CaptureLog()
    ip_intel = _ip_intel(settings)
    alerts = AlertLog()
    insights = _insights(settings, state, ledger, events, ip_intel, alerts)
    malware_scanner, intel_settings = _malware_scanner(settings, state, events)

    persistence = PersistenceRefresher(_persistence_scanner(signatures), state, events)
    findings = FindingsRefresher(ThreatScanner(), rules, state)
    response = ResponseService(ProcessController(ProcessKillPolicy(rules.protected_processes)), vault, firewall,
                               PersistenceRemover(vault, settings.backup_dir), defender, state, events)
    guard = _guard(settings, rules, state, events, response, alerts)
    metrics = MetricsRecorder(state, ledger)
    snapshot = SnapshotRefresher(ProcessCollector(signatures), ConnectionCollector(dns, meter), ledger, state, events,
                                 SelfIdentity(settings.install_root), guard.check)
    jobs = [
        PeriodicJob("snapshot", 2, snapshot.refresh),
        PeriodicJob("metrics", SAMPLE_INTERVAL_SECONDS, metrics.sample),
        PeriodicJob("signatures", 3, signatures.verify_pending),
        PeriodicJob("dns-cache", 15, dns.refresh_from_system_cache),
        PeriodicJob("findings", 5, findings.refresh),
        PeriodicJob("persistence", 120, persistence.refresh),
        PeriodicJob("defender", 300, DefenderRefresher(defender, state).refresh),
        # Only checks whether an AI Watch run is due; the schedule's own interval decides when tokens are spent.
        PeriodicJob("ai-watch", 30, insights.scheduler.tick),
    ]
    if settings.demo:
        jobs = []  # nothing may read or change the real system in demo mode
    services = AppServices(
        settings=settings, rules=rules, state=state, events=events, ledger=ledger, meter=meter,
        capture_log=capture_log, sniffer=PacketSniffer(capture_log, dns, state.endpoint_owner),
        quarantine=vault, firewall=firewall, defender=defender,
        source_scanner=SourceScanner(rules.source_patterns, excluded_roots=[settings.install_root]),
        response=response, process_queries=ProcessQueries(state), persistence_refresher=persistence,
        findings_refresher=findings, reports=insights.reports, ai_settings=insights.ai_settings,
        ai_analysis=insights.ai_analysis, analysis_archive=insights.archive, ai_scheduler=insights.scheduler,
        flockion_settings=insights.flockion_settings, flockion=insights.flockion,
        malware_scanner=malware_scanner, intel_settings=intel_settings, ip_intel=ip_intel, guard=guard, metrics=metrics, jobs=jobs,
    )
    if settings.demo:
        seed_demo(services)
    return services
