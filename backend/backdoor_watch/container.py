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
from backdoor_watch.flockion.client import FlockionClient
from backdoor_watch.flockion.service import FlockionService
from backdoor_watch.flockion.settings_store import FlockionSettingsStore
from backdoor_watch.monitoring.event_log import EventLog
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


def _insights(settings: Settings, state: SystemState, ledger: TrafficLedger, events: EventLog) -> _Insights:
    archive = AnalysisArchive(settings.ai_history_path)
    builder = ReportBuilder(state, ledger, events, lambda: archive.latest)
    ai_settings = AiSettingsStore(settings.ai_settings_path)
    analysis = AiAnalysisService(ai_settings, builder, archive, events)
    scheduler = AiAnalysisScheduler(AiScheduleStore(settings.ai_schedule_path), analysis, archive, events)
    flockion_settings = FlockionSettingsStore(settings.flockion_settings_path)
    return _Insights(reports=ReportService(builder, ReportUploader(), events), ai_settings=ai_settings,
                     ai_analysis=analysis, archive=archive, scheduler=scheduler,
                     flockion_settings=flockion_settings,
                     flockion=FlockionService(flockion_settings, builder, FlockionClient(), events))


def build_services(settings: Settings) -> AppServices:
    rules = load_rules(settings.rules_path)
    state, events, ledger = SystemState(), EventLog(settings.log_dir), TrafficLedger()
    signatures, dns, meter = SignatureVerifier(), DnsNameResolver(), TcpTrafficMeter()
    defender, vault = DefenderClient(), QuarantineVault(settings.quarantine_dir)
    firewall, capture_log = FirewallController(), CaptureLog()
    insights = _insights(settings, state, ledger, events)

    snapshot = SnapshotRefresher(ProcessCollector(signatures), ConnectionCollector(dns, meter), ledger, state, events,
                                 SelfIdentity(settings.install_root))
    persistence = PersistenceRefresher(_persistence_scanner(signatures), state, events)
    findings = FindingsRefresher(ThreatScanner(), rules, state)
    response = ResponseService(ProcessController(ProcessKillPolicy(rules.protected_processes)), vault, firewall,
                               PersistenceRemover(vault, settings.backup_dir), defender, state, events)
    jobs = [
        PeriodicJob("snapshot", 2, snapshot.refresh),
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
        flockion_settings=insights.flockion_settings, flockion=insights.flockion, jobs=jobs,
    )
    if settings.demo:
        seed_demo(services)
    return services
