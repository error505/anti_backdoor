export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface SignatureInfo {
  status: string;
  subject: string | null;
  signer: string | null;
  is_valid: boolean;
  is_untrusted: boolean;
  is_microsoft: boolean;
}

export interface ProcessInfo {
  pid: number;
  ppid: number | null;
  name: string;
  exe: string | null;
  cmdline: string;
  username: string | null;
  create_time: number | null;
  cpu_percent: number | null;
  memory_mb: number | null;
  signature: SignatureInfo | null;
}

export interface Connection {
  protocol: "tcp" | "udp";
  family: "ipv4" | "ipv6";
  local_ip: string;
  local_port: number;
  remote_ip: string | null;
  remote_port: number | null;
  state: string;
  pid: number | null;
  process_name: string | null;
  remote_host: string | null;
  is_external: boolean;
  bytes_out: number | null;
  bytes_in: number | null;
  is_listener: boolean;
  exposure: "network" | "local";
}

export interface ProcessTraffic {
  pid: number;
  process_name: string;
  bytes_out: number;
  bytes_in: number;
  rate_out: number;
  rate_in: number;
  remotes: string[];
}

export interface RemoteTraffic {
  remote_ip: string;
  remote_host: string | null;
  bytes_out: number;
  bytes_in: number;
  processes: string[];
}

export interface TrafficSummary {
  metering_available: boolean;
  by_process: ProcessTraffic[];
  by_remote: RemoteTraffic[];
}

export type PersistenceKind = "run_key" | "startup_folder" | "scheduled_task" | "service" | "wmi_consumer";

export interface PersistenceEntry {
  id: string;
  kind: PersistenceKind;
  name: string;
  location: string;
  command: string;
  image_path: string | null;
  enabled: boolean;
  is_microsoft: boolean;
  image_exists: boolean;
  signature: SignatureInfo | null;
  details: Record<string, string>;
}

export type FindingTargetKind = "process" | "file" | "persistence" | "remote_ip" | "defender";

export interface FindingTarget {
  kind: FindingTargetKind;
  ref: string;
  label: string;
}

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  detail: string;
  remediation: string;
  targets: FindingTarget[];
}

export interface ActivityEvent {
  kind: string;
  summary: string;
  pid: number | null;
  process_name: string | null;
  details: Record<string, string>;
  seq: number;
  timestamp: number;
}

export interface ProcessDetail {
  process: ProcessInfo;
  ancestors: ProcessInfo[];
  children: ProcessInfo[];
  connections: Connection[];
  findings: Finding[];
}

export interface QuarantineItem {
  id: string;
  original_path: string;
  is_directory: boolean;
  sha256: string | null;
  reason: string;
  quarantined_at: number;
}

export interface FirewallRule {
  id: string;
  display_name: string;
  direction: string;
  target: string;
  enabled: boolean;
}

export interface DefenderStatus {
  available: boolean;
  antivirus_enabled: boolean | null;
  real_time_protection: boolean | null;
  running_mode: string | null;
  active_antivirus: string[];
  tamper_protected: boolean | null;
  signatures_updated: string | null;
  last_quick_scan: string | null;
  last_full_scan: string | null;
  error: string | null;
}

export interface DefenderThreat {
  threat_id: string;
  name: string;
  severity: string;
  detected_at: string | null;
  resources: string[];
  process_name: string | null;
  action_success: boolean | null;
}

export interface DefenderOverview {
  status: DefenderStatus;
  threats: DefenderThreat[];
}

export interface CaptureStatus {
  running: boolean;
  available: boolean;
  message: string;
}

export interface CaptureRecord {
  protocol: "dns" | "tls" | "http" | "payload";
  summary: string;
  local: string;
  remote: string;
  remote_host: string | null;
  pid: number | null;
  process_name: string | null;
  preview: string;
  seq: number;
  timestamp: number;
}

export interface SourceHit {
  file: string;
  line: number;
  rule_id: string;
  severity: Severity;
  description: string;
  snippet: string;
}

export interface SystemStatus {
  hostname: string;
  is_admin: boolean;
  traffic_metering: boolean;
  capture: CaptureStatus;
  process_count: number;
  connection_count: number;
  external_connection_count: number;
  network_listener_count: number;
  persistence_scanned: boolean;
  persistence_count: number;
  findings_by_severity: Partial<Record<Severity, number>>;
  self_pids: number[];
  demo: boolean;
}

export type AiProvider = "anthropic" | "openai";

export interface AiSettings {
  provider: AiProvider;
  model: string;
  effort: string;
  has_stored_key: boolean;
  key_hint: string | null;
}

export interface ProviderOptions {
  suggested_models: string[];
  default_model: string;
  effort_levels: string[];
  default_effort: string;
}

export type AiProviderOptions = Record<AiProvider, ProviderOptions>;

export type AiVerdict = "compromise" | "suspicious" | "clear" | "unknown";

export interface AiAnalysis {
  provider: AiProvider;
  model: string;
  effort: string;
  question: string | null;
  markdown: string;
  created_at: number;
  context_chars: number;
  trigger: "manual" | "scheduled";
  verdict: AiVerdict;
}

export interface AiScheduleConfig {
  interval_minutes: number;
  duration_hours: number;
  skip_unchanged: boolean;
}

export interface AiScheduleState {
  enabled: boolean;
  interval_minutes: number;
  skip_unchanged: boolean;
  started_at: number | null;
  ends_at: number | null;
  last_check_at: number | null;
  last_run_at: number | null;
  runs: number;
  skipped: number;
  consecutive_failures: number;
  last_status: string | null;
  last_error: string | null;
  next_check_at: number | null;
  max_runs: number | null;
}

export interface ContextPreview {
  characters: number;
  content: string;
}

export interface FlockionSettings {
  endpoint: string;
  has_stored_key: boolean;
  key_hint: string | null;
}

export interface FlockionCheck {
  ok: boolean;
  asset_name: string | null;
  model_count: number;
  detail: string;
}

export interface FlockionResult {
  ok: boolean;
  status: string;
  output: string;
  sent_chars: number;
  cost_usd: number | null;
  total_tokens: number | null;
  denied_tool_requests: number;
}

export type FlockionMode = "findings" | "full";

export type ScanScope = "quick" | "deep";

export interface ThreatVerdict {
  sha256: string;
  source: "local-list" | "virustotal";
  malicious: number;
  suspicious: number;
  engines: number;
  label: string | null;
  name: string | null;
}

export interface MalwareHit {
  path: string;
  sha256: string;
  size: number;
  reason: string;
  verdict: ThreatVerdict;
  severity: Severity;
  pids: number[];
}

export interface MalwareScanStatus {
  state: "idle" | "running" | "finished" | "failed";
  scope: ScanScope;
  phase: string;
  files_total: number;
  files_hashed: number;
  lookups_planned: number;
  lookups_done: number;
  unknown_to_virustotal: number;
  started_at: number | null;
  finished_at: number | null;
  hits: MalwareHit[];
  message: string | null;
  rate_limited: boolean;
  virustotal_enabled: boolean;
  local_hashes: number;
}

export interface IntelSettings {
  has_stored_key: boolean;
  key_hint: string | null;
  uses_environment_key: boolean;
}

export type ReportFormat = "json" | "markdown" | "html";
export type UploadMethod = "PUT" | "POST";

export interface ActionResult {
  message: string;
}

export type DefenderScanType = "QuickScan" | "FullScan" | "CustomScan";
