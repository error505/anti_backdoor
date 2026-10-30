import { downloadFile, http } from "./client";
import type {
  ActionResult, ActivityEvent, AiAnalysis, AiProvider, AiProviderOptions, AiScheduleConfig, AiScheduleState, AiSettings, CaptureRecord, CaptureStatus, Connection,
  ContextPreview, DefenderOverview, DefenderScanType, Finding, FirewallRule, FlockionCheck, FlockionMode, FlockionResult,
  FlockionSettings, IntelSettings, MalwareScanStatus, ScanScope, PersistenceEntry, ProcessDetail,
  ProcessInfo, QuarantineItem, ReportFormat, SourceHit, SystemStatus, TrafficSummary, UploadMethod,
} from "./types";

export const systemApi = {
  status: () => http.get<SystemStatus>("/api/status"),
};

export const processApi = {
  list: () => http.get<ProcessInfo[]>("/api/processes"),
  detail: (pid: number) => http.get<ProcessDetail>(`/api/processes/${pid}`),
  kill: (pid: number, includeChildren: boolean) =>
    http.post<ActionResult>(`/api/processes/${pid}/kill`, { include_children: includeChildren }),
  suspend: (pid: number) => http.post<ActionResult>(`/api/processes/${pid}/suspend`),
  resume: (pid: number) => http.post<ActionResult>(`/api/processes/${pid}/resume`),
  quarantineExecutable: (pid: number) => http.post<ActionResult>(`/api/processes/${pid}/quarantine`),
  blockNetwork: (pid: number) => http.post<ActionResult>(`/api/processes/${pid}/block`),
};

export const networkApi = {
  connections: () => http.get<Connection[]>("/api/connections"),
  traffic: () => http.get<TrafficSummary>("/api/traffic"),
};

export const firewallApi = {
  rules: () => http.get<FirewallRule[]>("/api/firewall/rules"),
  blockIp: (ip: string) => http.post<ActionResult>("/api/firewall/block-ip", { ip }),
  blockProgram: (path: string) => http.post<ActionResult>("/api/firewall/block-program", { path }),
  removeRule: (id: string) => http.post<ActionResult>("/api/firewall/rules/remove", { id }),
};

export const threatApi = {
  findings: () => http.get<Finding[]>("/api/findings"),
  rescanFindings: () => http.post<ActionResult>("/api/findings/rescan"),
  persistence: () => http.get<PersistenceEntry[]>("/api/persistence"),
  rescanPersistence: () => http.post<ActionResult>("/api/persistence/rescan"),
  removePersistence: (id: string) => http.post<ActionResult>(`/api/persistence/${id}/remove`),
  events: (limit: number) => http.get<ActivityEvent[]>(`/api/events?limit=${limit}`),
};

export const quarantineApi = {
  list: () => http.get<QuarantineItem[]>("/api/quarantine"),
  add: (path: string, reason: string) => http.post<ActionResult>("/api/quarantine", { path, reason }),
  restore: (id: string) => http.post<ActionResult>(`/api/quarantine/${id}/restore`),
  purge: (id: string) => http.post<ActionResult>(`/api/quarantine/${id}/purge`),
};

export const defenderApi = {
  overview: () => http.get<DefenderOverview>("/api/defender"),
  enableRealtime: () => http.post<ActionResult>("/api/defender/enable-realtime"),
  openWindowsSecurity: () => http.post<ActionResult>("/api/defender/open"),
  scan: (scanType: DefenderScanType, path?: string) =>
    http.post<ActionResult>("/api/defender/scan", { scan_type: scanType, path: path || null }),
};

export const captureApi = {
  status: () => http.get<CaptureStatus>("/api/capture/status"),
  start: () => http.post<CaptureStatus>("/api/capture/start"),
  stop: () => http.post<CaptureStatus>("/api/capture/stop"),
  records: (limit: number) => http.get<CaptureRecord[]>(`/api/capture/records?limit=${limit}`),
};

export const sourceScanApi = {
  scan: (path: string, includeNodeModules: boolean) =>
    http.post<SourceHit[]>("/api/source-scan", { path, include_node_modules: includeNodeModules }),
  sweepRoots: () => http.get<string[]>("/api/source-scan/sweep-roots"),
  sweep: () => http.post<SourceHit[]>("/api/source-scan/sweep"),
};

export const aiApi = {
  options: () => http.get<AiProviderOptions>("/api/ai/options"),
  settings: () => http.get<AiSettings>("/api/ai/settings"),
  saveSettings: (provider: AiProvider, model: string, effort: string, apiKey: string | null) =>
    http.post<AiSettings>("/api/ai/settings", { provider, model, effort, api_key: apiKey }),
  clearKey: () => http.post<ActionResult>("/api/ai/settings/clear-key"),
  context: () => http.get<ContextPreview>("/api/ai/context"),
  analyze: (question: string) => http.post<AiAnalysis>("/api/ai/analyze", { question: question || null }),
  history: () => http.get<AiAnalysis[]>("/api/ai/history"),
  schedule: () => http.get<AiScheduleState>("/api/ai/schedule"),
  startSchedule: (config: AiScheduleConfig) => http.post<AiScheduleState>("/api/ai/schedule/start", config),
  stopSchedule: () => http.post<AiScheduleState>("/api/ai/schedule/stop"),
};

export const malwareApi = {
  status: () => http.get<MalwareScanStatus>("/api/malware/status"),
  scan: (scope: ScanScope, maxLookups: number) =>
    http.post<MalwareScanStatus>("/api/malware/scan", { scope, max_lookups: maxLookups }),
  settings: () => http.get<IntelSettings>("/api/malware/settings"),
  saveKey: (apiKey: string) => http.post<IntelSettings>("/api/malware/settings", { api_key: apiKey }),
  clearKey: () => http.post<ActionResult>("/api/malware/clear-key"),
};

export const flockionApi = {
  settings: () => http.get<FlockionSettings>("/api/flockion/settings"),
  save: (endpoint: string, apiKey: string | null) =>
    http.post<FlockionSettings>("/api/flockion/settings", { endpoint, api_key: apiKey }),
  clearKey: () => http.post<ActionResult>("/api/flockion/clear-key"),
  preview: (mode: FlockionMode) => http.post<ContextPreview>("/api/flockion/preview", { mode }),
  test: () => http.post<FlockionCheck>("/api/flockion/test"),
  send: (mode: FlockionMode) => http.post<FlockionResult>("/api/flockion/send", { mode }),
};

export const reportApi = {
  download: (format: ReportFormat, redact: boolean) => downloadFile(`/api/report?format=${format}&redact=${redact}`),
  upload: (url: string, method: UploadMethod, format: ReportFormat, redact: boolean) =>
    http.post<ActionResult>("/api/report/upload", { url, method, format, redact }),
};
