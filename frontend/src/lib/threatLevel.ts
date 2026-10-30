import type { Severity } from "../api/types";

export type ThreatLevel = "nominal" | "guarded" | "elevated" | "critical";

export interface ThreatAssessment {
  level: ThreatLevel;
  label: string;
  /** 0..1 fill of the gauge. */
  score: number;
}

// Informational findings (e.g. "Defender passive because McAfee is active") never raise the level.
export function assessThreatLevel(counts: Partial<Record<Severity, number>>): ThreatAssessment {
  if ((counts.critical ?? 0) > 0) return { level: "critical", label: "CRITICAL", score: 1 };
  if ((counts.high ?? 0) > 0) return { level: "elevated", label: "ELEVATED", score: 0.72 };
  if ((counts.medium ?? 0) > 0) return { level: "guarded", label: "GUARDED", score: 0.42 };
  return { level: "nominal", label: "NOMINAL", score: 0.12 };
}
