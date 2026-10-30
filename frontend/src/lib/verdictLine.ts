import type { AiVerdict } from "../api/types";

const VERDICT_LINE = /^\s*VERDICT:\s*(COMPROMISE|SUSPICIOUS|CLEAR)\b[^\n]*\n?/i;
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

export interface SplitAnalysis {
  verdict: AiVerdict;
  body: string;
}

/** The model is asked to open with one VERDICT line; the UI shows it as a banner instead of body text. */
export function splitVerdictLine(markdown: string, fallback: AiVerdict = "unknown"): SplitAnalysis {
  const match = VERDICT_LINE.exec(markdown);
  if (!match) return { verdict: fallback, body: markdown };
  return { verdict: match[1].toLowerCase() as AiVerdict, body: markdown.slice(match[0].length).trimStart() };
}

export function ipv4Addresses(text: string): string[] {
  return [...new Set(text.match(IPV4) ?? [])];
}

export function isIpWithOptionalPort(text: string): string | null {
  const match = /^((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?$/.exec(text.trim());
  return match ? match[1] : null;
}
