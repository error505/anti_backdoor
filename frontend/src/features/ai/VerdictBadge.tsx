import type { AiVerdict } from "../../api/types";
import { Badge, type BadgeTone } from "../../components/Badge";

const VERDICTS: Record<AiVerdict, { tone: BadgeTone; label: string }> = {
  compromise: { tone: "critical", label: "SIGNS OF COMPROMISE" },
  suspicious: { tone: "high", label: "SUSPICIOUS" },
  clear: { tone: "ok", label: "NO EVIDENCE" },
  unknown: { tone: "neutral", label: "NO VERDICT" },
};

export function VerdictBadge({ verdict }: { verdict: AiVerdict }) {
  const { tone, label } = VERDICTS[verdict];
  return <Badge tone={tone}>{label}</Badge>;
}
