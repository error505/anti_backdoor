import type { AiVerdict } from "../../api/types";

const HERO: Record<AiVerdict, { tone: string; icon: string; title: string; hint: string }> = {
  compromise: { tone: "critical", icon: "⚠", title: "Signs of compromise", hint: "Act on the items below, starting from the top." },
  suspicious: { tone: "high", icon: "◈", title: "Suspicious, needs checking", hint: "Nothing confirmed, but verify the items below." },
  clear: { tone: "ok", icon: "✔", title: "No evidence of compromise", hint: "In this snapshot only; see the blind spots." },
  unknown: { tone: "neutral", icon: "?", title: "No verdict given", hint: "Read the answer below." },
};

export function VerdictHero({ verdict }: { verdict: AiVerdict }) {
  const { tone, icon, title, hint } = HERO[verdict];
  return (
    <div className={`verdict-hero verdict-${tone}`} role="status">
      <span className="verdict-icon" aria-hidden="true">{icon}</span>
      <div>
        <div className="verdict-title">{title}</div>
        <div className="muted small">{hint}</div>
      </div>
    </div>
  );
}
