import { useEffect, useState } from "react";
import type { AiScheduleState, SystemStatus } from "../api/types";
import { LogoMark } from "./LogoMark";

type ChipTone = "ok" | "warn" | "danger" | "neutral";

function StatusChip({ label, value, tone, pulse }: { label: string; value: string; tone: ChipTone; pulse?: boolean }) {
  return (
    <div className={`chip chip-${tone}`}>
      {pulse && <span className="pulse-dot" aria-hidden="true" />}
      <span className="chip-label">{label}</span>
      <span className="chip-value">{value}</span>
    </div>
  );
}

function useClock(): Date {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);
  return now;
}

interface Props {
  status: SystemStatus | undefined;
  aiWatch: AiScheduleState | undefined;
  offline: boolean;
}

function aiWatchLabel(aiWatch: AiScheduleState): string {
  if (!aiWatch.next_check_at) return "ON";
  return `ON · next ${new Date(aiWatch.next_check_at * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })}`;
}

export function TopBar({ status, aiWatch, offline }: Props) {
  const now = useClock();
  return (
    <header className="topbar">
      <div className="brand">
        <LogoMark />
        <div>
          <h1 className="glitch" data-text="FLOCKION // BACKDOOR WATCH">FLOCKION // BACKDOOR WATCH</h1>
          <div className="brand-sub">Threat surveillance console</div>
        </div>
      </div>
      <div className="status-strip">
        <StatusChip label="Link" value={offline ? "OFFLINE" : "ONLINE"} tone={offline ? "danger" : "ok"} pulse={!offline} />
        {status?.demo && <StatusChip label="Mode" value="DEMO DATA" tone="warn" />}
        {status && <StatusChip label="Host" value={status.hostname} tone="neutral" />}
        {status && (status.is_admin
          ? <StatusChip label="Access" value="ADMIN" tone="ok" />
          : <StatusChip label="Access" value="LIMITED (not admin)" tone="warn" />)}
        {aiWatch && (aiWatch.enabled
          ? <StatusChip label="AI Watch" value={aiWatchLabel(aiWatch)} tone="ok" pulse />
          : <StatusChip label="AI Watch" value="OFF" tone="neutral" />)}
        <StatusChip label="T" value={now.toLocaleTimeString([], { hour12: false })} tone="neutral" />
      </div>
    </header>
  );
}
