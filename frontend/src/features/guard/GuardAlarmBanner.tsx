import { useEffect } from "react";
import { guardApi } from "../../api/endpoints";
import { ActionButton } from "../../components/ActionButton";
import { useGuard } from "../../hooks/queries";
import type { ActionSpec } from "../../hooks/useActionRunner";
import { GuardAlertCard } from "./GuardAlertCard";

const MAX_SHOWN = 2;
const ACKNOWLEDGE_ALL: ActionSpec = { label: "Acknowledge all", run: () => guardApi.acknowledge(null) };

function useAlarmTitle(active: boolean) {
  useEffect(() => {
    const original = document.title.replace(/^⚠ ALERT · /, "");
    document.title = active ? `⚠ ALERT · ${original}` : original;
    return () => { document.title = original; };
  }, [active]);
}

/** Shown on every tab until each guard alert is acknowledged: the siren is on the PC, this is what to do about it. */
export function GuardAlarmBanner({ onOpenGuard }: { onOpenGuard: () => void }) {
  const guard = useGuard();
  const pending = (guard.data?.alerts ?? []).filter((a) => !a.acknowledged);
  useAlarmTitle(pending.length > 0);
  if (pending.length === 0) return null;
  return (
    <section className="guard-alarm" role="alert">
      <div className="banner-row">
        <strong className="guard-alarm-title">⚠ Guard alert: {pending.length} unacknowledged</strong>
        <span className="action-bar">
          <button type="button" className="btn" onClick={onOpenGuard}>Open Guard</button>
          <ActionButton action={ACKNOWLEDGE_ALL} />
        </span>
      </div>
      {pending.slice(0, MAX_SHOWN).map((alert) => <GuardAlertCard key={alert.id} alert={alert} />)}
      {pending.length > MAX_SHOWN && <p className="muted small">+{pending.length - MAX_SHOWN} more on the Guard tab.</p>}
    </section>
  );
}
