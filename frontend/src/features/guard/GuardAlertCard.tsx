import type { GuardAlert } from "../../api/types";
import { ActionBar } from "../../components/ActionButton";
import { Badge } from "../../components/Badge";
import { formatEpoch } from "../../lib/format";
import { actionsForAlert } from "./guardActions";

const KIND_LABEL: Record<GuardAlert["kind"], string> = {
  install_leak: "Install script leaking data",
  untrusted_outbound: "Untrusted program online",
};

export function GuardAlertCard({ alert }: { alert: GuardAlert }) {
  const stopped = alert.action === "suspended";
  return (
    <article className={alert.acknowledged ? "guard-card guard-card-done" : "guard-card"}>
      <header>
        <Badge tone="critical">{KIND_LABEL[alert.kind]}</Badge>
        <Badge tone={stopped ? "ok" : "high"}>{stopped ? "STOPPED" : "NOT STOPPED"}</Badge>
        <span className="muted small">{formatEpoch(alert.created_at)}</span>
      </header>
      <h3>{alert.title}</h3>
      <p className="muted small mono">{alert.chain.join("  ›  ")}</p>
      <p>{alert.detail}</p>
      {!alert.acknowledged && <ActionBar actions={actionsForAlert(alert)} />}
    </article>
  );
}
