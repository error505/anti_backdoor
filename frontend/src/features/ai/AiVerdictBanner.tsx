import { useState } from "react";
import { Notice } from "../../components/Layout";
import { useAiHistory } from "../../hooks/queries";
import { formatEpoch } from "../../lib/format";

/** Raises the latest AI verdict on every tab when it is not "clear", so scheduled runs get noticed. */
export function AiVerdictBanner({ onOpen }: { onOpen: () => void }) {
  const history = useAiHistory();
  const [dismissed, setDismissed] = useState<number | null>(null);
  const latest = history.data?.[0];
  if (!latest || dismissed === latest.created_at) return null;
  if (latest.verdict !== "compromise" && latest.verdict !== "suspicious") return null;

  const critical = latest.verdict === "compromise";
  return (
    <Notice tone={critical ? "danger" : "warn"}>
      <div className="banner-row">
        <span>
          <strong>{critical ? "AI analysis reports SIGNS OF COMPROMISE" : "AI analysis flagged items that need checking"}</strong>
          <span className="muted"> · {latest.trigger} run at {formatEpoch(latest.created_at)}</span>
        </span>
        <span className="action-bar">
          <button type="button" className={critical ? "btn btn-danger" : "btn"} onClick={onOpen}>Open analysis</button>
          <button type="button" className="btn" onClick={() => setDismissed(latest.created_at)}>Dismiss</button>
        </span>
      </div>
    </Notice>
  );
}
