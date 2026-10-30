import { useState } from "react";
import { threatApi } from "../../api/endpoints";
import type { Finding, Severity } from "../../api/types";
import { ActionButton } from "../../components/ActionButton";
import { EmptyState, Panel, QueryState } from "../../components/Layout";
import { useFindings } from "../../hooks/queries";
import { FindingCard } from "./FindingCard";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const atLeast = (minimum: Severity) => (finding: Finding) =>
  SEVERITY_ORDER.indexOf(finding.severity) <= SEVERITY_ORDER.indexOf(minimum);

export function FindingsPage() {
  const findings = useFindings();
  const [minimum, setMinimum] = useState<Severity>("low");

  return (
    <Panel
      title="Threat findings"
      actions={<>
        <label className="toggle">
          Minimum severity
          <select value={minimum} onChange={(e) => setMinimum(e.target.value as Severity)}>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <ActionButton action={{ label: "Rescan now", run: threatApi.rescanFindings }} />
      </>}
    >
      <p className="muted">
        The scan re-runs every 5 seconds against processes, connections, autostart entries, known Contagious
        Interview artifacts (.n2, .npl, .pyp, C2 ports 1224/1244/1245/2245) and Microsoft Defender detections.
        A finding is a lead, not a verdict: check it before you act.
      </p>
      <QueryState query={findings}>
        {(data) => {
          const visible = data.filter(atLeast(minimum));
          if (visible.length === 0) return <EmptyState>No findings at this severity. 👍</EmptyState>;
          return <div className="finding-list">{visible.map((f) => <FindingCard key={f.id} finding={f} />)}</div>;
        }}
      </QueryState>
    </Panel>
  );
}
