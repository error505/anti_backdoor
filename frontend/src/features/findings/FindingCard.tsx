import type { Finding } from "../../api/types";
import { ActionBar } from "../../components/ActionButton";
import { SeverityBadge } from "../../components/Badge";
import { actionsForTarget } from "../actions/actionCatalog";
import { useInspectProcess } from "../processes/ProcessInspector";

export function FindingCard({ finding }: { finding: Finding }) {
  const inspect = useInspectProcess();
  return (
    <article className={`finding finding-${finding.severity}`}>
      <header>
        <SeverityBadge severity={finding.severity} />
        <span className="muted">{finding.category}</span>
      </header>
      <h3>{finding.title}</h3>
      <p className="mono wrap small">{finding.detail}</p>
      <p><strong>What to do:</strong> {finding.remediation}</p>
      {finding.targets.map((target) => (
        <div key={`${target.kind}-${target.ref}`} className="target-row">
          {target.kind === "process"
            ? <button type="button" className="link" onClick={() => inspect(Number(target.ref))}>{target.label}</button>
            : <span className="mono small">{target.label}</span>}
          <ActionBar actions={actionsForTarget(target)} />
        </div>
      ))}
    </article>
  );
}
