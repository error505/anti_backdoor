import type { SystemStatus } from "../../api/types";
import { EmptyState, Panel, QueryState, StatTile } from "../../components/Layout";
import { useFindings, useSystemStatus, useTraffic } from "../../hooks/queries";
import { FindingCard } from "../findings/FindingCard";
import { ProcessTrafficTable } from "../traffic/TrafficTables";
import { IncidentChecklist } from "./IncidentChecklist";
import { ThreatGauge } from "./ThreatGauge";

const TOP_FINDINGS = 5;

const countTone = (count: number | undefined, tone: "danger" | "warn") => ((count ?? 0) > 0 ? tone : "ok");

function StatusHero({ status }: { status: SystemStatus }) {
  const counts = status.findings_by_severity;
  return (
    <div className="overview-hero">
      <ThreatGauge counts={counts} />
      <div className="stats">
        <StatTile label="Critical findings" value={counts.critical ?? 0} tone={countTone(counts.critical, "danger")} />
        <StatTile label="High findings" value={counts.high ?? 0} tone={countTone(counts.high, "warn")} />
        <StatTile label="Medium findings" value={counts.medium ?? 0} />
        <StatTile label="Internet connections" value={status.external_connection_count} />
        <StatTile label="Ports open to network" value={status.network_listener_count} />
        <StatTile label="Processes" value={status.process_count} />
        <StatTile label="Autostart entries" value={status.persistence_scanned ? status.persistence_count : "scanning…"} />
      </div>
    </div>
  );
}

export function OverviewPage({ onOpenFindings }: { onOpenFindings: () => void }) {
  const status = useSystemStatus();
  const findings = useFindings();
  const traffic = useTraffic();

  return (
    <>
      <QueryState query={status}>{(s) => <StatusHero status={s} />}</QueryState>
      <div className="grid-2">
        <Panel title="Most severe findings" actions={<button type="button" className="btn" onClick={onOpenFindings}>All findings →</button>}>
          <QueryState query={findings}>
            {(data) => data.length === 0
              ? <EmptyState>No findings.</EmptyState>
              : <div className="finding-list">{data.slice(0, TOP_FINDINGS).map((f) => <FindingCard key={f.id} finding={f} />)}</div>}
          </QueryState>
        </Panel>
        <div>
          <Panel title="Top talkers (data sent)">
            <QueryState query={traffic}>{(data) => <ProcessTrafficTable rows={data.by_process} limit={8} />}</QueryState>
          </Panel>
          <IncidentChecklist />
        </div>
      </div>
    </>
  );
}
