import { EmptyState, Panel, QueryState } from "../../components/Layout";
import { useGuard } from "../../hooks/queries";
import { AllowedHostsPanel } from "./AllowedHostsPanel";
import { GuardAlertCard } from "./GuardAlertCard";
import { GuardModesPanel } from "./GuardModesPanel";
import { TrustPanel } from "./TrustPanel";

export function GuardPage() {
  const guard = useGuard();
  return (
    <QueryState query={guard}>
      {(status) => (
        <>
          <Panel title="Guard alerts">
            <p className="muted">
              Cloned a repo and ran <code>npm i</code>? The guard watches what the install starts. If it sends data to a server
              that is not a known registry, you hear a siren and the install is frozen before it can finish stealing.
            </p>
            {status.alerts.length === 0
              ? <EmptyState>No alerts. The guard is watching.</EmptyState>
              : <div className="finding-list">{status.alerts.map((alert) => <GuardAlertCard key={alert.id} alert={alert} />)}</div>}
          </Panel>
          <div className="grid-2">
            <GuardModesPanel config={status.config} />
            <AllowedHostsPanel status={status} />
          </div>
          <TrustPanel status={status} />
          <p className="muted small">
            Limits: the guard checks every 2 seconds, so the first moments of a connection can get through; it sees
            addresses and process names, never encrypted content; and it cannot stop code that runs inside an already
            trusted program.
          </p>
        </>
      )}
    </QueryState>
  );
}
