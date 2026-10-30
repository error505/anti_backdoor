import { useState } from "react";
import { defenderApi } from "../../api/endpoints";
import type { DefenderStatus } from "../../api/types";
import { ActionButton } from "../../components/ActionButton";
import { Badge } from "../../components/Badge";
import { EmptyState, Notice, Panel, QueryState } from "../../components/Layout";
import { useDefender } from "../../hooks/queries";
import { formatIso } from "../../lib/format";
import { enableRealtimeProtection, openWindowsSecurity } from "../actions/actionCatalog";

const flag = (value: boolean | null) =>
  value === null ? <Badge tone="neutral">?</Badge> : value ? <Badge tone="ok">on</Badge> : <Badge tone="critical">OFF</Badge>;

export function DefenderPanel() {
  const defender = useDefender();
  const [scanPath, setScanPath] = useState("");

  return (
    <Panel title="Microsoft Defender" actions={<>
      <ActionButton action={enableRealtimeProtection} />
      <ActionButton action={openWindowsSecurity} />
      <ActionButton action={{ label: "Quick scan", run: () => defenderApi.scan("QuickScan") }} />
      <ActionButton action={{ label: "Full scan", confirm: "A full scan can take an hour or more. Start it?", run: () => defenderApi.scan("FullScan") }} />
    </>}>
      <QueryState query={defender}>
        {(data) => (
          <>
            <DefenderStatusFacts status={data.status} />
            <h3>Detections ({data.threats.length})</h3>
            {data.threats.length === 0 ? <EmptyState>No detections in Defender history.</EmptyState> : (
              <ul className="plain-list">
                {data.threats.map((t) => (
                  <li key={`${t.threat_id}-${t.detected_at}`}>
                    <strong>{t.name}</strong> <span className="muted">{formatIso(t.detected_at)}</span>
                    {t.action_success === false && <> <Badge tone="critical">not remediated</Badge></>}
                    <div className="mono small wrap">{t.resources.join("; ")}</div>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </QueryState>
      <form className="inline-form" onSubmit={(e) => e.preventDefault()}>
        <input aria-label="Folder to scan" placeholder="Folder to scan, e.g. C:\Users\you\Downloads\interview-repo" value={scanPath} onChange={(e) => setScanPath(e.target.value)} />
        <ActionButton action={{ label: "Scan folder", run: () => defenderApi.scan("CustomScan", scanPath) }} />
      </form>
    </Panel>
  );
}

function DefenderStatusFacts({ status }: { status: DefenderStatus }) {
  if (!status.available) return <Notice tone="warn">Defender status unavailable: {status.error ?? "another antivirus may be active"}</Notice>;
  return (
    <dl className="facts">
      <dt>Mode</dt><dd>{status.running_mode ?? "—"}</dd>
      <dt>Other active antivirus</dt>
      <dd>{status.active_antivirus.length ? <Badge tone="ok">{status.active_antivirus.join(", ")}</Badge> : "none"}</dd>
      <dt>Antivirus</dt><dd>{flag(status.antivirus_enabled)}</dd>
      <dt>Real-time protection</dt>
      <dd>{status.real_time_protection === false && status.active_antivirus.length
        ? <Badge tone="neutral">passive (another antivirus is active)</Badge>
        : flag(status.real_time_protection)}</dd>
      <dt>Tamper protection</dt><dd>{flag(status.tamper_protected)}</dd>
      <dt>Signatures updated</dt><dd>{formatIso(status.signatures_updated)}</dd>
      <dt>Last quick / full scan</dt><dd>{formatIso(status.last_quick_scan)} / {formatIso(status.last_full_scan)}</dd>
    </dl>
  );
}
