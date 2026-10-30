import { useState } from "react";
import { threatApi } from "../../api/endpoints";
import type { PersistenceEntry, PersistenceKind } from "../../api/types";
import { ActionBar, ActionButton } from "../../components/ActionButton";
import { Badge, SignatureBadge } from "../../components/Badge";
import { EmptyState, Panel, QueryState, SearchBox, Toggle } from "../../components/Layout";
import { usePersistence } from "../../hooks/queries";
import { matchesQuery } from "../../lib/format";
import { quarantinePath, removePersistenceEntry } from "../actions/actionCatalog";

const KIND_LABELS: Record<PersistenceKind, string> = {
  run_key: "Run key",
  startup_folder: "Startup folder",
  scheduled_task: "Scheduled task",
  service: "Service",
  wmi_consumer: "WMI consumer",
};

interface PersistenceFilter {
  query: string;
  hideMicrosoft: boolean;
  kind: PersistenceKind | "all";
}

function selectEntries(entries: PersistenceEntry[], filter: PersistenceFilter) {
  return entries
    .filter((e) => !filter.hideMicrosoft || !e.is_microsoft)
    .filter((e) => filter.kind === "all" || e.kind === filter.kind)
    .filter((e) => matchesQuery(filter.query, e.name, e.command, e.location, e.signature?.signer));
}

export function PersistencePage() {
  const entries = usePersistence();
  const [filter, setFilter] = useState<PersistenceFilter>({ query: "", hideMicrosoft: true, kind: "all" });
  const update = (patch: Partial<PersistenceFilter>) => setFilter((current) => ({ ...current, ...patch }));

  return (
    <Panel
      title="Autostart & persistence"
      actions={<>
        <SearchBox value={filter.query} onChange={(query) => update({ query })} placeholder="Search name or command" />
        <select aria-label="Type" value={filter.kind} onChange={(e) => update({ kind: e.target.value as PersistenceFilter["kind"] })}>
          <option value="all">All types</option>
          {Object.entries(KIND_LABELS).map(([kind, label]) => <option key={kind} value={kind}>{label}</option>)}
        </select>
        <Toggle label="Hide Microsoft-signed" checked={filter.hideMicrosoft} onChange={(hideMicrosoft) => update({ hideMicrosoft })} />
        <ActionButton action={{ label: "Rescan", run: threatApi.rescanPersistence }} />
      </>}
    >
      <p className="muted">
        Everything that starts automatically: Run keys, Startup folders, scheduled tasks, services and WMI
        consumers. A full rescan runs every 2 minutes, and any NEW entry is reported in Activity.
      </p>
      <QueryState query={entries}>
        {(data) => <PersistenceTable entries={selectEntries(data, filter)} />}
      </QueryState>
    </Panel>
  );
}

function PersistenceTable({ entries }: { entries: PersistenceEntry[] }) {
  if (entries.length === 0) return <EmptyState>Nothing here (the first scan can take up to a minute).</EmptyState>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th>Type</th><th>Name</th><th>Command</th><th>Signer</th><th>State</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.id}>
              <td>{KIND_LABELS[e.kind]}</td>
              <td><strong>{e.name}</strong><div className="muted small mono">{e.location}</div></td>
              <td className="mono wrap small">{e.command}{!e.image_exists && e.image_path && <> <Badge tone="low">file missing</Badge></>}</td>
              <td><SignatureBadge signature={e.signature} /></td>
              <td>{e.enabled ? <Badge tone="info">enabled</Badge> : <Badge tone="neutral">disabled</Badge>}</td>
              <td>
                <ActionBar actions={[removePersistenceEntry(e),
                  ...(e.image_path && e.image_exists && !e.is_microsoft ? [quarantinePath(e.image_path)] : [])]} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
