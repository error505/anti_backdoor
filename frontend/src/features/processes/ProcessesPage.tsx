import { useState } from "react";
import type { ProcessInfo } from "../../api/types";
import { SelfBadge, SignatureBadge } from "../../components/Badge";
import { EmptyState, Panel, QueryState, SearchBox, Toggle } from "../../components/Layout";
import { useConnections, useProcesses, useSelfPids } from "../../hooks/queries";
import { matchesQuery } from "../../lib/format";
import { useInspectProcess } from "./ProcessInspector";

const MAX_ROWS = 400;

interface ProcessFilter {
  query: string;
  hideMicrosoft: boolean;
  networkOnly: boolean;
}

function selectProcesses(processes: ProcessInfo[], networkPids: Set<number>, filter: ProcessFilter) {
  return processes
    .filter((p) => !filter.hideMicrosoft || !p.signature?.is_microsoft)
    .filter((p) => !filter.networkOnly || networkPids.has(p.pid))
    .filter((p) => matchesQuery(filter.query, p.name, p.pid, p.exe, p.cmdline, p.username, p.signature?.signer))
    .sort((a, b) => Number(b.signature?.is_untrusted ?? false) - Number(a.signature?.is_untrusted ?? false)
      || a.name.localeCompare(b.name));
}

export function ProcessesPage() {
  const processes = useProcesses();
  const connections = useConnections();
  const [filter, setFilter] = useState<ProcessFilter>({ query: "", hideMicrosoft: true, networkOnly: false });
  const update = (patch: Partial<ProcessFilter>) => setFilter((current) => ({ ...current, ...patch }));
  const networkPids = new Set((connections.data ?? []).filter((c) => c.is_external).map((c) => c.pid ?? -1));

  return (
    <Panel
      title="Processes"
      actions={<>
        <SearchBox value={filter.query} onChange={(query) => update({ query })} placeholder="Search name, path, command line" />
        <Toggle label="Hide Microsoft-signed" checked={filter.hideMicrosoft} onChange={(hideMicrosoft) => update({ hideMicrosoft })} />
        <Toggle label="Talking to internet" checked={filter.networkOnly} onChange={(networkOnly) => update({ networkOnly })} />
      </>}
    >
      <QueryState query={processes}>
        {(data) => <ProcessTable processes={selectProcesses(data, networkPids, filter)} />}
      </QueryState>
    </Panel>
  );
}

function ProcessTable({ processes }: { processes: ProcessInfo[] }) {
  const inspect = useInspectProcess();
  const selfPids = useSelfPids();
  if (processes.length === 0) return <EmptyState>No processes match.</EmptyState>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th className="num">PID</th><th>Signer</th><th>User</th><th className="num">CPU %</th><th className="num">MB</th><th>Command line</th></tr>
        </thead>
        <tbody>
          {processes.slice(0, MAX_ROWS).map((p) => (
            <tr key={p.pid} className="clickable" onClick={() => inspect(p.pid)}>
              <td><button type="button" className="link">{p.name}</button>{selfPids.has(p.pid) && <> <SelfBadge /></>}</td>
              <td className="num mono">{p.pid}</td>
              <td><SignatureBadge signature={p.signature} /></td>
              <td>{p.username?.split("\\").pop() ?? "—"}</td>
              <td className="num">{p.cpu_percent?.toFixed(1) ?? "—"}</td>
              <td className="num">{p.memory_mb?.toFixed(0) ?? "—"}</td>
              <td className="mono truncate" title={p.cmdline}>{p.cmdline || p.exe || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {processes.length > MAX_ROWS && <p className="muted">Showing first {MAX_ROWS} of {processes.length}.</p>}
    </div>
  );
}
