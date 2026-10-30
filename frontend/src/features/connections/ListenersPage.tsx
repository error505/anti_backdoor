import { useState } from "react";
import type { Connection } from "../../api/types";
import { ActionBar } from "../../components/ActionButton";
import { Badge } from "../../components/Badge";
import { EmptyState, Panel, QueryState, SearchBox, Toggle } from "../../components/Layout";
import { useConnections } from "../../hooks/queries";
import { matchesQuery } from "../../lib/format";
import { blockProcessNetwork, killProcess } from "../actions/actionCatalog";
import { ProcessLink } from "../processes/ProcessInspector";

function selectListeners(connections: Connection[], query: string, networkOnly: boolean, includeUdp: boolean) {
  return connections
    .filter((c) => c.is_listener)
    .filter((c) => includeUdp || c.protocol === "tcp")
    .filter((c) => !networkOnly || c.exposure === "network")
    .filter((c) => matchesQuery(query, c.process_name, c.pid, c.local_port, c.local_ip))
    .sort((a, b) => a.local_port - b.local_port);
}

export function ListenersPage() {
  const connections = useConnections();
  const [query, setQuery] = useState("");
  const [networkOnly, setNetworkOnly] = useState(true);
  const [includeUdp, setIncludeUdp] = useState(false);

  return (
    <Panel
      title="Open ports (listening)"
      actions={<>
        <SearchBox value={query} onChange={setQuery} placeholder="Filter by process or port" />
        <Toggle label="Reachable from network only" checked={networkOnly} onChange={setNetworkOnly} />
        <Toggle label="Include UDP" checked={includeUdp} onChange={setIncludeUdp} />
      </>}
    >
      <p className="muted">
        A backdoor that waits for the attacker shows up here as a listening port. Ports bound to 0.0.0.0 or ::
        can be reached from other machines, unless the firewall blocks them.
      </p>
      <QueryState query={connections}>
        {(data) => <ListenerTable listeners={selectListeners(data, query, networkOnly, includeUdp)} />}
      </QueryState>
    </Panel>
  );
}

function ListenerTable({ listeners }: { listeners: Connection[] }) {
  if (listeners.length === 0) return <EmptyState>No listening ports match.</EmptyState>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th className="num">Port</th><th>Proto</th><th>Bound to</th><th>Exposure</th><th>Process</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {listeners.map((l) => (
            <tr key={`${l.protocol}-${l.local_ip}-${l.local_port}-${l.pid}`}>
              <td className="num mono">{l.local_port}</td>
              <td>{l.protocol.toUpperCase()}</td>
              <td className="mono">{l.local_ip}</td>
              <td>{l.exposure === "network" ? <Badge tone="medium">network</Badge> : <Badge tone="neutral">this PC only</Badge>}</td>
              <td><ProcessLink pid={l.pid} name={l.process_name} /></td>
              <td>
                {l.pid && <ActionBar actions={[killProcess(l.pid, l.process_name ?? "process"),
                  blockProcessNetwork(l.pid, l.process_name ?? "process")]} />}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
