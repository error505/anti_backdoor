import { useState } from "react";
import type { Connection } from "../../api/types";
import { Panel, QueryState, SearchBox, Toggle } from "../../components/Layout";
import { useConnections, useIpIntel } from "../../hooks/queries";
import { matchesQuery } from "../../lib/format";
import { IpIntelToggle } from "../intel/IpIntelToggle";
import { ConnectionTable } from "./ConnectionTable";

interface ConnectionFilter {
  query: string;
  internetOnly: boolean;
  establishedOnly: boolean;
}

function filterConnections(connections: Connection[], filter: ConnectionFilter): Connection[] {
  return connections
    .filter((c) => !c.is_listener)
    .filter((c) => !filter.internetOnly || c.is_external)
    .filter((c) => !filter.establishedOnly || c.state === "ESTABLISHED")
    .filter((c) => matchesQuery(filter.query, c.process_name, c.pid, c.remote_ip, c.remote_host, c.remote_port, c.local_port))
    .sort((a, b) => (b.bytes_out ?? -1) - (a.bytes_out ?? -1));
}

export function ConnectionsPage() {
  const connections = useConnections();
  const [filter, setFilter] = useState<ConnectionFilter>({ query: "", internetOnly: true, establishedOnly: true });
  const update = (patch: Partial<ConnectionFilter>) => setFilter((current) => ({ ...current, ...patch }));

  return (
    <Panel
      title="Active connections"
      actions={<>
        <SearchBox value={filter.query} onChange={(query) => update({ query })} placeholder="Filter by process, IP, host, port" />
        <Toggle label="Internet only" checked={filter.internetOnly} onChange={(internetOnly) => update({ internetOnly })} />
        <Toggle label="Established only" checked={filter.establishedOnly} onChange={(establishedOnly) => update({ establishedOnly })} />
      </>}
    >
      <p className="muted">
        Who is talking to whom right now. Host names come from DNS. Byte counts start when the monitor first
        sees a connection and need administrator rights.
      </p>
      <IpIntelToggle />
      <QueryState query={connections}>
        {(data) => <FilteredConnections connections={filterConnections(data, filter)} />}
      </QueryState>
    </Panel>
  );
}

function FilteredConnections({ connections }: { connections: Connection[] }) {
  const remoteIps = connections.filter((c) => c.is_external && c.remote_ip).map((c) => c.remote_ip as string);
  const intel = useIpIntel(remoteIps);
  return <ConnectionTable connections={connections} intel={intel.data ?? new Map()} />;
}
