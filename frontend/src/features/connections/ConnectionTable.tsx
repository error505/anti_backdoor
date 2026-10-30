import type { Connection } from "../../api/types";
import { ActionBar } from "../../components/ActionButton";
import { Badge } from "../../components/Badge";
import { EmptyState } from "../../components/Layout";
import { formatBytes, formatEndpoint } from "../../lib/format";
import type { ActionSpec } from "../../hooks/useActionRunner";
import { blockIp, killProcess } from "../actions/actionCatalog";
import { ProcessLink } from "../processes/ProcessInspector";

const MAX_ROWS = 500;

function connectionActions(conn: Connection, includeKill: boolean): ActionSpec[] {
  const actions: ActionSpec[] = [];
  if (conn.remote_ip && conn.is_external) actions.push(blockIp(conn.remote_ip, conn.remote_host ?? undefined));
  if (includeKill && conn.pid) actions.push(killProcess(conn.pid, conn.process_name ?? "process"));
  return actions;
}

export function ConnectionTable({ connections, showProcess = true }: { connections: Connection[]; showProcess?: boolean }) {
  if (connections.length === 0) return <EmptyState>No connections.</EmptyState>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {showProcess && <th>Process</th>}
            <th>Proto</th>
            <th>Local</th>
            <th>Remote</th>
            <th>State</th>
            <th className="num">Sent</th>
            <th className="num">Received</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {connections.slice(0, MAX_ROWS).map((conn) => (
            <tr key={`${conn.protocol}-${conn.local_ip}-${conn.local_port}-${conn.remote_ip}-${conn.remote_port}-${conn.pid}`}>
              {showProcess && <td><ProcessLink pid={conn.pid} name={conn.process_name} /></td>}
              <td>{conn.protocol.toUpperCase()}</td>
              <td className="mono">{formatEndpoint(null, conn.local_ip, conn.local_port)}</td>
              <td className="mono">
                {formatEndpoint(conn.remote_host, conn.remote_ip, conn.remote_port)}
                {conn.remote_host && <div className="muted">{conn.remote_ip}</div>}
                {conn.is_external && <> <Badge tone="info">internet</Badge></>}
              </td>
              <td>{conn.state}</td>
              <td className="num">{formatBytes(conn.bytes_out)}</td>
              <td className="num">{formatBytes(conn.bytes_in)}</td>
              <td><ActionBar actions={connectionActions(conn, showProcess)} /></td>
            </tr>
          ))}
        </tbody>
      </table>
      {connections.length > MAX_ROWS && <p className="muted">Showing first {MAX_ROWS} of {connections.length}; refine the filter.</p>}
    </div>
  );
}
