import type { ProcessTraffic, RemoteTraffic } from "../../api/types";
import { ActionBar } from "../../components/ActionButton";
import { EmptyState } from "../../components/Layout";
import { formatBytes, formatRate } from "../../lib/format";
import { blockIp } from "../actions/actionCatalog";
import { ProcessLink } from "../processes/ProcessInspector";

export function ProcessTrafficTable({ rows, limit }: { rows: ProcessTraffic[]; limit?: number }) {
  if (rows.length === 0) return <EmptyState>No traffic measured yet.</EmptyState>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th>Process</th><th className="num">Sent</th><th className="num">Received</th><th className="num">Up now</th><th className="num">Down now</th><th>Talks to</th></tr>
        </thead>
        <tbody>
          {rows.slice(0, limit).map((row) => (
            <tr key={row.pid}>
              <td><ProcessLink pid={row.pid || null} name={row.process_name} /></td>
              <td className="num">{formatBytes(row.bytes_out)}</td>
              <td className="num">{formatBytes(row.bytes_in)}</td>
              <td className="num">{formatRate(row.rate_out)}</td>
              <td className="num">{formatRate(row.rate_in)}</td>
              <td className="small mono truncate" title={row.remotes.join("\n")}>{row.remotes.slice(0, 4).join(", ")}{row.remotes.length > 4 ? ` +${row.remotes.length - 4}` : ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function RemoteTrafficTable({ rows }: { rows: RemoteTraffic[] }) {
  if (rows.length === 0) return <EmptyState>No traffic measured yet.</EmptyState>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr><th>Remote server</th><th className="num">Sent to it</th><th className="num">Received</th><th>Processes</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.remote_ip}>
              <td className="mono">{row.remote_host ?? row.remote_ip}{row.remote_host && <div className="muted">{row.remote_ip}</div>}</td>
              <td className="num">{formatBytes(row.bytes_out)}</td>
              <td className="num">{formatBytes(row.bytes_in)}</td>
              <td className="small">{row.processes.join(", ")}</td>
              <td><ActionBar actions={[blockIp(row.remote_ip, row.remote_host ?? undefined)]} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
