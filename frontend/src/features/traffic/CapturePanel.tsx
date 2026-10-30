import { useState } from "react";
import { captureApi } from "../../api/endpoints";
import type { CaptureRecord, CaptureStatus } from "../../api/types";
import { ActionButton } from "../../components/ActionButton";
import { Badge } from "../../components/Badge";
import { EmptyState, Notice, Panel, QueryState, SearchBox } from "../../components/Layout";
import { useCaptureRecords } from "../../hooks/queries";
import { formatTime, matchesQuery } from "../../lib/format";
import { ProcessLink } from "../processes/ProcessInspector";

const PROTOCOL_TONES = { dns: "neutral", tls: "info", http: "high", payload: "medium" } as const;

const startCapture = { label: "Start capture", run: async () => ({ message: (await captureApi.start()).message }) };
const stopCapture = { label: "Stop capture", run: async () => ({ message: (await captureApi.stop()).message }) };

export function CapturePanel({ status }: { status: CaptureStatus | undefined }) {
  const records = useCaptureRecords(1500);
  const [query, setQuery] = useState("");

  return (
    <Panel
      title="Live packet inspection"
      actions={<>
        <SearchBox value={query} onChange={setQuery} placeholder="Filter host, process, content" />
        <ActionButton action={status?.running ? stopCapture : startCapture} />
      </>}
    >
      <p className="muted">
        Shows <strong>what</strong> is being sent: DNS lookups, the server name of every TLS connection (the
        content is encrypted), and any <strong>plaintext</strong> HTTP or raw data leaving this PC. BeaverTail-style
        loaders often use plain HTTP to a raw IP, and that shows up here in red. Requires Npcap.
      </p>
      {status && !status.available && <Notice tone="warn">{status.message}</Notice>}
      <QueryState query={records}>
        {(data) => <CaptureTable records={[...data].reverse().filter((r) =>
          matchesQuery(query, r.summary, r.remote, r.remote_host, r.process_name, r.preview))} />}
      </QueryState>
    </Panel>
  );
}

function CaptureTable({ records }: { records: CaptureRecord[] }) {
  if (records.length === 0) return <EmptyState>Nothing captured yet.</EmptyState>;
  return (
    <div className="table-wrap tall">
      <table>
        <thead><tr><th>Time</th><th>Type</th><th>Process</th><th>Destination</th><th>What</th></tr></thead>
        <tbody>
          {records.map((r) => (
            <tr key={r.seq}>
              <td className="small">{formatTime(r.timestamp)}</td>
              <td><Badge tone={PROTOCOL_TONES[r.protocol]}>{r.protocol.toUpperCase()}</Badge></td>
              <td><ProcessLink pid={r.pid} name={r.process_name} /></td>
              <td className="mono small">{r.remote_host ?? r.remote}<div className="muted">{r.remote}</div></td>
              <td>
                {r.summary}
                {r.preview && <details><summary className="small">payload preview</summary><pre className="preview">{r.preview}</pre></details>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
