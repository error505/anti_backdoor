import type { ProcessTraffic } from "../../api/types";
import { formatBytes, formatRate } from "../../lib/format";

const SHOWN = 6;

/** Who sent the most data, as bars that grow to length. The shimmer marks programs sending right now. */
export function TopTalkersBars({ rows }: { rows: ProcessTraffic[] }) {
  const top = rows.filter((r) => r.bytes_out > 0).slice(0, SHOWN);
  if (top.length === 0) return <p className="chart-empty">No outbound data counted yet (needs administrator rights).</p>;
  const max = Math.max(...top.map((r) => r.bytes_out));
  return (
    <ul className="bars">
      {top.map((row) => (
        <li key={`${row.pid}-${row.process_name}`}>
          <div className="bar-label"><span>{row.process_name}</span><b>{formatBytes(row.bytes_out)}</b></div>
          <div className="bar-track">
            <span className={row.rate_out > 0 ? "bar-fill bar-live" : "bar-fill"} style={{ width: `${Math.max((row.bytes_out / max) * 100, 2)}%` }} />
          </div>
          <div className="bar-sub muted small">{row.rate_out > 0 ? `${formatRate(row.rate_out)} now` : "idle"} · received {formatBytes(row.bytes_in)}</div>
        </li>
      ))}
    </ul>
  );
}
