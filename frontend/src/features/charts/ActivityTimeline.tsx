import type { ActivityEvent } from "../../api/types";
import { useElementWidth } from "../../hooks/useElementWidth";
import { binByTime } from "./chartMath";

const BIN_SECONDS = 60;
const BIN_COUNT = 30;
const BOX = { height: 150, left: 28, bottom: 20, top: 8 };
const DEFAULT_WIDTH = 760;

const CATEGORY_OF: Record<string, string> = {
  process_started: "processes", process_exited: "processes",
  connection_opened: "network", connection_closed: "network", listener_opened: "ports", listener_closed: "ports",
  persistence_added: "autostart", persistence_removed: "autostart", action_taken: "actions",
};
const CATEGORIES = [
  { id: "processes", label: "Processes", color: "var(--accent)" },
  { id: "network", label: "Connections", color: "var(--info)" },
  { id: "ports", label: "Ports", color: "var(--medium)" },
  { id: "autostart", label: "Autostart", color: "var(--high)" },
  { id: "actions", label: "Your actions", color: "var(--ok)" },
];

/** Events per minute for the last half hour, stacked by kind. Columns rise into place. */
export function ActivityTimeline({ events, now }: { events: ActivityEvent[]; now: number }) {
  const [wrap, width] = useElementWidth<HTMLDivElement>(DEFAULT_WIDTH);
  const items = events.filter((e) => CATEGORY_OF[e.kind]).map((e) => ({ t: e.timestamp, category: CATEGORY_OF[e.kind] }));
  const bins = binByTime(items, now, BIN_SECONDS, BIN_COUNT);
  const peak = Math.max(1, ...bins.map((b) => Object.values(b.counts).reduce((a, c) => a + c, 0)));
  const plotHeight = BOX.height - BOX.bottom - BOX.top;
  const slot = (width - BOX.left) / BIN_COUNT;

  return (
    <div className="chart-wrap" ref={wrap}>
      <svg className="chart" viewBox={`0 0 ${width} ${BOX.height}`} role="img" aria-label="Activity per minute, last 30 minutes">
        <g className="chart-grid">
          <line x1={BOX.left} x2={width} y1={BOX.top} y2={BOX.top} />
          <text x={BOX.left - 6} y={BOX.top + 4} textAnchor="end">{peak}</text>
          <line x1={BOX.left} x2={width} y1={BOX.height - BOX.bottom} y2={BOX.height - BOX.bottom} />
          <text x={BOX.left - 6} y={BOX.height - BOX.bottom + 4} textAnchor="end">0</text>
        </g>
        {bins.map((bin, column) => {
          let stacked = 0;
          return (
            <g key={bin.start} className="column" style={{ animationDelay: `${column * 18}ms` }}>
              {CATEGORIES.map((category) => {
                const count = bin.counts[category.id] ?? 0;
                if (count === 0) return null;
                const height = (count / peak) * plotHeight;
                stacked += height;
                return (
                  <rect key={category.id} fill={category.color} x={BOX.left + column * slot + 2} width={Math.max(slot - 4, 2)}
                    y={BOX.height - BOX.bottom - stacked} height={height}>
                    <title>{`${new Date(bin.start * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })}: ${count} ${category.label.toLowerCase()}`}</title>
                  </rect>
                );
              })}
            </g>
          );
        })}
        <text className="chart-axis" x={BOX.left} y={BOX.height - 5}>30 min ago</text>
        <text className="chart-axis" x={width} y={BOX.height - 5} textAnchor="end">now</text>
      </svg>
      <ul className="chart-legend">
        {CATEGORIES.map((c) => <li key={c.id}><span className="swatch" style={{ background: c.color }} />{c.label}</li>)}
      </ul>
    </div>
  );
}
