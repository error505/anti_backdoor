import { useState } from "react";
import type { ActivityEvent } from "../../api/types";
import { Badge, type BadgeTone } from "../../components/Badge";
import { EmptyState, Panel, QueryState, SearchBox } from "../../components/Layout";
import { useActivity } from "../../hooks/queries";
import { formatTime, matchesQuery } from "../../lib/format";
import { ProcessLink } from "../processes/ProcessInspector";

const KIND_STYLE: Record<string, { label: string; tone: BadgeTone }> = {
  monitoring_started: { label: "monitor", tone: "neutral" },
  process_started: { label: "process +", tone: "info" },
  process_exited: { label: "process −", tone: "neutral" },
  connection_opened: { label: "connect", tone: "info" },
  connection_closed: { label: "disconnect", tone: "neutral" },
  listener_opened: { label: "PORT OPENED", tone: "medium" },
  listener_closed: { label: "port closed", tone: "neutral" },
  persistence_added: { label: "NEW AUTOSTART", tone: "high" },
  persistence_removed: { label: "autostart gone", tone: "low" },
  action_taken: { label: "your action", tone: "ok" },
};

const CATEGORIES: Record<string, string[]> = {
  all: [],
  network: ["connection_opened", "connection_closed", "listener_opened", "listener_closed"],
  processes: ["process_started", "process_exited"],
  persistence: ["persistence_added", "persistence_removed"],
  actions: ["action_taken"],
};

function selectEvents(events: ActivityEvent[], category: string, query: string) {
  const kinds = CATEGORIES[category];
  return [...events]
    .reverse()
    .filter((e) => kinds.length === 0 || kinds.includes(e.kind))
    .filter((e) => matchesQuery(query, e.summary, e.process_name, e.pid, ...Object.values(e.details)));
}

export function ActivityPage() {
  const events = useActivity(3000);
  const [category, setCategory] = useState("all");
  const [query, setQuery] = useState("");

  return (
    <Panel
      title="Activity timeline"
      actions={<>
        <SearchBox value={query} onChange={setQuery} placeholder="Search events" />
        <select aria-label="Category" value={category} onChange={(e) => setCategory(e.target.value)}>
          {Object.keys(CATEGORIES).map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      </>}
    >
      <p className="muted">
        Every process start, internet connection, new listening port and new autostart entry since the monitor
        started. The same events are written to backend/data/logs/activity-YYYYMMDD.jsonl as forensic evidence.
      </p>
      <QueryState query={events}>
        {(data) => <EventList events={selectEvents(data, category, query)} />}
      </QueryState>
    </Panel>
  );
}

function EventList({ events }: { events: ActivityEvent[] }) {
  if (events.length === 0) return <EmptyState>No events yet.</EmptyState>;
  return (
    <div className="table-wrap tall">
      <table>
        <thead><tr><th>Time</th><th>Event</th><th>Process</th><th>Details</th></tr></thead>
        <tbody>
          {events.map((e) => {
            const style = KIND_STYLE[e.kind] ?? { label: e.kind, tone: "neutral" as const };
            return (
              <tr key={e.seq}>
                <td className="small">{formatTime(e.timestamp)}</td>
                <td><Badge tone={style.tone}>{style.label}</Badge></td>
                <td>{e.pid !== null ? <ProcessLink pid={e.pid} name={e.process_name} /> : "—"}</td>
                <td>
                  {e.summary}
                  {(e.details.cmdline || e.details.command) && (
                    <div className="mono small muted wrap">{e.details.cmdline || e.details.command}</div>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
