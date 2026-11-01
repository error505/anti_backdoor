import type { Severity } from "../../api/types";
import { EmptyState, Panel, QueryState } from "../../components/Layout";
import { useActivity, useMetrics, useTraffic } from "../../hooks/queries";
import { formatRate } from "../../lib/format";
import { ActivityTimeline } from "./ActivityTimeline";
import { SeverityDonut } from "./SeverityDonut";
import { TimeSeriesChart } from "./TimeSeriesChart";
import { TopTalkersBars } from "./TopTalkersBars";

const EVENT_WINDOW = 4000;

/** The live charts under the overview tiles. Each panel loads on its own, so one slow query never blanks the rest. */
export function ChartsSection({ severities }: { severities: Partial<Record<Severity, number>> }) {
  const metrics = useMetrics();
  const traffic = useTraffic();
  const activity = useActivity(EVENT_WINDOW);

  return (
    <>
      <div className="grid-charts">
        <Panel title="Data leaving and entering this PC">
          <QueryState query={metrics}>
            {(history) => (
              <TimeSeriesChart
                times={history.samples.map((s) => s.t)} format={formatRate}
                emptyHint={history.metering ? "Collecting data…" : "Byte counting needs administrator rights (start with start.ps1)."}
                series={[
                  { label: "Sent", color: "var(--accent)", values: history.samples.map((s) => s.rate_out) },
                  { label: "Received", color: "var(--accent-2)", values: history.samples.map((s) => s.rate_in) },
                ]} />
            )}
          </QueryState>
        </Panel>
        <Panel title="Findings by severity">
          <SeverityDonut counts={severities} />
        </Panel>
      </div>
      <div className="grid-2">
        <div className="stack-panels">
          <Panel title="Internet connections over time">
            <QueryState query={metrics}>
              {(history) => (
                <TimeSeriesChart
                  times={history.samples.map((s) => s.t)} format={(v) => String(Math.round(v))} height={190}
                  series={[
                    { label: "Internet connections", color: "var(--info)", values: history.samples.map((s) => s.external_connections) },
                    { label: "Ports open to network", color: "var(--medium)", values: history.samples.map((s) => s.network_listeners) },
                  ]} />
              )}
            </QueryState>
          </Panel>
          <Panel title="Activity, last 30 minutes">
            <QueryState query={activity}>
              {(events) => events.length === 0
                ? <EmptyState>No activity recorded yet.</EmptyState>
                : <ActivityTimeline events={events} now={Date.now() / 1000} />}
            </QueryState>
          </Panel>
        </div>
        <Panel title="Top senders">
          <QueryState query={traffic}>{(data) => <TopTalkersBars rows={data.by_process} />}</QueryState>
        </Panel>
      </div>
    </>
  );
}
