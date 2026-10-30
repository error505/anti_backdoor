import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { aiApi } from "../../api/endpoints";
import type { AiScheduleState } from "../../api/types";
import { Badge } from "../../components/Badge";
import { Notice, Panel, QueryState, Toggle } from "../../components/Layout";
import { useToast } from "../../components/Toasts";
import { useAiSchedule, useAiSettings } from "../../hooks/queries";
import { formatEpoch } from "../../lib/format";

// Mirrors INTERVAL_CHOICES_MINUTES in the backend, which rejects anything else.
const INTERVALS = [
  { minutes: 5, label: "every 5 minutes" }, { minutes: 10, label: "every 10 minutes" },
  { minutes: 15, label: "every 15 minutes" }, { minutes: 30, label: "every 30 minutes" },
  { minutes: 60, label: "every hour" }, { minutes: 120, label: "every 2 hours" },
  { minutes: 360, label: "every 6 hours" }, { minutes: 720, label: "every 12 hours" },
];
const UNIT_HOURS = { hours: 1, days: 24 } as const;
const MAX_HOURS = 24 * 30;
type DurationUnit = keyof typeof UNIT_HOURS;

export function AiSchedulePanel() {
  const schedule = useAiSchedule();
  return (
    <Panel title="AI Watch: automatic analysis">
      <QueryState query={schedule}>
        {(state) => (state.enabled ? <ActiveSchedule state={state} /> : <ScheduleForm last={state} />)}
      </QueryState>
    </Panel>
  );
}

function useScheduleMutation<T>(run: (arg: T) => Promise<AiScheduleState>, success: string) {
  const queryClient = useQueryClient();
  const notify = useToast();
  return useMutation({
    mutationFn: run,
    onSuccess: (state) => {
      queryClient.setQueryData(["ai-schedule"], state);
      notify("success", success);
    },
    onError: (error: Error) => notify("error", error.message),
  });
}

function ScheduleForm({ last }: { last: AiScheduleState }) {
  const settings = useAiSettings();
  const [intervalMinutes, setIntervalMinutes] = useState(30);
  const [amount, setAmount] = useState(8);
  const [unit, setUnit] = useState<DurationUnit>("hours");
  const [skipUnchanged, setSkipUnchanged] = useState(true);
  const start = useScheduleMutation(aiApi.startSchedule, "AI Watch started");

  const durationHours = Math.min(Math.max(amount, 0) * UNIT_HOURS[unit], MAX_HOURS);
  const maxRuns = Math.floor((durationHours * 60) / intervalMinutes) + 1;
  const hasCredentials = settings.data?.has_stored_key ?? false;

  return (
    <form className="stack" onSubmit={(e) => { e.preventDefault(); start.mutate({ interval_minutes: intervalMinutes, duration_hours: durationHours, skip_unchanged: skipUnchanged }); }}>
      <p className="muted">
        Re-runs the AI analysis on a timer, using the provider, model and effort saved above. The
        monitoring itself runs every 2 seconds for free; only these scheduled checks use tokens.
      </p>
      <label className="field">Check
        <select value={intervalMinutes} onChange={(e) => setIntervalMinutes(Number(e.target.value))}>
          {INTERVALS.map((i) => <option key={i.minutes} value={i.minutes}>{i.label}</option>)}
        </select>
      </label>
      <div className="field">For
        <div className="duration-row">
          <input type="number" min={1} max={unit === "days" ? 30 : MAX_HOURS} value={amount} aria-label="Duration"
            onChange={(e) => setAmount(Number(e.target.value))} />
          <select value={unit} aria-label="Duration unit" onChange={(e) => setUnit(e.target.value as DurationUnit)}>
            <option value="hours">hours</option>
            <option value="days">days</option>
          </select>
        </div>
      </div>
      <Toggle label="Skip when nothing security-relevant changed (saves tokens)" checked={skipUnchanged} onChange={setSkipUnchanged} />
      <Notice tone="info">
        At most <strong>{maxRuns}</strong> analyses over {durationHours} h{skipUnchanged ? ", usually far fewer, because unchanged checks are skipped" : ""}.
        It stops by itself when the time is up, and pauses after 3 failures in a row.
      </Notice>
      {!hasCredentials && <Notice tone="warn">No API key is stored. Save one above (or set the provider's API-key environment variable) before starting.</Notice>}
      <div className="action-bar">
        <button type="submit" className="btn" disabled={start.isPending || durationHours <= 0}>Start AI Watch</button>
        {last.last_status && <span className="muted small">Last schedule: {last.last_status} · {last.runs} runs, {last.skipped} skipped</span>}
      </div>
    </form>
  );
}

function ActiveSchedule({ state }: { state: AiScheduleState }) {
  const stop = useScheduleMutation(aiApi.stopSchedule, "AI Watch stopped");
  return (
    <div className="stack">
      <div><Badge tone="ok">ACTIVE</Badge> <span className="muted">every {state.interval_minutes} min · skip unchanged: {state.skip_unchanged ? "on" : "off"}</span></div>
      <dl className="facts">
        <dt>Next check</dt><dd>{formatEpoch(state.next_check_at)}</dd>
        <dt>Ends</dt><dd>{formatEpoch(state.ends_at)}</dd>
        <dt>Analyses run</dt><dd>{state.runs} of at most {state.max_runs}</dd>
        <dt>Skipped (no change)</dt><dd>{state.skipped}</dd>
        <dt>Last status</dt><dd>{state.last_status ?? "—"}</dd>
        {state.last_error && <><dt>Last error</dt><dd className="mono wrap">{state.last_error}</dd></>}
      </dl>
      <div className="action-bar">
        <button type="button" className="btn btn-danger" disabled={stop.isPending} onClick={() => stop.mutate(undefined)}>Stop AI Watch</button>
      </div>
    </div>
  );
}
