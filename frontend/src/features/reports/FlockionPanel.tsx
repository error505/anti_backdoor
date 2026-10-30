import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import Markdown from "react-markdown";
import { flockionApi } from "../../api/endpoints";
import type { FlockionMode, FlockionSettings } from "../../api/types";
import { ActionButton } from "../../components/ActionButton";
import { Badge } from "../../components/Badge";
import { Panel, QueryState } from "../../components/Layout";
import { useToast } from "../../components/Toasts";
import { useFlockionSettings } from "../../hooks/queries";
import { formatBytes } from "../../lib/format";
import { FlockionGuide } from "./FlockionGuide";

export function FlockionPanel() {
  const settings = useFlockionSettings();
  return (
    <Panel title="Flockion agent">
      <QueryState query={settings}>{(current) => <FlockionForm current={current} />}</QueryState>
    </Panel>
  );
}

function FlockionForm({ current }: { current: FlockionSettings }) {
  const queryClient = useQueryClient();
  const notify = useToast();
  const [endpoint, setEndpoint] = useState(current.endpoint);
  const [apiKey, setApiKey] = useState("");
  const [mode, setMode] = useState<FlockionMode>("findings");
  const onError = (e: Error) => notify("error", e.message);

  const save = useMutation({
    mutationFn: () => flockionApi.save(endpoint.trim(), apiKey.trim() ? apiKey.trim() : null),
    onSuccess: (saved) => { setApiKey(""); queryClient.setQueryData(["flockion-settings"], saved); notify("success", "Flockion settings saved"); },
    onError,
  });
  const test = useMutation({ mutationFn: flockionApi.test, onError });
  const send = useMutation({ mutationFn: () => flockionApi.send(mode), onError });
  const preview = useMutation({ mutationFn: () => flockionApi.preview(mode), onError });

  const ready = current.has_stored_key && !current.endpoint.includes("AGENT_ID");

  return (
    <div className="stack">
      <p className="muted">
        Hands a <strong>redacted</strong> snapshot to one of your Flockion agents, the same way the Flockion VS Code
        extension connects. In Flockion open the agent → <em>API &amp; editor access</em>, copy the runtime URL and create a
        runtime key (<code>flk_…</code>, shown once).
      </p>
      <FlockionGuide />
      <form className="stack" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        <label className="field">Runtime endpoint
          <input value={endpoint} onChange={(e) => setEndpoint(e.target.value)} spellCheck={false}
            placeholder="https://api.flockion.com/api/v1/api-access/agent/AGENT_ID/run" />
        </label>
        <label className="field">Runtime key
          <input type="password" autoComplete="off" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
            placeholder={current.has_stored_key ? `stored (${current.key_hint}); type to replace` : "flk_…"} />
        </label>
        <div className="action-bar">
          <button type="submit" className="btn" disabled={save.isPending}>Save</button>
          {current.has_stored_key && <ActionButton action={{ label: "Remove key", tone: "danger", confirm: "Delete the stored Flockion key?", run: flockionApi.clearKey }} />}
          {current.has_stored_key ? <Badge tone="ok">key stored {current.key_hint}</Badge> : <Badge tone="neutral">no key</Badge>}
        </div>
      </form>

      <div className="action-bar">
        <button type="button" className="btn" disabled={!ready || test.isPending} onClick={() => test.mutate()}>Test connection</button>
        {test.data && (
          <span><Badge tone={test.data.ok ? "ok" : "high"}>{test.data.ok ? "CONNECTED" : "FAILED"}</Badge>{" "}
            <span className="small">{test.data.asset_name ? `${test.data.asset_name} · ` : ""}{test.data.detail}</span></span>
        )}
      </div>
      <p className="muted small">Test connection only validates the key. It starts no task and sends no system data.</p>

      <label className="field">What to send
        <select value={mode} onChange={(e) => setMode(e.target.value as FlockionMode)}>
          <option value="findings">Findings summary (small, recommended)</option>
          <option value="full">Full snapshot (processes, traffic, events)</option>
        </select>
      </label>
      <div className="action-bar">
        <button type="button" className="btn" disabled={preview.isPending} onClick={() => preview.mutate()}>Preview data to be sent</button>
        <button type="button" className="btn btn-danger" disabled={!ready || send.isPending}
          onClick={() => window.confirm(`Send the redacted ${mode} snapshot to your Flockion agent? This starts a task that uses its budget (capped at $2).`) && send.mutate()}>
          {send.isPending ? "Agent working… (up to 5 min)" : "Send to agent"}
        </button>
      </div>
      <p className="muted small">The agent runs in read-only <em>ask</em> mode; any request to read files, run commands or write is denied automatically.</p>
      {preview.data && (
        <details open>
          <summary>{formatBytes(preview.data.characters)} would be sent</summary>
          <pre className="preview">{preview.data.content}</pre>
        </details>
      )}
      {send.data && (
        <article className="analysis">
          <p className="muted small">
            <Badge tone={send.data.ok ? "ok" : "high"}>{send.data.status}</Badge>{" "}
            {formatBytes(send.data.sent_chars)} sent
            {send.data.cost_usd !== null && <> · ${send.data.cost_usd.toFixed(3)} · {send.data.total_tokens ?? "?"} tokens</>}
            {send.data.denied_tool_requests > 0 && <> · {send.data.denied_tool_requests} tool requests denied</>}
          </p>
          {/* react-markdown never renders raw HTML, so agent output stays inert text. */}
          <Markdown>{send.data.output}</Markdown>
        </article>
      )}
    </div>
  );
}
