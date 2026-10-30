import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { flockionApi } from "../../api/endpoints";
import type { FlockionMode, FlockionResult, FlockionSettings } from "../../api/types";
import { ActionButton } from "../../components/ActionButton";
import { Badge } from "../../components/Badge";
import { Notice, Panel, QueryState } from "../../components/Layout";
import { useToast } from "../../components/Toasts";
import { useFlockionSettings } from "../../hooks/queries";
import { formatBytes } from "../../lib/format";

type Draft = Omit<FlockionSettings, "has_stored_key" | "key_hint">;

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
  const [draft, setDraft] = useState<Draft>({ ...current });
  const [apiKey, setApiKey] = useState("");
  const [mode, setMode] = useState<FlockionMode>("findings");
  const [result, setResult] = useState<FlockionResult | null>(null);
  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => setDraft((d) => ({ ...d, [key]: value }));

  const save = useMutation({
    mutationFn: () => flockionApi.save(draft, apiKey.trim() ? apiKey.trim() : null),
    onSuccess: (saved) => { setApiKey(""); queryClient.setQueryData(["flockion-settings"], saved); notify("success", "Flockion settings saved"); },
    onError: (e: Error) => notify("error", e.message),
  });
  const call = useMutation({
    mutationFn: (kind: "test" | "send") => (kind === "test" ? flockionApi.test() : flockionApi.send(mode)),
    onSuccess: setResult,
    onError: (e: Error) => notify("error", e.message),
  });
  const preview = useMutation({ mutationFn: () => flockionApi.preview(mode), onError: (e: Error) => notify("error", e.message) });

  const ready = current.has_stored_key && current.agent_id !== "";
  const runUrl = `${draft.base_url}/api/v1/api-access/agent/${draft.agent_id || "AGENT_ID"}/run`;

  return (
    <div className="stack">
      <p className="muted">
        Sends a <strong>redacted</strong> snapshot to one of your Flockion agents through its API access. Create the
        runtime key (starts with <code>flk_</code>) on the agent's profile under <em>API &amp; editor access</em>; it is
        shown once. See the <a href="https://flockion.com/docs/vscode-extension" target="_blank" rel="noreferrer noopener">Flockion docs</a>.
      </p>
      <form className="stack" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        <label className="field">Agent ID
          <input value={draft.agent_id} onChange={(e) => set("agent_id", e.target.value)} placeholder="AGENT_ID" />
        </label>
        <label className="field">Runtime key (flk_…)
          <input type="password" autoComplete="off" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
            placeholder={current.has_stored_key ? `stored (${current.key_hint}); type to replace` : "flk_…"} />
        </label>
        <details>
          <summary>Request format (change if the Flockion test ping fails)</summary>
          <div className="stack">
            <label className="field">API URL
              <input value={draft.base_url} onChange={(e) => set("base_url", e.target.value)} />
            </label>
            <label className="field">Auth header
              <input value={draft.auth_header} onChange={(e) => set("auth_header", e.target.value)} />
            </label>
            <label className="field">Auth scheme prefix (empty to send the key alone)
              <input value={draft.auth_scheme} onChange={(e) => set("auth_scheme", e.target.value)} />
            </label>
            <label className="field">JSON field that carries the text
              <input value={draft.body_field} onChange={(e) => set("body_field", e.target.value)} />
            </label>
            <Notice tone="warn">
              The public docs give the endpoint and key format but not the header or body schema, so these
              defaults are assumptions. Use <strong>Test connection</strong> to verify them.
            </Notice>
          </div>
        </details>
        <div className="action-bar">
          <button type="submit" className="btn" disabled={save.isPending}>Save</button>
          {current.has_stored_key && <ActionButton action={{ label: "Remove key", tone: "danger", confirm: "Delete the stored Flockion key?", run: flockionApi.clearKey }} />}
          {current.has_stored_key ? <Badge tone="ok">key stored {current.key_hint}</Badge> : <Badge tone="neutral">no key</Badge>}
        </div>
        <p className="mono small muted">POST {runUrl}</p>
      </form>

      <label className="field">What to send
        <select value={mode} onChange={(e) => setMode(e.target.value as FlockionMode)}>
          <option value="findings">Findings summary (small, recommended)</option>
          <option value="full">Full snapshot (processes, traffic, events)</option>
        </select>
      </label>
      <div className="action-bar">
        <button type="button" className="btn" disabled={!ready || call.isPending} onClick={() => call.mutate("test")}>Test connection</button>
        <button type="button" className="btn" disabled={preview.isPending} onClick={() => preview.mutate()}>Preview data to be sent</button>
        <button type="button" className="btn btn-danger" disabled={!ready || call.isPending}
          onClick={() => window.confirm(`Send the redacted ${mode} snapshot to Flockion agent ${current.agent_id}?`) && call.mutate("send")}>
          {call.isPending ? "Waiting for agent…" : "Send to agent"}
        </button>
      </div>
      {preview.data && (
        <details open>
          <summary>{formatBytes(preview.data.characters)} would be sent</summary>
          <pre className="preview">{preview.data.content}</pre>
        </details>
      )}
      {result && (
        <div>
          <Badge tone={result.ok ? "ok" : "high"}>HTTP {result.status_code}</Badge>{" "}
          <span className="muted small">{formatBytes(result.sent_chars)} sent</span>
          <pre className="preview">{result.response_text || "(empty response)"}</pre>
        </div>
      )}
    </div>
  );
}
