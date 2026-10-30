import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { aiApi } from "../../api/endpoints";
import type { AiProvider, AiProviderOptions, AiSettings } from "../../api/types";
import { ActionButton } from "../../components/ActionButton";
import { Badge } from "../../components/Badge";
import { Notice, Panel, QueryState } from "../../components/Layout";
import { useToast } from "../../components/Toasts";
import { useAiOptions, useAiSettings } from "../../hooks/queries";

const KEY_ENV_VARS: Record<AiProvider, string> = { anthropic: "ANTHROPIC_API_KEY", openai: "OPENAI_API_KEY" };

const EFFORT_HINTS: Record<string, string> = {
  minimal: "fastest, least reasoning",
  low: "quick triage",
  medium: "balanced",
  high: "thorough (recommended)",
  xhigh: "very thorough, slower",
  max: "deepest, slowest and most expensive",
};

export function AiSettingsPanel() {
  const settings = useAiSettings();
  const options = useAiOptions();
  return (
    <Panel title="AI provider">
      <QueryState query={options}>
        {(providerOptions) => (
          <QueryState query={settings}>
            {(current) => <AiSettingsForm current={current} options={providerOptions} />}
          </QueryState>
        )}
      </QueryState>
    </Panel>
  );
}

function AiSettingsForm({ current, options }: { current: AiSettings; options: AiProviderOptions }) {
  const queryClient = useQueryClient();
  const notify = useToast();
  const [provider, setProvider] = useState<AiProvider>(current.provider);
  const [model, setModel] = useState(current.model);
  const [effort, setEffort] = useState(current.effort);
  const [apiKey, setApiKey] = useState("");
  const providerOptions = options[provider];

  const changeProvider = (next: AiProvider) => {
    const isSaved = next === current.provider;
    setProvider(next);
    setModel(isSaved ? current.model : options[next].default_model);
    setEffort(isSaved ? current.effort : options[next].default_effort);
  };

  const save = useMutation({
    mutationFn: () => aiApi.saveSettings(provider, model, effort, apiKey.trim() ? apiKey.trim() : null),
    onSuccess: (saved) => {
      setApiKey("");
      queryClient.setQueryData(["ai-settings"], saved);
      notify("success", `Saved: ${saved.provider} / ${saved.model} / effort ${saved.effort}`);
    },
    onError: (error: Error) => notify("error", error.message),
  });

  return (
    <form className="stack" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
      <label className="field">Provider
        <select value={provider} onChange={(e) => changeProvider(e.target.value as AiProvider)}>
          <option value="anthropic">Anthropic (Claude)</option>
          <option value="openai">OpenAI</option>
        </select>
      </label>
      <label className="field">Model
        <input list={`models-${provider}`} value={model} onChange={(e) => setModel(e.target.value)}
          placeholder={providerOptions.default_model} />
        <datalist id={`models-${provider}`}>
          {providerOptions.suggested_models.map((m) => <option key={m} value={m} />)}
        </datalist>
      </label>
      <label className="field">Effort
        <select value={effort} onChange={(e) => setEffort(e.target.value)}>
          {providerOptions.effort_levels.map((level) => (
            <option key={level} value={level}>{level} · {EFFORT_HINTS[level] ?? ""}</option>
          ))}
        </select>
      </label>
      <label className="field">API key
        <input type="password" autoComplete="off" value={apiKey} onChange={(e) => setApiKey(e.target.value)}
          placeholder={current.has_stored_key && current.provider === provider ? `stored (${current.key_hint}); type to replace` : "paste API key"} />
      </label>
      <div className="action-bar">
        <button type="submit" className="btn" disabled={save.isPending}>{save.isPending ? "Saving…" : "Save"}</button>
        {current.has_stored_key && <ActionButton action={{ label: "Remove stored key", tone: "danger", confirm: "Delete the stored API key?", run: aiApi.clearKey }} />}
        {current.has_stored_key ? <Badge tone="ok">key stored {current.key_hint}</Badge> : <Badge tone="neutral">no key stored</Badge>}
      </div>
      <p className="muted small">
        Pick a suggested model or type any model ID. Higher effort means more reasoning before answering:
        better on ambiguous evidence, but slower and more tokens.
      </p>
      <Notice tone="info">
        The key is encrypted with Windows DPAPI (only your Windows account can decrypt it) in
        backend/data/ai_settings.json and is never sent to the browser. With no stored key, the backend uses
        the {KEY_ENV_VARS[provider]} environment variable.
      </Notice>
    </form>
  );
}
