import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import Markdown from "react-markdown";
import { aiApi } from "../../api/endpoints";
import type { AiAnalysis } from "../../api/types";
import { Badge } from "../../components/Badge";
import { EmptyState, Notice, Panel, QueryState } from "../../components/Layout";
import { useAiHistory } from "../../hooks/queries";
import { formatBytes, formatEpoch } from "../../lib/format";
import { VerdictBadge } from "./VerdictBadge";

export function AnalysisPanel() {
  const queryClient = useQueryClient();
  const history = useAiHistory();
  const [question, setQuestion] = useState("");
  const [selected, setSelected] = useState<number | null>(null);
  const preview = useMutation({ mutationFn: aiApi.context });
  const analyze = useMutation({
    mutationFn: () => aiApi.analyze(question),
    onSuccess: () => {
      setSelected(null);
      void queryClient.invalidateQueries({ queryKey: ["ai-history"] });
    },
  });

  return (
    <Panel title="AI analysis">
      <p className="muted">
        Sends a <strong>redacted</strong> snapshot to the selected provider: findings, non-Microsoft processes,
        internet connections, open ports, autostart entries, traffic and recent events. Your username,
        hostname and anything that looks like a token or password are masked. Click "Preview" to see exactly
        what will be sent.
      </p>
      <form className="stack" onSubmit={(e) => { e.preventDefault(); analyze.mutate(); }}>
        <textarea aria-label="Optional question" rows={3} value={question} onChange={(e) => setQuestion(e.target.value)}
          placeholder="Optional question, e.g. 'Is anything here consistent with InvisibleFerret?' or 'Is the node.exe in .cache legitimate?'" />
        <div className="action-bar">
          <button type="submit" className="btn" disabled={analyze.isPending}>
            {analyze.isPending ? "Analysing… (can take 1–3 minutes)" : "Run AI analysis now"}
          </button>
          <button type="button" className="btn" disabled={preview.isPending} onClick={() => preview.mutate()}>
            Preview data to be sent
          </button>
        </div>
      </form>
      {analyze.isError && <Notice tone="danger">{analyze.error.message}</Notice>}
      {preview.data && (
        <details open>
          <summary>{formatBytes(preview.data.characters)} of redacted JSON would be sent</summary>
          <pre className="preview">{preview.data.content}</pre>
        </details>
      )}
      <QueryState query={history}>
        {(items) => {
          if (items.length === 0) return <EmptyState>No analysis yet.</EmptyState>;
          const shown = items.find((a) => a.created_at === selected) ?? items[0];
          return (
            <>
              <AnalysisHistory items={items} selected={shown} onSelect={setSelected} />
              <AnalysisResult analysis={shown} />
            </>
          );
        }}
      </QueryState>
    </Panel>
  );
}

function AnalysisHistory({ items, selected, onSelect }: { items: AiAnalysis[]; selected: AiAnalysis; onSelect: (createdAt: number) => void }) {
  return (
    <details className="history">
      <summary>History ({items.length})</summary>
      <ul className="plain-list">
        {items.map((a) => (
          <li key={a.created_at}>
            <button type="button" className={a === selected ? "link history-active" : "link"} onClick={() => onSelect(a.created_at)}>
              {formatEpoch(a.created_at)}
            </button>{" "}
            <VerdictBadge verdict={a.verdict} /> <Badge tone="neutral">{a.trigger}</Badge>{" "}
            <span className="muted small">{a.model} · {a.effort}</span>
          </li>
        ))}
      </ul>
    </details>
  );
}

function AnalysisResult({ analysis }: { analysis: AiAnalysis }) {
  return (
    <article className="analysis">
      <p className="muted small">
        <VerdictBadge verdict={analysis.verdict} /> <Badge tone="neutral">{analysis.trigger}</Badge>{" "}
        {analysis.provider} / {analysis.model} · effort {analysis.effort} · {formatEpoch(analysis.created_at)} · {formatBytes(analysis.context_chars)} sent
        {analysis.question && <> · question: “{analysis.question}”</>}
      </p>
      {/* react-markdown never renders raw HTML, so attacker strings quoted by the model stay inert. */}
      <Markdown>{analysis.markdown}</Markdown>
      <p className="muted small">AI output can be wrong. Check its claims against the Findings and Processes tabs before you act.</p>
    </article>
  );
}
