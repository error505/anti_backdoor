import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { sourceScanApi } from "../../api/endpoints";
import type { SourceHit } from "../../api/types";
import { SeverityBadge } from "../../components/Badge";
import { EmptyState, Notice, Panel, Toggle } from "../../components/Layout";

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function SourceScanPanel() {
  const [path, setPath] = useState("");
  const [includeNodeModules, setIncludeNodeModules] = useState(false);
  const scan = useMutation({ mutationFn: () => sourceScanApi.scan(path.trim(), includeNodeModules) });
  const sweep = useMutation({ mutationFn: sourceScanApi.sweep });
  const result = sweep.data ?? scan.data;
  const error = sweep.error ?? scan.error;

  return (
    <Panel title="Inspect a code folder (e.g. the interview repo)">
      <p className="muted">
        Statically searches JS/TS/Python/config files for loader and stealer patterns: eval / new Function, code
        fetched from vercel.app / npoint / jsonkeeper, raw-IP URLs, VS Code auto-run tasks, npm install hooks,
        wallet-extension IDs and keylogger packages. Nothing is executed.
      </p>
      <form className="inline-form" onSubmit={(e) => { e.preventDefault(); scan.mutate(); }}>
        <input aria-label="Folder path" placeholder="C:\path\to\cloned\repo" value={path} onChange={(e) => setPath(e.target.value)} />
        <Toggle label="Include node_modules" checked={includeNodeModules} onChange={setIncludeNodeModules} />
        <button type="submit" className="btn" disabled={scan.isPending || !path.trim()}>{scan.isPending ? "Scanning…" : "Scan"}</button>
        <button type="button" className="btn" disabled={sweep.isPending} onClick={() => { scan.reset(); sweep.mutate(); }}
          title="Searches Downloads, Desktop, Documents and common code folders for high-confidence patterns only">
          {sweep.isPending ? "Sweeping (about a minute)…" : "Sweep all my code folders"}
        </button>
      </form>
      {error && <Notice tone="danger">{error.message}</Notice>}
      {result && <SourceHits hits={result} />}
    </Panel>
  );
}

function SourceHits({ hits }: { hits: SourceHit[] }) {
  if (hits.length === 0) return <EmptyState>No suspicious patterns found.</EmptyState>;
  const sorted = [...hits].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
  return (
    <div className="table-wrap tall">
      <table>
        <thead><tr><th>Severity</th><th>Where</th><th>Why</th><th>Code</th></tr></thead>
        <tbody>
          {sorted.map((hit, index) => (
            <tr key={`${hit.file}-${hit.line}-${hit.rule_id}-${index}`}>
              <td><SeverityBadge severity={hit.severity} /></td>
              <td className="mono small wrap">{hit.file}:{hit.line}</td>
              <td className="small">{hit.description}</td>
              <td><code className="snippet">{hit.snippet}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
