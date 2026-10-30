import { useState } from "react";
import { quarantineApi } from "../../api/endpoints";
import { ActionBar, ActionButton } from "../../components/ActionButton";
import { EmptyState, Panel, QueryState } from "../../components/Layout";
import { useQuarantine } from "../../hooks/queries";
import { formatEpoch } from "../../lib/format";
import { quarantinePath } from "../actions/actionCatalog";

export function QuarantinePanel() {
  const items = useQuarantine();
  const [path, setPath] = useState("");

  return (
    <Panel title="Quarantine">
      <p className="muted">
        Files are moved to backend/data/quarantine without their extension, so they can't run, but they can be
        restored or handed to an incident responder. Look up the SHA-256 on virustotal.com.
      </p>
      <form className="inline-form" onSubmit={(e) => e.preventDefault()}>
        <input aria-label="File or folder to quarantine" placeholder="File or folder, e.g. C:\Users\you\.n2" value={path} onChange={(e) => setPath(e.target.value)} />
        <ActionButton action={quarantinePath(path.trim())} />
      </form>
      <QueryState query={items}>
        {(data) => data.length === 0 ? <EmptyState>Quarantine is empty.</EmptyState> : (
          <ul className="plain-list">
            {data.map((item) => (
              <li key={item.id}>
                <div className="target-row">
                  <span className="mono">{item.original_path}</span>
                  <ActionBar actions={[
                    { label: "Restore", confirm: `Restore ${item.original_path}?`, run: () => quarantineApi.restore(item.id) },
                    { label: "Delete forever", tone: "danger", confirm: `Permanently delete ${item.original_path}?`, run: () => quarantineApi.purge(item.id) },
                  ]} />
                </div>
                <div className="muted small">{formatEpoch(item.quarantined_at)} · {item.reason}</div>
                {item.sha256 && <div className="mono small">SHA-256 {item.sha256}</div>}
              </li>
            ))}
          </ul>
        )}
      </QueryState>
    </Panel>
  );
}
