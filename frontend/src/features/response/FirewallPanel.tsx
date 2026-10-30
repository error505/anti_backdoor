import { useState } from "react";
import { firewallApi } from "../../api/endpoints";
import { ActionBar, ActionButton } from "../../components/ActionButton";
import { EmptyState, Panel, QueryState } from "../../components/Layout";
import { useFirewallRules } from "../../hooks/queries";
import { blockIp } from "../actions/actionCatalog";

export function FirewallPanel() {
  const rules = useFirewallRules();
  const [ip, setIp] = useState("");
  const [program, setProgram] = useState("");

  return (
    <Panel title="Firewall blocks">
      <form className="inline-form" onSubmit={(e) => e.preventDefault()}>
        <input aria-label="IP address to block" placeholder="IP address, e.g. 95.164.17.24" value={ip} onChange={(e) => setIp(e.target.value)} />
        <ActionButton action={blockIp(ip.trim())} />
      </form>
      <form className="inline-form" onSubmit={(e) => e.preventDefault()}>
        <input aria-label="Program path to block" placeholder="Program path, e.g. C:\Users\you\.pyp\python.exe" value={program} onChange={(e) => setProgram(e.target.value)} />
        <ActionButton action={{ label: "Block program", tone: "danger", run: () => firewallApi.blockProgram(program.trim()) }} />
      </form>
      <h3>Rules created by Backdoor Watch</h3>
      <QueryState query={rules}>
        {(data) => data.length === 0 ? <EmptyState>No blocks yet.</EmptyState> : (
          <ul className="plain-list">
            {data.map((rule) => (
              <li key={rule.id} className="target-row">
                <span>{rule.display_name} <span className="muted mono small">{rule.target}</span></span>
                <ActionBar actions={[{ label: "Remove", run: () => firewallApi.removeRule(rule.id) }]} />
              </li>
            ))}
          </ul>
        )}
      </QueryState>
    </Panel>
  );
}
