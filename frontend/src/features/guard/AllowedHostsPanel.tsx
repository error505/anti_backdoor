import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { guardApi } from "../../api/endpoints";
import type { GuardStatus } from "../../api/types";
import { Panel } from "../../components/Layout";
import { useToast } from "../../components/Toasts";

export function AllowedHostsPanel({ status }: { status: GuardStatus }) {
  const queryClient = useQueryClient();
  const notify = useToast();
  const [host, setHost] = useState("");
  const onSuccess = () => queryClient.invalidateQueries({ queryKey: ["guard"] });
  const onError = (e: Error) => notify("error", e.message);
  const add = useMutation({ mutationFn: guardApi.allowHost, onSuccess: () => { setHost(""); return onSuccess(); }, onError });
  const remove = useMutation({ mutationFn: guardApi.disallowHost, onSuccess, onError });

  return (
    <Panel title="Servers install scripts may contact">
      <p className="muted">
        Package managers and their scripts may reach these hosts without an alert. Add a private registry or CDN you use.
        A host name covers its sub-domains; an IP address matches only itself.
      </p>
      <form className="inline-form" onSubmit={(e) => { e.preventDefault(); add.mutate(host); }}>
        <input aria-label="Host or IP to allow" placeholder="registry.example.com or 203.0.113.7" value={host}
          onChange={(e) => setHost(e.target.value)} />
        <button type="submit" className="btn" disabled={add.isPending || !host.trim()}>Allow</button>
      </form>
      <ul className="plain-list">
        {status.config.allowed_hosts.map((entry) => (
          <li key={entry}>
            <span className="mono">{entry}</span>{" "}
            <button type="button" className="link" onClick={() => remove.mutate(entry)}>remove</button>
          </li>
        ))}
      </ul>
      <details>
        <summary>Built-in allowed hosts ({status.default_allowed_hosts.length})</summary>
        <p className="mono small">{status.default_allowed_hosts.join("  ·  ")}</p>
      </details>
    </Panel>
  );
}
