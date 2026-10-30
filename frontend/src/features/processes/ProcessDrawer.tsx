import { useEffect } from "react";
import type { ProcessDetail, ProcessInfo } from "../../api/types";
import { ActionBar } from "../../components/ActionButton";
import { SelfBadge, SeverityBadge, SignatureBadge } from "../../components/Badge";
import { QueryState } from "../../components/Layout";
import { useProcessDetail, useSelfPids } from "../../hooks/queries";
import { formatEpoch } from "../../lib/format";
import {
  blockProcessNetwork, killProcess, killSingleProcess, quarantineProcess, resumeProcess, suspendProcess,
} from "../actions/actionCatalog";
import { ConnectionTable } from "../connections/ConnectionTable";

interface Props {
  pid: number;
  onClose: () => void;
  onInspect: (pid: number) => void;
}

export function ProcessDrawer({ pid, onClose, onInspect }: Props) {
  const detail = useProcessDetail(pid);

  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <aside className="drawer" role="dialog" aria-label={`Process ${pid}`} onClick={(e) => e.stopPropagation()}>
        <button type="button" className="btn drawer-close" onClick={onClose} aria-label="Close">✕</button>
        <QueryState query={detail}>
          {(data) => <ProcessDetailView detail={data} onInspect={onInspect} />}
        </QueryState>
      </aside>
    </div>
  );
}

function ProcessDetailView({ detail, onInspect }: { detail: ProcessDetail; onInspect: (pid: number) => void }) {
  const { process } = detail;
  const isSelf = useSelfPids().has(process.pid);
  return (
    <>
      <h2>{process.name} <span className="muted">PID {process.pid}</span> {isSelf && <SelfBadge />}</h2>
      {isSelf && <p className="muted">This is part of Backdoor Watch itself (its server, the window that launched it, or a helper it started).</p>}
      <ActionBar actions={[
        killProcess(process.pid, process.name), killSingleProcess(process.pid, process.name),
        suspendProcess(process.pid), resumeProcess(process.pid),
        quarantineProcess(process.pid, process.name), blockProcessNetwork(process.pid, process.name),
      ]} />
      {detail.findings.map((finding) => (
        <p key={finding.id}><SeverityBadge severity={finding.severity} /> {finding.title}</p>
      ))}
      <dl className="facts">
        <dt>Executable</dt><dd className="mono">{process.exe ?? "access denied"}</dd>
        <dt>Signature</dt><dd><SignatureBadge signature={process.signature} /></dd>
        <dt>User</dt><dd>{process.username ?? "—"}</dd>
        <dt>Started</dt><dd>{formatEpoch(process.create_time)}</dd>
        <dt>Command line</dt><dd className="mono wrap">{process.cmdline || "—"}</dd>
      </dl>
      <h3>Launched by</h3>
      <ProcessChain processes={[...detail.ancestors].reverse()} onInspect={onInspect} />
      <h3>Children ({detail.children.length})</h3>
      <ProcessChain processes={detail.children} onInspect={onInspect} />
      <h3>Network ({detail.connections.length})</h3>
      <ConnectionTable connections={detail.connections} showProcess={false} />
    </>
  );
}

function ProcessChain({ processes, onInspect }: { processes: ProcessInfo[]; onInspect: (pid: number) => void }) {
  if (processes.length === 0) return <p className="muted">none</p>;
  return (
    <ol className="chain">
      {processes.map((p) => (
        <li key={p.pid}>
          <button type="button" className="link" onClick={() => onInspect(p.pid)}>{p.name} ({p.pid})</button>
          <span className="muted mono"> {p.cmdline.slice(0, 160)}</span>
        </li>
      ))}
    </ol>
  );
}
