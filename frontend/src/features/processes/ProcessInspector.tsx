import { createContext, useContext, useState, type ReactNode } from "react";
import { SelfBadge } from "../../components/Badge";
import { useSelfPids } from "../../hooks/queries";
import { ProcessDrawer } from "./ProcessDrawer";

const InspectContext = createContext<(pid: number) => void>(() => undefined);

export function ProcessInspectorProvider({ children }: { children: ReactNode }) {
  const [pid, setPid] = useState<number | null>(null);
  return (
    <InspectContext.Provider value={setPid}>
      {children}
      {pid !== null && <ProcessDrawer pid={pid} onClose={() => setPid(null)} onInspect={setPid} />}
    </InspectContext.Provider>
  );
}

export const useInspectProcess = () => useContext(InspectContext);

export function ProcessLink({ pid, name }: { pid: number | null; name: string | null }) {
  const inspect = useInspectProcess();
  const selfPids = useSelfPids();
  if (pid === null) return <span className="muted">{name ?? "unknown"}</span>;
  return (
    <>
      <button type="button" className="link" onClick={() => inspect(pid)}>
        {name ?? "?"} <span className="muted">({pid})</span>
      </button>
      {selfPids.has(pid) && <> <SelfBadge /></>}
    </>
  );
}
