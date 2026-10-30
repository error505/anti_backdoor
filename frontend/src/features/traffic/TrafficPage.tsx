import { Notice, Panel, QueryState } from "../../components/Layout";
import { useSystemStatus, useTraffic } from "../../hooks/queries";
import { CapturePanel } from "./CapturePanel";
import { ProcessTrafficTable, RemoteTrafficTable } from "./TrafficTables";

export function TrafficPage() {
  const traffic = useTraffic();
  const status = useSystemStatus();

  return (
    <>
      {traffic.data && !traffic.data.metering_available && (
        <Notice tone="warn">Byte counters need administrator rights. Restart with start.ps1 (it elevates automatically).</Notice>
      )}
      <div className="grid-2">
        <Panel title="Data sent per process">
          <QueryState query={traffic}>{(data) => <ProcessTrafficTable rows={data.by_process} />}</QueryState>
        </Panel>
        <Panel title="Data sent per remote server">
          <QueryState query={traffic}>{(data) => <RemoteTrafficTable rows={data.by_remote} />}</QueryState>
        </Panel>
      </div>
      <CapturePanel status={status.data?.capture} />
    </>
  );
}
