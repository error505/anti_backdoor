import { DefenderPanel } from "./DefenderPanel";
import { FirewallPanel } from "./FirewallPanel";
import { QuarantinePanel } from "./QuarantinePanel";
import { SourceScanPanel } from "./SourceScanPanel";

export function ResponsePage() {
  return (
    <>
      <div className="grid-2">
        <DefenderPanel />
        <FirewallPanel />
      </div>
      <QuarantinePanel />
      <SourceScanPanel />
    </>
  );
}
