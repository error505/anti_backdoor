import { AiSchedulePanel } from "./AiSchedulePanel";
import { AiSettingsPanel } from "./AiSettingsPanel";
import { AnalysisPanel } from "./AnalysisPanel";

export function AiPage() {
  return (
    <div className="grid-sidebar">
      <div>
        <AiSettingsPanel />
        <AiSchedulePanel />
      </div>
      <AnalysisPanel />
    </div>
  );
}
