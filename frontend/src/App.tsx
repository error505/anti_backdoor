import { useState, type ReactNode } from "react";
import { ApiError, hasSessionToken } from "./api/client";
import { BootSequence } from "./components/BootSequence";
import { Notice } from "./components/Layout";
import { SciFiBackdrop } from "./components/SciFiBackdrop";
import { SideNav, type NavItem } from "./components/SideNav";
import { TopBar } from "./components/TopBar";
import { ActivityPage } from "./features/activity/ActivityPage";
import { AiPage } from "./features/ai/AiPage";
import { ReportsPage } from "./features/reports/ReportsPage";
import { ConnectionsPage } from "./features/connections/ConnectionsPage";
import { ListenersPage } from "./features/connections/ListenersPage";
import { FindingsPage } from "./features/findings/FindingsPage";
import { MalwarePage } from "./features/malware/MalwarePage";
import { OverviewPage } from "./features/overview/OverviewPage";
import { PersistencePage } from "./features/persistence/PersistencePage";
import { ProcessesPage } from "./features/processes/ProcessesPage";
import { ResponsePage } from "./features/response/ResponsePage";
import { TrafficPage } from "./features/traffic/TrafficPage";
import { AiVerdictBanner } from "./features/ai/AiVerdictBanner";
import { useAiSchedule, useSystemStatus } from "./hooks/queries";

type TabId = "overview" | "findings" | "connections" | "listeners" | "traffic" | "processes" | "persistence" | "activity"
  | "malware" | "response" | "ai" | "reports";

const TABS: NavItem<TabId>[] = [
  { id: "overview", label: "Overview", group: "Monitor" },
  { id: "findings", label: "Findings", group: "Monitor" },
  { id: "connections", label: "Connections", group: "Monitor" },
  { id: "listeners", label: "Open ports", group: "Monitor" },
  { id: "traffic", label: "Traffic & payloads", group: "Monitor" },
  { id: "processes", label: "Processes", group: "Monitor" },
  { id: "persistence", label: "Autostart", group: "Monitor" },
  { id: "activity", label: "Activity", group: "Monitor" },
  { id: "malware", label: "Malware scan", group: "Respond" },
  { id: "response", label: "Response tools", group: "Respond" },
  { id: "ai", label: "AI analysis", group: "Intelligence" },
  { id: "reports", label: "Reports & Flockion", group: "Intelligence" },
];

/** Allows deep links such as ?tab=findings (used for documentation screenshots). */
function initialTab(): TabId {
  const requested = new URLSearchParams(window.location.search).get("tab");
  return TABS.find((t) => t.id === requested)?.id ?? "overview";
}

export function App() {
  const [tab, setTab] = useState<TabId>(initialTab);
  const status = useSystemStatus();
  const aiWatch = useAiSchedule();
  const unauthorized = status.error instanceof ApiError && status.error.status === 401;
  const pages: Record<TabId, ReactNode> = {
    overview: <OverviewPage onOpenFindings={() => setTab("findings")} />,
    findings: <FindingsPage />,
    connections: <ConnectionsPage />,
    listeners: <ListenersPage />,
    traffic: <TrafficPage />,
    processes: <ProcessesPage />,
    persistence: <PersistencePage />,
    activity: <ActivityPage />,
    malware: <MalwarePage />,
    response: <ResponsePage />,
    ai: <AiPage />,
    reports: <ReportsPage />,
  };

  return (
    <>
      <SciFiBackdrop />
      <BootSequence />
      <div className="app">
        <TopBar status={status.data} aiWatch={aiWatch.data} offline={status.isError && !unauthorized} />
        <div className="shell">
          <SideNav items={TABS} active={tab} onSelect={setTab} />
          <main key={tab} className="page-enter">
            {(!hasSessionToken() || unauthorized) && (
              <Notice tone="danger">
                Missing or expired session token. Open the exact URL printed by the backend
                (http://127.0.0.1:8765/#token=…).
              </Notice>
            )}
            {tab !== "ai" && <AiVerdictBanner onOpen={() => setTab("ai")} />}
            {pages[tab]}
          </main>
        </div>
      </div>
    </>
  );
}
