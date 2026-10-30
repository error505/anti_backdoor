import { useState, type ReactNode } from "react";
import { ApiError, hasSessionToken } from "./api/client";
import { BootSequence } from "./components/BootSequence";
import { Notice } from "./components/Layout";
import { SciFiBackdrop } from "./components/SciFiBackdrop";
import { TopBar } from "./components/TopBar";
import { ActivityPage } from "./features/activity/ActivityPage";
import { AiPage } from "./features/ai/AiPage";
import { ReportsPage } from "./features/reports/ReportsPage";
import { ConnectionsPage } from "./features/connections/ConnectionsPage";
import { ListenersPage } from "./features/connections/ListenersPage";
import { FindingsPage } from "./features/findings/FindingsPage";
import { OverviewPage } from "./features/overview/OverviewPage";
import { PersistencePage } from "./features/persistence/PersistencePage";
import { ProcessesPage } from "./features/processes/ProcessesPage";
import { ResponsePage } from "./features/response/ResponsePage";
import { TrafficPage } from "./features/traffic/TrafficPage";
import { AiVerdictBanner } from "./features/ai/AiVerdictBanner";
import { useAiSchedule, useSystemStatus } from "./hooks/queries";

type TabId = "overview" | "findings" | "connections" | "listeners" | "traffic" | "processes" | "persistence" | "activity"
  | "response" | "ai" | "reports";

const TABS: { id: TabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "findings", label: "Findings" },
  { id: "connections", label: "Connections" },
  { id: "listeners", label: "Open ports" },
  { id: "traffic", label: "Traffic & payloads" },
  { id: "processes", label: "Processes" },
  { id: "persistence", label: "Autostart" },
  { id: "activity", label: "Activity" },
  { id: "response", label: "Response tools" },
  { id: "ai", label: "AI analysis" },
  { id: "reports", label: "Reports" },
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
        <nav className="tabs" aria-label="Sections">
          {TABS.map((t, index) => (
            <button key={t.id} type="button" className={t.id === tab ? "tab active" : "tab"} aria-current={t.id === tab} onClick={() => setTab(t.id)}>
              <span className="tab-index">{String(index + 1).padStart(2, "0")}</span>
              {t.label}
            </button>
          ))}
        </nav>
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
    </>
  );
}
