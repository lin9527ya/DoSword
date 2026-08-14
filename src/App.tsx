import { useCallback, useState } from "react";
import { Layout } from "./components/Layout";
import { DashboardView } from "./views/DashboardView";
import { SessionsView } from "./views/SessionsView";
import { RequestDebugView } from "./views/RequestDebugView";
import { SettingsView } from "./views/SettingsView";
import { AuditView } from "./views/AuditView";
import { ShellDetailView } from "./shells/ShellDetailView";
import type { ShellTab, View } from "./views/types";
import "./styles/base.css";
import "./styles/layout.css";
import "./styles/views.css";
import "./styles/widgets.css";

let tabSeq = 1;

function App() {
  const [mainView, setMainView] = useState<View>({ kind: "dashboard" });
  const [shellTabs, setShellTabs] = useState<ShellTab[]>([]);
  const [activeTab, setActiveTab] = useState<string | null>(null);

  const navigate = useCallback((view: View) => {
    if (view.kind === "shell") {
      // 多 Shell 标签页：同一 shell 复用标签，其余追加
      setShellTabs((prev) => {
        const existing = prev.find((tab) => tab.shellId === view.shellId);
        if (existing) {
          setActiveTab(existing.id);
          return prev;
        }
        const tab: ShellTab = {
          id: `shell-${tabSeq++}`,
          shellId: view.shellId,
          sessionId: view.sessionId,
          name: view.shellName,
        };
        setActiveTab(tab.id);
        return [...prev, tab];
      });
    } else {
      setMainView(view);
    }
  }, []);

  const closeTab = useCallback((id: string) => {
    setShellTabs((prev) => {
      const index = prev.findIndex((tab) => tab.id === id);
      const next = prev.filter((tab) => tab.id !== id);
      setActiveTab((current) => {
        if (current !== id) return current;
        if (next.length === 0) return null;
        return next[Math.min(index, next.length - 1)].id;
      });
      return next;
    });
  }, []);

  const activeShell = shellTabs.find((tab) => tab.id === activeTab) ?? null;

  return (
    <Layout
      view={activeShell ? { kind: "shell", shellId: activeShell.shellId, sessionId: activeShell.sessionId } : mainView}
      onNavigate={navigate}
      shellTabs={shellTabs}
      activeTab={activeTab}
      onSelectTab={setActiveTab}
      onCloseTab={closeTab}
    >
      {activeShell ? (
        <ShellDetailView
          key={activeShell.id}
          shellId={activeShell.shellId}
          initialSessionId={activeShell.sessionId}
          onNavigate={navigate}
        />
      ) : mainView.kind === "dashboard" ? (
        <DashboardView onNavigate={navigate} />
      ) : mainView.kind === "sessions" ? (
        <SessionsView onNavigate={navigate} />
      ) : mainView.kind === "debug" ? (
        <RequestDebugView />
      ) : mainView.kind === "audit" ? (
        <AuditView />
      ) : (
        <SettingsView />
      )}
    </Layout>
  );
}

export default App;
