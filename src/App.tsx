import { useState } from "react";
import { Layout } from "./components/Layout";
import { DashboardView } from "./views/DashboardView";
import { SessionsView } from "./views/SessionsView";
import { SettingsView } from "./views/SettingsView";
import { AuditView } from "./views/AuditView";
import { ShellDetailView } from "./shells/ShellDetailView";
import type { View } from "./views/types";
import "./styles/base.css";
import "./styles/layout.css";
import "./styles/views.css";
import "./styles/widgets.css";

function App() {
  const [view, setView] = useState<View>({ kind: "dashboard" });

  return (
    <Layout view={view} onNavigate={setView}>
      {view.kind === "dashboard" && <DashboardView onNavigate={setView} />}
      {view.kind === "shell" && (
        <ShellDetailView
          shellId={view.shellId}
          initialSessionId={view.sessionId}
          onNavigate={setView}
        />
      )}
      {view.kind === "sessions" && <SessionsView onNavigate={setView} />}
      {view.kind === "audit" && <AuditView />}
      {view.kind === "settings" && <SettingsView />}
    </Layout>
  );
}

export default App;
