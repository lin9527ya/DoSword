import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { Layout } from "./components/Layout";
import { DashboardView } from "./views/DashboardView";
import { SessionsView } from "./views/SessionsView";
import { RequestDebugView } from "./views/RequestDebugView";
import { GlobalFilesView } from "./views/GlobalFilesView";
import { GlobalDatabaseView } from "./views/GlobalDatabaseView";
import { OrchestrationView } from "./views/OrchestrationView";
import { ProxyChainView } from "./views/ProxyChainView";
import { PlaybookView } from "./views/PlaybookView";
import { SettingsView } from "./views/SettingsView";
import { AuditView } from "./views/AuditView";
import { ShellDetailView } from "./shells/ShellDetailView";
import { ToastProvider } from "./components/Toast";
import { ErrorBoundary } from "./components/common";
import { applyTheme } from "./theme";
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

  useEffect(() => {
    applyTheme();
  }, []);

  const navigate = useCallback(
    (view: View) => {
      if (view.kind === "shell") {
        const existing = shellTabs.find((tab) => tab.shellId === view.shellId);
        if (existing) {
          if (view.sessionId && existing.sessionId !== view.sessionId) {
            setShellTabs((prev) =>
              prev.map((t) =>
                t.id === existing.id
                  ? { ...t, sessionId: view.sessionId, name: view.shellName ?? t.name }
                  : t,
              ),
            );
          }
          setActiveTab(existing.id);
        } else {
          const newTabId = `shell-${tabSeq++}`;
          const newTab: ShellTab = {
            id: newTabId,
            shellId: view.shellId,
            sessionId: view.sessionId,
            name: view.shellName,
          };
          setShellTabs((prev) => [...prev, newTab]);
          setActiveTab(newTabId);
        }
      } else {
        // 切换至主功能视图时，清空当前活跃 shell 标签，确保立即呈现所选主视图
        setActiveTab(null);
        setMainView(view);
      }
    },
    [shellTabs],
  );

  const closeTab = useCallback((id: string) => {
    setShellTabs((prev) => {
      const index = prev.findIndex((tab) => tab.id === id);
      const closing = prev[index];
      // 关闭标签即断开该 Shell 的会话：此前只改数组，会话会一直活到 TTL（4h），
      // 在「终端会话」页仍可见可用，属于隐式泄漏（PTY 也一并级联清理）。
      if (closing?.sessionId) {
        void api.disconnectShell(closing.sessionId).catch(() => {});
      }
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
    <ToastProvider>
      <ErrorBoundary>
        <Layout
          view={activeShell ? { kind: "shell", shellId: activeShell.shellId, sessionId: activeShell.sessionId } : mainView}
          onNavigate={navigate}
          shellTabs={shellTabs}
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          onCloseTab={closeTab}
        >
          {/*
            已打开的 Shell 标签**全部常驻挂载**：切 Tab 只切显隐、不重挂载 —— 终端的
            回滚缓冲与视图状态因此保留（此前 `key={activeShell.id}` 会让整树重挂载，
            切回来就只剩一个空终端）。关闭标签时才真正卸载。

            非活动标签把 `active={false}` 传下去，轮询类子组件据此**暂停轮询**：
            隐藏期间的输出留在 socket / 服务端缓冲里，切回来继续读 —— 既不丢数据，
            也不会让后台标签持续向目标发包。
          */}
          {shellTabs.map((tab) => {
            const isActive = activeShell?.id === tab.id;
            return (
              <div
                key={tab.id}
                style={{ display: isActive ? "contents" : "none" }}
                aria-hidden={!isActive}
              >
                <ShellDetailView
                  shellId={tab.shellId}
                  initialSessionId={tab.sessionId}
                  onNavigate={navigate}
                  active={isActive}
                />
              </div>
            );
          })}
          {!activeShell &&
            (mainView.kind === "dashboard" ? (
              <DashboardView onNavigate={navigate} />
            ) : mainView.kind === "sessions" ? (
              <SessionsView onNavigate={navigate} />
            ) : mainView.kind === "debug" ? (
              <RequestDebugView />
            ) : mainView.kind === "files" ? (
              <GlobalFilesView onNavigate={navigate} />
            ) : mainView.kind === "database" ? (
              <GlobalDatabaseView onNavigate={navigate} />
            ) : mainView.kind === "orchestrate" ? (
              <OrchestrationView />
            ) : mainView.kind === "proxyChain" ? (
              <ProxyChainView />
            ) : mainView.kind === "playbook" ? (
              <PlaybookView />
            ) : mainView.kind === "audit" ? (
              <AuditView />
            ) : (
              <SettingsView />
            ))}
        </Layout>
      </ErrorBoundary>
    </ToastProvider>
  );
}

export default App;
