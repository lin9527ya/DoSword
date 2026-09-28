import {
  Activity,
  ArrowLeftRight,
  Boxes,
  FileCode2,
  LayoutDashboard,
  Settings,
  ShieldCheck,
  TerminalSquare,
  X,
} from "lucide-react";
import { useEffect } from "react";
import type { ReactNode } from "react";
import type { ShellTab, View } from "../views/types";
import { StatusBar } from "./StatusBar";

type NavItem = {
  key: string;
  label: string;
  icon: ReactNode;
  view?: View;
  soon?: boolean;
  shortcut?: string;
};

const NAV_ITEMS: NavItem[] = [
  { key: "dashboard", label: "总览", icon: <LayoutDashboard size={17} />, view: { kind: "dashboard" }, shortcut: "Ctrl+N" },
  { key: "sessions", label: "终端会话", icon: <TerminalSquare size={17} />, view: { kind: "sessions" }, shortcut: "Ctrl+T" },
  { key: "debug", label: "请求调试", icon: <ArrowLeftRight size={17} />, view: { kind: "debug" }, shortcut: "Ctrl+R" },
  { key: "files", label: "批量文件", icon: <FileCode2 size={17} />, view: { kind: "files" }, shortcut: "Ctrl+M" },
  { key: "database", label: "数据库", icon: <Boxes size={17} />, view: { kind: "database" }, shortcut: "Ctrl+D" },
];

const BOTTOM_ITEMS: NavItem[] = [
  { key: "audit", label: "审计日志", icon: <Activity size={17} />, view: { kind: "audit" } },
  { key: "settings", label: "系统设置", icon: <Settings size={17} />, view: { kind: "settings" } },
];

export function Layout({
  view,
  onNavigate,
  children,
  shellTabs = [],
  activeTab = null,
  onSelectTab,
  onCloseTab,
}: {
  view: View;
  onNavigate: (view: View) => void;
  children: ReactNode;
  shellTabs?: ShellTab[];
  activeTab?: string | null;
  onSelectTab?: (id: string) => void;
  onCloseTab?: (id: string) => void;
}) {
  const activeKey = view.kind === "shell" ? "dashboard" : view.kind;

  // 全局快捷键：Ctrl+T 会话页 / Ctrl+N 总览 / Ctrl+R 请求调试 / Ctrl+M 批量文件 / Ctrl+D 数据库 / F5 刷新 / Ctrl+W 关闭标签
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const mod = event.ctrlKey || event.metaKey;
      if (mod && event.key.toLowerCase() === "t") {
        event.preventDefault();
        onNavigate({ kind: "sessions" });
      } else if (mod && event.key.toLowerCase() === "n") {
        event.preventDefault();
        onNavigate({ kind: "dashboard" });
      } else if (mod && event.key.toLowerCase() === "r") {
        event.preventDefault();
        onNavigate({ kind: "debug" });
      } else if (mod && event.key.toLowerCase() === "m") {
        event.preventDefault();
        onNavigate({ kind: "files" });
      } else if (mod && event.key.toLowerCase() === "d") {
        event.preventDefault();
        onNavigate({ kind: "database" });
      } else if (event.key === "F5") {
        event.preventDefault();
        onNavigate({ kind: "dashboard" });
      } else if (mod && event.key.toLowerCase() === "w") {
        event.preventDefault();
        if (activeTab && onCloseTab) onCloseTab(activeTab);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onNavigate, activeTab, onCloseTab]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck size={24} className="brand-icon" />
          <span>DoSword</span>
          <span className="brand-badge">v2.0</span>
        </div>
        <div className="workspace-label">WORKSPACE ENGINE</div>
        <nav>
          {NAV_ITEMS.map((item) =>
            item.soon ? (
              <button key={item.key} className="nav-item" title="规划中" style={{ opacity: 0.6 }}>
                {item.icon}
                <span>{item.label}</span>
                <em className="nav-flag">规划中</em>
              </button>
            ) : (
              <button
                key={item.key}
                className={`nav-item ${activeKey === item.key ? "active" : ""}`}
                onClick={() => item.view && onNavigate(item.view)}
                title={item.shortcut ? `${item.label} (${item.shortcut})` : item.label}
              >
                {item.icon}
                <span>{item.label}</span>
                {item.shortcut && <kbd>{item.shortcut}</kbd>}
              </button>
            ),
          )}
        </nav>
        <div className="sidebar-bottom">
          {BOTTOM_ITEMS.map((item) => (
            <button
              key={item.key}
              className={`nav-item ${activeKey === item.key ? "active" : ""}`}
              onClick={() => item.view && onNavigate(item.view)}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          ))}
          <div className="safety-note">
            <ShieldCheck size={16} />
            <span>
              真实网络协议受安全门保护
              <br />
              请在授权测试范围内使用
            </span>
          </div>
        </div>
      </aside>
      <div className="content">
        <div className="content-inner">
          {shellTabs.length > 0 && (
            <div className="shell-tabs">
              {shellTabs.map((tab) => (
                <span
                  key={tab.id}
                  className={`shell-tab ${activeTab === tab.id ? "active" : ""}`}
                  onClick={() => onSelectTab?.(tab.id)}
                  title={tab.name || tab.shellId}
                >
                  <span className="shell-tab-dot" />
                  <span>{tab.name || tab.shellId}</span>
                  <button
                    className="shell-tab-close"
                    onClick={(event) => {
                      event.stopPropagation();
                      onCloseTab?.(tab.id);
                    }}
                    title="关闭标签页 (Ctrl+W)"
                  >
                    <X size={12} />
                  </button>
                </span>
              ))}
            </div>
          )}
          <main className="app-main">{children}</main>
        </div>
        <StatusBar activeSessionCount={shellTabs.length} />
      </div>
    </div>
  );
}
