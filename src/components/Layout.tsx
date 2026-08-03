import { Activity, Boxes, Braces, FileCode2, LayoutDashboard, Settings, ShieldCheck, TerminalSquare } from "lucide-react";
import type { ReactNode } from "react";
import type { View } from "../views/types";

type NavItem = {
  key: string;
  label: string;
  icon: ReactNode;
  view?: View;
  soon?: boolean;
};

const NAV_ITEMS: NavItem[] = [
  { key: "dashboard", label: "总览", icon: <LayoutDashboard size={18} />, view: { kind: "dashboard" } },
  { key: "sessions", label: "终端会话", icon: <TerminalSquare size={18} />, view: { kind: "sessions" } },
  { key: "files", label: "文件传输", icon: <FileCode2 size={18} />, soon: true },
  { key: "debug", label: "请求调试", icon: <Braces size={18} />, view: { kind: "debug" } },
  { key: "database", label: "数据库", icon: <Boxes size={18} />, soon: true },
];

const BOTTOM_ITEMS: NavItem[] = [
  { key: "audit", label: "审计日志", icon: <Activity size={18} />, view: { kind: "audit" } },
  { key: "settings", label: "设置", icon: <Settings size={18} />, view: { kind: "settings" } },
];

export function Layout({
  view,
  onNavigate,
  children,
}: {
  view: View;
  onNavigate: (view: View) => void;
  children: ReactNode;
}) {
  const activeKey = view.kind === "shell" ? "dashboard" : view.kind;
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck size={25} />
          <span>DoSword</span>
        </div>
        <div className="workspace-label">AUTHORIZED WORKSPACE</div>
        <nav>
          {NAV_ITEMS.map((item) =>
            item.soon ? (
              <button key={item.key} className="nav-item" title="规划于 V2.0">
                {item.icon}
                <span className="nav-label">{item.label}</span>
                <em className="nav-flag">规划中</em>
              </button>
            ) : (
              <button
                key={item.key}
                className={`nav-item ${activeKey === item.key ? "active" : ""}`}
                onClick={() => item.view && onNavigate(item.view)}
              >
                {item.icon}
                {item.label}
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
              {item.label}
            </button>
          ))}
          <div className="safety-note">
            <ShieldCheck size={16} />
            <span>
              真实网络协议默认关闭
              <br />
              仅在授权范围内使用
            </span>
          </div>
        </div>
      </aside>
      <main className="content">{children}</main>
    </div>
  );
}
