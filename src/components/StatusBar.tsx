import { useEffect, useState } from "react";
import { TerminalSquare, Layers, Wifi, WifiOff } from "lucide-react";
import { api } from "../api";
import type { AppSettings, SessionInfo } from "../api";

export function StatusBar({ activeSessionCount = 0 }: { activeSessionCount?: number }) {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [sessionCount, setSessionCount] = useState(activeSessionCount);

  useEffect(() => {
    void api.getSettings().then(setSettings).catch(() => {});
    void api.listSessions().then((s: SessionInfo[]) => setSessionCount(s.length)).catch(() => {});
    const interval = setInterval(() => {
      void api.listSessions().then((s: SessionInfo[]) => setSessionCount(s.length)).catch(() => {});
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <footer className="status-bar">
      <div className="status-bar-left">
        <span className="status-indicator">
          {settings?.httpEnabled ? (
            <>
              <span className="dot online" />
              <span style={{ color: "var(--ok)", display: "inline-flex", alignItems: "center", gap: 4 }}>
                <Wifi size={12} />
                真实网络协议已就绪
              </span>
            </>
          ) : (
            <>
              <span className="dot offline" />
              <span style={{ color: "var(--text-faint)", display: "inline-flex", alignItems: "center", gap: 4 }}>
                <WifiOff size={12} />
                本地 Mock 安全沙箱模式
              </span>
            </>
          )}
        </span>
        {settings?.proxy && (
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-dim)" }}>
            代理: {settings.proxy}
          </span>
        )}
      </div>

      <div className="status-bar-right">
        <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
          <TerminalSquare size={12} color="var(--accent)" />
          活跃会话: <strong>{sessionCount}</strong>
        </span>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
          <Layers size={12} />
          DoSword v0.1.0 (Core Engine v2.0)
        </span>
      </div>
    </footer>
  );
}
