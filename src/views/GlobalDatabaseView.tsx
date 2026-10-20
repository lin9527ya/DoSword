import { useCallback, useEffect, useState } from "react";
import {
  Boxes,
  Database,
  LoaderCircle,
  RefreshCw,
  TerminalSquare,
} from "lucide-react";
import { api, errorText } from "../api";
import type { SessionInfo, ShellSummary } from "../api";
import { Empty, ErrorBanner, Panel } from "../components/common";
import { DatabaseManager } from "../widgets/DatabaseManager";
import { useToast } from "../components/Toast";
import type { View } from "./types";

export function GlobalDatabaseView({ onNavigate }: { onNavigate?: (view: View) => void }) {
  const toast = useToast();
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [shells, setShells] = useState<ShellSummary[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState<string | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      // Shell 选择器只要精简列表（无密码），不再拉整个看板
      const [sessionList, shellList] = await Promise.all([
        api.listSessions(),
        api.listShellSummaries(),
      ]);
      setSessions(sessionList);
      setShells(shellList);

      if (sessionList.length > 0) {
        setSelectedSessionId((prev) =>
          prev && sessionList.some((s) => s.sessionId === prev) ? prev : sessionList[0].sessionId,
        );
      } else {
        setSelectedSessionId(null);
      }
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "加载会话失败");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  async function connectAndOpen(shell: ShellSummary) {
    setConnecting(shell.id);
    try {
      const res = await api.connectShell(shell.id);
      toast.success(`已连接 ${shell.name}`, "会话建立成功");
      await load();
      setSelectedSessionId(res.sessionId);
    } catch (cause) {
      toast.error(errorText(cause), `连接 ${shell.name} 失败`);
    } finally {
      setConnecting(null);
    }
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">GLOBAL DATABASE CENTER</p>
          <h1>全局数据库管理中心</h1>
        </div>
        <div className="top-actions">
          {sessions.length > 0 && (
            <select
              className="select"
              value={selectedSessionId ?? ""}
              onChange={(e) => setSelectedSessionId(e.target.value)}
              style={{ minWidth: 240 }}
            >
              {sessions.map((s) => {
                const sh = shells.find((item) => item.id === s.profileId);
                return (
                  <option key={s.sessionId} value={s.sessionId}>
                    {sh ? `${sh.name} (${sh.endpoint})` : `会话 #${s.sessionId}`}
                  </option>
                );
              })}
            </select>
          )}
          <button className="button secondary" onClick={() => void load()} title="刷新会话">
            <RefreshCw size={14} />
            刷新
          </button>
          {onNavigate && (
            <button className="button secondary" onClick={() => onNavigate({ kind: "dashboard" })}>
              返回总览
            </button>
          )}
        </div>
      </header>

      {error && <ErrorBanner message={error} />}

      {loading ? (
        <Panel eyebrow="DATABASE" title="加载中…">
          <Empty icon={<LoaderCircle className="spin" size={24} />} title="正在检索活跃会话…" />
        </Panel>
      ) : sessions.length === 0 ? (
        <Panel eyebrow="TARGET SELECTION" title="选择目标端点建立会话">
          <Empty
            icon={<Boxes size={32} />}
            title="当前暂无活跃连接的会话"
            detail="数据库管理需要通过活跃 WebShell 会话在目标主机本地代理连接目标数据库（支持 MySQL、PostgreSQL、MSSQL、Oracle、Redis、SQLite）。"
            action={
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "center", maxWidth: 600, marginTop: 12 }}>
                {shells.map((shell) => (
                  <button
                    key={shell.id}
                    className="button compact connect"
                    disabled={connecting === shell.id}
                    onClick={() => void connectAndOpen(shell)}
                  >
                    {connecting === shell.id ? (
                      <LoaderCircle className="spin" size={13} />
                    ) : (
                      <TerminalSquare size={13} />
                    )}
                    连接 {shell.name}
                  </button>
                ))}
              </div>
            }
          />
        </Panel>
      ) : (
        <div className="panel detail-panel" style={{ padding: 0 }}>
          {/* 会话快捷选择芯片 */}
          <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "10px 16px", borderBottom: "1px solid var(--border)", background: "var(--panel-2)", overflowX: "auto" }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text-faint)", textTransform: "uppercase", letterSpacing: "0.06em", marginRight: 4 }}>
              当前连接代理会话:
            </span>
            {sessions.map((s) => {
              const sh = shells.find((item) => item.id === s.profileId);
              const isActive = s.sessionId === selectedSessionId;
              return (
                <button
                  key={s.sessionId}
                  className={`file-bookmark-chip ${isActive ? "active" : ""}`}
                  style={isActive ? { borderColor: "var(--accent)", color: "var(--accent)", background: "var(--accent-soft)", fontWeight: 600 } : undefined}
                  onClick={() => setSelectedSessionId(s.sessionId)}
                >
                  <Database size={11} color={isActive ? "var(--accent)" : "var(--text-dim)"} />
                  {sh ? sh.name : s.sessionId}
                </button>
              );
            })}
          </div>

          {selectedSessionId && (
            <DatabaseManager key={selectedSessionId} sessionId={selectedSessionId} />
          )}
        </div>
      )}
    </>
  );
}
