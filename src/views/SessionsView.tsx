import { useCallback, useEffect } from "react";
import {
  ExternalLink,
  LoaderCircle,
  RefreshCw,
  TerminalSquare,
  Unplug,
} from "lucide-react";
import { api, errorText, shortTime } from "../api";
import type { SessionInfo } from "../api";
import { Empty, ErrorBanner, Panel } from "../components/common";
import { useToast } from "../components/Toast";
import { useAsync } from "../hooks/useAsync";
import type { View } from "./types";

/** 空列表常量：保持引用稳定，避免每次渲染都造新数组 */
const EMPTY_SESSIONS: SessionInfo[] = [];

export function SessionsView({ onNavigate }: { onNavigate: (view: View) => void }) {
  const toast = useToast();
  // loading / error / 乱序响应交给 useAsync（加载器是「取一份数据 → 设一个主状态」）；
  // 心跳会改这份数据，故把 setData 取出来复用
  const {
    data,
    setData: setSessions,
    loading,
    error,
    reload: load,
  } = useAsync(() => api.listSessions(), {
    onError: (message) => toast.error(message, "读取会话失败"),
  });
  const sessions = data ?? EMPTY_SESSIONS;

  // W4 心跳：空闲时每 45s 探活一次，失败只更新 stale 状态（不打断页面）
  const heartbeat = useCallback(async () => {
    try {
      setSessions(await api.heartbeatSessions());
    } catch {
      // 会话可能已被清理：保留现有列表，下次手动刷新
    }
  }, [setSessions]);

  useEffect(() => {
    const timer = window.setInterval(() => void heartbeat(), 45_000);
    return () => window.clearInterval(timer);
  }, [heartbeat]);

  async function disconnect(sessionId: string) {
    try {
      await api.disconnectShell(sessionId);
      toast.info(`会话 ${sessionId} 已安全断开`, "已断开连接");
      await load();
    } catch (cause) {
      toast.error(errorText(cause), "断开失败");
    }
  }

  async function disconnectAll() {
    for (const session of sessions) {
      try {
        await api.disconnectShell(session.sessionId);
      } catch {
        // 忽略
      }
    }
    toast.info("已断开所有活跃会话", "批量断开");
    await load();
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">ACTIVE SESSIONS</p>
          <h1>终端活跃会话</h1>
        </div>
        <div className="top-actions">
          <button className="button secondary" onClick={() => void load()}>
            <RefreshCw size={14} />
            刷新
          </button>
          {sessions.length > 0 && (
            <button className="button danger" onClick={() => void disconnectAll()}>
              <Unplug size={14} />
              断开全部
            </button>
          )}
        </div>
      </header>

      {error && <ErrorBanner message={error} />}

      <Panel
        eyebrow="SESSION REGISTRY"
        title={`活跃会话 (${sessions.length})`}
      >
        {loading ? (
          <Empty icon={<LoaderCircle className="spin" size={24} />} title="正在检索活跃会话…" />
        ) : sessions.length === 0 ? (
          <Empty
            icon={<TerminalSquare size={28} />}
            title="暂无活跃终端会话"
            detail="在总览列表中点击「连接」建立会话后，将在此持久保持并可快速切换。"
            action={
              <button className="button primary compact" onClick={() => onNavigate({ kind: "dashboard" })}>
                前往环境总览
              </button>
            }
          />
        ) : (
          <div className="shell-list">
            {sessions.map((session) => (
              <article className="shell-row" key={session.sessionId} style={{ gridTemplateColumns: "10px minmax(220px, 1fr) 90px 140px 100px 76px" }}>
                <div className={`status-dot ${session.stale ? "error" : "online"}`} />
                <div className="shell-identity">
                  <strong>会话 #{session.sessionId}</strong>
                  <span>{session.server || "目标服务器已连接"}</span>
                </div>
                <span
                  className={`runtime-badge ${session.stale ? "stale" : "php"}`}
                  title={
                    session.lastHeartbeatAt > 0
                      ? `最后心跳：${shortTime(new Date(session.lastHeartbeatAt * 1000).toISOString())}`
                      : "尚未心跳"
                  }
                >
                  {session.stale ? "STALE" : "ACTIVE"}
                </span>
                <div className="last-seen">
                  <span>最后交互</span>
                  <small>{shortTime(new Date(session.lastUsedAt * 1000).toISOString())}</small>
                </div>
                <button
                  className="button compact connect"
                  onClick={() =>
                    onNavigate({ kind: "shell", shellId: session.profileId, sessionId: session.sessionId })
                  }
                >
                  <ExternalLink size={13} />
                  进入会话
                </button>
                <button
                  className="icon-button danger"
                  title="断开会话"
                  onClick={() => void disconnect(session.sessionId)}
                >
                  <Unplug size={15} />
                </button>
              </article>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}
