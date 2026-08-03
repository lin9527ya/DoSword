import { useCallback, useEffect, useState } from "react";
import { LoaderCircle, TerminalSquare, Unplug } from "lucide-react";
import { api, errorText, shortTime } from "../api";
import type { SessionInfo } from "../api";
import { Empty, ErrorBanner } from "../components/common";
import { Panel } from "../components/common";
import type { View } from "./types";

export function SessionsView({ onNavigate }: { onNavigate: (view: View) => void }) {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setSessions(await api.listSessions());
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function disconnect(sessionId: string) {
    setError("");
    try {
      await api.disconnectShell(sessionId);
      await load();
    } catch (cause) {
      setError(errorText(cause));
    }
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">ACTIVE CONNECTIONS</p>
          <h1>终端会话</h1>
        </div>
      </header>
      {error && <ErrorBanner message={error} />}
      <Panel eyebrow="SESSION LIST" title="活跃会话">
        {loading ? (
          <Empty icon={<LoaderCircle className="spin" />} title="正在读取会话" />
        ) : sessions.length === 0 ? (
          <Empty icon={<TerminalSquare />} title="暂无活跃会话" detail="在总览中连接 Shell 后会出现在这里。" />
        ) : (
          <div className="shell-list">
            {sessions.map((session) => (
              <article className="shell-row" key={session.sessionId}>
                <div className="status-dot online" />
                <div className="shell-identity">
                  <strong>会话 {session.sessionId}</strong>
                  <span>{session.server}</span>
                </div>
                <code>ACTIVE</code>
                <div className="last-seen">
                  <span>最后使用</span>
                  <small>{shortTime(new Date(session.lastUsedAt * 1000).toISOString())}</small>
                </div>
                <button
                  className="icon-button"
                  title="打开会话"
                  onClick={() =>
                    onNavigate({ kind: "shell", shellId: session.profileId, sessionId: session.sessionId })
                  }
                >
                  <TerminalSquare size={16} />
                </button>
                <button
                  className="icon-button danger"
                  title="断开"
                  onClick={() => void disconnect(session.sessionId)}
                >
                  <Unplug size={16} />
                </button>
              </article>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}
