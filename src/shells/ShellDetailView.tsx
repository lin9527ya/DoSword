import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeft, Database, FileCode2, Info, LoaderCircle, Puzzle, TerminalSquare, Unplug } from "lucide-react";
import { api, errorText, shortTime } from "../api";
import type { ConnectResult, ShellProfile } from "../api";
import { ErrorBanner } from "../components/common";
import { Terminal } from "../widgets/Terminal";
import { FileManager } from "../widgets/FileManager";
import { DatabaseManager } from "../widgets/DatabaseManager";
import { PluginPanel } from "../widgets/PluginPanel";
import type { View } from "../views/types";

type Tab = "info" | "files" | "terminal" | "database" | "plugins";

type TerminalTab = { id: number; dir: string };

/** Shell 详情页：连接信息 / 文件管理 / 命令终端 三个标签页。 */
export function ShellDetailView({
  shellId,
  initialSessionId,
  onNavigate,
}: {
  shellId: string;
  initialSessionId?: string;
  onNavigate: (view: View) => void;
}) {
  const [shell, setShell] = useState<ShellProfile | null>(null);
  const [capabilities, setCapabilities] = useState<string[] | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(initialSessionId ?? null);
  const [info, setInfo] = useState<ConnectResult | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("info");
  const [terminals, setTerminals] = useState<TerminalTab[]>([]);
  const [activeTerminal, setActiveTerminal] = useState<number | null>(null);
  const terminalSeq = useRef(0);

  // 进入详情页时自动连接（若尚未持有会话）
  const ensureConnected = useCallback(async () => {
    if (sessionId) {
      // 从总览页"测试连接"进入：会话已存在，补拉缓存的环境信息
      if (!info) {
        api
          .getSessionProbe(sessionId)
          .then((probe) => setInfo({ ...probe, sessionId }))
          .catch(() => {});
      }
      return;
    }
    setConnecting(true);
    setError("");
    try {
      const result = await api.connectShell(shellId);
      setSessionId(result.sessionId);
      setInfo(result);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setConnecting(false);
    }
  }, [shellId, sessionId, info]);

  function openTerminal(dir?: string) {
    const id = ++terminalSeq.current;
    const target = dir ?? info?.currentDir ?? "/";
    setTerminals((prev) => [...prev, { id, dir: target }]);
    setActiveTerminal(id);
  }

  function closeTerminal(id: number) {
    setTerminals((prev) => {
      const next = prev.filter((item) => item.id !== id);
      if (next.length === 0) setActiveTerminal(null);
      return next;
    });
  }

  function updateTerminalDir(id: number, dir: string) {
    setTerminals((prev) => prev.map((item) => (item.id === id ? { ...item, dir } : item)));
  }

  useEffect(() => {
    if (sessionId && terminals.length === 0) openTerminal();
  }, [sessionId]);

  useEffect(() => {
    void api
      .dashboard()
      .then((data) => {
        const profile = data.shells.find((item) => item.id === shellId);
        if (!profile) return;
        setShell(profile);
        void api
          .listProtocols()
          .then((protocols) => {
            const meta = protocols.find((item) => item.id === profile.protocolId);
            setCapabilities(meta?.capabilities ?? null);
          })
          .catch(() => {});
      })
      .catch((cause) => setError(errorText(cause)));
    void ensureConnected();
  }, [shellId, ensureConnected]);

  async function disconnect() {
    if (!sessionId) return;
    setError("");
    try {
      await api.disconnectShell(sessionId);
      setSessionId(null);
      setInfo(null);
      setTerminals([]);
      setActiveTerminal(null);
    } catch (cause) {
      setError(errorText(cause));
    }
  }

  if (!shell) {
    return (
      <header className="topbar">
        <div>
          <p className="eyebrow">Shell 详情</p>
          <h1>{error || "正在加载…"}</h1>
        </div>
      </header>
    );
  }

  /** 能力检查：capabilities 未加载或为空列表视为全支持（SDK 语义）。 */
  const supports = (capability: string) =>
    capabilities === null || capabilities.length === 0 || capabilities.includes(capability);

  const tabs: { key: Tab; label: string; icon: React.ReactNode }[] = [
    { key: "info", label: "连接信息", icon: <Info size={15} /> },
    ...(supports("files")
      ? [{ key: "files" as Tab, label: "文件管理", icon: <FileCode2 size={15} /> }]
      : []),
    ...(supports("database")
      ? [{ key: "database" as Tab, label: "数据库", icon: <Database size={15} /> }]
      : []),
    ...(supports("terminal")
      ? [{ key: "terminal" as Tab, label: "终端", icon: <TerminalSquare size={15} /> }]
      : []),
    { key: "plugins", label: "插件", icon: <Puzzle size={15} /> },
  ];

  return (
    <>
      <header className="topbar detail-topbar">
        <div className="detail-heading">
          <button className="icon-button" onClick={() => onNavigate({ kind: "dashboard" })} title="返回总览">
            <ArrowLeft size={17} />
          </button>
          <div>
            <p className="eyebrow">Shell 详情</p>
            <h1>{shell.name}</h1>
          </div>
          <span className={`status-dot ${sessionId ? "online" : shell.status}`} />
          <code className="detail-endpoint">{shell.endpoint}</code>
        </div>
        <div className="top-actions">
          {sessionId ? (
            <button className="button secondary" onClick={() => void disconnect()}>
              <Unplug size={16} />
              断开
            </button>
          ) : (
            <button className="button primary" onClick={() => void ensureConnected()} disabled={connecting}>
              {connecting ? <LoaderCircle className="spin" size={16} /> : <TerminalSquare size={16} />}
              {connecting ? "连接中…" : "连接"}
            </button>
          )}
        </div>
      </header>
      {error && <ErrorBanner message={error} />}

      <div className="detail-tabs">
        {tabs.map((item) => (
          <button
            key={item.key}
            className={`detail-tab ${tab === item.key ? "active" : ""}`}
            onClick={() => setTab(item.key)}
          >
            {item.icon}
            {item.label}
          </button>
        ))}
      </div>

      {tab === "info" && <InfoPanel shell={shell} info={info} sessionId={sessionId} />}
      {sessionId ? (
        <>
          <div className={`detail-tabpane ${tab === "files" ? "" : "hidden"}`}>
            <div className="panel detail-panel">
              <FileManager
                sessionId={sessionId}
                startDir={info?.currentDir ?? "/"}
                separator={info?.separator ?? "/"}
              />
            </div>
          </div>
          <div className={`detail-tabpane ${tab === "database" ? "" : "hidden"}`}>
            <div className="panel detail-panel">
              <DatabaseManager sessionId={sessionId} />
            </div>
          </div>
          <div className={`detail-tabpane ${tab === "plugins" ? "" : "hidden"}`}>
            <PluginPanel sessionId={sessionId} />
          </div>
          <div className={`detail-tabpane ${tab === "terminal" ? "" : "hidden"}`}>
            <div className="panel detail-panel terminal-panel">
              <div className="terminal-tabs">
                {terminals.map((terminal) => (
                  <button
                    key={terminal.id}
                    className={`terminal-tab ${activeTerminal === terminal.id ? "active" : ""}`}
                    onClick={() => setActiveTerminal(terminal.id)}
                  >
                    <span className="terminal-tab-dir">{terminal.dir}</span>
                    <span
                      className="terminal-tab-close"
                      role="button"
                      title="关闭终端"
                      onClick={(event) => {
                        event.stopPropagation();
                        closeTerminal(terminal.id);
                      }}
                    >
                      ×
                    </span>
                  </button>
                ))}
                <button className="terminal-tab add" title="新建终端" onClick={() => openTerminal()}>
                  +
                </button>
              </div>
              {terminals.map((terminal) => (
                <div
                  key={terminal.id}
                  className={`detail-tabpane ${activeTerminal === terminal.id ? "" : "hidden"}`}
                >
                  <Terminal
                    sessionId={sessionId}
                    currentDir={terminal.dir}
                    active={activeTerminal === terminal.id}
                    onCwdChange={(cwd) => updateTerminalDir(terminal.id, cwd)}
                  />
                </div>
              ))}
            </div>
          </div>
        </>
      ) : (
        <p className="panel-note">连接成功后才能使用文件管理 / 数据库 / 插件 / 终端。</p>
      )}
    </>
  );
}

function InfoPanel({
  shell,
  info,
  sessionId,
}: {
  shell: ShellProfile;
  info: ConnectResult | null;
  sessionId: string | null;
}) {
  const rows: [string, string][] = [
    ["端点", shell.endpoint],
    ["协议", shell.protocolId],
    ["运行时", shell.runtime.toUpperCase()],
    ["授权确认", shell.authorizationAck ? "已确认（创建时勾选）" : "未确认（Mock 协议）"],
    ["最近连接", shortTime(shell.lastConnectedAt)],
  ];
  if (info) {
    rows.push(["会话 ID", info.sessionId]);
    rows.push(["服务器", info.server]);
    rows.push(["系统架构", info.arch || "—"]);
    rows.push(["Web 服务", info.webServer]);
    rows.push(["PHP 版本", info.runtime]);
    rows.push(["SAPI", info.phpSapi || "—"]);
    rows.push(["当前目录", info.currentDir]);
    rows.push(["路径分隔符", info.separator]);
    if (info.extensions && info.extensions.length > 0) {
      rows.push(["已加载扩展", info.extensions.join(", ")]);
    }
    rows.push(["禁用函数", info.disableFunctions || "—"]);
  }
  const infoEntries = info ? Object.entries(info.info ?? {}) : [];
  return (
    <div className="panel detail-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">环境信息</p>
          <h2>环境信息</h2>
        </div>
        <span className={`status-badge ${sessionId ? "online" : ""}`}>
          {sessionId ? "已连接" : "未连接"}
        </span>
      </div>
      <div className="info-grid">
        {rows.map(([label, value]) => (
          <div className="info-row" key={label}>
            <span>{label}</span>
            <code>{value}</code>
          </div>
        ))}
      </div>
      {infoEntries.length > 0 && (
        <div className="osinfo-block">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">环境详情</p>
              <h2>环境详情（OsInfo）</h2>
            </div>
          </div>
          <div className="osinfo-grid">
            {infoEntries.map(([key, value]) => (
              <div className="osinfo-row" key={key}>
                <span>{key}</span>
                <code>{value || "—"}</code>
              </div>
            ))}
          </div>
        </div>
      )}
      <p className="muted">{info?.message}</p>
    </div>
  );
}
