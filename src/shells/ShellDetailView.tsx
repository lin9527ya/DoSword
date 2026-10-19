import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  BookOpen,
  Database,
  FileCode2,
  Info,
  LoaderCircle,
  Puzzle,
  Search,
  ShieldOff,
  TerminalSquare,
  Unplug,
} from "lucide-react";
import { api, errorText, shortTime } from "../api";
import type { ConnectResult, ShellProfile } from "../api";
import { ErrorBanner } from "../components/common";
import { Terminal } from "../widgets/Terminal";
import { FileManager } from "../widgets/FileManager";
import { DatabaseManager } from "../widgets/DatabaseManager";
import { PluginPanel } from "../widgets/PluginPanel";
import { NotesPanel } from "../widgets/NotesPanel";
import { MemshellPanel } from "../widgets/MemshellPanel";
import { ForwardTerminal } from "../widgets/ForwardTerminal";
import { NativePtyTerminal } from "../widgets/NativePtyTerminal";
import { useToast } from "../components/Toast";
import type { View } from "../views/types";

type Tab = "info" | "files" | "terminal" | "database" | "notes" | "plugins" | "memshell";
type TerminalTab = { id: number; dir: string };

export function ShellDetailView({
  shellId,
  initialSessionId,
  onNavigate,
}: {
  shellId: string;
  initialSessionId?: string;
  onNavigate: (view: View) => void;
}) {
  const toast = useToast();
  const [shell, setShell] = useState<ShellProfile | null>(null);
  const [capabilities, setCapabilities] = useState<string[] | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(initialSessionId ?? null);
  const [terminalMode, setTerminalMode] = useState<"command" | "forward" | "native">("command");
  const [info, setInfo] = useState<ConnectResult | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>("info");
  const [terminals, setTerminals] = useState<TerminalTab[]>([]);
  const [activeTerminal, setActiveTerminal] = useState<number | null>(null);
  const terminalSeq = useRef(0);

  const ensureConnected = useCallback(async () => {
    if (sessionId) {
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
      toast.success(`已连接 ${result.server} · ${result.runtime}`, "会话建立成功");
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "连接目标失败");
    } finally {
      setConnecting(false);
    }
  }, [shellId, sessionId, info, toast]);

  const openTerminal = useCallback(
    (dir?: string) => {
      const id = ++terminalSeq.current;
      const target = dir ?? info?.currentDir ?? "/";
      setTerminals((prev) => [...prev, { id, dir: target }]);
      setActiveTerminal(id);
    },
    [info?.currentDir],
  );

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

  // 建立会话后自动开一个终端；依赖 terminals.length，
  // 否则手动关掉全部终端后不会再自动打开（此前缺该依赖）
  useEffect(() => {
    if (sessionId && terminals.length === 0) openTerminal();
  }, [sessionId, terminals.length, openTerminal]);

  // 拉取 Shell 档案与协议能力：只依赖 shellId。
  // 此前依赖 ensureConnected（随 sessionId/info 变化），导致每次会话状态更新
  // 都重新拉一次 dashboard + listProtocols（打开一个 Shell 会发 3 次 dashboard）。
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
  }, [shellId]);

  useEffect(() => {
    void ensureConnected();
  }, [ensureConnected]);

  async function disconnect() {
    if (!sessionId) return;
    try {
      await api.disconnectShell(sessionId);
      setSessionId(null);
      setInfo(null);
      setTerminals([]);
      setActiveTerminal(null);
      toast.info("已安全断开远程会话", "会话已断开");
    } catch (cause) {
      toast.error(errorText(cause), "断开失败");
    }
  }

  if (!shell) {
    return (
      <header className="topbar">
        <div>
          <p className="eyebrow">SHELL DETAIL</p>
          <h1>{error || "正在加载 Shell 配置…"}</h1>
        </div>
      </header>
    );
  }

  const supports = (capability: string) =>
    capabilities === null || capabilities.length === 0 || capabilities.includes(capability);

  const tabs: { key: Tab; label: string; icon: React.ReactNode }[] = [
    { key: "info", label: "基本环境", icon: <Info size={15} /> },
    ...(supports("files")
      ? [{ key: "files" as Tab, label: "文件管理", icon: <FileCode2 size={15} /> }]
      : []),
    ...(supports("database")
      ? [{ key: "database" as Tab, label: "数据库", icon: <Database size={15} /> }]
      : []),
    ...(supports("terminal")
      ? [{ key: "terminal" as Tab, label: "终端执行", icon: <TerminalSquare size={15} /> }]
      : []),
    { key: "notes", label: "操作笔记", icon: <BookOpen size={15} /> },
    // 内存马目前仅实现 PHP（Java 需先给 JSP 协议补 run_code 通道）
    ...(!shell.runtime || shell.runtime === "php"
      ? [{ key: "memshell" as Tab, label: "内存马", icon: <ShieldOff size={15} /> }]
      : []),
    { key: "plugins", label: "功能插件", icon: <Puzzle size={15} /> },
  ];

  return (
    <>
      <header className="topbar detail-topbar">
        <div className="detail-heading">
          <button
            className="icon-button"
            onClick={() => onNavigate({ kind: "dashboard" })}
            title="返回工作区总览"
          >
            <ArrowLeft size={16} />
          </button>
          <div>
            <p className="eyebrow">WORKSPACE / SHELL INSPECTOR</p>
            <h1>{shell.name}</h1>
          </div>
          <span className={`status-dot ${sessionId ? "online" : shell.status}`} />
          <code className="detail-endpoint">{shell.endpoint}</code>
        </div>
        <div className="top-actions">
          {sessionId ? (
            <button className="button danger compact" onClick={() => void disconnect()}>
              <Unplug size={14} />
              断开连接
            </button>
          ) : (
            <button
              className="button primary"
              onClick={() => void ensureConnected()}
              disabled={connecting}
            >
              {connecting ? <LoaderCircle className="spin" size={15} /> : <TerminalSquare size={15} />}
              {connecting ? "连接中…" : "立即连接"}
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

      {tab === "info" && (
        <InfoPanel
          shell={shell}
          info={info}
          sessionId={sessionId}
        />
      )}

      <div className={`detail-tabpane ${tab === "notes" ? "" : "hidden"}`}>
        <NotesPanel
          sessionId={sessionId ?? undefined}
          shellId={shell.id}
          shellName={shell.name}
        />
      </div>

      <div className={`detail-tabpane ${tab === "memshell" ? "" : "hidden"}`}>
        <MemshellPanel
          sessionId={sessionId}
          shellId={shell.id}
          endpoint={shell.endpoint}
          documentRoot={info?.info?.DOCUMENT_ROOT ?? info?.info?.FileRoot}
        />
      </div>

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
            <div style={{ display: "flex", gap: 6, padding: "0 0 8px", flexWrap: "wrap" }}>
              {[
                { key: "command", label: "命令终端" },
                { key: "forward", label: "交互式（HTTP 隧道）" },
                { key: "native", label: "本地 PTY（反弹接收）" },
              ].map((item) => (
                <button
                  key={item.key}
                  className={`button compact ${terminalMode === item.key ? "primary" : "secondary"}`}
                  onClick={() => setTerminalMode(item.key as typeof terminalMode)}
                >
                  {item.label}
                </button>
              ))}
            </div>
            {terminalMode === "forward" ? (
              <ForwardTerminal sessionId={sessionId} active={tab === "terminal"} />
            ) : terminalMode === "native" ? (
              <NativePtyTerminal sessionId={sessionId} active={tab === "terminal"} />
            ) : (
            <div className="panel detail-panel terminal-panel">
              <div className="terminal-tabs">
                {terminals.map((terminal) => (
                  <button
                    key={terminal.id}
                    className={`terminal-tab ${activeTerminal === terminal.id ? "active" : ""}`}
                    onClick={() => setActiveTerminal(terminal.id)}
                  >
                    <span>终端 #{terminal.id} ({terminal.dir})</span>
                    <span
                      className="terminal-tab-close"
                      role="button"
                      title="关闭该终端"
                      onClick={(event) => {
                        event.stopPropagation();
                        closeTerminal(terminal.id);
                      }}
                    >
                      ×
                    </span>
                  </button>
                ))}
                <button
                  className="terminal-tab add"
                  title="新建终端窗口"
                  onClick={() => openTerminal()}
                >
                  + 新建
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
                    active={activeTerminal === terminal.id && tab === "terminal"}
                    onCwdChange={(cwd) => updateTerminalDir(terminal.id, cwd)}
                  />
                </div>
              ))}
            </div>
            )}
          </div>
        </>
      ) : tab !== "info" ? (
        <div className="panel detail-panel" style={{ padding: "40px 20px" }}>
          <div className="empty-state">
            <Unplug size={32} />
            <strong>尚未建立远程会话</strong>
            <p>点击右上角「立即连接」建立安全通信会话后方可使用该模块。</p>
            <button className="button primary" onClick={() => void ensureConnected()}>
              连接目标
            </button>
          </div>
        </div>
      ) : null}
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
  const toast = useToast();
  const [search, setSearch] = useState("");

  const copy = (val: string, label: string) => {
    void navigator.clipboard.writeText(val);
    toast.info(`已复制 ${label}`);
  };

  const infoEntries: [string, string | undefined][] = useMemo(() => {
    if (!info?.info) return [];
    return Object.entries(info.info).sort(([a], [b]) => a.localeCompare(b));
  }, [info]);

  const filteredEntries: [string, string | undefined][] = useMemo(() => {
    if (!search.trim()) return infoEntries;
    const q = search.toLowerCase();
    return infoEntries.filter(
      ([k, v]) =>
        k.toLowerCase().includes(q) ||
        (v ?? "").toLowerCase().includes(q),
    );
  }, [infoEntries, search]);

  const sortedExtensions: string[] = useMemo(() => {
    if (!info?.extensions) return [];
    return [...info.extensions].sort((a, b) => a.localeCompare(b));
  }, [info]);

  return (
    <div className="panel detail-panel" style={{ overflowY: "auto", flex: 1, minHeight: 0 }}>
      <div className="panel-heading">
        <div className="panel-heading-title">
          <p className="eyebrow">ENVIRONMENT TELEMETRY</p>
          <h2>目标环境探测信息</h2>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className={`status-badge ${sessionId ? "online" : ""}`}>
            {sessionId ? "● 已连接活跃" : "○ 未连接"}
          </span>
        </div>
      </div>

      <div className="info-grid">
        <div className="info-card">
          <span>端点 URL</span>
          <code onClick={() => copy(shell.endpoint, "端点 URL")} style={{ cursor: "pointer" }}>
            {shell.endpoint}
          </code>
        </div>
        <div className="info-card">
          <span>协议与运行时</span>
          <code>{shell.protocolId} · {shell.runtime.toUpperCase()}</code>
        </div>
        <div className="info-card">
          <span>授权状态</span>
          <code>{shell.authorizationAck ? "已在创建时完成授权确认" : "本地安全 Mock 沙箱"}</code>
        </div>
        <div className="info-card">
          <span>最近会话时间</span>
          <code>{shortTime(shell.lastConnectedAt)}</code>
        </div>
        {info && (
          <>
            <div className="info-card">
              <span>系统核心与架构</span>
              <code>{info.server} ({info.arch || "x86_64"})</code>
            </div>
            <div className="info-card">
              <span>Web 服务容器</span>
              <code>{info.webServer}</code>
            </div>
            <div className="info-card">
              <span>PHP / 语言版本</span>
              <code>{info.runtime} (SAPI: {info.phpSapi || "standard"})</code>
            </div>
            <div className="info-card">
              <span>工作根目录</span>
              <code>{info.currentDir} (分隔符: {info.separator})</code>
            </div>
            <div className="info-card">
              <span>目标能力（stub 自报）</span>
              {info.capabilities ? (
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                  <code style={{ marginRight: 4 }}>v{info.capabilities.protoVersion}</code>
                  <code style={{ marginRight: 4 }}>{info.capabilities.shellType}</code>
                  {info.capabilities.capabilities.length === 0 && (
                    <span style={{ fontSize: 12, color: "var(--muted)" }}>未声明能力位</span>
                  )}
                  {info.capabilities.capabilities.map((capability) => (
                    <span key={capability} className="tag-badge">
                      {capability}
                    </span>
                  ))}
                </div>
              ) : (
                <span style={{ fontSize: 12, color: "var(--muted)" }}>
                  旧 stub（协议 v1）：未上报能力。用当前版本重新生成并上传 stub 可获得
                  分块读写、数据库与非只读 SQL 的精确门禁。
                </span>
              )}
            </div>
          </>
        )}
      </div>

      {info?.disableFunctions && (
        <div style={{ padding: "0 22px 16px" }}>
          <span className="eyebrow" style={{ display: "block", marginBottom: 6 }}>
            禁用函数 (disable_functions)
          </span>
          <pre
            style={{
              background: "var(--code-bg)",
              padding: "10px 14px",
              borderRadius: "var(--radius-md)",
              border: "1px solid var(--border)",
              fontFamily: "var(--font-mono)",
              fontSize: 11.5,
              color: "var(--err)",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              maxHeight: 120,
              overflow: "auto",
            }}
          >
            {info.disableFunctions}
          </pre>
        </div>
      )}

      {sortedExtensions.length > 0 && (
        <div style={{ padding: "0 22px 16px" }}>
          <span className="eyebrow" style={{ display: "block", marginBottom: 6 }}>
            已加载扩展模块 ({sortedExtensions.length})
          </span>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
            {sortedExtensions.map((ext) => (
              <span key={ext} className="shell-tag">
                {ext}
              </span>
            ))}
          </div>
        </div>
      )}

      {infoEntries.length > 0 && (
        <div className="osinfo-block">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
            <span className="eyebrow">全量环境详情 (OsInfo 探针 · 按字母排序)</span>
            <label className="search" style={{ height: 28, width: 220 }}>
              <Search size={13} />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="快速筛选环境参数…"
                style={{ fontSize: 11.5 }}
              />
            </label>
          </div>
          <div className="osinfo-grid">
            {filteredEntries.map(([key, value]) => (
              <div className="osinfo-row" key={key}>
                <span>{key}</span>
                <code onClick={() => copy(String(value || ""), key)} style={{ cursor: "pointer" }}>
                  {value || "—"}
                </code>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
