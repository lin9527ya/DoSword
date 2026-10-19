import { useCallback, useEffect, useState } from "react";
import {
  FileCode2,
  LoaderCircle,
  RefreshCw,
  Send,
  TerminalSquare,
  Upload,
} from "lucide-react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText, formatSize } from "../api";
import type { SessionInfo, ShellProfile } from "../api";
import { Empty, ErrorBanner, Panel } from "../components/common";
import { FileManager } from "../widgets/FileManager";
import { useToast } from "../components/Toast";
import type { View } from "./types";

export function GlobalFilesView({ onNavigate }: { onNavigate?: (view: View) => void }) {
  const toast = useToast();
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [shells, setShells] = useState<ShellProfile[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [currentDir, setCurrentDir] = useState("/");
  const [separator, setSeparator] = useState("/");
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState<string | null>(null);
  const [error, setError] = useState("");
  // 多目录概览（batch_list_dir：单会话多目录一次拉取）
  const [overview, setOverview] = useState<
    Array<{ path: string; count: number | null; error?: string }> | null
  >(null);
  const [overviewLoading, setOverviewLoading] = useState(false);

  // 批量分发/上传状态
  const [batchModal, setBatchModal] = useState(false);
  const [batchTargetDir, setBatchTargetDir] = useState("/tmp");
  const [batchFile, setBatchFile] = useState<{ path: string; name: string; size: number; contentB64: string } | null>(null);
  const [batchTargets, setBatchTargets] = useState<string[]>([]);
  const [batchProgress, setBatchProgress] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [sessionList, dash] = await Promise.all([
        api.listSessions(),
        api.dashboard(),
      ]);
      setSessions(sessionList);
      setShells(dash.shells);

      if (sessionList.length > 0) {
        const active = sessionList[0];
        setSelectedSessionId((prev) => (prev && sessionList.some((s) => s.sessionId === prev) ? prev : active.sessionId));
        try {
          const probe = await api.getSessionProbe(active.sessionId);
          setCurrentDir(probe.currentDir || "/");
          setSeparator(probe.separator || "/");
        } catch {
          // 忽略 probe 失败
        }
      } else {
        setSelectedSessionId(null);
      }
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "加载会话列表失败");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  async function loadOverview() {
    if (!selectedSessionId) return;
    const windows = separator === "\\" || /^[A-Za-z]:/.test(currentDir);
    const paths = windows
      ? ["C:\\inetpub\\wwwroot", "C:\\Windows\\Temp", "C:\\Users", "C:\\"]
      : ["/var/www/html", "/tmp", "/etc", "/home", "/root", "/var/log"];
    setOverviewLoading(true);
    try {
      const result = await api.batchListDir(selectedSessionId, paths);
      setOverview(
        paths.map((path) => {
          const item = result[path] as { entries?: unknown[]; error?: string } | undefined;
          if (!item) return { path, count: null, error: "无返回" };
          if (item.error) return { path, count: null, error: item.error };
          return { path, count: item.entries?.length ?? 0 };
        }),
      );
    } catch (cause) {
      toast.error(errorText(cause), "多目录概览失败");
    } finally {
      setOverviewLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, [load]);

  async function switchSession(sessionId: string) {
    setSelectedSessionId(sessionId);
    try {
      const probe = await api.getSessionProbe(sessionId);
      setCurrentDir(probe.currentDir || "/");
      setSeparator(probe.separator || "/");
    } catch {
      // 忽略
    }
  }

  async function connectAndOpen(shell: ShellProfile) {
    setConnecting(shell.id);
    try {
      const res = await api.connectShell(shell.id);
      toast.success(`已建立会话 · ${shell.name}`, "连接成功");
      await load();
      setSelectedSessionId(res.sessionId);
      setCurrentDir(res.currentDir || "/");
      setSeparator(res.separator || "/");
    } catch (cause) {
      toast.error(errorText(cause), `连接 ${shell.name} 失败`);
    } finally {
      setConnecting(null);
    }
  }

  async function selectLocalFile() {
    try {
      const localPath = await open({ multiple: false });
      if (!localPath || Array.isArray(localPath)) return;
      const pathStr = String(localPath);
      const name = pathStr.split(/[\\/]/).pop() ?? "file";
      const contentB64 = await api.readLocalFile(pathStr);
      const bytes = b64.decodeBytes(contentB64);
      setBatchFile({ path: pathStr, name, size: bytes.length, contentB64 });
      setBatchTargets(sessions.map((s) => s.sessionId));
      setBatchModal(true);
    } catch (cause) {
      toast.error(`读取本地文件失败：${errorText(cause)}`);
    }
  }

  async function executeBatchUpload() {
    if (!batchFile || batchTargets.length === 0) {
      toast.warning("请选择要分发的文件与至少一个目标会话");
      return;
    }
    setBatchProgress("正在分发中…");
    let success = 0;
    let failed = 0;

    for (const sid of batchTargets) {
      const session = sessions.find((s) => s.sessionId === sid);
      const sep = separator || "/";
      const dest = batchTargetDir.endsWith(sep)
        ? `${batchTargetDir}${batchFile.name}`
        : `${batchTargetDir}${sep}${batchFile.name}`;
      try {
        await api.writeFile(sid, dest, batchFile.contentB64);
        success++;
      } catch (e) {
        failed++;
        toast.warning(`向会话 ${session?.server || sid} 分发失败：${errorText(e)}`);
      }
    }

    setBatchProgress(null);
    setBatchModal(false);
    toast.success(`分发完成：成功 ${success} 个节点，失败 ${failed} 个节点`, "批量上传完成");
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">GLOBAL FILE MANAGER</p>
          <h1>批量与全局文件管理</h1>
        </div>
        <div className="top-actions">
          {sessions.length > 0 && (
            <select
              className="select"
              value={selectedSessionId ?? ""}
              onChange={(e) => void switchSession(e.target.value)}
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

          <button
            className="button secondary"
            onClick={() => void selectLocalFile()}
            disabled={sessions.length === 0}
            title="选择本地文件并批量分发到多个已连接的 WebShell 节点"
          >
            <Upload size={14} />
            批量分发文件
          </button>
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
        <Panel eyebrow="FILES" title="加载中…">
          <Empty icon={<LoaderCircle className="spin" size={24} />} title="正在检索活跃会话…" />
        </Panel>
      ) : sessions.length === 0 ? (
        <Panel eyebrow="TARGET SELECTION" title="选择目标端点建立会话">
          <Empty
            icon={<FileCode2 size={32} />}
            title="当前暂无活跃连接的会话"
            detail="请选择下方已登记的 Shell 进行一键连接，或前往总览添加新的目标端点。"
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
              当前目标:
            </span>
            {sessions.map((s) => {
              const sh = shells.find((item) => item.id === s.profileId);
              const isActive = s.sessionId === selectedSessionId;
              return (
                <button
                  key={s.sessionId}
                  className={`file-bookmark-chip ${isActive ? "active" : ""}`}
                  style={isActive ? { borderColor: "var(--accent)", color: "var(--accent)", background: "var(--accent-soft)", fontWeight: 600 } : undefined}
                  onClick={() => void switchSession(s.sessionId)}
                >
                  <span className={`dot ${isActive ? "online" : "offline"}`} style={{ width: 6, height: 6 }} />
                  {sh ? sh.name : s.sessionId}
                </button>
              );
            })}
            <button
              className="button compact secondary"
              style={{ marginLeft: "auto", flexShrink: 0 }}
              onClick={() => void loadOverview()}
              disabled={overviewLoading || !selectedSessionId}
              title="一次拉取多个常用目录（batch_list_dir）"
            >
              {overviewLoading ? (
                <LoaderCircle className="spin" size={12} />
              ) : (
                <FileCode2 size={12} />
              )}
              多目录概览
            </button>
          </div>

          {overview && (
            <div
              style={{
                display: "flex",
                gap: 6,
                flexWrap: "wrap",
                padding: "8px 16px",
                borderBottom: "1px solid var(--border)",
              }}
            >
              {overview.map((item) => (
                <button
                  key={item.path}
                  className="file-bookmark-chip"
                  title={item.error ?? `${item.count ?? 0} 项`}
                  onClick={() => setCurrentDir(item.path)}
                >
                  <code style={{ fontSize: 11 }}>{item.path}</code>
                  <span style={{ marginLeft: 6, opacity: 0.7 }}>
                    {item.error ? "×" : (item.count ?? 0)}
                  </span>
                </button>
              ))}
            </div>
          )}

          {selectedSessionId && (
            <FileManager
              key={`${selectedSessionId}:${currentDir}`}
              sessionId={selectedSessionId}
              startDir={currentDir}
              separator={separator}
            />
          )}
        </div>
      )}

      {/* 批量文件分发 Modal */}
      {batchModal && batchFile && (
        <div className="dialog-backdrop" onClick={() => setBatchModal(false)} role="dialog">
          <div className="dialog" onClick={(e) => e.stopPropagation()}>
            <div className="dialog-title">
              <h2>批量分发文件至多个目标</h2>
              <button className="icon-button" onClick={() => setBatchModal(false)}>
                ×
              </button>
            </div>
            <div className="dialog-form">
              <div className="info-row">
                <span>本地待分发文件</span>
                <code>{batchFile.name} ({formatSize(batchFile.size)})</code>
              </div>

              <label>
                目标服务器存放目录
                <input
                  value={batchTargetDir}
                  onChange={(e) => setBatchTargetDir(e.target.value)}
                  placeholder="/tmp 或 /var/www/html"
                  spellCheck={false}
                />
              </label>

              <label>
                选择分发目标节点 ({batchTargets.length} / {sessions.length})
                <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 160, overflowY: "auto", padding: 8, background: "var(--input-bg)", borderRadius: "var(--radius-md)", border: "1px solid var(--border)" }}>
                  {sessions.map((s) => {
                    const sh = shells.find((item) => item.id === s.profileId);
                    const isChecked = batchTargets.includes(s.sessionId);
                    return (
                      <label key={s.sessionId} className="confirm-row" style={{ fontSize: 12 }}>
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={() => {
                            if (isChecked) setBatchTargets(batchTargets.filter((id) => id !== s.sessionId));
                            else setBatchTargets([...batchTargets, s.sessionId]);
                          }}
                        />
                        <span>{sh ? `${sh.name} (${sh.endpoint})` : `会话 #${s.sessionId}`}</span>
                      </label>
                    );
                  })}
                </div>
              </label>

              <div className="dialog-actions">
                <button className="button secondary" onClick={() => setBatchModal(false)}>
                  取消
                </button>
                <button
                  className="button primary"
                  onClick={() => void executeBatchUpload()}
                  disabled={batchProgress !== null || batchTargets.length === 0}
                >
                  {batchProgress ? <LoaderCircle className="spin" size={14} /> : <Send size={14} />}
                  {batchProgress ? "分发中…" : `立即分发到 ${batchTargets.length} 个节点`}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
