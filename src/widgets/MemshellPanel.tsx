import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  LoaderCircle,
  Play,
  RefreshCw,
  ShieldOff,
  TerminalSquare,
} from "lucide-react";
import { api, errorText } from "../api";
import type { MemoryShell, MemshellCapability } from "../api";
import { useToast } from "../components/Toast";

const STATUS_LABEL: Record<string, string> = {
  active: "存活",
  pending: "待生效",
  stale: "未响应",
  neutered: "已中和",
  orphaned: "无法卸载",
  uninstalled: "已卸载",
};

const STATUS_COLOR: Record<string, string> = {
  active: "var(--success, #3fb950)",
  pending: "var(--warning, #d29922)",
  stale: "var(--warning, #d29922)",
  neutered: "var(--text-dim)",
  orphaned: "var(--danger, #f85149)",
  uninstalled: "var(--text-dim)",
};

/**
 * 内存马面板（后渗透）。
 *
 * 安全约束：
 * - 注入前必须勾选授权确认；
 * - 中和后**不立即删除载荷**（目标 PHP 会缓存 .user.ini，删除会让站点 500），
 *   文件由句柄保留，待 user_ini.cache_ttl 过后再清理。
 */
export function MemshellPanel({
  sessionId,
  shellId,
  endpoint,
  documentRoot,
}: {
  sessionId: string | null;
  shellId: string;
  endpoint: string;
  documentRoot?: string;
}) {
  const toast = useToast();
  const [capabilities, setCapabilities] = useState<MemshellCapability[]>([]);
  const [handles, setHandles] = useState<MemoryShell[]>([]);
  const [selectedKind, setSelectedKind] = useState("php_user_ini");
  const [installDir, setInstallDir] = useState(documentRoot ?? "");
  const [triggerUrl, setTriggerUrl] = useState(endpoint);
  const [fpmTarget, setFpmTarget] = useState("127.0.0.1:9000");
  const [scriptFilename, setScriptFilename] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [pendingUninstall, setPendingUninstall] = useState<string | null>(null);
  const [execHandle, setExecHandle] = useState<string | null>(null);
  const [execCommand, setExecCommand] = useState("id");
  const [execOutput, setExecOutput] = useState("");
  const [execBusy, setExecBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      setHandles(await api.memshellList(undefined, shellId));
    } catch (cause) {
      setError(errorText(cause));
    }
  }, [shellId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (documentRoot && !installDir) setInstallDir(documentRoot);
  }, [documentRoot, installDir]);

  useEffect(() => {
    if (!sessionId) {
      setCapabilities([]);
      return;
    }
    void api
      .memshellCapabilities(sessionId)
      .then(setCapabilities)
      .catch((cause) => setError(errorText(cause)));
  }, [sessionId]);

  const installable = capabilities.filter((item) => item.feasible);
  const live = handles.filter((item) => item.status === "active" || item.status === "pending");
  const orphans = handles.filter((item) => item.status === "orphaned");

  async function install() {
    if (!sessionId) {
      toast.warning("请先连接目标");
      return;
    }
    if (!confirmed) {
      toast.warning("请先勾选授权确认");
      return;
    }
    if (selectedKind === "php_fcgi") {
      if (!fpmTarget.trim() || !scriptFilename.trim()) {
        toast.warning("请填写 FPM 地址与 SCRIPT_FILENAME");
        return;
      }
    } else if (!installDir.trim() || !triggerUrl.trim()) {
      toast.warning("请填写安装目录与触发 URL");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const handle = await api.memshellInstall(
        sessionId,
        selectedKind,
        selectedKind === "php_fcgi"
          ? { fpmTarget: fpmTarget.trim(), scriptFilename: scriptFilename.trim() }
          : { installDir: installDir.trim(), triggerUrl: triggerUrl.trim() },
      );
      await refresh();
      if (handle.status === "active") {
        toast.success(`内存马已生效：${handle.installPath}`, "注入成功");
      } else {
        toast.info(
          `已写入 ${handle.installPath}，但尚未生效：目标 PHP 会缓存 .user.ini（默认 300s），请稍后点「检测」。`,
          "等待生效",
        );
      }
      setConfirmed(false);
    } catch (cause) {
      const message = errorText(cause);
      setError(message);
      toast.error(message, "注入失败");
    } finally {
      setBusy(false);
    }
  }

  async function check(handle: MemoryShell) {
    try {
      const alive = await api.memshellCheck(handle.id);
      await refresh();
      if (alive) toast.success("内存马存活", "检测通过");
      else toast.warning("未检测到存活（可能仍在 cache_ttl 窗口内）", "检测结果");
    } catch (cause) {
      toast.error(errorText(cause), "检测失败");
    }
  }

  async function uninstall(handle: MemoryShell) {
    try {
      const message = await api.memshellUninstall(handle.id);
      setPendingUninstall(null);
      await refresh();
      toast.success(message, "已中和");
    } catch (cause) {
      await refresh();
      toast.error(errorText(cause), "中和失败");
    }
  }

  async function exec(handle: MemoryShell) {
    setExecBusy(true);
    setExecOutput("");
    try {
      setExecOutput(await api.memshellExec(handle.id, execCommand));
    } catch (cause) {
      setExecOutput(errorText(cause));
    } finally {
      setExecBusy(false);
    }
  }

  return (
    <div className="panel detail-panel" style={{ padding: 16, display: "grid", gap: 14 }}>
      <div className="panel-heading" style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <div className="panel-heading-title">
          <ShieldOff size={15} /> 内存马（后渗透）
        </div>
        <button className="button compact secondary" onClick={() => void refresh()}>
          <RefreshCw size={13} /> 刷新
        </button>
      </div>

      {error && <p className="form-note error">{error}</p>}

      {(live.length > 0 || orphans.length > 0) && (
        <div
          style={{
            border: "1px solid var(--danger, #f85149)",
            borderRadius: "var(--radius-md)",
            padding: "10px 12px",
            background: "color-mix(in srgb, var(--danger, #f85149) 10%, transparent)",
          }}
        >
          <strong style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <AlertTriangle size={14} /> 当前目标存在 {live.length} 个存活/待生效
            {orphans.length > 0 && `、${orphans.length} 个无法卸载`} 的内存马
          </strong>
          <div className="form-note" style={{ marginTop: 4 }}>
            内存马会持续改变目标状态。评估结束后请务必「中和」，并在 TTL 过后清理残留文件。
          </div>
        </div>
      )}

      <div
        style={{
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-md)",
          padding: "10px 12px",
        }}
      >
        <strong style={{ fontSize: 12.5 }}>可用形态</strong>
        {capabilities.length === 0 ? (
          <div className="form-note" style={{ marginTop: 4 }}>
            {sessionId ? "正在检测目标环境…" : "建立会话后可检测目标是否支持内存马。"}
          </div>
        ) : (
          <div style={{ display: "grid", gap: 4, marginTop: 4 }}>
            {capabilities.map((item) => (
              <div key={item.kind} className="form-note">
                {item.feasible ? (
                  <span style={{ color: "var(--success, #3fb950)" }}>
                    <CheckCircle2 size={12} /> {item.kind}：可用
                  </span>
                ) : (
                  <span>
                    <AlertTriangle size={12} /> {item.kind}：不可用 —— {item.reason}
                  </span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {installable.length > 0 && !orphans.length && (
        <div
          style={{
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-md)",
            padding: "10px 12px",
            display: "grid",
            gap: 8,
          }}
        >
          <strong style={{ fontSize: 12.5 }}>注入内存马</strong>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {capabilities.map((item) => (
              <button
                key={item.kind}
                className={`button compact ${selectedKind === item.kind ? "primary" : "secondary"}`}
                disabled={!item.feasible}
                title={item.feasible ? "" : (item.reason ?? "")}
                onClick={() => setSelectedKind(item.kind)}
              >
                {item.feasible ? "" : "不可用 · "}
                {item.kind}
              </button>
            ))}
          </div>
          {selectedKind === "php_fcgi" ? (
            <>
              <label>
                FPM 地址（客户端需能直连）
                <input
                  value={fpmTarget}
                  onChange={(event) => setFpmTarget(event.target.value)}
                  placeholder="127.0.0.1:9000"
                />
              </label>
              <label>
                SCRIPT_FILENAME（目标上已存在的 PHP 文件绝对路径）
                <input
                  value={scriptFilename}
                  onChange={(event) => setScriptFilename(event.target.value)}
                  placeholder="/var/www/html/index.php"
                />
              </label>
              <div className="form-note">
                零落盘：请求体即载荷，目标不留文件、无缓存延迟；前提是 FPM 端口可达。
              </div>
            </>
          ) : (
            <>
              <label>
                安装目录（.user.ini 所在目录，须是触发 URL 的所在目录）
                <input
                  value={installDir}
                  onChange={(event) => setInstallDir(event.target.value)}
                  placeholder="/var/www/html"
                />
              </label>
              <label>
                触发 URL（该目录下已存在的 PHP 页面）
                <input
                  value={triggerUrl}
                  onChange={(event) => setTriggerUrl(event.target.value)}
                  placeholder="http://target/index.php"
                />
              </label>
              <div className="form-note">
                生效可能延迟：目标 PHP 缓存 .user.ini 默认 300 秒，首次检测可能为「待生效」。
              </div>
            </>
          )}
          <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
              style={{ width: "auto", margin: 0 }}
            />
            我确认该目标在授权范围内，并了解注入会改变目标状态、需在结束后中和
          </label>
          <div>
            <button className="button primary" onClick={() => void install()} disabled={busy}>
              {busy ? <LoaderCircle className="spin" size={14} /> : <ShieldOff size={14} />}
              {busy ? "注入中…" : "注入内存马"}
            </button>
          </div>
        </div>
      )}

      <div>
        <strong style={{ fontSize: 12.5 }}>已注入（{handles.length}）</strong>
        {handles.length === 0 ? (
          <div className="empty-state" style={{ padding: "18px 0" }}>
            <ShieldOff size={26} />
            <strong>暂无内存马</strong>
            <p>注入后这里会显示句柄、存活状态与中和入口。</p>
          </div>
        ) : (
          <div style={{ display: "grid", gap: 8, marginTop: 6 }}>
            {handles.map((handle) => (
              <div
                key={handle.id}
                style={{
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-md)",
                  padding: "9px 11px",
                  display: "grid",
                  gap: 5,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <strong style={{ color: STATUS_COLOR[handle.status] ?? "inherit" }}>
                    {STATUS_LABEL[handle.status] ?? handle.status}
                  </strong>
                  <code className="mono" style={{ fontSize: 11.5 }}>{handle.kind}</code>
                  <span className="form-note">{handle.installPath}</span>
                </div>
                <div className="form-note">
                  端点：{handle.endpoint} · 注入于 {handle.installedAt}
                  {handle.lastCheckAt ? ` · 最近检测 ${handle.lastCheckAt}` : ""}
                  {handle.notes ? ` · ${handle.notes}` : ""}
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <button className="button compact secondary" onClick={() => void check(handle)}>
                    <RefreshCw size={12} /> 检测
                  </button>
                  <button
                    className="button compact secondary"
                    onClick={() => {
                      setExecHandle(execHandle === handle.id ? null : handle.id);
                      setExecOutput("");
                    }}
                  >
                    <TerminalSquare size={12} /> 执行
                  </button>
                  {pendingUninstall === handle.id ? (
                    <>
                      <button className="button compact primary" onClick={() => void uninstall(handle)}>
                        <CheckCircle2 size={12} /> 确认中和
                      </button>
                      <button
                        className="button compact secondary"
                        onClick={() => setPendingUninstall(null)}
                      >
                        取消
                      </button>
                    </>
                  ) : (
                    <button
                      className="button compact secondary"
                      onClick={() => setPendingUninstall(handle.id)}
                    >
                      中和
                    </button>
                  )}
                </div>
                {execHandle === handle.id && (
                  <div style={{ display: "grid", gap: 6, marginTop: 4 }}>
                    <div style={{ display: "flex", gap: 6 }}>
                      <input
                        value={execCommand}
                        onChange={(event) => setExecCommand(event.target.value)}
                        placeholder="id"
                        style={{ flex: 1 }}
                        onKeyDown={(event) => {
                          if (event.key === "Enter") void exec(handle);
                        }}
                      />
                      <button
                        className="button compact primary"
                        onClick={() => void exec(handle)}
                        disabled={execBusy}
                      >
                        {execBusy ? <LoaderCircle className="spin" size={12} /> : <Play size={12} />}
                        运行
                      </button>
                    </div>
                    {execOutput && (
                      <pre
                        style={{
                          margin: 0,
                          padding: "8px 10px",
                          background: "var(--panel-2)",
                          borderRadius: "var(--radius-sm)",
                          fontSize: 11.5,
                          maxHeight: 200,
                          overflow: "auto",
                          whiteSpace: "pre-wrap",
                        }}
                      >
                        {execOutput}
                      </pre>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="form-note">
        中和只把载荷改写为无害占位并摘除 .user.ini，**不会立即删除文件** ——
        目标 PHP 会缓存 .user.ini，删除会让站点在缓存窗口内 500。
        待 user_ini.cache_ttl 过后再手动清理该文件。
      </div>
    </div>
  );
}
