import { useCallback, useEffect, useMemo, useState } from "react";
import { CheckCircle2, LoaderCircle, Play, Search, XCircle } from "lucide-react";
import { api, errorText } from "../api";
import type { FeatureManifest, OrchestrationReport, ShellProfile } from "../api";
import { useToast } from "../components/Toast";

const CONCURRENCY_OPTIONS = [1, 2, 4, 8];

export function OrchestrationView() {
  const toast = useToast();
  const [shells, setShells] = useState<ShellProfile[]>([]);
  const [plugins, setPlugins] = useState<FeatureManifest[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [opType, setOpType] = useState<"command" | "plugin" | "listDir">("command");
  const [command, setCommand] = useState("id");
  const [pluginId, setPluginId] = useState("");
  const [pluginParams, setPluginParams] = useState("{}");
  const [path, setPath] = useState("/");
  const [concurrency, setConcurrency] = useState(4);
  const [autoConnect, setAutoConnect] = useState(true);
  const [disconnectAfter, setDisconnectAfter] = useState(false);
  const [stopOnError, setStopOnError] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState<OrchestrationReport | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [dashboard, pluginList] = await Promise.all([
        api.dashboard(),
        api.listFeaturePlugins(),
      ]);
      setShells(dashboard.shells);
      setPlugins(pluginList);
      setPluginId((current) => current || pluginList[0]?.id || "");
    } catch (cause) {
      setError(errorText(cause));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return shells;
    return shells.filter(
      (shell) =>
        shell.name.toLowerCase().includes(q) ||
        shell.endpoint.toLowerCase().includes(q) ||
        shell.runtime.toLowerCase().includes(q),
    );
  }, [shells, query]);

  function toggle(id: string) {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAll() {
    setSelected((current) =>
      current.size === filtered.length ? new Set() : new Set(filtered.map((shell) => shell.id)),
    );
  }

  async function run() {
    if (selected.size === 0) {
      toast.warning("请至少选择一个目标");
      return;
    }
    let op: Record<string, unknown>;
    if (opType === "command") {
      if (!command.trim()) {
        toast.warning("请填写命令");
        return;
      }
      op = { type: "command", command };
    } else if (opType === "listDir") {
      if (!path.trim()) {
        toast.warning("请填写目录路径");
        return;
      }
      op = { type: "listDir", path: path.trim() };
    } else {
      if (!pluginId) {
        toast.warning("请选择插件");
        return;
      }
      let params: unknown;
      try {
        params = pluginParams.trim() ? JSON.parse(pluginParams) : {};
      } catch {
        toast.warning("插件参数不是合法 JSON");
        return;
      }
      op = { type: "plugin", pluginId, params };
    }

    setBusy(true);
    setError("");
    setReport(null);
    try {
      const result = await api.orchestrateRun({
        shellIds: [...selected],
        op,
        concurrency,
        stopOnError,
        autoConnect,
        disconnectAfter,
      });
      setReport(result);
      if (result.failed === 0) {
        toast.success(`全部 ${result.total} 个目标执行成功`, "编排完成");
      } else {
        toast.warning(`${result.failed}/${result.total} 个目标失败`, "编排完成");
      }
    } catch (cause) {
      const message = errorText(cause);
      setError(message);
      toast.error(message, "编排失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="detail-panel" style={{ display: "grid", gap: 14 }}>
      <div className="panel" style={{ padding: 14 }}>
        <div className="panel-heading">
          <div className="panel-heading-title">批量与多目标编排</div>
          <button className="button compact secondary" onClick={() => void load()}>
            刷新目标
          </button>
        </div>
        <p className="form-note" style={{ marginTop: 6 }}>
          对多个 Shell 并发执行同一操作。每个目标仍会单独做授权复查；未连接的目标可按需自动连接，
          任务结束后只断开本次自动建立的会话。
        </p>
      </div>

      {error && <p className="form-note error">{error}</p>}

      <div style={{ display: "grid", gridTemplateColumns: "minmax(280px, 1fr) minmax(320px, 1.2fr)", gap: 14 }}>
        <div className="panel" style={{ padding: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <strong style={{ fontSize: 12.5 }}>目标（已选 {selected.size} / {shells.length}）</strong>
            <button className="button compact secondary" onClick={toggleAll}>
              {selected.size === filtered.length ? "取消全选" : "全选"}
            </button>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
            <Search size={13} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="搜索名称 / 端点 / 运行时"
              style={{ flex: 1 }}
            />
          </div>
          <div style={{ maxHeight: 340, overflow: "auto", display: "grid", gap: 4 }}>
            {filtered.length === 0 ? (
              <div className="form-note">没有匹配的 Shell。</div>
            ) : (
              filtered.map((shell) => (
                <label
                  key={shell.id}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    padding: "4px 6px",
                    borderRadius: "var(--radius-sm)",
                    background: selected.has(shell.id) ? "var(--panel-2)" : "transparent",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={selected.has(shell.id)}
                    onChange={() => toggle(shell.id)}
                    style={{ width: "auto", margin: 0 }}
                  />
                  <span style={{ fontSize: 12 }}>{shell.name}</span>
                  <code className="mono" style={{ fontSize: 10.5, color: "var(--text-dim)" }}>
                    {shell.runtime || "php"}
                  </code>
                </label>
              ))
            )}
          </div>
        </div>

        <div className="panel" style={{ padding: 12, display: "grid", gap: 8 }}>
          <strong style={{ fontSize: 12.5 }}>操作</strong>
          <div style={{ display: "flex", gap: 6 }}>
            {[
              { key: "command", label: "命令" },
              { key: "plugin", label: "功能插件" },
              { key: "listDir", label: "列目录" },
            ].map((item) => (
              <button
                key={item.key}
                className={`button compact ${opType === item.key ? "primary" : "secondary"}`}
                onClick={() => setOpType(item.key as typeof opType)}
              >
                {item.label}
              </button>
            ))}
          </div>

          {opType === "command" && (
            <label>
              命令（在目标上执行）
              <textarea
                value={command}
                onChange={(event) => setCommand(event.target.value)}
                rows={3}
                className="mono"
              />
            </label>
          )}

          {opType === "listDir" && (
            <label>
              目录路径
              <input value={path} onChange={(event) => setPath(event.target.value)} placeholder="/" />
            </label>
          )}

          {opType === "plugin" && (
            <>
              <label>
                功能插件
                <select value={pluginId} onChange={(event) => setPluginId(event.target.value)}>
                  {plugins.map((plugin) => (
                    <option key={plugin.id} value={plugin.id}>
                      {plugin.name}（{plugin.id}）
                    </option>
                  ))}
                </select>
              </label>
              <label>
                参数（JSON）
                <textarea
                  value={pluginParams}
                  onChange={(event) => setPluginParams(event.target.value)}
                  rows={3}
                  className="mono"
                />
              </label>
            </>
          )}

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
            <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
              并发
              <select
                value={concurrency}
                onChange={(event) => setConcurrency(Number(event.target.value))}
              >
                {CONCURRENCY_OPTIONS.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <input
                type="checkbox"
                checked={autoConnect}
                onChange={(event) => setAutoConnect(event.target.checked)}
                style={{ width: "auto", margin: 0 }}
              />
              自动连接
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <input
                type="checkbox"
                checked={disconnectAfter}
                onChange={(event) => setDisconnectAfter(event.target.checked)}
                style={{ width: "auto", margin: 0 }}
              />
              结束后断开本次连接
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <input
                type="checkbox"
                checked={stopOnError}
                onChange={(event) => setStopOnError(event.target.checked)}
                style={{ width: "auto", margin: 0 }}
              />
              遇错停止
            </label>
          </div>

          <div>
            <button className="button primary" onClick={() => void run()} disabled={busy}>
              {busy ? <LoaderCircle className="spin" size={14} /> : <Play size={14} />}
              {busy ? "执行中…" : `对 ${selected.size} 个目标执行`}
            </button>
          </div>
        </div>
      </div>

      {report && (
        <div className="panel" style={{ padding: 12 }}>
          <div className="panel-heading">
            <div className="panel-heading-title">
              结果：成功 {report.ok} / 失败 {report.failed} / 共 {report.total}
            </div>
          </div>
          <div style={{ display: "grid", gap: 6, marginTop: 8 }}>
            {report.outcomes.map((outcome) => (
              <div
                key={outcome.shellId}
                style={{
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "6px 9px",
                }}
              >
                <div
                  style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}
                  onClick={() =>
                    setExpanded(expanded === outcome.shellId ? null : outcome.shellId)
                  }
                >
                  {outcome.ok ? (
                    <CheckCircle2 size={13} style={{ color: "var(--success, #3fb950)" }} />
                  ) : (
                    <XCircle size={13} style={{ color: "var(--danger, #f85149)" }} />
                  )}
                  <span style={{ fontSize: 12 }}>{outcome.shellName}</span>
                  <span className="form-note">{outcome.elapsedMs} ms</span>
                  {!outcome.ok && (
                    <span className="form-note error" style={{ marginLeft: "auto" }}>
                      {outcome.error}
                    </span>
                  )}
                </div>
                {expanded === outcome.shellId && (
                  <pre
                    style={{
                      margin: "6px 0 0",
                      padding: "8px 10px",
                      background: "var(--panel-2)",
                      borderRadius: "var(--radius-sm)",
                      fontSize: 11.5,
                      maxHeight: 240,
                      overflow: "auto",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {outcome.output || outcome.error}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
