import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ChevronsLeft,
  ChevronsRight,
  Clock3,
  Copy,
  Download,
  History,
  LoaderCircle,
  Play,
  Search,
  Zap,
} from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText } from "../api";
import type { FeatureManifest } from "../api";
import { UpwardPageSizeSelect } from "../components/common";
import { ForwardTerminal } from "./ForwardTerminal";
import { useToast } from "../components/Toast";

/** 需要多行输入框的参数名（代码 / 命令 / SQL / 载荷…）。
 *
 *  此前判据是「参数名含 code/commands **且当前值已含换行**」——首次编辑时值里没有换行，
 *  于是渲染成单行 `<input>`，用户根本敲不出换行，永远进不到多行模式。
 */
function isMultilineParam(name: string): boolean {
  const lower = name.toLowerCase();
  return ["code", "command", "commands", "script", "sql", "query", "payload", "body"].some(
    (key) => lower.includes(key),
  );
}

export function PluginPanel({ sessionId }: { sessionId: string }) {
  const toast = useToast();
  const [plugins, setPlugins] = useState<FeatureManifest[]>([]);
  const [selected, setSelected] = useState<FeatureManifest | null>(null);
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [result, setResult] = useState<{
    ok: boolean;
    data: unknown;
    raw: string;
    ms: number;
  } | null>(null);
  const [history, setHistory] = useState<
    { name: string; ok: boolean; text: string; ms: number; at: string }[]
  >([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [filterQuery, setFilterQuery] = useState("");

  const DISABLED_PLUGINS_KEY = "dosword:disabled-plugins";

  const load = useCallback(() => {
    void api.listFeaturePlugins().then((items) => {
      let disabledList: string[] = [];
      try {
        disabledList = JSON.parse(localStorage.getItem(DISABLED_PLUGINS_KEY) ?? "[]") as string[];
      } catch {
        disabledList = [];
      }
      const enabled = items.filter((p) => !disabledList.includes(p.id));
      setPlugins(enabled);
      if (!selected && enabled.length > 0) {
        setSelected(enabled[0]);
        setValues(defaults(enabled[0]));
      }
    });
  }, [selected]);

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const MEM_KEY = "dosword:plugin-values";

  function defaults(plugin: FeatureManifest): Record<string, unknown> {
    return Object.fromEntries(
      plugin.params.map((p) => [
        p.name,
        p.default ?? (p.type === "int" ? 0 : p.type === "bool" ? false : ""),
      ]),
    );
  }

  function remembered(plugin: FeatureManifest): Record<string, unknown> {
    try {
      const stored = JSON.parse(
        localStorage.getItem(MEM_KEY) ?? "{}",
      ) as Record<string, Record<string, unknown>>;
      const saved = stored[plugin.id];
      if (!saved) return defaults(plugin);
      const merged: Record<string, unknown> = { ...defaults(plugin) };
      for (const param of plugin.params) {
        if (saved[param.name] !== undefined) merged[param.name] = saved[param.name];
      }
      return merged;
    } catch {
      return defaults(plugin);
    }
  }

  function remember(pluginId: string, value: Record<string, unknown>) {
    try {
      const stored = JSON.parse(
        localStorage.getItem(MEM_KEY) ?? "{}",
      ) as Record<string, Record<string, unknown>>;
      stored[pluginId] = value;
      localStorage.setItem(MEM_KEY, JSON.stringify(stored));
    } catch {
      // 忽略
    }
  }

  const [viewRaw, setViewRaw] = useState(false);

  function pick(plugin: FeatureManifest) {
    setSelected(plugin);
    setResult(null);
    setError("");
    setViewRaw(false);
    setValues(remembered(plugin));
  }

  async function run(pluginId?: string, runValues?: Record<string, unknown>) {
    const target = plugins.find((p) => p.id === (pluginId ?? selected?.id));
    if (!target) return;
    const params = runValues ?? values;
    setBusy(true);
    setError("");
    const started = performance.now();
    try {
      const out = await api.runFeaturePlugin(sessionId, target.id, params);
      remember(target.id, params);
      const ms = Math.round(performance.now() - started);

      let parsedData: unknown = out;
      if (typeof out === "string") {
        try {
          parsedData = JSON.parse(out);
        } catch {
          parsedData = out;
        }
      }
      if (parsedData && typeof parsedData === "object") {
        const obj = parsedData as Record<string, unknown>;
        if (obj.data !== undefined && (obj.ok === true || obj.ok === undefined)) {
          parsedData = obj.data;
        }
      }

      const raw = typeof out === "string" ? out : JSON.stringify(out, null, 2);
      setResult({ ok: true, data: parsedData, raw, ms });
      toast.success(`插件「${target.name}」执行完成 (${ms} ms)`);
      setHistory((prev) =>
        [
          { name: target.name, ok: true, text: raw, ms, at: new Date().toLocaleTimeString() },
          ...prev,
        ].slice(0, 20),
      );
    } catch (cause) {
      const ms = Math.round(performance.now() - started);
      const text = errorText(cause);
      setResult({ ok: false, data: null, raw: text, ms });
      toast.error(text, `插件「${target.name}」执行异常`);
      setHistory((prev) =>
        [
          { name: target.name, ok: false, text, ms, at: new Date().toLocaleTimeString() },
          ...prev,
        ].slice(0, 20),
      );
    } finally {
      setBusy(false);
    }
  }

  async function downloadResult() {
    if (!result) return;
    const stamp = new Date().toISOString().slice(0, 19).replace(/:/g, "-");
    const localPath = await save({
      defaultPath: `dosword-plugin-${selected?.id ?? "result"}-${stamp}.json`,
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (!localPath) return;
    try {
      await api.writeLocalFile(localPath, b64.encodeBytes(new TextEncoder().encode(result.raw)));
      toast.success(`结果已保存至 ${localPath}`);
    } catch (cause) {
      toast.error(`下载保存失败：${errorText(cause)}`);
    }
  }

  const QUICK_IDS = [
    "sysinfo",
    "netinfo",
    "userlist",
    "processes",
    "port_scan",
    "task_scheduler",
    "cred_scan",
    "webshell_scan",
    "file_search",
    "php_env",
  ];
  const quickPlugins = QUICK_IDS.map((id) => plugins.find((p) => p.id === id)).filter(
    (p): p is FeatureManifest => Boolean(p),
  );

  async function quickRun(plugin: FeatureManifest) {
    pick(plugin);
    await run(plugin.id, remembered(plugin));
  }

  const filteredPlugins = useMemo(() => {
    if (!filterQuery.trim()) return plugins;
    const q = filterQuery.toLowerCase();
    return plugins.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.id.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.category.toLowerCase().includes(q),
    );
  }, [plugins, filterQuery]);

  const byKind = (kind: string) => filteredPlugins.filter((p) => p.kind === kind);
  const isBypass = (p: FeatureManifest) => p.id.startsWith("bypass_");
  const dfBypass = filteredPlugins.filter((p) => isBypass(p) && p.id !== "bypass_open_basedir");
  const obBypass = filteredPlugins.filter((p) => p.id === "bypass_open_basedir");
  const feature = byKind("feature").filter((p) => !isBypass(p));
  const loader = byKind("loader").filter((p) => !isBypass(p));
  const crypto = byKind("crypto");
  const others = filteredPlugins.filter(
    (p) => !["feature", "crypto", "loader"].includes(p.kind) && !isBypass(p),
  );

  return (
    <div className="plugin-panel">
      {/* 常用探测快捷栏 */}
      {quickPlugins.length > 0 && (
        <div className="plugin-quickbar">
          <span className="plugin-quickbar-label">
            <Zap size={12} color="var(--accent)" style={{ display: "inline", verticalAlign: "middle", marginRight: 4 }} />
            常用快捷
          </span>
          {quickPlugins.map((plugin) => (
            <button
              key={plugin.id}
              className="plugin-quick-item"
              onClick={() => void quickRun(plugin)}
              title={plugin.description}
              disabled={busy}
            >
              {plugin.name}
            </button>
          ))}
        </div>
      )}

      <div className="plugin-panel-body">
        {/* 左侧分类导航 */}
        <div className="plugin-sidebar">
          <div className="file-search" style={{ height: 28, width: "100%", marginBottom: 6 }}>
            <Search size={12} />
            <input
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              placeholder="搜索插件…"
              style={{ fontSize: 11 }}
            />
          </div>

          {dfBypass.length > 0 && <p className="plugin-group">Bypass DisableFunctions</p>}
          {dfBypass.length > 0 && (
            <select
              className="plugin-bypass-select"
              value={selected && dfBypass.some((p) => p.id === selected.id) ? selected.id : ""}
              onChange={(event) => {
                const plugin = dfBypass.find((p) => p.id === event.target.value);
                if (plugin) pick(plugin);
              }}
            >
              <option value="" disabled>
                选择绕过向量…
              </option>
              {dfBypass.map((plugin) => (
                <option key={plugin.id} value={plugin.id}>
                  {plugin.name}
                </option>
              ))}
            </select>
          )}

          {obBypass.length > 0 && <p className="plugin-group">Bypass OpenBasedir</p>}
          {obBypass.length > 0 && (
            <select
              className="plugin-bypass-select"
              value={selected && obBypass.some((p) => p.id === selected.id) ? selected.id : ""}
              onChange={(event) => {
                const plugin = obBypass.find((p) => p.id === event.target.value);
                if (plugin) pick(plugin);
              }}
            >
              <option value="" disabled>
                选择绕过方法…
              </option>
              {obBypass.map((plugin) => (
                <option key={plugin.id} value={plugin.id}>
                  {plugin.name}
                </option>
              ))}
            </select>
          )}

          {feature.length > 0 && <p className="plugin-group">功能插件 ({feature.length})</p>}
          {feature.map((plugin) => (
            <button
              key={plugin.id}
              className={`plugin-item ${selected?.id === plugin.id ? "active" : ""}`}
              onClick={() => pick(plugin)}
              title={plugin.description}
            >
              {plugin.name}
            </button>
          ))}

          {crypto.length > 0 && <p className="plugin-group">加密器 ({crypto.length})</p>}
          {crypto.map((plugin) => (
            <button
              key={plugin.id}
              className={`plugin-item ${selected?.id === plugin.id ? "active" : ""}`}
              onClick={() => pick(plugin)}
              title={plugin.description}
            >
              {plugin.name}
            </button>
          ))}

          {loader.length > 0 && <p className="plugin-group">加载器 ({loader.length})</p>}
          {loader.map((plugin) => (
            <button
              key={plugin.id}
              className={`plugin-item ${selected?.id === plugin.id ? "active" : ""}`}
              onClick={() => pick(plugin)}
              title={plugin.description}
            >
              {plugin.name}
            </button>
          ))}

          {others.length > 0 && <p className="plugin-group">其他</p>}
          {others.map((plugin) => (
            <button
              key={plugin.id}
              className={`plugin-item ${selected?.id === plugin.id ? "active" : ""}`}
              onClick={() => pick(plugin)}
              title={plugin.description}
            >
              {plugin.name}
            </button>
          ))}
        </div>

        {/* 右侧执行与结果渲染 */}
        <div className="plugin-main">
          {selected ? (
            <>
              <div className="plugin-head">
                <div>
                  <h3>{selected.name}</h3>
                  <p className="field-hint">{selected.description}</p>
                </div>
                <span className={`plugin-kind-badge ${selected.kind}`}>
                  {selected.kind === "crypto"
                    ? "加密器"
                    : selected.kind === "loader"
                      ? "加载器"
                      : "功能模块"}
                  {selected.languages.length > 0 && ` · ${selected.languages.join("/")}`}
                </span>
              </div>

              {selected.id === "super_terminal" ? (
                <div style={{ marginTop: 12 }}>
                  <ForwardTerminal sessionId={sessionId} />
                </div>
              ) : (
                <>
                  {selected.params.length > 0 && (
                    <div className="plugin-params">
                      {selected.params.map((param) => (
                        <label key={param.name} className="plugin-param">
                          {param.label}
                          {param.type === "bool" ? (
                            <input
                              type="checkbox"
                              checked={Boolean(values[param.name])}
                              onChange={(event) =>
                                setValues((prev) => ({ ...prev, [param.name]: event.target.checked }))
                              }
                            />
                          ) : param.type === "int" ? (
                            <input
                              type="number"
                              value={String(values[param.name] ?? "")}
                              onChange={(event) =>
                                setValues((prev) => ({
                                  ...prev,
                                  [param.name]: Number(event.target.value),
                                }))
                              }
                            />
                          ) : param.type === "select" ||
                            (param.options && param.options.length > 0) ? (
                            <select
                              value={String(values[param.name] ?? "")}
                              onChange={(event) =>
                                setValues((prev) => ({ ...prev, [param.name]: event.target.value }))
                              }
                            >
                              {(param.options ?? []).map((option) => (
                                <option key={option} value={option}>
                                  {option}
                                </option>
                              ))}
                            </select>
                          ) : isMultilineParam(param.name) ? (
                            <textarea
                              rows={6}
                              value={String(values[param.name] ?? "")}
                              onChange={(event) =>
                                setValues((prev) => ({ ...prev, [param.name]: event.target.value }))
                              }
                              spellCheck={false}
                            />
                          ) : (
                            <input
                              value={String(values[param.name] ?? "")}
                              onChange={(event) =>
                                setValues((prev) => ({ ...prev, [param.name]: event.target.value }))
                              }
                              placeholder={param.default != null ? String(param.default) : ""}
                              spellCheck={false}
                            />
                          )}
                        </label>
                      ))}
                    </div>
                  )}

                  <div className="plugin-run-row">
                    <button
                      className="button primary"
                      onClick={() => void run()}
                      disabled={busy}
                    >
                      {busy ? <LoaderCircle className="spin" size={14} /> : <Play size={14} />}
                      {busy ? "执行中…" : "执行插件"}
                    </button>
                    {result && (
                      <span className="plugin-run-meta">
                        <Clock3 size={13} />
                        耗时: {result.ms} ms
                        <span className={`plugin-result-status ${result.ok ? "ok" : "err"}`}>
                          {result.ok ? "● 执行成功" : "✕ 执行失败"}
                        </span>
                      </span>
                    )}
                  </div>

                  {error && <p className="form-note error">{error}</p>}

                  {result && (
                    <div className="plugin-result-box">
                      <div className="plugin-result-actions">
                        <button
                          className="button compact secondary"
                          onClick={() => setViewRaw((prev) => !prev)}
                        >
                          {viewRaw ? "切换为格式化视图" : "查看原始 JSON"}
                        </button>
                        <button
                          className="button compact secondary"
                          onClick={() => {
                            void navigator.clipboard.writeText(result.raw);
                            toast.success("原始结果已复制到剪贴板");
                          }}
                        >
                          <Copy size={13} />
                          复制结果
                        </button>
                        <button
                          className="button compact secondary"
                          onClick={() => void downloadResult()}
                        >
                          <Download size={13} />
                          导出 JSON
                        </button>
                      </div>
                      {result.ok ? (
                        <PluginResultView data={result.data} viewRaw={viewRaw} />
                      ) : (
                        <pre className="plugin-result error">{result.raw}</pre>
                      )}
                    </div>
                  )}
                </>
              )}

              {history.length > 0 && (
                <details className="plugin-history">
                  <summary>
                    <History size={13} />
                    执行历史记录 ({history.length})
                  </summary>
                  <ul>
                    {history.map((item, index) => (
                      <li key={index}>
                        <span className={`plugin-history-status ${item.ok ? "ok" : "err"}`}>
                          {item.ok ? "✓" : "✗"}
                        </span>
                        <strong>{item.name}</strong>
                        <small>
                          {item.at} · {item.ms} ms
                        </small>
                      </li>
                    ))}
                  </ul>
                </details>
              )}
            </>
          ) : (
            <p className="muted pad">请在左侧选择要执行的功能或绕过插件。</p>
          )}
        </div>
      </div>
    </div>
  );
}

function PluginResultView({ data, viewRaw }: { data: unknown; viewRaw: boolean }) {
  const toast = useToast();
  const [tablePage, setTablePage] = useState(0);
  const [tablePageSize, setTablePageSize] = useState(50);
  const [tableJumpInput, setTableJumpInput] = useState("");

  const copy = (val: string, label: string) => {
    void navigator.clipboard.writeText(val);
    toast.info(`已复制 ${label}`);
  };

  const textOutput = useMemo(() => {
    function extract(val: unknown): string | null {
      if (val === null || val === undefined) return null;
      if (typeof val === "string") {
        const trimmed = val.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
          try {
            const parsed = JSON.parse(trimmed);
            const inner = extract(parsed);
            if (inner) return inner;
          } catch {
            // not json
          }
        }
        return val;
      }
      if (typeof val === "object") {
        const obj = val as Record<string, unknown>;
        for (const key of ["stdout", "output_text", "content", "output", "result", "text"]) {
          const v = obj[key];
          if (typeof v === "string" && v.length > 0) return v;
        }
        if (obj.data) {
          const inner = extract(obj.data);
          if (inner) return inner;
        }
      }
      return null;
    }
    return extract(data);
  }, [data]);

  const rendered = useMemo(() => {
    if (data && typeof data === "object") {
      const obj = data as Record<string, unknown>;
      if (Array.isArray(obj.columns) && Array.isArray(obj.rows)) {
        const columns = obj.columns.map((c) => String(c));
        const rows = (obj.rows as unknown[][]).map((row) =>
          row.map((v) => (v === null ? "NULL" : String(v))),
        );
        return { kind: "table" as const, columns, rows };
      }
      for (const key of ["entries", "matches", "webshells", "users", "processes", "databases", "tables", "findings"]) {
        const items = obj[key];
        if (Array.isArray(items) && items.length > 0 && typeof items[0] === "object") {
          const first = items[0] as Record<string, unknown>;
          const columns = Object.keys(first);
          const rows = (items as Record<string, unknown>[]).map((item) =>
            columns.map((c) => {
              const v = item[c];
              if (v === null || v === undefined) return "";
              if (Array.isArray(v)) return v.join(", ");
              return String(v);
            }),
          );
          return { kind: "table" as const, columns, rows };
        }
      }
      if (Array.isArray(obj.open) || Array.isArray(obj.open_ports) || Array.isArray(obj.ports)) {
        const ports = (obj.open ?? obj.open_ports ?? obj.ports) as unknown[];
        return {
          kind: "table" as const,
          columns: ["开放端口 / 发现项目"],
          rows: ports.map((p) => [String(p)]),
        };
      }
      if (Array.isArray(obj.results)) {
        const items = obj.results as Record<string, unknown>[];
        if (items.length > 0 && typeof items[0] === "object") {
          const columns = Object.keys(items[0]);
          return {
            kind: "table" as const,
            columns,
            rows: items.map((item) => columns.map((c) => String(item[c] ?? ""))),
          };
        }
      }
      // 对象属性看板（两列 Key-Value 属性表，替代原始 JSON）
      const entries = Object.entries(obj).filter(([k]) => k !== "ok" && k !== "error");
      if (entries.length > 0) {
        return { kind: "props" as const, entries };
      }
    }
    return null;
  }, [data]);

  if (viewRaw) {
    return (
      <div className="plugin-json-view">
        <pre>{typeof data === "string" ? data : JSON.stringify(data, null, 2)}</pre>
      </div>
    );
  }

  if (textOutput !== null) {
    return <pre className="plugin-result-text">{textOutput}</pre>;
  }

  if (rendered?.kind === "table") {
    const effectiveSize = tablePageSize === 0 ? rendered.rows.length : tablePageSize;
    const tablePageCount = tablePageSize === 0 ? 1 : Math.max(1, Math.ceil(rendered.rows.length / effectiveSize));
    const pageRows = tablePageSize === 0 ? rendered.rows : rendered.rows.slice(tablePage * effectiveSize, (tablePage + 1) * effectiveSize);

    const handleJump = () => {
      const p = parseInt(tableJumpInput.trim(), 10);
      if (!Number.isNaN(p) && p >= 1 && p <= tablePageCount) {
        setTablePage(p - 1);
        setTableJumpInput("");
      } else {
        toast.warning(`请输入 1 到 ${tablePageCount} 之间的有效页码`);
      }
    };

    return (
      <div className="plugin-table-wrap" style={{ display: "flex", flexDirection: "column" }}>
        <div style={{ flex: 1, overflow: "auto" }}>
          <table className="plugin-table">
            <thead>
              <tr>
                {rendered.columns.map((column) => (
                  <th key={column}>{column}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {pageRows.map((row, i) => (
                <tr key={i}>
                  {row.map((cell, j) => (
                    <td
                      key={j}
                      title={cell}
                      onClick={() => {
                        if (cell) {
                          void navigator.clipboard.writeText(cell);
                          toast.info("单元格内容已复制");
                        }
                      }}
                      style={{ cursor: "pointer" }}
                    >
                      {cell.length > 120 ? `${cell.slice(0, 120)}…` : cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {rendered.rows.length > 20 && (
          <div className="file-pager" style={{ borderTop: "1px solid var(--border)", margin: 0 }}>
            <div className="file-pager-info">
              共 <strong>{rendered.rows.length}</strong> 条数据
            </div>

            <div className="file-pager-controls">
              <button
                className="button compact secondary"
                disabled={tablePage === 0}
                onClick={() => setTablePage(0)}
                title="第一页"
              >
                <ChevronsLeft size={13} />
              </button>
              <button
                className="button compact secondary"
                disabled={tablePage === 0}
                onClick={() => setTablePage((p) => Math.max(0, p - 1))}
              >
                上一页
              </button>
              <span className="pagination-info" style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                第 <strong>{tablePage + 1}</strong> / {tablePageCount} 页
              </span>
              <button
                className="button compact secondary"
                disabled={tablePage + 1 >= tablePageCount}
                onClick={() => setTablePage((p) => Math.min(tablePageCount - 1, p + 1))}
              >
                下一页
              </button>
              <button
                className="button compact secondary"
                disabled={tablePage + 1 >= tablePageCount}
                onClick={() => setTablePage(tablePageCount - 1)}
                title="最后一页"
              >
                <ChevronsRight size={13} />
              </button>
            </div>

            <div className="file-pager-jump">
              <span style={{ fontSize: 11, color: "var(--text-faint)" }}>每页:</span>
              <UpwardPageSizeSelect
                value={tablePageSize}
                onChange={(val) => {
                  setTablePageSize(val);
                  setTablePage(0);
                }}
                options={[20, 50, 100, 200, 0]}
                unit="条"
              />

              <span style={{ fontSize: 11, color: "var(--text-faint)", marginLeft: 6 }}>跳至:</span>
              <input
                className="file-pager-input"
                value={tableJumpInput}
                onChange={(e) => setTableJumpInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleJump();
                }}
                placeholder={String(tablePage + 1)}
              />
              <button className="button compact secondary" onClick={handleJump}>
                跳转
              </button>
            </div>
          </div>
        )}
      </div>
    );
  }

  if (rendered?.kind === "props") {
    return (
      <div className="plugin-prop-grid">
        {rendered.entries.map(([key, val]) => {
          const isArr = Array.isArray(val);
          const isObj = val !== null && typeof val === "object" && !isArr;
          const displayStr = isObj
            ? JSON.stringify(val)
            : isArr
              ? (val as unknown[]).join(", ")
              : String(val ?? "—");

          return (
            <div className="plugin-prop-card" key={key}>
              <span>{key}</span>
              {isArr ? (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 3 }}>
                  {(val as unknown[]).map((item, idx) => (
                    <span key={idx} className="plugin-prop-tag">
                      {String(item)}
                    </span>
                  ))}
                </div>
              ) : (
                <code
                  onClick={() => copy(displayStr, key)}
                  style={{ cursor: "pointer" }}
                  title="点击复制属性值"
                >
                  {typeof val === "boolean" ? (val ? "✓ 是 (true)" : "✕ 否 (false)") : displayStr}
                </code>
              )}
            </div>
          );
        })}
      </div>
    );
  }

  return (
    <div className="plugin-json-view">
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </div>
  );
}
