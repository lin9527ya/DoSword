import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Clock3,
  Copy,
  Download,
  History,
  LoaderCircle,
  Play,
} from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText } from "../api";
import type { FeatureManifest } from "../api";

/** 功能插件面板：插件列表 → 参数表单 → 执行 → 结构化结果（表格/JSON/文本）。 */
export function PluginPanel({ sessionId }: { sessionId: string }) {
  const [plugins, setPlugins] = useState<FeatureManifest[]>([]);
  const [selected, setSelected] = useState<FeatureManifest | null>(null);
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [result, setResult] = useState<{ ok: boolean; data: unknown; raw: string; ms: number } | null>(null);
  const [history, setHistory] = useState<{ name: string; ok: boolean; text: string; ms: number; at: string }[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    void api.listFeaturePlugins().then((items) => {
      setPlugins(items);
      if (!selected && items.length > 0) {
        setSelected(items[0]);
        setValues(defaults(items[0]));
      }
    });
  }, [selected]);

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function defaults(plugin: FeatureManifest): Record<string, unknown> {
    return Object.fromEntries(
      plugin.params.map((p) => [p.name, p.default ?? (p.type === "int" ? 0 : p.type === "bool" ? false : "")]),
    );
  }

  function pick(plugin: FeatureManifest) {
    setSelected(plugin);
    setResult(null);
    setError("");
    setValues(defaults(plugin));
  }

  async function run() {
    if (!selected) return;
    setBusy(true);
    setError("");
    const started = performance.now();
    try {
      const out = await api.runFeaturePlugin(sessionId, selected.id, values);
      const ms = Math.round(performance.now() - started);
      const raw = JSON.stringify(out, null, 2);
      setResult({ ok: true, data: out, raw, ms });
      setHistory((prev) =>
        [{ name: selected.name, ok: true, text: raw, ms, at: new Date().toLocaleTimeString() }, ...prev].slice(0, 20),
      );
    } catch (cause) {
      const ms = Math.round(performance.now() - started);
      const text = errorText(cause);
      setResult({ ok: false, data: null, raw: text, ms });
      setHistory((prev) =>
        [{ name: selected?.name ?? "", ok: false, text, ms, at: new Date().toLocaleTimeString() }, ...prev].slice(0, 20),
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
    } catch (cause) {
      setError(`下载失败：${errorText(cause)}`);
    }
  }

  const byKind = (kind: string) => plugins.filter((p) => p.kind === kind);
  const isBypass = (p: FeatureManifest) => p.id.startsWith("bypass_");
  const dfBypass = plugins.filter((p) => isBypass(p) && p.id !== "bypass_open_basedir");
  const obBypass = plugins.filter((p) => p.id === "bypass_open_basedir");
  const feature = byKind("feature").filter((p) => !isBypass(p));
  const loader = byKind("loader").filter((p) => !isBypass(p));
  const crypto = byKind("crypto");
  const others = plugins.filter((p) => !["feature", "crypto", "loader"].includes(p.kind));

  return (
    <div className="plugin-panel">
      <div className="plugin-sidebar">
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
        {feature.length > 0 && <p className="plugin-group">功能</p>}
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
        {crypto.length > 0 && <p className="plugin-group">加密器</p>}
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
        {loader.length > 0 && <p className="plugin-group">加载器</p>}
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
      <div className="plugin-main">
        {selected ? (
          <>
            <div className="plugin-head">
              <div>
                <h3>{selected.name}</h3>
                <p className="field-hint">{selected.description}</p>
              </div>
              <span className={`plugin-kind-badge ${selected.kind}`}>
                {selected.kind === "crypto" ? "加密器" : selected.kind === "loader" ? "加载器" : "功能"}
                {selected.languages.length > 0 && ` · ${selected.languages.join("/")}`}
              </span>
            </div>
            {selected.params.length > 0 && (
              <div className="plugin-params">
                {selected.params.map((param) => (
                  <label key={param.name} className="plugin-param">
                    {param.label}
                    {param.type === "bool" ? (
                      <input
                        type="checkbox"
                        checked={Boolean(values[param.name])}
                        onChange={(event) => setValues((prev) => ({ ...prev, [param.name]: event.target.checked }))}
                      />
                    ) : param.type === "int" ? (
                      <input
                        type="number"
                        value={String(values[param.name] ?? "")}
                        onChange={(event) => setValues((prev) => ({ ...prev, [param.name]: Number(event.target.value) }))}
                      />
                    ) : param.type === "select" || (param.options && param.options.length > 0) ? (
                      <select
                        value={String(values[param.name] ?? "")}
                        onChange={(event) => setValues((prev) => ({ ...prev, [param.name]: event.target.value }))}
                      >
                        {(param.options ?? []).map((option) => (
                          <option key={option} value={option}>
                            {option}
                          </option>
                        ))}
                      </select>
                    ) : (param.name.includes("code") || param.name.includes("commands")) &&
                      String(values[param.name] ?? "").includes("\n") ? (
                      <textarea
                        rows={6}
                        value={String(values[param.name] ?? "")}
                        onChange={(event) => setValues((prev) => ({ ...prev, [param.name]: event.target.value }))}
                        spellCheck={false}
                      />
                    ) : (
                      <input
                        value={String(values[param.name] ?? "")}
                        onChange={(event) => setValues((prev) => ({ ...prev, [param.name]: event.target.value }))}
                        placeholder={param.default != null ? String(param.default) : ""}
                        spellCheck={false}
                      />
                    )}
                  </label>
                ))}
              </div>
            )}
            <div className="plugin-run-row">
              <button className="button primary" onClick={() => void run()} disabled={busy}>
                {busy ? <LoaderCircle className="spin" size={15} /> : <Play size={15} />}
                {busy ? "执行中…" : "执行"}
              </button>
              {result && (
                <span className="plugin-run-meta">
                  <Clock3 size={13} />
                  {result.ms} ms
                  <span className={`plugin-result-status ${result.ok ? "ok" : "err"}`}>
                    {result.ok ? "成功" : "失败"}
                  </span>
                </span>
              )}
            </div>
            {error && <p className="form-note error">{error}</p>}
            {result && (
              <div className="plugin-result-box">
                <div className="plugin-result-actions">
                  <button
                    className="button compact"
                    onClick={() => void navigator.clipboard?.writeText(result.raw)}
                  >
                    <Copy size={13} />
                    复制原始
                  </button>
                  <button className="button compact" onClick={() => void downloadResult()}>
                    <Download size={13} />
                    下载 JSON
                  </button>
                </div>
                {result.ok ? (
                  <PluginResultView data={result.data} />
                ) : (
                  <pre className="plugin-result error">{result.raw}</pre>
                )}
              </div>
            )}
            {history.length > 0 && (
              <details className="plugin-history">
                <summary>
                  <History size={13} />
                  执行历史（{history.length}）
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
          <p className="panel-note">选择左侧插件开始。</p>
        )}
      </div>
    </div>
  );
}

/** 结构化结果渲染：表格（rows/columns、entries、matches）→ JSON → 文本。 */
function PluginResultView({ data }: { data: unknown }) {
  const rendered = useMemo(() => {
    if (data && typeof data === "object") {
      const obj = data as Record<string, unknown>;
      // 表格结构：columns + rows
      if (Array.isArray(obj.columns) && Array.isArray(obj.rows)) {
        const columns = obj.columns.map((c) => String(c));
        const rows = (obj.rows as unknown[][]).map((row) => row.map((v) => (v === null ? "NULL" : String(v))));
        return { kind: "table" as const, columns, rows };
      }
      // 文件条目列表：entries / matches / webshells
      for (const key of ["entries", "matches", "webshells"]) {
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
      // 开放端口等纯数组字段
      if (Array.isArray(obj.open)) {
        return {
          kind: "table" as const,
          columns: ["端口"],
          rows: (obj.open as unknown[]).map((p) => [String(p)]),
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
    }
    return null;
  }, [data]);

  if (rendered?.kind === "table") {
    return (
      <div className="plugin-table-wrap">
        <table className="plugin-table">
          <thead>
            <tr>
              {rendered.columns.map((column) => (
                <th key={column}>{column}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rendered.rows.map((row, i) => (
              <tr key={i}>
                {row.map((cell, j) => (
                  <td key={j} title={cell.length > 120 ? cell : undefined}>
                    {cell.length > 120 ? `${cell.slice(0, 120)}…` : cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }
  return (
    <div className="plugin-json-view">
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </div>
  );
}
