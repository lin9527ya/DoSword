import { useCallback, useEffect, useState } from "react";
import { LoaderCircle, Play } from "lucide-react";
import { api, errorText } from "../api";
import type { FeatureManifest } from "../api";

/** 功能插件面板：列出插件 → 填参数 → 执行 → 展示结果（通用/专用分类）。 */
export function PluginPanel({ sessionId }: { sessionId: string }) {
  const [plugins, setPlugins] = useState<FeatureManifest[]>([]);
  const [selected, setSelected] = useState<FeatureManifest | null>(null);
  const [values, setValues] = useState<Record<string, unknown>>({});
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    void api.listFeaturePlugins().then((items) => {
      setPlugins(items);
      if (!selected && items.length > 0) {
        setSelected(items[0]);
        setValues(
          Object.fromEntries(
            items[0].params.map((p) => [p.name, p.default ?? (p.type === "int" ? 0 : p.type === "bool" ? false : "")]),
          ),
        );
      }
    });
  }, [selected]);

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function pick(plugin: FeatureManifest) {
    setSelected(plugin);
    setResult(null);
    setValues(
      Object.fromEntries(
        plugin.params.map((p) => [p.name, p.default ?? (p.type === "int" ? 0 : p.type === "bool" ? false : "")]),
      ),
    );
  }

  async function run() {
    if (!selected) return;
    setBusy(true);
    setResult(null);
    try {
      const out = await api.runFeaturePlugin(sessionId, selected.id, values);
      setResult({ ok: true, text: JSON.stringify(out, null, 2) });
    } catch (cause) {
      setResult({ ok: false, text: errorText(cause) });
    } finally {
      setBusy(false);
    }
  }

  const byKind = (kind: string) => plugins.filter((p) => p.kind === kind);
  const feature = byKind("feature");
  const crypto = byKind("crypto");
  const loader = byKind("loader");
  const others = plugins.filter((p) => !["feature", "crypto", "loader"].includes(p.kind));

  return (
    <div className="plugin-panel">
      <div className="plugin-sidebar">
        {feature.length > 0 && <p className="plugin-group">功能</p>}
        {feature.map((plugin) => (
          <button
            key={plugin.id}
            className={`plugin-item ${selected?.id === plugin.id ? "active" : ""}`}
            onClick={() => pick(plugin)}
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
          >
            {plugin.name}
          </button>
        ))}
      </div>
      <div className="plugin-main">
        {selected ? (
          <>
            <h3>{selected.name}</h3>
            <p className="field-hint">{selected.description}</p>
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
                ) : (
                  <input
                    value={String(values[param.name] ?? "")}
                    onChange={(event) => setValues((prev) => ({ ...prev, [param.name]: event.target.value }))}
                    placeholder={param.default != null ? String(param.default) : ""}
                  />
                )}
              </label>
            ))}
            <button className="button primary" onClick={() => void run()} disabled={busy}>
              {busy ? <LoaderCircle className="spin" size={15} /> : <Play size={15} />}
              执行
            </button>
            {result && (
              <>
                <div className="plugin-result-actions">
                  <button
                    className="button compact"
                    onClick={() => void navigator.clipboard?.writeText(result.text)}
                  >
                    复制结果
                  </button>
                </div>
                <pre className={`plugin-result ${result.ok ? "" : "error"}`}>{result.text}</pre>
              </>
            )}
          </>
        ) : (
          <p className="panel-note">选择左侧插件开始。</p>
        )}
      </div>
    </div>
  );
}
