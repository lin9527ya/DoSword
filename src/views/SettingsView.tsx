import { useCallback, useEffect, useState } from "react";
import { Blocks, Moon, PackageOpen, Save, ShieldAlert, ShieldCheck, Sun, Trash2 } from "lucide-react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText } from "../api";
import type { AppSettings, FeatureManifest, PluginManifest } from "../api";
import { Dialog } from "../components/Dialog";
import { ErrorBanner, Panel } from "../components/common";
import { applyTheme, THEME_KEY, currentTheme } from "../theme";

export function SettingsView() {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [plugins, setPlugins] = useState<PluginManifest[]>([]);
  const [featurePlugins, setFeaturePlugins] = useState<FeatureManifest[]>([]);
  const [theme, setTheme] = useState<"light" | "dark">(currentTheme());
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const [confirmDialog, setConfirmDialog] = useState(false);

  function changeTheme(next: "light" | "dark") {
    setTheme(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      // 忽略存储失败
    }
    applyTheme();
  }

  const loadFeaturePlugins = useCallback(() => {
    void api.listFeaturePlugins().then(setFeaturePlugins).catch(() => {});
  }, []);

  async function installPlugin() {
    const localPath = await open({
      multiple: false,
      filters: [
        { name: "DoSword 插件", extensions: ["plugin", "json", "so", "dll", "dylib"] },
      ],
    });
    if (!localPath || Array.isArray(localPath)) return;
    try {
      const ext = String(localPath).split(".").pop()?.toLowerCase();
      if (ext === "so" || ext === "dll" || ext === "dylib") {
        // 二进制插件（Rust cdylib，dlopen 加载）
        await api.installNativePlugin(String(localPath));
      } else {
        // 脚本型插件（JSON 清单）
        const contentB64 = await api.readLocalFile(String(localPath));
        await api.installPlugin(b64.decodeText(contentB64));
      }
      loadFeaturePlugins();
    } catch (cause) {
      setError(`安装失败：${errorText(cause)}`);
    }
  }

  async function uninstallPlugin(id: string) {
    try {
      await api.uninstallPlugin(id);
      loadFeaturePlugins();
    } catch (cause) {
      setError(`卸载失败：${errorText(cause)}`);
    }
  }

  useEffect(() => {
    loadFeaturePlugins();
    void (async () => {
      try {
        setSettings(await api.getSettings());
      } catch (cause) {
        setError(errorText(cause));
      }
    })();
    void (async () => {
      try {
        setPlugins(await api.listPlugins());
      } catch {
        // 插件列表失败不阻塞设置页
      }
    })();
  }, []);

  async function save() {
    if (!settings) return;
    if (settings.httpEnabled && !confirmDialog) {
      setConfirmDialog(true);
      return;
    }
    setError("");
    setSaved(false);
    try {
      await api.updateSettings(settings);
      setSaved(true);
      setConfirmDialog(false);
    } catch (cause) {
      setError(errorText(cause));
    }
  }

  if (!settings) {
    return (
      <>
        <header className="topbar">
          <div>
            <p className="eyebrow">PREFERENCES</p>
            <h1>设置</h1>
          </div>
        </header>
        <ErrorBanner message={error || "正在加载设置…"} />
      </>
    );
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">PREFERENCES</p>
          <h1>设置</h1>
        </div>
        <div className="top-actions">
          <button className="button primary" onClick={() => void save()}>
            <Save size={16} />
            保存
          </button>
        </div>
      </header>
      {error && <ErrorBanner message={error} />}
      {saved && <div className="success-banner">设置已保存。</div>}

      <Panel eyebrow="NETWORK SAFETY GATE" title="真实网络协议">
        <div className="settings-body">
          <label className="toggle-row">
            <div>
              <strong>启用真实网络协议</strong>
              <span>允许向 Shell 端点发送真实 HTTP 请求。关闭后仅可使用本地 Mock 协议。</span>
            </div>
            <input
              type="checkbox"
              checked={settings.httpEnabled}
              onChange={(event) =>
                setSettings({ ...settings, httpEnabled: event.target.checked })
              }
            />
          </label>
          <div className={`safety-banner ${settings.httpEnabled ? "on" : ""}`}>
            <ShieldCheck size={16} />
            {settings.httpEnabled
              ? "真实网络协议已开启：所有请求将发送到已登记且通过授权范围校验的端点。"
              : "真实网络协议已关闭：当前不会产生任何对外网络流量。"}
          </div>
        </div>
      </Panel>

      <Panel eyebrow="COMMUNICATION" title="通信配置">
        <div className="settings-form">
          <label>
            请求超时（秒）
            <input
              type="number"
              min={1}
              max={300}
              value={settings.defaultTimeoutSecs}
              onChange={(event) =>
                setSettings({ ...settings, defaultTimeoutSecs: Number(event.target.value) })
              }
            />
          </label>
          <label>
            HTTP 代理
            <input
              placeholder="留空表示直连，例如 http://127.0.0.1:8080"
              value={settings.proxy ?? ""}
              onChange={(event) =>
                setSettings({ ...settings, proxy: event.target.value || null })
              }
            />
          </label>
          <label>
            响应大小上限（MB）
            <input
              type="number"
              min={1}
              max={1024}
              value={settings.maxFileSizeMb}
              onChange={(event) =>
                setSettings({ ...settings, maxFileSizeMb: Number(event.target.value) })
              }
            />
          </label>
        </div>
      </Panel>

      <Panel eyebrow="APPEARANCE" title="主题">
        <div className="theme-switch">
          <button
            className={`theme-option ${theme === "light" ? "active" : ""}`}
            onClick={() => changeTheme("light")}
          >
            <Sun size={16} />
            明亮
          </button>
          <button
            className={`theme-option ${theme === "dark" ? "active" : ""}`}
            onClick={() => changeTheme("dark")}
          >
            <Moon size={16} />
            暗色
          </button>
        </div>
      </Panel>

      <Panel
        eyebrow="FEATURE PLUGINS"
        title="功能插件"
        actions={
          <button className="button compact" onClick={() => void installPlugin()}>
            <PackageOpen size={14} />
            安装 .plugin
          </button>
        }
      >
        <div className="plugin-list">
          {featurePlugins.length === 0 ? (
            <p className="muted">无功能插件。</p>
          ) : (
            featurePlugins.map((plugin) => (
              <article className="plugin-row" key={plugin.id}>
                <Blocks size={16} />
                <div className="plugin-identity">
                  <strong>{plugin.name}</strong>
                  <code>{plugin.id}</code>
                </div>
                <span className="plugin-kind">
                  {plugin.category === "general" ? "通用" : plugin.category.toUpperCase()}
                </span>
                <span className="plugin-version">v{plugin.version}</span>
                <p className="plugin-desc">{plugin.description}</p>
                {plugin.languages.length > 0 && (
                  <span className="plugin-caps">
                    {plugin.languages.map((language) => (
                      <code key={language} className="shell-tag">
                        {language}
                      </code>
                    ))}
                  </span>
                )}
                <button
                  className="icon-button danger"
                  title="卸载"
                  onClick={() => void uninstallPlugin(plugin.id)}
                >
                  <Trash2 size={15} />
                </button>
              </article>
            ))
          )}
        </div>
      </Panel>

      <Panel eyebrow="PLUGINS" title="协议插件">
        <div className="plugin-list">
          {plugins.length === 0 ? (
            <p className="muted">无插件。</p>
          ) : (
            plugins.map((plugin) => (
              <article className="plugin-row" key={plugin.id}>
                <Blocks size={16} />
                <div className="plugin-identity">
                  <strong>{plugin.name}</strong>
                  <code>{plugin.id}</code>
                </div>
                <span className="plugin-kind">
                  {plugin.kind === "protocol" ? "协议" : "功能"}
                </span>
                <span className="plugin-version">v{plugin.version}</span>
                <p className="plugin-desc">{plugin.description}</p>
                {plugin.capabilities.length > 0 && (
                  <span className="plugin-caps">
                    {plugin.capabilities.map((capability) => (
                      <code key={capability} className="shell-tag">
                        {capability}
                      </code>
                    ))}
                  </span>
                )}
              </article>
            ))
          )}
        </div>
      </Panel>

      {confirmDialog && (
        <Dialog title="确认开启真实网络协议" onClose={() => setConfirmDialog(false)}>
          <div className="dialog-warning">
            <ShieldAlert size={20} />
            <p>
              开启后，DoSword 将向已登记的端点发送真实 HTTP 请求。请确认：所有目标均位于你的授权测试范围内，
              且每个 Shell 的创建流程已要求勾选「我已确认目标位于授权范围内」。
            </p>
          </div>
          <div className="dialog-actions">
            <button className="button secondary" onClick={() => setConfirmDialog(false)}>
              取消
            </button>
            <button className="button primary" onClick={() => void save()}>
              我已了解，开启
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}
