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
  const [backupDir, setBackupDir] = useState(() => localStorage.getItem("dosword:backup-dir") ?? "");
  const [backupEnabled, setBackupEnabled] = useState(() => localStorage.getItem("dosword:backup-enabled") === "1");
  const [backupNote, setBackupNote] = useState("");
  const [customStub, setCustomStub] = useState("");
  const [stubBusy, setStubBusy] = useState(false);
  const [stubNote, setStubNote] = useState("");

  async function registerStub() {
    setStubBusy(true);
    setStubNote("");
    try {
      await api.registerCustomEncoder(customStub);
      setStubNote("注册成功：生成 Shell 时编码器选择「自定义」即可使用");
    } catch (cause) {
      setStubNote(`注册失败：${errorText(cause)}`);
    } finally {
      setStubBusy(false);
    }
  }

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

  async function runBackup() {
    if (!backupDir.trim()) return;
    try {
      const file = await api.backupShells(backupDir.trim());
      setBackupNote(`备份完成：${file}`);
    } catch (cause) {
      setBackupNote(`备份失败：${errorText(cause)}`);
    }
  }

  function saveBackupConfig(enabled: boolean, dir: string) {
    setBackupEnabled(enabled);
    setBackupDir(dir);
    localStorage.setItem("dosword:backup-enabled", enabled ? "1" : "0");
    localStorage.setItem("dosword:backup-dir", dir);
  }

  useEffect(() => {
    if (!backupEnabled) return;
    // 启动备份 + 每小时轮询（V3.0 远程同步本地版）
    void runBackup();
    const timer = setInterval(() => void runBackup(), 60 * 60 * 1000);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [backupEnabled, backupDir]);

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
            <p className="eyebrow">偏好设置</p>
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
          <p className="eyebrow">偏好设置</p>
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

      <Panel eyebrow="网络安全门" title="真实网络协议">
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

      <Panel eyebrow="通信配置" title="通信配置">
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
          <label>
            分块传输大小（MB）
            <input
              type="number"
              min={1}
              max={64}
              value={settings.chunkSizeMb}
              onChange={(event) =>
                setSettings({ ...settings, chunkSizeMb: Number(event.target.value) })
              }
            />
          </label>
          <label className="settings-check">
            <input
              type="checkbox"
              checked={settings.allowArbitraryCode}
              onChange={(event) =>
                setSettings({ ...settings, allowArbitraryCode: event.target.checked })
              }
            />
            允许 run_code 任意代码执行（关闭后插件载荷将无法运行）
          </label>
          <label>
            审计日志保留天数（0 = 不清理）
            <input
              type="number"
              min={0}
              max={3650}
              value={settings.auditRetentionDays}
              onChange={(event) =>
                setSettings({ ...settings, auditRetentionDays: Number(event.target.value) })
              }
            />
          </label>
        </div>
      </Panel>

      <Panel eyebrow="自定义编码器" title="自定义编码器（Custom）">
        <div className="settings-form">
          <p className="field-hint">
            粘贴自定义 PHP stub（需包含 &lt;?php）。载荷协议为 XOR + Base64（密钥由密码 md5 派生），
            stub 需实现：读取 POST formData 参数 → base64 解码 → XOR 还原 → 执行。
          </p>
          <textarea
            className="custom-stub-input"
            rows={8}
            value={customStub}
            onChange={(event) => setCustomStub(event.target.value)}
            placeholder="<?php&#10;// 自定义 stub：解析 formData（base64 + XOR md5 密钥）并执行载荷&#10;..."
            spellCheck={false}
          />
          <div className="settings-row">
            <button className="button primary" onClick={() => void registerStub()} disabled={stubBusy}>
              <Blocks size={15} />
              {stubBusy ? "注册中…" : "注册 stub"}
            </button>
            {stubNote && <span className={stubNote.startsWith("注册失败") ? "form-note error" : "form-note"}>{stubNote}</span>}
          </div>
        </div>
      </Panel>

      <Panel eyebrow="外观" title="主题">
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
        eyebrow="功能插件"
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

      <Panel eyebrow="自动备份" title="自动备份（V3.0 远程同步·本地版）">
        <div className="backup-form">
          <label className="confirm-row">
            <input
              type="checkbox"
              checked={backupEnabled}
              onChange={(event) => saveBackupConfig(event.target.checked, backupDir)}
            />
            <span>启用自动备份（启动时 + 每小时导出全部 Shell 配置）</span>
          </label>
          <div className="repeater-row">
            <input
              className="backup-dir"
              value={backupDir}
              onChange={(event) => saveBackupConfig(backupEnabled, event.target.value)}
              placeholder="备份目录，如 /home/user/dosword-backups"
              spellCheck={false}
            />
            <button className="button compact" onClick={() => void runBackup()} disabled={!backupDir.trim()}>
              立即备份
            </button>
          </div>
          {backupNote && <p className="form-note ok">{backupNote}</p>}
          <p className="field-hint">
            备份文件为 JSON（含全部 Shell 配置与密码），请妥善保管；
            配合「导入」可在其他机器恢复（团队共享 / 迁移）。
          </p>
        </div>
      </Panel>

      <Panel eyebrow="协议插件" title="协议插件">
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
