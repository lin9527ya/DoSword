import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Blocks,
  ChevronsLeft,
  ChevronsRight,
  Clock,
  Edit3,
  Globe,
  HardDrive,
  Moon,
  PackageOpen,
  Palette,
  Plus,
  Save,
  Search,
  Shield,
  ShieldAlert,
  Sun,
  Trash2,
  Wifi,
  WifiOff,
  X,
  Zap,
} from "lucide-react";
import { open } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText } from "../api";
import type { AppSettings, FeatureManifest, PluginManifest } from "../api";
import { Dialog } from "../components/Dialog";
import { ErrorBanner, Metric, Panel, UpwardPageSizeSelect } from "../components/common";
import { applyTheme, THEME_KEY, currentTheme } from "../theme";
import { useToast } from "../components/Toast";
import { PluginStudioModal } from "../components/PluginStudioModal";

type SettingsTab = "security" | "network" | "plugins" | "encoder" | "backup" | "appearance";

const DISABLED_PLUGINS_KEY = "dosword:disabled-plugins";

export function SettingsView() {
  const toast = useToast();
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [plugins, setPlugins] = useState<PluginManifest[]>([]);
  const [featurePlugins, setFeaturePlugins] = useState<FeatureManifest[]>([]);
  const [disabledPlugins, setDisabledPlugins] = useState<string[]>(() => {
    try {
      return JSON.parse(localStorage.getItem(DISABLED_PLUGINS_KEY) ?? "[]") as string[];
    } catch {
      return [];
    }
  });
  const [studioOpen, setStudioOpen] = useState(false);
  const [studioInitialMode, setStudioInitialMode] = useState<"edit" | "test">("edit");
  const [editingPlugin, setEditingPlugin] = useState<FeatureManifest | null>(null);
  const [theme, setTheme] = useState<"light" | "dark">(currentTheme());
  const [activeTab, setActiveTab] = useState<SettingsTab>("security");
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const [confirmDialog, setConfirmDialog] = useState(false);
  const [backupDir, setBackupDir] = useState(() => localStorage.getItem("dosword:backup-dir") ?? "");
  const [backupEnabled, setBackupEnabled] = useState(() => localStorage.getItem("dosword:backup-enabled") === "1");
  const [backupNote, setBackupNote] = useState("");
  const [customStub, setCustomStub] = useState("");
  const [stubBusy, setStubBusy] = useState(false);
  const [stubNote, setStubNote] = useState("");

  // 代理连通性测试状态
  const [proxyTesting, setProxyTesting] = useState(false);
  const [proxyTestResult, setProxyTestResult] = useState<{
    ok: boolean;
    latency_ms: number;
    message: string;
    exit_ip?: string | null;
  } | null>(null);

  async function handleTestProxy() {
    if (!settings) return;
    setProxyTesting(true);
    setProxyTestResult(null);
    try {
      const res = await api.testProxyUpstream(settings.proxy, settings.defaultTimeoutSecs);
      setProxyTestResult(res);
      if (res.ok) {
        toast.success(res.message, `代理连通有效 (${res.latency_ms}ms)`);
      } else {
        toast.error(res.message, "代理测试失败");
      }
    } catch (e) {
      const msg = errorText(e);
      setProxyTestResult({ ok: false, latency_ms: 0, message: msg });
      toast.error(msg, "代理测试异常");
    } finally {
      setProxyTesting(false);
    }
  }

  // 插件管理：搜索、分类过滤、分页与跳转页
  const [pluginSearch, setPluginSearch] = useState("");
  const [pluginCategory, setPluginCategory] = useState<string>("all");
  const [pluginStatusFilter, setPluginStatusFilter] = useState<"all" | "enabled" | "disabled">("all");
  const [pluginPage, setPluginPage] = useState(0);
  const [pluginPageSize, setPluginPageSize] = useState(10);
  const [jumpPageStr, setJumpPageStr] = useState("");

  function togglePluginStatus(id: string, name: string) {
    setDisabledPlugins((prev) => {
      const isCurrentlyDisabled = prev.includes(id);
      const next = isCurrentlyDisabled ? prev.filter((x) => x !== id) : [...prev, id];
      localStorage.setItem(DISABLED_PLUGINS_KEY, JSON.stringify(next));
      toast.info(isCurrentlyDisabled ? `已启用插件「${name}」` : `已禁用插件「${name}」`);
      return next;
    });
  }

  const allPluginsList = useMemo(() => {
    const protocolItems: FeatureManifest[] = plugins.map((p) => ({
      id: p.id,
      name: p.name,
      version: p.version,
      description: p.description || "底层 WebShell 载荷编解码与通信协议引擎",
      category: "protocol",
      kind: "protocol",
      languages: p.capabilities && p.capabilities.length > 0 ? p.capabilities : ["核心"],
      params: [],
    }));
    return [...featurePlugins, ...protocolItems];
  }, [featurePlugins, plugins]);

  const filteredPlugins = useMemo(() => {
    return allPluginsList.filter((plugin) => {
      const isDisabled = disabledPlugins.includes(plugin.id);
      if (pluginStatusFilter === "enabled" && isDisabled) return false;
      if (pluginStatusFilter === "disabled" && !isDisabled) return false;

      if (pluginCategory !== "all") {
        if (pluginCategory === "protocol") {
          if (plugin.category !== "protocol" && plugin.kind !== "protocol") return false;
        } else {
          const cat = (plugin.category || "general").toLowerCase();
          if (pluginCategory === "general" && (cat !== "general" || plugin.kind === "protocol")) return false;
          if (pluginCategory === "php" && cat !== "php") return false;
          if (pluginCategory === "bypass" && !plugin.id.startsWith("bypass") && cat !== "bypass") return false;
          if (pluginCategory === "proxy" && !plugin.id.includes("proxy") && !plugin.id.includes("forward") && !plugin.id.includes("port_map")) return false;
          if (pluginCategory === "crypto" && cat !== "crypto" && !plugin.id.includes("crypto")) return false;
        }
      }

      if (pluginSearch.trim()) {
        const q = pluginSearch.trim().toLowerCase();
        const matchName = plugin.name.toLowerCase().includes(q);
        const matchId = plugin.id.toLowerCase().includes(q);
        const matchDesc = plugin.description.toLowerCase().includes(q);
        const matchCat = plugin.category.toLowerCase().includes(q);
        const matchLang = plugin.languages.some((l) => l.toLowerCase().includes(q));
        if (!matchName && !matchId && !matchDesc && !matchCat && !matchLang) return false;
      }

      return true;
    });
  }, [allPluginsList, disabledPlugins, pluginStatusFilter, pluginCategory, pluginSearch]);

  const pluginPageCount = useMemo(() => {
    if (pluginPageSize === 0) return 1;
    return Math.max(1, Math.ceil(filteredPlugins.length / pluginPageSize));
  }, [filteredPlugins.length, pluginPageSize]);

  useEffect(() => {
    if (pluginPage >= pluginPageCount) {
      setPluginPage(Math.max(0, pluginPageCount - 1));
    }
  }, [pluginPage, pluginPageCount]);

  const pagedPlugins = useMemo(() => {
    if (pluginPageSize === 0) return filteredPlugins;
    const start = pluginPage * pluginPageSize;
    return filteredPlugins.slice(start, start + pluginPageSize);
  }, [filteredPlugins, pluginPage, pluginPageSize]);

  const enabledCount = useMemo(() => {
    return allPluginsList.filter((p) => !disabledPlugins.includes(p.id)).length;
  }, [allPluginsList, disabledPlugins]);

  const disabledCount = useMemo(() => {
    return allPluginsList.filter((p) => disabledPlugins.includes(p.id)).length;
  }, [allPluginsList, disabledPlugins]);

  function handleJumpPage() {
    const p = parseInt(jumpPageStr, 10);
    if (!isNaN(p) && p >= 1 && p <= pluginPageCount) {
      setPluginPage(p - 1);
      setJumpPageStr("");
    } else {
      toast.warning(`请输入 1 到 ${pluginPageCount} 之间的有效页码`);
    }
  }

  async function registerStub() {
    if (!customStub.trim()) {
      toast.warning("请粘贴自定义 PHP Stub 代码");
      return;
    }
    setStubBusy(true);
    setStubNote("");
    try {
      await api.registerCustomEncoder(customStub);
      const msg = "注册成功：生成 Webshell 时编码器选择「自定义 (Custom)」即可生效";
      setStubNote(msg);
      toast.success(msg, "编码器已就绪");
    } catch (cause) {
      const msg = `注册失败：${errorText(cause)}`;
      setStubNote(msg);
      toast.error(msg);
    } finally {
      setStubBusy(false);
    }
  }

  function changeTheme(next: "light" | "dark") {
    setTheme(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      // 忽略
    }
    applyTheme();
    toast.info(`已切换至${next === "dark" ? "暗色极客" : "明亮清晰"}主题`);
  }

  const loadFeaturePlugins = useCallback(() => {
    void api.listFeaturePlugins().then(setFeaturePlugins).catch(() => {});
    void api.listPlugins().then(setPlugins).catch(() => {});
  }, []);

  async function installPlugin() {
    try {
      const localPath = await open({
        multiple: false,
        filters: [
          { name: "DoSword 插件包", extensions: ["plugin", "json", "so", "dll", "dylib"] },
        ],
      });
      if (!localPath || Array.isArray(localPath)) return;
      const ext = String(localPath).split(".").pop()?.toLowerCase();
      if (ext === "so" || ext === "dll" || ext === "dylib") {
        // 二进制插件（Rust cdylib，dlopen 加载）
        await api.installNativePlugin(String(localPath));
      } else {
        // 脚本型插件（JSON 清单）
        const contentB64 = await api.readLocalFile(String(localPath));
        await api.installPlugin(b64.decodeText(contentB64));
      }
      toast.success("插件模块安装并装配完成", "安装成功");
      loadFeaturePlugins();
    } catch (cause) {
      toast.error(errorText(cause), "安装插件失败");
    }
  }

  async function uninstallPlugin(id: string) {
    try {
      await api.uninstallPlugin(id);
      toast.info(`已卸载插件 ${id}`);
      loadFeaturePlugins();
    } catch (cause) {
      toast.error(errorText(cause), "卸载失败");
    }
  }

  async function runBackup() {
    if (!backupDir.trim()) {
      toast.warning("请填写有效的备份存放目录");
      return;
    }
    try {
      const file = await api.backupShells(backupDir.trim());
      setBackupNote(`备份完成：${file}`);
      toast.success(`Shell 配置已备份至 ${file}`, "备份成功");
    } catch (cause) {
      const msg = `备份失败：${errorText(cause)}`;
      setBackupNote(msg);
      toast.error(msg);
    }
  }

  function saveBackupConfig(enabled: boolean, dir: string) {
    setBackupEnabled(enabled);
    setBackupDir(dir);
    localStorage.setItem("dosword:backup-enabled", enabled ? "1" : "0");
    localStorage.setItem("dosword:backup-dir", dir);
    toast.info(enabled ? "已开启定时自动备份 (每小时导出)" : "已关闭自动备份");
  }

  useEffect(() => {
    if (!backupEnabled) return;
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
        // 忽略
      }
    })();
  }, [loadFeaturePlugins]);

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
      toast.success("系统首选项已更新并持久化保存", "保存成功");
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "保存失败");
    }
  }

  if (!settings) {
    return (
      <>
        <header className="topbar">
          <div>
            <p className="eyebrow">PREFERENCES</p>
            <h1>系统设置与首选项</h1>
          </div>
        </header>
        <ErrorBanner message={error || "正在加载系统设置…"} />
      </>
    );
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">SYSTEM CONFIGURATION & SECURITY</p>
          <h1>系统首选项与环境设置</h1>
        </div>
        <div className="top-actions">
          <button className="button primary" onClick={() => void save()}>
            <Save size={15} />
            保存全部设置
          </button>
        </div>
      </header>

      {error && <ErrorBanner message={error} />}
      {saved && <div className="success-banner">✓ 系统设置已成功保存并立即生效。</div>}

      {/* 状态统计卡片 */}
      <section className="metrics">
        <Metric
          label="网络安全门"
          value={settings.httpEnabled ? "真实网络" : "沙箱模式"}
          detail={settings.httpEnabled ? "允许对外 HTTP 发包" : "只读 Mock 隔离"}
          accent={settings.httpEnabled}
          icon={settings.httpEnabled ? <Wifi size={16} /> : <WifiOff size={16} />}
          onClick={() => setActiveTab("security")}
        />
        <Metric
          label="上游代理"
          value={settings.proxy ? "已配置" : "直连"}
          detail={settings.proxy || "未启用代理"}
          icon={<Globe size={16} />}
          onClick={() => setActiveTab("network")}
        />
        <Metric
          label="超时阈值"
          value={`${settings.defaultTimeoutSecs} 秒`}
          detail="HTTP 探测超时"
          icon={<Clock size={16} />}
          onClick={() => setActiveTab("network")}
        />
        <Metric
          label="已装载插件"
          value={featurePlugins.length + plugins.length}
          detail="功能/协议模块"
          icon={<PackageOpen size={16} />}
          onClick={() => setActiveTab("plugins")}
        />
        <Metric
          label="界面主题"
          value={theme === "dark" ? "暗色极客" : "明亮清晰"}
          detail="外观色彩配置"
          icon={<Palette size={16} />}
          onClick={() => setActiveTab("appearance")}
        />
      </section>

      {/* 设置分类选项卡 */}
      <div className="detail-tabs">
        <button
          className={`detail-tab ${activeTab === "security" ? "active" : ""}`}
          onClick={() => setActiveTab("security")}
        >
          <Shield size={15} />
          安全门禁
        </button>
        <button
          className={`detail-tab ${activeTab === "network" ? "active" : ""}`}
          onClick={() => setActiveTab("network")}
        >
          <Globe size={15} />
          通信性能与代理
        </button>
        <button
          className={`detail-tab ${activeTab === "plugins" ? "active" : ""}`}
          onClick={() => setActiveTab("plugins")}
        >
          <PackageOpen size={15} />
          插件与扩展模块 ({featurePlugins.length + plugins.length})
        </button>
        <button
          className={`detail-tab ${activeTab === "encoder" ? "active" : ""}`}
          onClick={() => setActiveTab("encoder")}
        >
          <Blocks size={15} />
          自定义编码器
        </button>
        <button
          className={`detail-tab ${activeTab === "backup" ? "active" : ""}`}
          onClick={() => setActiveTab("backup")}
        >
          <HardDrive size={15} />
          自动定时备份
        </button>
        <button
          className={`detail-tab ${activeTab === "appearance" ? "active" : ""}`}
          onClick={() => setActiveTab("appearance")}
        >
          <Palette size={15} />
          外观与主题
        </button>
      </div>

      {/* 1. 安全门禁 */}
      {activeTab === "security" && (
        <Panel eyebrow="SECURITY GATEWAY" title="真实网络发包安全门与授权防护">
          <div className="settings-body">
            <label className="toggle-row">
              <div>
                <strong>启用真实对外网络发包协议</strong>
                <span>允许客户端向已授权的 WebShell 端点发送真实 HTTP/HTTPS 请求。关闭后仅限本地 Mock 沙箱协议。</span>
              </div>
              <input
                type="checkbox"
                checked={settings.httpEnabled}
                onChange={(event) =>
                  setSettings({ ...settings, httpEnabled: event.target.checked })
                }
              />
            </label>

            <label>
              审计轨迹日志自动保留天数 (0 为永久保留)
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
      )}

      {/* 2. 通信性能与代理 */}
      {activeTab === "network" && (
        <Panel eyebrow="NETWORK & PROXY" title="全局网络代理上游与通信传输性能">
          <div className="settings-body">
            <div>
              <label>
                全局 HTTP / SOCKS5 代理上游 (支持 Burp Suite、Charles、SOCKS5 隧道或 Clash 联动)
                <div style={{ display: "flex", gap: 10, marginTop: 6 }}>
                  <input
                    type="text"
                    style={{ flex: 1 }}
                    placeholder="留空为直连，例如 socks5://127.0.0.1:10808 或 http://127.0.0.1:8080"
                    value={settings.proxy ?? ""}
                    onChange={(event) => {
                      setProxyTestResult(null);
                      setSettings({
                        ...settings,
                        proxy: event.target.value ? event.target.value : null,
                      });
                    }}
                  />
                  <button
                    type="button"
                    className="button secondary"
                    disabled={proxyTesting}
                    onClick={() => void handleTestProxy()}
                    style={{ whiteSpace: "nowrap", display: "inline-flex", alignItems: "center", gap: 6 }}
                  >
                    <Zap size={14} className={proxyTesting ? "spin" : ""} />
                    {proxyTesting ? "正在测速..." : "⚡ 测试代理连通性"}
                  </button>
                </div>
              </label>

              {/* 常用代理快捷填入预设 */}
              <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap", alignItems: "center" }}>
                <span style={{ fontSize: 12, color: "var(--muted)" }}>常用预设:</span>
                <button
                  type="button"
                  className="tag-badge"
                  style={{ cursor: "pointer", background: !settings.proxy ? "var(--accent-soft)" : undefined, borderColor: !settings.proxy ? "var(--accent)" : undefined }}
                  onClick={() => {
                    setProxyTestResult(null);
                    setSettings({ ...settings, proxy: null });
                  }}
                >
                  直连 (不使用代理)
                </button>
                <button
                  type="button"
                  className="tag-badge"
                  style={{ cursor: "pointer" }}
                  onClick={() => {
                    setProxyTestResult(null);
                    setSettings({ ...settings, proxy: "http://127.0.0.1:8080" });
                  }}
                >
                  Burp Suite (http://127.0.0.1:8080)
                </button>
                <button
                  type="button"
                  className="tag-badge"
                  style={{ cursor: "pointer" }}
                  onClick={() => {
                    setProxyTestResult(null);
                    setSettings({ ...settings, proxy: "http://127.0.0.1:8888" });
                  }}
                >
                  Charles (http://127.0.0.1:8888)
                </button>
                <button
                  type="button"
                  className="tag-badge"
                  style={{ cursor: "pointer" }}
                  onClick={() => {
                    setProxyTestResult(null);
                    setSettings({ ...settings, proxy: "socks5://127.0.0.1:10808" });
                  }}
                >
                  SOCKS5 隧道 (socks5://127.0.0.1:10808)
                </button>
                <button
                  type="button"
                  className="tag-badge"
                  style={{ cursor: "pointer" }}
                  onClick={() => {
                    setProxyTestResult(null);
                    setSettings({ ...settings, proxy: "http://127.0.0.1:7890" });
                  }}
                >
                  Clash 代理 (http://127.0.0.1:7890)
                </button>
              </div>

              {/* 代理测试结果卡片 */}
              {proxyTestResult && (
                <div
                  style={{
                    marginTop: 12,
                    padding: "10px 14px",
                    borderRadius: "var(--radius-sm)",
                    background: proxyTestResult.ok ? "rgba(34, 197, 94, 0.08)" : "rgba(239, 68, 68, 0.08)",
                    border: `1px solid ${proxyTestResult.ok ? "rgba(34, 197, 94, 0.3)" : "rgba(239, 68, 68, 0.3)"}`,
                    fontSize: 13,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 12,
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, color: proxyTestResult.ok ? "var(--success)" : "var(--danger)" }}>
                      {proxyTestResult.ok ? "✅ " : "❌ "}
                      {proxyTestResult.message}
                    </div>
                    {proxyTestResult.exit_ip && (
                      <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 2 }}>
                        出口 IP: <code>{proxyTestResult.exit_ip}</code>
                      </div>
                    )}
                  </div>
                  {proxyTestResult.ok && (
                    <span className="badge" style={{ background: "rgba(34, 197, 94, 0.15)", color: "var(--success)" }}>
                      耗时 {proxyTestResult.latency_ms}ms
                    </span>
                  )}
                </div>
              )}
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14 }}>
              <label>
                默认请求超时时间 (秒)
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
                单文件上传分块大小 (MB)
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
              <label>
                单次响应包大小上限 (MB)
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

            <label className="toggle-row">
              <div>
                <strong>开启 Gzip 传输压缩</strong>
                <span>目标服务端支持 zlib 时自动启用双向压缩，显著节省渗透与文件交互带宽。</span>
              </div>
              <input
                type="checkbox"
                checked={settings.gzipEnabled}
                onChange={(event) =>
                  setSettings({ ...settings, gzipEnabled: event.target.checked })
                }
              />
            </label>
          </div>
        </Panel>
      )}

      {/* 3. 插件与扩展模块 */}
      {activeTab === "plugins" && (
        <Panel
          eyebrow="EXTENSIONS & MODULES"
          title={`已装载功能与协议插件 (${featurePlugins.length + plugins.length})`}
          actions={
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="button compact secondary"
                onClick={() => {
                  setEditingPlugin(null);
                  setStudioInitialMode("edit");
                  setStudioOpen(true);
                }}
              >
                <Plus size={14} />
                开发自定义插件 (.plugin)
              </button>
              <button className="button compact primary" onClick={() => void installPlugin()}>
                <PackageOpen size={14} />
                安装插件包 (.plugin / .so / .dll)
              </button>
            </div>
          }
        >
          <div className="plugin-mgmt-wrap">
            {/* 顶部指标卡片 */}
            <div className="plugin-stats-row">
              <div className="plugin-stat-card accent">
                <span>已装载插件总数</span>
                <strong>{allPluginsList.length}</strong>
              </div>
              <div className="plugin-stat-card ok">
                <span>已启用插件</span>
                <strong>{enabledCount}</strong>
              </div>
              <div className="plugin-stat-card warn">
                <span>已禁用插件</span>
                <strong>{disabledCount}</strong>
              </div>
              <div className="plugin-stat-card">
                <span>当前筛选匹配</span>
                <strong>{filteredPlugins.length}</strong>
              </div>
            </div>

            {/* 搜索与分类过滤栏 */}
            <div className="plugin-filter-toolbar">
              <div className="plugin-search-input-wrap">
                <Search size={14} style={{ color: "var(--text-faint)" }} />
                <input
                  type="text"
                  placeholder="搜索插件名称、标识 ID、功能描述或运行时语言…"
                  value={pluginSearch}
                  onChange={(e) => {
                    setPluginSearch(e.target.value);
                    setPluginPage(0);
                  }}
                />
                {pluginSearch && (
                  <button
                    type="button"
                    className="icon-button compact"
                    onClick={() => {
                      setPluginSearch("");
                      setPluginPage(0);
                    }}
                    title="清空搜索"
                  >
                    <X size={12} />
                  </button>
                )}
              </div>

              {/* 分类标签 */}
              <div className="plugin-category-pills">
                {[
                  { id: "all", label: "全部", count: allPluginsList.length },
                  { id: "protocol", label: "通信协议", count: allPluginsList.filter((p) => p.category === "protocol" || p.kind === "protocol").length },
                  { id: "general", label: "通用工具", count: allPluginsList.filter((p) => (p.category || "general") === "general" && p.kind !== "protocol").length },
                  { id: "php", label: "PHP 专项", count: allPluginsList.filter((p) => p.category === "php").length },
                  { id: "bypass", label: "Bypass 绕过", count: allPluginsList.filter((p) => p.id.startsWith("bypass") || p.category === "bypass").length },
                  { id: "proxy", label: "网络代理", count: allPluginsList.filter((p) => p.id.includes("proxy") || p.id.includes("forward") || p.id.includes("port_map")).length },
                  { id: "crypto", label: "密码学", count: allPluginsList.filter((p) => p.category === "crypto" || p.id.includes("crypto")).length },
                ].map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    className={`plugin-pill-btn ${pluginCategory === item.id ? "active" : ""}`}
                    onClick={() => {
                      setPluginCategory(item.id);
                      setPluginPage(0);
                    }}
                  >
                    <span>{item.label}</span>
                    <span className="plugin-pill-count">{item.count}</span>
                  </button>
                ))}
              </div>

              {/* 状态筛选 */}
              <div className="button-group compact">
                <button
                  type="button"
                  className={`button compact ${pluginStatusFilter === "all" ? "primary" : "secondary"}`}
                  onClick={() => {
                    setPluginStatusFilter("all");
                    setPluginPage(0);
                  }}
                >
                  全部
                </button>
                <button
                  type="button"
                  className={`button compact ${pluginStatusFilter === "enabled" ? "primary" : "secondary"}`}
                  onClick={() => {
                    setPluginStatusFilter("enabled");
                    setPluginPage(0);
                  }}
                >
                  仅已启用
                </button>
                <button
                  type="button"
                  className={`button compact ${pluginStatusFilter === "disabled" ? "primary" : "secondary"}`}
                  onClick={() => {
                    setPluginStatusFilter("disabled");
                    setPluginPage(0);
                  }}
                >
                  仅已禁用
                </button>
              </div>
            </div>

            {/* 插件数据表格 */}
            <div className="plugin-mgmt-table">
              <div className="plugin-mgmt-header">
                <span>状态</span>
                <span></span>
                <span>插件名称 / ID</span>
                <span>分类</span>
                <span>版本</span>
                <span>运行时</span>
                <span>功能描述</span>
                <span style={{ textAlign: "right" }}>操作</span>
              </div>

              <div className="plugin-list">
                {filteredPlugins.length === 0 ? (
                  <p className="muted" style={{ padding: "28px 20px", textAlign: "center", margin: 0 }}>
                    未检索到匹配的扩展插件。可调整搜索关键词或重置筛选条件。
                  </p>
                ) : (
                  pagedPlugins.map((plugin) => {
                    const isDisabled = disabledPlugins.includes(plugin.id);
                    return (
                      <article
                        className={`plugin-row ${isDisabled ? "disabled" : ""}`}
                        key={plugin.id}
                      >
                        {/* 启用/禁用 开关 */}
                        <label className="plugin-switch" title={isDisabled ? "点击启用该插件" : "点击禁用该插件"}>
                          <input
                            type="checkbox"
                            checked={!isDisabled}
                            onChange={() => togglePluginStatus(plugin.id, plugin.name)}
                          />
                          <span className="plugin-slider" />
                        </label>

                        <Blocks size={16} color={isDisabled ? "var(--text-faint)" : "var(--accent)"} />
                        <div className="plugin-identity">
                          <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                            <strong>{plugin.name}</strong>
                            {isDisabled && <span className="plugin-disabled-badge">已禁用</span>}
                          </div>
                          <code>{plugin.id}</code>
                        </div>
                        <div>
                          <span className="plugin-kind">
                            {plugin.category === "general"
                              ? "通用"
                              : plugin.category === "protocol"
                              ? "通信协议"
                              : plugin.category.toUpperCase()}
                          </span>
                        </div>
                        <span className="plugin-version">v{plugin.version}</span>
                        <div className="plugin-caps">
                          {plugin.languages.length > 0 ? (
                            plugin.languages.map((language) => (
                              <code key={language} className="shell-tag">
                                {language}
                              </code>
                            ))
                          ) : (
                            <span style={{ color: "var(--text-faint)", fontSize: 11 }}>通用</span>
                          )}
                        </div>
                        <p className="plugin-desc" title={plugin.description}>
                          {plugin.description}
                        </p>
                        <div style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                          <button
                            className="icon-button"
                            title="联调测试与验证可用性"
                            onClick={() => {
                              setEditingPlugin(plugin);
                              setStudioInitialMode("test");
                              setStudioOpen(true);
                            }}
                          >
                            <Zap size={14} color="var(--accent)" />
                          </button>
                          <button
                            className="icon-button"
                            title="在线编辑此插件"
                            onClick={() => {
                              setEditingPlugin(plugin);
                              setStudioInitialMode("edit");
                              setStudioOpen(true);
                            }}
                          >
                            <Edit3 size={14} />
                          </button>
                          <button
                            className="icon-button danger"
                            title="卸载插件"
                            onClick={() => void uninstallPlugin(plugin.id)}
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </article>
                    );
                  })
                )}
              </div>

              {/* 分页与跳转页工具栏 */}
              <div className="plugin-pagination-bar">
                <div className="plugin-pager-left">
                  <span>
                    第 <strong>{pluginPage + 1}</strong> / {pluginPageCount} 页（共 {filteredPlugins.length} 个插件）
                  </span>
                </div>

                <div className="plugin-pager-right">
                  <button
                    className="button compact secondary"
                    disabled={pluginPage === 0}
                    onClick={() => setPluginPage(0)}
                    title="第一页"
                  >
                    <ChevronsLeft size={13} />
                  </button>
                  <button
                    className="button compact secondary"
                    disabled={pluginPage === 0}
                    onClick={() => setPluginPage((p) => Math.max(0, p - 1))}
                  >
                    上一页
                  </button>
                  <button
                    className="button compact secondary"
                    disabled={pluginPage + 1 >= pluginPageCount}
                    onClick={() => setPluginPage((p) => Math.min(pluginPageCount - 1, p + 1))}
                  >
                    下一页
                  </button>
                  <button
                    className="button compact secondary"
                    disabled={pluginPage + 1 >= pluginPageCount}
                    onClick={() => setPluginPage(pluginPageCount - 1)}
                    title="最后一页"
                  >
                    <ChevronsRight size={13} />
                  </button>

                  <div className="notes-divider-v" />

                  {/* 跳转页输入框 */}
                  <form
                    className="plugin-jump-box"
                    onSubmit={(e) => {
                      e.preventDefault();
                      handleJumpPage();
                    }}
                  >
                    <span>跳至</span>
                    <input
                      type="text"
                      className="plugin-jump-input"
                      value={jumpPageStr}
                      onChange={(e) => setJumpPageStr(e.target.value.replace(/\D/g, ""))}
                      placeholder={String(pluginPage + 1)}
                    />
                    <span>页</span>
                    <button
                      type="submit"
                      className="button compact secondary"
                      disabled={!jumpPageStr}
                    >
                      前往
                    </button>
                  </form>

                  <div className="notes-divider-v" />

                  {/* 每页条数选择 */}
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <span style={{ fontSize: 11, color: "var(--text-faint)" }}>每页:</span>
                    <UpwardPageSizeSelect
                      value={pluginPageSize}
                      onChange={(val) => {
                        setPluginPageSize(val);
                        setPluginPage(0);
                      }}
                      options={[10, 20, 50, 0]}
                    />
                  </div>
                </div>
              </div>
            </div>
          </div>

          <PluginStudioModal
            open={studioOpen}
            onClose={() => {
              setStudioOpen(false);
              setEditingPlugin(null);
            }}
            onSaved={() => {
              loadFeaturePlugins();
            }}
            initialPlugin={editingPlugin}
            initialMode={studioInitialMode}
          />
        </Panel>
      )}

      {/* 4. 自定义编码器 */}
      {activeTab === "encoder" && (
        <Panel eyebrow="CUSTOM ENCODER" title="自定义加解密编码器 (XOR + Base64 模板)">
          <div className="settings-form">
            <p className="field-hint">
              粘贴自定义 PHP Stub 模板。协议规范为：POST formData 载荷经过 XOR 派生密钥混淆与 Base64 编码，Stub 负责还原后动态执行。
            </p>
            <textarea
              className="custom-stub-input"
              rows={8}
              value={customStub}
              onChange={(event) => setCustomStub(event.target.value)}
              placeholder="<?php&#10;// 自定义解码 Stub 示例：读取 POST 参数，XOR 解密后执行&#10;..."
              spellCheck={false}
            />
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <button className="button primary" onClick={() => void registerStub()} disabled={stubBusy}>
                <Blocks size={15} />
                {stubBusy ? "注册中…" : "注册并热装载 Stub"}
              </button>
              {stubNote && (
                <span className={stubNote.startsWith("注册失败") ? "form-note error" : "form-note ok"}>
                  {stubNote}
                </span>
              )}
            </div>
          </div>
        </Panel>
      )}

      {/* 5. 自动定时备份 */}
      {activeTab === "backup" && (
        <Panel eyebrow="BACKUP & SYNC" title="配置持久化与定时全量备份">
          <div className="backup-form">
            <label className="toggle-row">
              <div>
                <strong>启用自动定时备份</strong>
                <span>软件启动及每小时定时将所有已登记的 Shell 凭据配置导出至本地备份目录。</span>
              </div>
              <input
                type="checkbox"
                checked={backupEnabled}
                onChange={(event) => saveBackupConfig(event.target.checked, backupDir)}
              />
            </label>
            <div className="repeater-row" style={{ marginTop: 8 }}>
              <input
                className="backup-dir"
                value={backupDir}
                onChange={(event) => saveBackupConfig(backupEnabled, event.target.value)}
                placeholder="本地备份绝对路径，例如 /home/kali/dosword-backups"
                spellCheck={false}
              />
              <button className="button primary compact" onClick={() => void runBackup()} disabled={!backupDir.trim()}>
                立即备份
              </button>
            </div>
            {backupNote && <p className="form-note ok">{backupNote}</p>}
            <p className="field-hint">
              备份文件为格式化 JSON，可用于在团队成员间分发或机器迁移时通过总览「导入」快速恢复。
            </p>
          </div>
        </Panel>
      )}

      {/* 6. 外观与主题 */}
      {activeTab === "appearance" && (
        <Panel eyebrow="APPEARANCE" title="界面色彩与主题设置">
          <div className="theme-switch">
            <button
              className={`theme-option ${theme === "dark" ? "active" : ""}`}
              onClick={() => changeTheme("dark")}
            >
              <Moon size={16} />
              暗色极客 (Dark)
            </button>
            <button
              className={`theme-option ${theme === "light" ? "active" : ""}`}
              onClick={() => changeTheme("light")}
            >
              <Sun size={16} />
              明亮清晰 (Light)
            </button>
          </div>
        </Panel>
      )}

      {confirmDialog && (
        <Dialog title="确认开启真实对外网络发包" onClose={() => setConfirmDialog(false)}>
          <div className="dialog-warning">
            <ShieldAlert size={22} />
            <p>
              开启后，DoSword 将允许向已登记的真实 WebShell 发起 HTTP 探测及命令执行请求。
              <br />
              请务必确保所有测试端点已取得正规合法授权，并在对应的 Workspace 中正确设定了白名单范围。
            </p>
          </div>
          <div className="dialog-actions" style={{ padding: "16px 20px" }}>
            <button className="button secondary" onClick={() => setConfirmDialog(false)}>
              取消
            </button>
            <button className="button primary" onClick={() => void save()}>
              我已确认授权，开启
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}
