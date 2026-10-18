import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  CirclePlus,
  Wand2,
  FilePenLine,
  FolderKanban,
  LayoutGrid,
  List,
  LoaderCircle,
  PlugZap,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  TerminalSquare,
  Upload,
  Download,
} from "lucide-react";
import { ask, open, save } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText, shortTime } from "../api";
import type { Dashboard, ProtocolMeta, ShellProfile, Workspace } from "../api";
import { Dialog } from "../components/Dialog";
import { Empty, ErrorBanner, Metric, Panel } from "../components/common";
import { GenerateShellDialog } from "../widgets/GenerateShellDialog";
import { useToast } from "../components/Toast";
import type { View } from "./types";

const EMPTY_DASHBOARD: Dashboard = { workspaces: [], shells: [], auditEvents: [] };

/** 解析标签输入（逗号/空格/顿号分隔，去重去空）。 */
function parseTags(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[,，;\s]+/)
        .map((tag) => tag.trim())
        .filter(Boolean),
    ),
  ];
}

/** Workspace 到期状态。 */
function expiryInfo(workspace: Workspace): { label: string; kind: "ok" | "warn" | "expired" } {
  if (!workspace.expiresAt) return { label: "长期有效", kind: "ok" };
  const days = Math.ceil((new Date(workspace.expiresAt).getTime() - Date.now()) / 86_400_000);
  if (days < 0) return { label: `已过期 ${-days} 天`, kind: "expired" };
  if (days === 0) return { label: "今日到期", kind: "warn" };
  if (days <= 7) return { label: `${days} 天后到期`, kind: "warn" };
  return { label: `${days} 天后到期`, kind: "ok" };
}

export function DashboardView({
  onNavigate,
}: {
  onNavigate: (view: View) => void;
}) {
  const toast = useToast();
  const [data, setData] = useState<Dashboard>(EMPTY_DASHBOARD);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [dialog, setDialog] = useState<"workspace" | "shell" | "generate" | null>(null);
  const [editingWorkspace, setEditingWorkspace] = useState<Workspace | null>(null);
  const [editingShell, setEditingShell] = useState<ShellProfile | null>(null);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [batchTags, setBatchTags] = useState("");
  const [batchBusy, setBatchBusy] = useState(false);
  const [pluginCount, setPluginCount] = useState(0);
  const [page, setPage] = useState(0);
  const [tagFilter, setTagFilter] = useState("");
  const [workspaceFilter, setWorkspaceFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [viewMode, setViewMode] = useState<"list" | "grid">("list");
  const [probing, setProbing] = useState<string | null>(null);
  const [batchProbing, setBatchProbing] = useState<string[] | null>(null);
  const [connecting, setConnecting] = useState<string | null>(null);

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setData(await api.dashboard());
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "加载失败");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  useEffect(() => {
    void api.listFeaturePlugins().then((plugins) => setPluginCount(plugins.length)).catch(() => {});
  }, []);

  const lastConnected = useMemo(() => {
    const times = data.shells
      .map((shell) => shell.lastConnectedAt)
      .filter((value): value is string => Boolean(value))
      .sort()
      .reverse();
    return times.length > 0 ? shortTime(times[0]) : "—";
  }, [data.shells]);

  // Shell 状态自动刷新（60s 轮询，仅更新在线/错误状态）
  useEffect(() => {
    const timer = setInterval(() => {
      void api.refreshShellStatus().then(() => loadDashboard()).catch(() => {});
    }, 60_000);
    return () => clearInterval(timer);
  }, [loadDashboard]);

  const allTags = useMemo(() => {
    const tags = new Set<string>();
    for (const shell of data.shells) for (const tag of shell.tags) tags.add(tag);
    return [...tags].sort();
  }, [data.shells]);

  const filteredShells = useMemo(() => {
    const query = search.trim().toLowerCase();
    return data.shells.filter((shell) => {
      if (workspaceFilter && shell.workspaceId !== workspaceFilter) return false;
      if (tagFilter && !shell.tags.includes(tagFilter)) return false;
      if (statusFilter && shell.status !== statusFilter) return false;
      if (!query) return true;
      return [shell.name, shell.endpoint, shell.runtime, ...shell.tags].some((value) =>
        value.toLowerCase().includes(query),
      );
    });
  }, [data.shells, search, tagFilter, workspaceFilter, statusFilter]);

  const PAGE_SIZE = 50;
  const pageCount = Math.max(1, Math.ceil(filteredShells.length / PAGE_SIZE));
  const pageShells = filteredShells.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  async function probe(shell: ShellProfile) {
    setProbing(shell.id);
    try {
      const res = await api.probeShell(shell.id);
      toast.success(`${shell.name} 在线 · ${res.runtime} · ${res.server}`, "探测成功");
      await loadDashboard();
    } catch (cause) {
      toast.error(errorText(cause), `探测 ${shell.name} 失败`);
    } finally {
      setProbing(null);
    }
  }

  /** 批量探测当前筛选结果（逐个执行，完成后刷新）。 */
  async function probeAll() {
    const targets = filteredShells;
    if (targets.length === 0) return;
    setBatchProbing([]);
    const done: string[] = [];
    for (const shell of targets) {
      try {
        await api.probeShell(shell.id);
      } catch (cause) {
        toast.warning(`探测 ${shell.name} 失败：${errorText(cause)}`);
      }
      done.push(shell.id);
      setBatchProbing([...done]);
    }
    setBatchProbing(null);
    toast.success(`完成 ${targets.length} 个端点的连通性探测`, "批量探测完成");
    await loadDashboard();
  }

  function toggleSelect(id: string) {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id],
    );
  }

  function toggleSelectAll() {
    if (selected.length === pageShells.length) {
      setSelected([]);
    } else {
      setSelected(pageShells.map((s) => s.id));
    }
  }

  async function batchConnect() {
    setBatchBusy(true);
    let connected = 0;
    for (const id of selected) {
      const shell = data.shells.find((item) => item.id === id);
      if (!shell) continue;
      try {
        await api.connectShell(shell.id);
        connected += 1;
      } catch (cause) {
        toast.error(`连接 ${shell.name} 失败：${errorText(cause)}`);
        break;
      }
    }
    setBatchBusy(false);
    setSelected([]);
    await loadDashboard();
    if (connected > 0) {
      toast.success(`已建立 ${connected} 个活跃会话，可在「终端会话」中切换使用`, "批量连接成功");
    }
  }

  async function batchApplyTags() {
    const tags = batchTags
      .split(/[,，]/)
      .map((tag) => tag.trim())
      .filter(Boolean);
    setBatchBusy(true);
    try {
      const count = await api.batchUpdateShells(selected, tags);
      toast.success(`已为 ${count} 个 Shell 应用新标签`, "标签更新成功");
      setBatchTags("");
      setSelected([]);
      await loadDashboard();
    } catch (cause) {
      toast.error(errorText(cause), "批量标签失败");
    } finally {
      setBatchBusy(false);
    }
  }

  async function batchDelete() {
    const confirmed = await ask(`确定删除选中的 ${selected.length} 个 Shell？`, {
      title: "批量删除确认",
      kind: "warning",
      okLabel: "删除",
      cancelLabel: "取消",
    });
    if (!confirmed) return;
    setBatchBusy(true);
    let deleted = 0;
    for (const id of selected) {
      try {
        await api.deleteShell(id);
        deleted += 1;
      } catch (cause) {
        toast.error(errorText(cause), "删除出错");
        break;
      }
    }
    setBatchBusy(false);
    setSelected([]);
    toast.success(`已删除 ${deleted} 个 Shell 配置`, "批量删除完成");
    await loadDashboard();
  }

  async function exportShells() {
    try {
      const json = await api.exportShells();
      const localPath = await save({
        defaultPath: `dosword-shells-${new Date().toISOString().slice(0, 10)}.json`,
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (!localPath) return;
      const bytes = new TextEncoder().encode(json);
      await api.writeLocalFile(localPath, b64.encodeBytes(bytes));
      toast.success(`已成功导出 ${data.shells.length} 个 Shell 配置`, "导出完成");
    } catch (cause) {
      toast.error(errorText(cause), "导出失败");
    }
  }

  async function importShells() {
    if (data.workspaces.length === 0) {
      toast.warning("请先创建 Workspace 后再执行导入", "缺少工作区");
      return;
    }
    const workspaceId = data.workspaces[0].id;
    try {
      const localPath = await open({
        multiple: false,
        filters: [{ name: "Shell 配置文件", extensions: ["json", "csv"] }],
      });
      if (!localPath || Array.isArray(localPath)) return;
      const contentB64 = await api.readLocalFile(String(localPath));
      const text = b64.decodeText(contentB64);
      const payload = text.trim().startsWith("[") || text.trim().startsWith("{")
        ? text
        : csvToJson(text);
      const result = await api.importShells(payload, workspaceId);
      toast.success(`导入完成：新增 ${result.imported} 个，跳过 ${result.skipped} 个`, "导入成功");
      await loadDashboard();
    } catch (cause) {
      toast.error(errorText(cause), "导入失败");
    }
  }

  function csvToJson(csv: string): string {
    const rows = csv
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => line.split(",").map((cell) => cell.trim()));
    if (rows.length === 0) return "[]";
    const headers = rows[0];
    const items = rows.slice(1)
      .filter((row) => row.length >= 2)
      .map((row) => {
        const item: Record<string, string> = {};
        headers.forEach((header, index) => {
          item[header] = row[index] ?? "";
        });
        return item;
      });
    return JSON.stringify(items);
  }

  async function connect(shell: ShellProfile) {
    setConnecting(shell.id);
    try {
      const result = await api.connectShell(shell.id);
      toast.success(`已连接 ${shell.name} · ${result.server}`, "连接成功");
      onNavigate({ kind: "shell", shellId: shell.id, sessionId: result.sessionId, shellName: shell.name });
    } catch (cause) {
      toast.error(errorText(cause), `连接 ${shell.name} 失败`);
      setConnecting(null);
    }
  }

  async function removeShell(shell: ShellProfile) {
    const confirmed = await ask(`确定删除 Shell「${shell.name}」（${shell.endpoint}）？`, {
      title: "删除确认",
      kind: "warning",
      okLabel: "删除",
      cancelLabel: "取消",
    });
    if (!confirmed) return;
    try {
      await api.deleteShell(shell.id);
      toast.success(`已删除 ${shell.name}`, "删除成功");
      await loadDashboard();
    } catch (cause) {
      toast.error(errorText(cause), "删除失败");
    }
  }

  async function removeWorkspace(workspace: Workspace) {
    const count = data.shells.filter((shell) => shell.workspaceId === workspace.id).length;
    const confirmed = await ask(
      `确定删除 Workspace「${workspace.name}」？${count > 0 ? `其中 ${count} 个 Shell 配置将一并删除。` : ""}`,
      { title: "删除确认", kind: "warning", okLabel: "删除", cancelLabel: "取消" },
    );
    if (!confirmed) return;
    try {
      await api.deleteWorkspace(workspace.id);
      toast.success(`已删除工作区 ${workspace.name}`, "删除成功");
      await loadDashboard();
    } catch (cause) {
      toast.error(errorText(cause), "删除失败");
    }
  }

  async function copyEndpoint(endpoint: string) {
    try {
      await navigator.clipboard.writeText(endpoint);
      toast.info("端点 URL 已复制到剪贴板");
    } catch {
      // 忽略
    }
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">CONTROL CENTER</p>
          <h1>授权环境总览</h1>
        </div>
        <div className="top-actions">
          <label className="search">
            <Search size={15} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="搜索 Shell 名称 / 端点 / 标签…"
            />
          </label>
          <select
            className="select"
            value={workspaceFilter}
            onChange={(event) => setWorkspaceFilter(event.target.value)}
          >
            <option value="">全部工作区</option>
            {data.workspaces.map((workspace) => (
              <option key={workspace.id} value={workspace.id}>
                {workspace.name}
              </option>
            ))}
          </select>
          <select
            className="select"
            value={tagFilter}
            onChange={(event) => setTagFilter(event.target.value)}
          >
            <option value="">全部标签</option>
            {allTags.map((tag) => (
              <option key={tag} value={tag}>
                #{tag}
              </option>
            ))}
          </select>
          <select
            className="select"
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
          >
            <option value="">全部状态</option>
            <option value="online">在线 (Online)</option>
            <option value="error">离线/异常 (Error)</option>
            <option value="untested">未测试 (Untested)</option>
          </select>

          <button
            className="button secondary"
            onClick={() => void probeAll()}
            disabled={batchProbing !== null || filteredShells.length === 0}
            title="一键测试所有筛选出的 Shell 连通性"
          >
            {batchProbing !== null ? (
              <LoaderCircle className="spin" size={15} />
            ) : (
              <PlugZap size={15} />
            )}
            {batchProbing !== null
              ? `探测中 ${batchProbing.length}/${filteredShells.length}`
              : `探测全部 (${filteredShells.length})`}
          </button>
          <button className="button secondary" onClick={() => void loadDashboard()} title="刷新数据">
            <RefreshCw size={15} />
            刷新
          </button>
          <button className="button secondary" onClick={() => setDialog("generate")}>
            <Wand2 size={15} />
            生成 Webshell
          </button>
          <button className="button primary" onClick={() => setDialog("workspace")}>
            <CirclePlus size={16} />
            新建 Workspace
          </button>
        </div>
      </header>

      {error && <ErrorBanner message={error} />}

      <section className="metrics">
        <Metric
          label="工作空间"
          value={data.workspaces.length}
          detail="授权隔离项目"
          onClick={() => { setWorkspaceFilter(""); setTagFilter(""); setStatusFilter(""); }}
        />
        <Metric
          label="Shell 配置"
          value={data.shells.length}
          detail="已登记端点"
          onClick={() => { setStatusFilter(""); setSearch(""); }}
        />
        <Metric
          label="在线端点"
          value={data.shells.filter((item) => item.status === "online").length}
          detail="最新探测可用"
          accent
          onClick={() => setStatusFilter(statusFilter === "online" ? "" : "online")}
        />
        <Metric
          label="功能/协议插件"
          value={pluginCount}
          detail="已装载模块"
        />
        <Metric
          label="审计记录"
          value={data.auditEvents.length}
          detail="最近安全轨迹"
        />
        <Metric
          label="最近连接"
          value={lastConnected}
          detail="最后会话时间"
        />
      </section>

      <section className="main-grid">
        <Panel
          className="shell-panel"
          eyebrow="SHELL REGISTRY"
          title={`Shell 列表 (${filteredShells.length})`}
          actions={
            <>
              <div className="view-mode-toggle">
                <button
                  className={`view-mode-btn ${viewMode === "list" ? "active" : ""}`}
                  onClick={() => setViewMode("list")}
                  title="列表视图"
                >
                  <List size={14} />
                </button>
                <button
                  className={`view-mode-btn ${viewMode === "grid" ? "active" : ""}`}
                  onClick={() => setViewMode("grid")}
                  title="卡片网格视图"
                >
                  <LayoutGrid size={14} />
                </button>
              </div>
              <button className="button compact secondary" onClick={() => void exportShells()} title="导出 Shell 配置 JSON">
                <Download size={13} />
                导出
              </button>
              <button className="button compact secondary" onClick={() => void importShells()} title="导入 Shell 配置 JSON/CSV">
                <Upload size={13} />
                导入
              </button>
              <button
                className="button compact primary"
                disabled={data.workspaces.length === 0}
                onClick={() => setDialog("shell")}
              >
                <CirclePlus size={14} />
                登记 Shell
              </button>
            </>
          }
        >
          {loading ? (
            <Empty icon={<LoaderCircle className="spin" size={24} />} title="正在读取本地数据…" />
          ) : filteredShells.length === 0 ? (
            <Empty
              icon={<PlugZap size={28} />}
              title="暂无匹配的 Shell 配置"
              detail={
                data.workspaces.length
                  ? "点击「登记 Shell」添加端点，或调整筛选条件。"
                  : "请先在下方创建带有授权范围的 Workspace。"
              }
              action={
                data.workspaces.length ? (
                  <button className="button primary compact" onClick={() => setDialog("shell")}>
                    <CirclePlus size={14} />
                    立即登记
                  </button>
                ) : (
                  <button className="button primary compact" onClick={() => setDialog("workspace")}>
                    <CirclePlus size={14} />
                    创建 Workspace
                  </button>
                )
              }
            />
          ) : (
            <>
              {selected.length > 0 && (
                <div className="batch-bar">
                  <span>已选中 {selected.length} 个端点</span>
                  <button className="button compact" onClick={toggleSelectAll}>
                    {selected.length === pageShells.length ? "取消全选" : "全选本页"}
                  </button>
                  <button className="button compact primary" disabled={batchBusy} onClick={() => void batchConnect()}>
                    <TerminalSquare size={13} />
                    批量连接
                  </button>
                  <input
                    className="batch-tags"
                    value={batchTags}
                    onChange={(event) => setBatchTags(event.target.value)}
                    placeholder="为选中项批量设置标签（逗号分隔）"
                  />
                  <button
                    className="button compact"
                    disabled={batchBusy || !batchTags.trim()}
                    onClick={() => void batchApplyTags()}
                  >
                    应用标签
                  </button>
                  <button className="button compact danger" disabled={batchBusy} onClick={() => void batchDelete()}>
                    <Trash2 size={13} />
                    批量删除
                  </button>
                  <button className="button compact" onClick={() => setSelected([])}>
                    取消选择
                  </button>
                </div>
              )}

              {viewMode === "list" ? (
                <div className="shell-list">
                  {pageShells.map((shell) => (
                    <article
                      className={`shell-row ${selected.includes(shell.id) ? "selected" : ""}`}
                      key={shell.id}
                      onDoubleClick={() => void connect(shell)}
                      title="双击直接连接并打开控制台"
                    >
                      <input
                        type="checkbox"
                        className="shell-check"
                        checked={selected.includes(shell.id)}
                        onChange={() => toggleSelect(shell.id)}
                      />
                      <div className={`status-dot ${shell.status}`} title={`状态: ${shell.status}`} />
                      <div className="shell-identity">
                        <strong>{shell.name}</strong>
                        <span
                          title={shell.endpoint}
                          onClick={() => void copyEndpoint(shell.endpoint)}
                          style={{ cursor: "pointer" }}
                        >
                          {shell.endpoint}
                        </span>
                        {shell.tags.length > 0 && (
                          <span className="shell-tags">
                            {shell.tags.map((tag) => (
                              <code
                                key={tag}
                                className="shell-tag"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setTagFilter(tag);
                                }}
                                style={{ cursor: "pointer" }}
                              >
                                #{tag}
                              </code>
                            ))}
                          </span>
                        )}
                      </div>
                      <span className={`runtime-badge ${shell.runtime}`}>{shell.runtime}</span>
                      <div className="last-seen">
                        <span>{shell.status}</span>
                        <small>{shortTime(shell.lastConnectedAt)}</small>
                      </div>
                      <button
                        className="icon-button"
                        title="编辑配置"
                        onClick={() => {
                          setEditingShell(shell);
                          setDialog("shell");
                        }}
                      >
                        <FilePenLine size={15} />
                      </button>
                      <button
                        className="icon-button danger"
                        title="删除配置"
                        onClick={() => void removeShell(shell)}
                      >
                        <Trash2 size={15} />
                      </button>
                      <button
                        className="icon-button"
                        title="测试探测"
                        onClick={() => void probe(shell)}
                        disabled={probing === shell.id}
                      >
                        {probing === shell.id ? (
                          <LoaderCircle className="spin" size={16} />
                        ) : (
                          <PlugZap size={16} />
                        )}
                      </button>
                      <button
                        className="button compact connect"
                        onClick={() => void connect(shell)}
                        disabled={connecting === shell.id}
                      >
                        {connecting === shell.id ? (
                          <LoaderCircle className="spin" size={13} />
                        ) : (
                          <TerminalSquare size={13} />
                        )}
                        {connecting === shell.id ? "连接中…" : "连接"}
                      </button>
                    </article>
                  ))}
                </div>
              ) : (
                <div className="shell-grid">
                  {pageShells.map((shell) => (
                    <article
                      className={`shell-card ${selected.includes(shell.id) ? "selected" : ""}`}
                      key={shell.id}
                      onDoubleClick={() => void connect(shell)}
                      title="双击直接连接并打开控制台"
                    >
                      <div className="shell-card-header">
                        <div className="shell-card-title">
                          <input
                            type="checkbox"
                            className="shell-check"
                            checked={selected.includes(shell.id)}
                            onChange={() => toggleSelect(shell.id)}
                          />
                          <div className={`status-dot ${shell.status}`} />
                          <strong>{shell.name}</strong>
                        </div>
                        <span className={`runtime-badge ${shell.runtime}`}>{shell.runtime}</span>
                      </div>
                      <p
                        className="shell-card-endpoint"
                        onClick={() => void copyEndpoint(shell.endpoint)}
                        title="点击复制端点"
                        style={{ cursor: "pointer" }}
                      >
                        {shell.endpoint}
                      </p>
                      {shell.tags.length > 0 && (
                        <div className="shell-tags" style={{ marginBottom: 12 }}>
                          {shell.tags.map((tag) => (
                            <code
                              key={tag}
                              className="shell-tag"
                              onClick={() => setTagFilter(tag)}
                              style={{ cursor: "pointer" }}
                            >
                              #{tag}
                            </code>
                          ))}
                        </div>
                      )}
                      <div className="shell-card-footer">
                        <small style={{ color: "var(--text-faint)", fontSize: 11 }}>
                          {shortTime(shell.lastConnectedAt)}
                        </small>
                        <div className="shell-card-actions">
                          <button
                            className="icon-button"
                            title="探测连通性"
                            onClick={() => void probe(shell)}
                            disabled={probing === shell.id}
                          >
                            {probing === shell.id ? (
                              <LoaderCircle className="spin" size={14} />
                            ) : (
                              <PlugZap size={14} />
                            )}
                          </button>
                          <button
                            className="icon-button"
                            title="编辑"
                            onClick={() => {
                              setEditingShell(shell);
                              setDialog("shell");
                            }}
                          >
                            <FilePenLine size={14} />
                          </button>
                          <button
                            className="button compact connect"
                            onClick={() => void connect(shell)}
                            disabled={connecting === shell.id}
                          >
                            <TerminalSquare size={13} />
                            连接
                          </button>
                        </div>
                      </div>
                    </article>
                  ))}
                </div>
              )}

              {filteredShells.length > PAGE_SIZE && (
                <div className="pagination">
                  <button
                    className="button compact"
                    disabled={page === 0}
                    onClick={() => setPage(page - 1)}
                  >
                    上一页
                  </button>
                  <span className="pagination-info">
                    第 {page + 1} / {pageCount} 页（共 {filteredShells.length} 项）
                  </span>
                  <button
                    className="button compact"
                    disabled={page >= pageCount - 1}
                    onClick={() => setPage(page + 1)}
                  >
                    下一页
                  </button>
                </div>
              )}
            </>
          )}
        </Panel>

        <Panel eyebrow="ACTIVITY LOG" title="安全审计事件">
          {data.auditEvents.length === 0 ? (
            <Empty icon={<Activity size={24} />} title="暂无活动事件" />
          ) : (
            <div className="timeline">
              {data.auditEvents.slice(0, 8).map((event) => (
                <div className="timeline-item" key={event.id}>
                  <span className={`timeline-mark ${event.outcome}`} />
                  <div>
                    <strong>{event.action}</strong>
                    <p>{event.detail}</p>
                    <small>{shortTime(event.createdAt)}</small>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </section>

      <section className="panel workspace-panel">
        <div className="panel-heading">
          <div className="panel-heading-title">
            <p className="eyebrow">SECURITY BOUNDARY</p>
            <h2>授权工作空间</h2>
          </div>
          <button className="button compact primary" onClick={() => setDialog("workspace")}>
            <CirclePlus size={14} />
            新建 Workspace
          </button>
        </div>
        <div className="workspace-cards">
          {data.workspaces.map((workspace) => {
            const expiry = expiryInfo(workspace);
            const shellCount = data.shells.filter((shell) => shell.workspaceId === workspace.id).length;
            return (
              <article key={workspace.id} className="workspace-card">
                <div className="workspace-card-head">
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <FolderKanban size={18} color="var(--accent)" />
                    <strong>{workspace.name}</strong>
                  </div>
                  <span className={`expiry-badge ${expiry.kind}`}>{expiry.label}</span>
                </div>
                <p className="workspace-card-scope" title="授权目标范围">
                  {workspace.authorizationScope}
                </p>
                <div className="workspace-card-meta">
                  <small style={{ color: "var(--text-faint)" }}>{shellCount} 个端点配置</small>
                  <div style={{ display: "flex", gap: 4 }}>
                    <button
                      className="icon-button"
                      title="编辑工作区"
                      onClick={() => {
                        setEditingWorkspace(workspace);
                        setDialog("workspace");
                      }}
                    >
                      <FilePenLine size={14} />
                    </button>
                    <button
                      className="icon-button danger"
                      title="删除工作区"
                      onClick={() => void removeWorkspace(workspace)}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              </article>
            );
          })}
          {data.workspaces.length === 0 && (
            <p className="muted" style={{ padding: "16px 20px" }}>
              创建 Workspace 后，所有 Shell 配置和审计轨迹将按授权空间物理隔离。
            </p>
          )}
        </div>
      </section>

      {dialog === "generate" && <GenerateShellDialog onClose={() => setDialog(null)} />}
      {dialog === "workspace" && (
        <WorkspaceDialog
          initial={editingWorkspace}
          onClose={() => {
            setDialog(null);
            setEditingWorkspace(null);
          }}
          onCreated={loadDashboard}
        />
      )}
      {dialog === "shell" && (
        <ShellDialog
          workspaces={data.workspaces}
          initial={editingShell}
          onClose={() => {
            setDialog(null);
            setEditingShell(null);
          }}
          onCreated={loadDashboard}
        />
      )}
    </>
  );
}

function WorkspaceDialog({
  initial,
  onClose,
  onCreated,
}: {
  initial: Workspace | null;
  onClose: () => void;
  onCreated: () => Promise<void>;
}) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError("");
    try {
      const input = {
        name: String(form.get("name")),
        authorizationScope: String(form.get("scope")),
        expiresAt: form.get("expiresAt") ? String(form.get("expiresAt")) : null,
      };
      if (initial) {
        await api.updateWorkspace({ id: initial.id, ...input });
        toast.success(`工作区 ${input.name} 已更新`, "保存成功");
      } else {
        await api.createWorkspace(input);
        toast.success(`工作区 ${input.name} 创建成功`, "创建成功");
      }
      await onCreated();
      onClose();
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "操作失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title={initial ? "编辑授权 Workspace" : "新建授权 Workspace"} onClose={onClose}>
      <form onSubmit={(event) => void submit(event)}>
        {error && <p className="form-note error">{error}</p>}
        <label>
          项目空间名称
          <input name="name" required defaultValue={initial?.name} placeholder="例如：某系统渗透测试项目" />
        </label>
        <label>
          授权目标范围 (IP / 域名 / CIDR)
          <textarea
            name="scope"
            required
            defaultValue={initial?.authorizationScope}
            placeholder="例如：127.0.0.1、192.168.1.0/24 或 test.local"
          />
          <span className="field-hint">真实网络发包将自动校验目标是否属于此授权范围</span>
        </label>
        <label>
          授权到期时间
          <input name="expiresAt" type="date" defaultValue={initial?.expiresAt?.slice(0, 10)} />
        </label>
        <div className="dialog-actions">
          <button type="button" className="button secondary" onClick={onClose}>
            取消
          </button>
          <button className="button primary" disabled={busy}>
            {busy ? "保存中…" : initial ? "保存修改" : "创建 Workspace"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function ShellDialog({
  workspaces,
  initial,
  onClose,
  onCreated,
}: {
  workspaces: Workspace[];
  initial: ShellProfile | null;
  onClose: () => void;
  onCreated: () => Promise<void>;
}) {
  const toast = useToast();
  const [protocols, setProtocols] = useState<ProtocolMeta[]>([]);
  const [protocolId, setProtocolId] = useState(initial?.protocolId ?? "builtin.mock.v1");
  const [encoders, setEncoders] = useState<[string, string][]>([]);
  const [encoderId, setEncoderId] = useState("native");
  const [settings, setSettings] = useState<{ httpEnabled: boolean }>({ httpEnabled: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  // 连通性测试默认要求目标命中某个 Workspace 的授权范围
  const [allowUnscoped, setAllowUnscoped] = useState(false);
  const [testState, setTestState] = useState<
    { busy: boolean; ok: boolean; message: string } | null
  >(null);
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    void api.listProtocols().then(setProtocols);
    void api.listEncoders().then(setEncoders).catch(() => {});
    void api.getSettings().then(setSettings).catch(() => {});
  }, []);

  async function runTest() {
    if (!formRef.current) return;
    const form = new FormData(formRef.current);
    setTestState({ busy: true, ok: false, message: "正在探测目标连通性…" });
    try {
      const result = await api.testConnection(
        String(form.get("endpoint")),
        String(form.get("password") ?? ""),
        protocolId,
        protocolId === "builtin.php.v1"
          ? JSON.stringify({ encoder: encoderId })
          : undefined,
        String(form.get("runtime") ?? "php"),
        allowUnscoped,
      );
      setTestState({
        busy: false,
        ok: true,
        message: `✓ 连接成功：${result.server} · ${result.runtime} · 目录: ${result.currentDir}`,
      });
      toast.success("目标端点与密钥握手成功", "测试通过");
    } catch (cause) {
      const msg = `连接失败：${errorText(cause)}`;
      setTestState({ busy: false, ok: false, message: msg });
      toast.error(msg, "测试未通过");
    }
  }

  const selected = protocols.find((protocol) => protocol.id === protocolId);
  const connectionTestable = selected?.requiresNetwork === true && settings.httpEnabled;
  const networkProtocols = protocols.filter((protocol) => protocol.requiresNetwork);
  const networkLocked = networkProtocols.length > 0 && !settings.httpEnabled;
  const editing = initial !== null;

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError("");
    try {
      if (initial) {
        await api.updateShell({
          id: initial.id,
          name: String(form.get("name")),
          endpoint: String(form.get("endpoint")),
          password: form.get("password") ? String(form.get("password")) : initial.password,
          tags: parseTags(String(form.get("tags") ?? "")),
        });
        toast.success(`Shell「${form.get("name")}」已更新`, "保存成功");
      } else {
        await api.createShell({
          workspaceId: String(form.get("workspaceId")),
          name: String(form.get("name")),
          endpoint: String(form.get("endpoint")),
          runtime: String(form.get("runtime")),
          protocolId,
          password: form.get("password") ? String(form.get("password")) : undefined,
          confirmNetwork: form.get("confirm") === "on",
          tags: parseTags(String(form.get("tags") ?? "")),
          protocolParams:
            protocolId === "builtin.php.v1"
              ? JSON.stringify({ encoder: encoderId })
              : undefined,
        });
        toast.success(`Shell「${form.get("name")}」登记完成`, "登记成功");
      }
      await onCreated();
      onClose();
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "登记失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title={editing ? "编辑 Shell 配置" : "登记 Shell 端点"} onClose={onClose}>
      <form ref={formRef} onSubmit={(event) => void submit(event)}>
        {error && <p className="form-note error">{error}</p>}
        {testState && (
          <p className={testState.ok ? "form-note ok" : "form-note error"}>
            {testState.message}
          </p>
        )}
        <label>
          所属 Workspace
          <select name="workspaceId" required defaultValue={initial?.workspaceId} disabled={editing}>
            {workspaces.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name} ({item.authorizationScope})
              </option>
            ))}
          </select>
        </label>
        <label>
          Shell 名称
          <input name="name" required defaultValue={initial?.name} placeholder="例如：测试主机-Nginx-PHP" />
        </label>
        <label>
          端点 URL
          <input
            name="endpoint"
            required
            defaultValue={initial?.endpoint ?? "mock://local"}
            placeholder="http://192.168.1.100/shell.php"
          />
        </label>
        <label>
          标签 (Tags)
          <input
            name="tags"
            defaultValue={initial?.tags.join(", ")}
            placeholder="可选：生产环境, Linux, Nginx (逗号分隔)"
          />
        </label>
        {editing ? (
          <p className="form-note">
            协议与运行时不可在编辑中变更（当前：{initial.protocolId} · {initial.runtime}）。
          </p>
        ) : (
          <>
            <label>
              连接协议
              <select
                value={protocolId}
                onChange={(event) => setProtocolId(event.target.value)}
                disabled={networkLocked && protocolId !== "builtin.mock.v1"}
              >
                {protocols.map((protocol) => (
                  <option
                    key={protocol.id}
                    value={protocol.id}
                    disabled={protocol.requiresNetwork && !settings.httpEnabled}
                  >
                    {protocol.displayName} {protocol.requiresNetwork ? "（真实网络）" : "（本地沙箱）"}
                  </option>
                ))}
              </select>
            </label>
            <label>
              目标运行时
              <select name="runtime">
                <option value="php">PHP</option>
                <option value="jsp">JSP</option>
                <option value="aspnet">ASP.NET</option>
                <option value="python">Python</option>
                <option value="node">Node.js</option>
              </select>
            </label>
          </>
        )}
        {selected?.requiresNetwork && (
          <>
            <label>
              连接密码
              <input
                name="password"
                type="password"
                required={!editing}
                placeholder={editing ? "留空保持原密码" : "WebShell 鉴权密钥"}
              />
            </label>
            {!editing && protocolId === "builtin.php.v1" && (
              <label>
                编码方式
                <select value={encoderId} onChange={(event) => setEncoderId(event.target.value)}>
                  {encoders.map(([id, displayName]) => (
                    <option key={id} value={id}>
                      {displayName}
                    </option>
                  ))}
                </select>
                <span className="field-hint">
                  需与目标 stub 的解码方式一致；可在「生成 Webshell」中生成配套代码。
                </span>
              </label>
            )}

            {!editing && settings.httpEnabled && (
              <label className="confirm-row">
                <input name="confirm" type="checkbox" required />
                <span>我已确认该端点位于所属 Workspace 授权范围内</span>
              </label>
            )}
            {!editing && settings.httpEnabled && (
              <label className="confirm-row" title="默认仅允许命中某个 Workspace 授权范围的目标">
                <input
                  type="checkbox"
                  checked={allowUnscoped}
                  onChange={(event) => setAllowUnscoped(event.target.checked)}
                />
                <span>允许未授权范围目标（越界测试将记入审计日志）</span>
              </label>
            )}
            {!editing && !settings.httpEnabled && (
              <p className="form-note">
                <ShieldCheck size={15} />
                真实网络协议尚未在「系统设置」中开启，请先前往设置页开启真实网络协议。
              </p>
            )}
          </>
        )}
        {!editing && !selected?.requiresNetwork && (
          <p className="form-note">
            <ShieldCheck size={15} />
            当前选择的是本地 Mock 协议，用于离线模拟测试，不会产生真实对外网络流量。
          </p>
        )}
        <div className="dialog-actions">
          {connectionTestable && !editing && (
            <button
              type="button"
              className="button secondary"
              disabled={testState?.busy}
              onClick={() => void runTest()}
            >
              {testState?.busy ? <LoaderCircle className="spin" size={13} /> : <PlugZap size={13} />}
              {testState?.busy ? "测试中…" : "测试连接"}
            </button>
          )}
          <button type="button" className="button secondary" onClick={onClose}>
            取消
          </button>
          <button
            className="button primary"
            disabled={busy || (!editing && !!selected?.requiresNetwork && !settings.httpEnabled)}
          >
            {busy ? "保存中…" : "保存配置"}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
