import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  ChevronRight,
  CirclePlus,
  Wand2,
  FilePenLine,
  FolderKanban,
  LoaderCircle,
  PlugZap,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { ask, open, save } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText, shortTime } from "../api";
import type { Dashboard, ProtocolMeta, ShellProfile, Workspace } from "../api";
import { Dialog } from "../components/Dialog";
import { Empty, ErrorBanner, Metric, Panel } from "../components/common";
import { GenerateShellDialog } from "../widgets/GenerateShellDialog";
import type { View } from "./types";

const EMPTY_DASHBOARD: Dashboard = { workspaces: [], shells: [], auditEvents: [] };

/** 解析标签输入（逗号/空格/顿号分隔，去重去空）。 */
function parseTags(value: string): string[] {
  return [...new Set(
    value
      .split(/[,，;\s]+/)
      .map((tag) => tag.trim())
      .filter(Boolean),
  )];
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
  const [notice, setNotice] = useState("");
  const [pluginCount, setPluginCount] = useState(0);
  const [page, setPage] = useState(0);
  const [tagFilter, setTagFilter] = useState("");
  const [workspaceFilter, setWorkspaceFilter] = useState("");
  const [probing, setProbing] = useState<string | null>(null);
  const [batchProbing, setBatchProbing] = useState<string[] | null>(null);
  const [connecting, setConnecting] = useState<string | null>(null);

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setData(await api.dashboard());
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setLoading(false);
    }
  }, []);

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
      if (!query) return true;
      return [shell.name, shell.endpoint, shell.runtime, ...shell.tags].some((value) =>
        value.toLowerCase().includes(query),
      );
    });
  }, [data.shells, search, tagFilter, workspaceFilter]);

  const PAGE_SIZE = 50;
  const pageCount = Math.max(1, Math.ceil(filteredShells.length / PAGE_SIZE));
  const pageShells = filteredShells.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  async function probe(shell: ShellProfile) {
    setProbing(shell.id);
    setError("");
    try {
      await api.probeShell(shell.id);
      await loadDashboard();
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setProbing(null);
    }
  }

  /** 批量探测当前筛选结果（逐个执行，完成后刷新）。 */
  async function probeAll() {
    const targets = filteredShells;
    if (targets.length === 0) return;
    setBatchProbing([]);
    setError("");
    const done: string[] = [];
    for (const shell of targets) {
      try {
        await api.probeShell(shell.id);
      } catch (cause) {
        setError(`探测 ${shell.name} 失败：${errorText(cause)}`);
        break;
      }
      done.push(shell.id);
      setBatchProbing([...done]);
    }
    setBatchProbing(null);
    await loadDashboard();
  }

  function toggleSelect(id: string) {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id],
    );
  }

  async function batchConnect() {
    setBatchBusy(true);
    setError("");
    let connected = 0;
    for (const id of selected) {
      const shell = data.shells.find((item) => item.id === id);
      if (!shell) continue;
      try {
        await api.connectShell(shell.id);
        connected += 1;
      } catch (cause) {
        setError(`连接 ${shell.name} 失败：${errorText(cause)}`);
        break;
      }
    }
    setBatchBusy(false);
    setSelected([]);
    await loadDashboard();
    if (connected > 0) {
      setNotice(`已建立 ${connected} 个会话（可在「会话」页查看）`);
    }
  }

  async function batchApplyTags() {
    const tags = batchTags
      .split(/[,，]/)
      .map((tag) => tag.trim())
      .filter(Boolean);
    setBatchBusy(true);
    setError("");
    try {
      const count = await api.batchUpdateShells(selected, tags);
      setNotice(`已为 ${count} 个 Shell 设置标签`);
      setBatchTags("");
      setSelected([]);
      await loadDashboard();
    } catch (cause) {
      setError(errorText(cause));
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
    setError("");
    for (const id of selected) {
      try {
        await api.deleteShell(id);
      } catch (cause) {
        setError(errorText(cause));
        break;
      }
    }
    setBatchBusy(false);
    setSelected([]);
    await loadDashboard();
  }

  async function exportShells() {
    setError("");
    try {
      const json = await api.exportShells();
      const localPath = await save({
        defaultPath: `dosword-shells-${new Date().toISOString().slice(0, 10)}.json`,
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (!localPath) return;
      const bytes = new TextEncoder().encode(json);
      await api.writeLocalFile(localPath, b64.encodeBytes(bytes));
      setNotice(`已导出 ${data.shells.length} 个 Shell 配置`);
    } catch (cause) {
      setError(`导出失败：${errorText(cause)}`);
    }
  }

  async function importShells() {
    if (data.workspaces.length === 0) {
      setError("请先创建 Workspace 再导入");
      return;
    }
    const workspaceId = data.workspaces[0].id;
    setError("");
    try {
      const localPath = await open({
        multiple: false,
        filters: [{ name: "Shell 配置", extensions: ["json", "csv"] }],
      });
      if (!localPath || Array.isArray(localPath)) return;
      const contentB64 = await api.readLocalFile(String(localPath));
      const text = b64.decodeText(contentB64);
      const payload = text.trim().startsWith("[") || text.trim().startsWith("{")
        ? text
        : csvToJson(text);
      const result = await api.importShells(payload, workspaceId);
      setNotice(`导入完成：新增 ${result.imported}，跳过 ${result.skipped}`);
      await loadDashboard();
    } catch (cause) {
      setError(`导入失败：${errorText(cause)}`);
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
    setError("");
    try {
      const result = await api.connectShell(shell.id);
      onNavigate({ kind: "shell", shellId: shell.id, sessionId: result.sessionId });
    } catch (cause) {
      setError(errorText(cause));
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
    setError("");
    try {
      await api.deleteShell(shell.id);
      await loadDashboard();
    } catch (cause) {
      setError(errorText(cause));
    }
  }

  async function removeWorkspace(workspace: Workspace) {
    const count = data.shells.filter((shell) => shell.workspaceId === workspace.id).length;
    const confirmed = await ask(
      `确定删除 Workspace「${workspace.name}」？${count > 0 ? `其中 ${count} 个 Shell 配置将一并删除。` : ""}`,
      { title: "删除确认", kind: "warning", okLabel: "删除", cancelLabel: "取消" },
    );
    if (!confirmed) return;
    setError("");
    try {
      await api.deleteWorkspace(workspace.id);
      await loadDashboard();
    } catch (cause) {
      setError(errorText(cause));
    }
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">OPERATIONS CONSOLE</p>
          <h1>授权环境总览</h1>
        </div>
        <div className="top-actions">
          <label className="search">
            <Search size={17} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="搜索 Shell"
            />
          </label>
          <select className="select" value={workspaceFilter} onChange={(event) => setWorkspaceFilter(event.target.value)}>
            <option value="">全部 Workspace</option>
            {data.workspaces.map((workspace) => (
              <option key={workspace.id} value={workspace.id}>
                {workspace.name}
              </option>
            ))}
          </select>
          <select className="select" value={tagFilter} onChange={(event) => setTagFilter(event.target.value)}>
            <option value="">全部标签</option>
            {allTags.map((tag) => (
              <option key={tag} value={tag}>
                #{tag}
              </option>
            ))}
          </select>
          <button
            className="button secondary"
            onClick={() => void probeAll()}
            disabled={batchProbing !== null || filteredShells.length === 0}
          >
            {batchProbing !== null ? (
              <LoaderCircle className="spin" size={16} />
            ) : (
              <PlugZap size={16} />
            )}
            {batchProbing !== null
              ? `探测中 ${batchProbing.length}/${filteredShells.length}`
              : `探测全部（${filteredShells.length}）`}
          </button>
          <button className="button secondary" onClick={() => void loadDashboard()}>
            <RefreshCw size={16} />
            刷新
          </button>
          <button className="button secondary" onClick={() => setDialog("generate")}>
            <Wand2 size={16} />
            生成 Webshell
          </button>
          <button className="button primary" onClick={() => setDialog("workspace")}>
            <CirclePlus size={17} />
            新建 Workspace
          </button>
        </div>
      </header>
      {error && <ErrorBanner message={error} />}
      <section className="metrics">
        <Metric label="WORKSPACES" value={data.workspaces.length} detail="授权项目空间" />
        <Metric label="SHELL PROFILES" value={data.shells.length} detail="已登记端点" />
        <Metric
          label="ONLINE"
          value={data.shells.filter((item) => item.status === "online").length}
          detail="最近探测在线"
          accent
        />
        <Metric label="AUDIT EVENTS" value={data.auditEvents.length} detail="最近操作记录" />
        <Metric label="PLUGINS" value={pluginCount} detail="功能/协议插件" />
        <Metric label="LAST CONNECT" value={data.shells.filter((s) => s.lastConnectedAt).length} detail={lastConnected} />
      </section>

      <section className="main-grid">
        <Panel
          className="shell-panel"
          eyebrow="SHELL REGISTRY"
          title="连接配置"
          actions={
            <>
              <button className="button compact" onClick={() => void exportShells()}>
                导出
              </button>
              <button className="button compact" onClick={() => void importShells()}>
                导入
              </button>
              <button
                className="button compact"
                disabled={data.workspaces.length === 0}
                onClick={() => setDialog("shell")}
              >
                <CirclePlus size={16} />
                登记 Shell
              </button>
            </>
          }
        >
          {loading ? (
            <Empty icon={<LoaderCircle className="spin" />} title="正在读取本地数据" />
          ) : filteredShells.length === 0 ? (
            <Empty
              icon={<PlugZap />}
              title="尚无 Shell 配置"
              detail={
                data.workspaces.length
                  ? "登记一个 Shell 验证连接流程。"
                  : "请先创建带授权范围的 Workspace。"
              }
            />
          ) : (
            <>
            {selected.length > 0 && (
              <div className="batch-bar">
                <span>已选 {selected.length} 项</span>
                <button className="button compact" disabled={batchBusy} onClick={() => void batchConnect()}>
                  批量连接
                </button>
                <input
                  className="batch-tags"
                  value={batchTags}
                  onChange={(event) => setBatchTags(event.target.value)}
                  placeholder="批量设置标签（逗号分隔）"
                />
                <button className="button compact" disabled={batchBusy || !batchTags.trim()} onClick={() => void batchApplyTags()}>
                  应用标签
                </button>
                <button className="button compact danger" disabled={batchBusy} onClick={() => void batchDelete()}>
                  批量删除
                </button>
                <button className="button compact" onClick={() => setSelected([])}>
                  取消选择
                </button>
              </div>
            )}
            {notice && <p className="form-note ok">{notice}</p>}
            <div className="shell-list">
              {pageShells.map((shell) => (
                <article className={`shell-row ${selected.includes(shell.id) ? "selected" : ""}`} key={shell.id}>
                  <input
                    type="checkbox"
                    className="shell-check"
                    checked={selected.includes(shell.id)}
                    onChange={() => toggleSelect(shell.id)}
                  />
                  <div className={`status-dot ${shell.status}`} />
                  <div className="shell-identity">
                    <strong>{shell.name}</strong>
                    <span>{shell.endpoint}</span>
                    {shell.tags.length > 0 && (
                      <span className="shell-tags">
                        {shell.tags.map((tag) => (
                          <code key={tag} className="shell-tag">#{tag}</code>
                        ))}
                      </span>
                    )}
                  </div>
                  <code>{shell.runtime.toUpperCase()}</code>
                  <div className="last-seen">
                    <span>{shell.status}</span>
                    <small>{shortTime(shell.lastConnectedAt)}</small>
                  </div>
                  <button
                    className="icon-button"
                    title="编辑"
                    onClick={() => { setEditingShell(shell); setDialog("shell"); }}
                  >
                    <FilePenLine size={16} />
                  </button>
                  <button
                    className="icon-button danger"
                    title="删除"
                    onClick={() => void removeShell(shell)}
                  >
                    <Trash2 size={16} />
                  </button>
                  <button
                    className="icon-button"
                    title="探测"
                    onClick={() => void probe(shell)}
                    disabled={probing === shell.id}
                  >
                    {probing === shell.id ? (
                      <LoaderCircle className="spin" size={18} />
                    ) : (
                      <ChevronRight size={18} />
                    )}
                  </button>
                  <button
                    className="button compact connect"
                    onClick={() => void connect(shell)}
                    disabled={connecting === shell.id}
                  >
                    {connecting === shell.id ? "连接中…" : "连接"}
                  </button>
                </article>
              ))}
            </div>
            {filteredShells.length > PAGE_SIZE && (
              <div className="pager">
                <button className="button compact" disabled={page === 0} onClick={() => setPage(page - 1)}>
                  上一页
                </button>
                <span className="pager-info">
                  第 {page + 1} / {pageCount} 页（共 {filteredShells.length}）
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

        <Panel eyebrow="RECENT ACTIVITY" title="审计事件">
          {data.auditEvents.length === 0 ? (
            <Empty icon={<Activity />} title="暂无审计事件" />
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
          <div>
            <p className="eyebrow">AUTHORIZATION BOUNDARIES</p>
            <h2>工作空间</h2>
          </div>
        </div>
        <div className="workspace-cards">
          {data.workspaces.map((workspace) => {
            const expiry = expiryInfo(workspace);
            return (
            <article key={workspace.id} className="workspace-card">
              <FolderKanban size={21} />
              <div>
                <strong>{workspace.name}</strong>
                <span>{workspace.authorizationScope}</span>
              </div>
              <small>
                {data.shells.filter((shell) => shell.workspaceId === workspace.id).length} 个配置
              </small>
              <span className={`expiry-badge ${expiry.kind}`}>{expiry.label}</span>
              <span className="workspace-ops">
                <button
                  className="icon-button"
                  title="编辑"
                  onClick={() => { setEditingWorkspace(workspace); setDialog("workspace"); }}
                >
                  <FilePenLine size={15} />
                </button>
                <button
                  className="icon-button danger"
                  title="删除"
                  onClick={() => void removeWorkspace(workspace)}
                >
                  <Trash2 size={15} />
                </button>
              </span>
            </article>
            );
          })}
          {data.workspaces.length === 0 && (
            <p className="muted">
              创建 Workspace 后，所有 Shell 和审计记录都将按项目隔离。
            </p>
          )}
        </div>
      </section>

      {dialog === "generate" && <GenerateShellDialog onClose={() => setDialog(null)} />}
      {dialog === "workspace" && (
        <WorkspaceDialog
          initial={editingWorkspace}
          onClose={() => { setDialog(null); setEditingWorkspace(null); }}
          onCreated={loadDashboard}
        />
      )}
      {dialog === "shell" && (
        <ShellDialog
          workspaces={data.workspaces}
          initial={editingShell}
          onClose={() => { setDialog(null); setEditingShell(null); }}
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
      } else {
        await api.createWorkspace(input);
      }
      await onCreated();
      onClose();
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog title={initial ? "编辑授权 Workspace" : "新建授权 Workspace"} onClose={onClose}>
      <form onSubmit={(event) => void submit(event)}>
        {error && <p className="form-note error">{error}</p>}
        <label>
          项目名称
          <input name="name" required defaultValue={initial?.name} placeholder="Internal Security Test" />
        </label>
        <label>
          授权范围
          <textarea
            name="scope"
            required
            defaultValue={initial?.authorizationScope}
            placeholder="例如：localhost、10.0.0.0/24 或测试域名"
          />
        </label>
        <label>
          授权到期日
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
  const [protocols, setProtocols] = useState<ProtocolMeta[]>([]);
  const [protocolId, setProtocolId] = useState(initial?.protocolId ?? "builtin.mock.v1");
  const [encoders, setEncoders] = useState<[string, string][]>([]);
  const [encoderId, setEncoderId] = useState("native");
  const [settings, setSettings] = useState<{ httpEnabled: boolean }>({ httpEnabled: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
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
    setTestState({ busy: true, ok: false, message: "正在探测目标…" });
    try {
      const result = await api.testConnection(
        String(form.get("endpoint")),
        String(form.get("password") ?? ""),
        protocolId,
        protocolId === "builtin.php.v1"
          ? JSON.stringify({ encoder: encoderId })
          : undefined,
        String(form.get("runtime") ?? "php"),
      );
      setTestState({
        busy: false,
        ok: true,
        message: `连接成功：${result.server} · ${result.runtime} · ${result.currentDir}`,
      });
    } catch (cause) {
      setTestState({ busy: false, ok: false, message: `连接失败：${errorText(cause)}` });
    }
  }

  const selected = protocols.find((protocol) => protocol.id === protocolId);
  const connectionTestable =
    selected?.requiresNetwork === true && settings.httpEnabled;
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
      }
      await onCreated();
      onClose();
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog title={editing ? "编辑 Shell" : "登记 Shell"} onClose={onClose}>
      <form ref={formRef} onSubmit={(event) => void submit(event)}>
        {error && <p className="form-note error">{error}</p>}
        {testState && (
          <p className={testState.ok ? "form-note ok" : "form-note error"}>
            {testState.message}
          </p>
        )}
        <label>
          Workspace
          <select name="workspaceId" required defaultValue={initial?.workspaceId} disabled={editing}>
            {workspaces.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          名称
          <input name="name" required defaultValue={initial?.name} placeholder="Local Test Endpoint" />
        </label>
        <label>
          Endpoint
          <input
            name="endpoint"
            required
            defaultValue={initial?.endpoint ?? "mock://local"}
            placeholder="http://target/shell.php"
          />
        </label>
        <label>
          标签
          <input
            name="tags"
            defaultValue={initial?.tags.join(", ")}
            placeholder="可选：web, test（逗号分隔）"
          />
        </label>
        {editing ? (
          <p className="form-note">
            协议与运行时不可在编辑中变更（{initial.protocolId}）。
          </p>
        ) : (
          <>
            <label>
              协议
              <select
                value={protocolId}
                onChange={(event) => setProtocolId(event.target.value)}
                disabled={networkLocked && protocolId !== "builtin.mock.v1"}
              >
                {protocols.map((protocol) => (
                  <option key={protocol.id} value={protocol.id} disabled={protocol.requiresNetwork && !settings.httpEnabled}>
                    {protocol.displayName}
                    {protocol.requiresNetwork ? "（真实网络）" : "（本地）"}
                  </option>
                ))}
              </select>
            </label>
            <label>
              运行时
              <select name="runtime">
                <option value="php">PHP</option>
                <option value="jsp">JSP</option>
                <option value="aspnet">ASP.NET</option>
              </select>
            </label>
          </>
        )}
        {selected?.requiresNetwork && (
          <>
            <label>
              连接密码
              <input name="password" type="password" required={!editing} placeholder={editing ? "留空保持原密码" : "WebShell 鉴权密码"} />
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
                  与目标 stub 的解码方式一致；可在「生成 Webshell」中生成配套 stub。
                </span>
              </label>
            )}
            
            {!editing && settings.httpEnabled && (
              <label className="confirm-row">
                <input name="confirm" type="checkbox" />
                <span>我已确认目标位于授权范围内，且有权进行测试</span>
              </label>
            )}
            {!editing && !settings.httpEnabled && (
              <p className="form-note">
                <ShieldCheck size={15} />
                真实网络协议尚未在「设置」中开启，请先前往设置页确认授权声明。
              </p>
            )}
          </>
        )}
        {!editing && !selected?.requiresNetwork && (
          <p className="form-note">
            <ShieldCheck size={15} />
            当前选择的是本地 Mock 协议，不会产生真实网络流量。
          </p>
        )}
        <div className="dialog-actions">
          {connectionTestable && !editing && (
            <button
              type="button"
              className="button"
              disabled={testState?.busy}
              onClick={() => void runTest()}
            >
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
