import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  CheckCircle2,
  Download,
  LoaderCircle,
  RefreshCw,
  XCircle,
} from "lucide-react";
import { api, errorText, shortTime } from "../api";
import { buildCsv } from "../lib/csv";
import { saveTextFile } from "../lib/exportFile";
import type { AuditEvent } from "../api";
import { Empty, ErrorBanner, Panel } from "../components/common";
import { useToast } from "../components/Toast";

const PAGE_SIZE = 50;

const ACTION_LABELS: Record<string, string> = {
  "workspace.create": "创建 Workspace",
  "workspace.update": "更新 Workspace",
  "workspace.delete": "删除 Workspace",
  "shell.create": "登记 Shell",
  "shell.update": "更新 Shell",
  "shell.delete": "删除 Shell",
  "shell.probe": "探测 Shell",
  "shell.connect": "连接 Shell",
  "shell.disconnect": "断开连接",
  "shell.exec": "执行命令",
  "file.list": "浏览目录",
  "file.read": "读取文件",
  "file.write": "写入文件",
  "file.upload": "上传文件",
  "file.download": "下载文件",
  "file.delete": "删除文件",
  "file.rename": "重命名/移动",
  "file.mkdir": "新建目录",
  "db.probe": "数据库探测",
  "db.query": "数据库查询",
  "shell.generate": "生成 Webshell",
  "settings.update": "设置变更",
};

export function actionLabel(action: string): string {
  return ACTION_LABELS[action] ?? action;
}

export function AuditView() {
  const toast = useToast();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState<string>("");
  // 按 Shell 过滤：定位「某个目标上做过什么」（后端 idx_audit_shell 支撑）
  const [shellFilter, setShellFilter] = useState<string>("");
  const [outcome, setOutcome] = useState<string>("");
  const [page, setPage] = useState(0);
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const load = useCallback(
    async (targetPage: number, action: string, result: string, shellId: string) => {
      setLoading(true);
      setError("");
      try {
        const data = await api.listAudit({
          workspaceId: null,
          shellId: shellId.trim() || null,
          action: action || null,
          outcome: result || null,
          limit: PAGE_SIZE,
          offset: targetPage * PAGE_SIZE,
        });
        setEvents(data.events);
        setTotal(data.total);
        setPage(targetPage);
      } catch (cause) {
        const msg = errorText(cause);
        setError(msg);
        toast.error(msg, "加载审计日志失败");
      } finally {
        setLoading(false);
      }
    },
    [toast],
  );

  useEffect(() => {
    void load(0, filter, outcome, shellFilter);
    // shellFilter 故意不进依赖：它是「按 Enter / 点刷新才生效」的输入框，
    // 逐字符触发全量审计查询既慢又抖。需要即时生效时把 shellFilter 加进来即可。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load, filter, outcome]);

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  async function exportCsv() {
    try {
      const rows = [
        ["时间", "操作类型", "执行结果", "详细轨迹", "Workspace ID", "Shell ID"],
        ...events.map((event) => [
          event.createdAt,
          actionLabel(event.action),
          event.outcome,
          event.detail,
          event.workspaceId || "",
          event.shellId ?? "",
        ]),
      ];
      const saved = await saveTextFile({
        defaultPath: `dosword-audit-${new Date().toISOString().slice(0, 10)}.csv`,
        filters: [{ name: "CSV 表格文件", extensions: ["csv"] }],
        text: buildCsv(rows),
      });
      if (!saved) return;
      toast.success(`已成功导出 ${events.length} 条审计日志`, "导出完成");
    } catch (cause) {
      toast.error(errorText(cause), "导出失败");
    }
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">SECURITY TRACEABILITY</p>
          <h1>安全审计轨迹</h1>
        </div>
        <div className="top-actions">
          <input
            className="input"
            style={{ width: 200 }}
            placeholder="按 Shell ID 过滤（可选）"
            value={shellFilter}
            onChange={(event) => setShellFilter(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") void load(0, filter, outcome, shellFilter);
            }}
          />
          <select
            className="select"
            value={outcome}
            onChange={(event) => setOutcome(event.target.value)}
          >
            <option value="">全部结果</option>
            <option value="success">成功 (Success)</option>
            <option value="error">失败 (Error)</option>
          </select>
          <select
            className="select"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          >
            <option value="">全部操作类型</option>
            {Object.entries(ACTION_LABELS).map(([action, label]) => (
              <option key={action} value={action}>
                {label}
              </option>
            ))}
          </select>
          <button
            className="button secondary"
            onClick={() => void load(page, filter, outcome, shellFilter)}
            title="刷新日志"
          >
            <RefreshCw size={14} />
            刷新
          </button>
          <button
            className="button secondary"
            onClick={() => void exportCsv()}
            disabled={events.length === 0}
            title="导出当前筛选结果为 CSV"
          >
            <Download size={14} />
            导出 CSV
          </button>
        </div>
      </header>

      {error && <ErrorBanner message={error} />}

      <Panel eyebrow="AUDIT EVENTS" title={`操作记录 (${total})`}>
        {loading ? (
          <Empty icon={<LoaderCircle className="spin" size={24} />} title="正在检索审计日志…" />
        ) : events.length === 0 ? (
          <Empty
            icon={<Activity size={28} />}
            title="暂无审计事件"
            detail="所有 Workspace、Shell 注册、连接握手、命令执行、文件上传下载等操作均会自动在本地持久化审计。"
          />
        ) : (
          <>
            <div className="audit-table">
              <div className="audit-head">
                <span>时间</span>
                <span>操作类型</span>
                <span>执行结果</span>
                <span>详细信息</span>
              </div>
              {events.map((event) => (
                <div
                  className="audit-row"
                  key={event.id}
                  onClick={() => setSelectedEvent(event)}
                  style={{ cursor: "pointer" }}
                >
                  <span className="mono" style={{ color: "var(--text-faint)", fontSize: 11 }}>
                    {shortTime(event.createdAt)}
                  </span>
                  <span className="mono" style={{ fontWeight: 600, color: "var(--text)" }}>
                    {actionLabel(event.action)}
                  </span>
                  <div>
                    <span className={`audit-outcome ${event.outcome}`}>
                      {event.outcome === "success" ? (
                        <CheckCircle2 size={11} style={{ marginRight: 3 }} />
                      ) : (
                        <XCircle size={11} style={{ marginRight: 3 }} />
                      )}
                      {event.outcome}
                    </span>
                  </div>
                  <span className="detail" title={event.detail}>
                    {event.detail}
                  </span>
                </div>
              ))}
            </div>

            <div className="pagination">
              <button
                className="button compact"
                disabled={page === 0}
                onClick={() => void load(page - 1, filter, outcome, shellFilter)}
              >
                上一页
              </button>
              <span className="pagination-info">
                第 {page + 1} / {pageCount} 页（共 {total} 条审计记录）
              </span>
              <button
                className="button compact"
                disabled={page + 1 >= pageCount}
                onClick={() => void load(page + 1, filter, outcome, shellFilter)}
              >
                下一页
              </button>
            </div>
          </>
        )}
      </Panel>

      {selectedEvent && (
        <div
          className="dialog-backdrop"
          onClick={() => setSelectedEvent(null)}
          role="dialog"
          aria-modal="true"
        >
          <div className="dialog" onClick={(e) => e.stopPropagation()}>
            <div className="dialog-title">
              <h2>审计记录详情 #{selectedEvent.id}</h2>
              <button className="icon-button" onClick={() => setSelectedEvent(null)}>
                ×
              </button>
            </div>
            <div style={{ padding: 20, display: "flex", flexDirection: "column", gap: 12 }}>
              <div className="info-row">
                <span>操作动作</span>
                <code>{actionLabel(selectedEvent.action)} ({selectedEvent.action})</code>
              </div>
              <div className="info-row">
                <span>发生时间</span>
                <code>{selectedEvent.createdAt}</code>
              </div>
              <div className="info-row">
                <span>执行状态</span>
                <span className={`audit-outcome ${selectedEvent.outcome}`}>
                  {selectedEvent.outcome}
                </span>
              </div>
              {selectedEvent.workspaceId && (
                <div className="info-row">
                  <span>Workspace</span>
                  <code>{selectedEvent.workspaceId}</code>
                </div>
              )}
              {selectedEvent.shellId && (
                <div className="info-row">
                  <span>Shell ID</span>
                  <code>{selectedEvent.shellId}</code>
                </div>
              )}
              <div>
                <span className="eyebrow" style={{ display: "block", marginBottom: 6 }}>
                  详细操作载荷 / 轨迹说明
                </span>
                <pre
                  style={{
                    background: "var(--code-bg)",
                    padding: 12,
                    borderRadius: "var(--radius-md)",
                    border: "1px solid var(--border)",
                    fontFamily: "var(--font-mono)",
                    fontSize: 12,
                    lineHeight: 1.5,
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                    maxHeight: 260,
                    overflow: "auto",
                  }}
                >
                  {selectedEvent.detail}
                </pre>
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 8 }}>
                <button className="button primary" onClick={() => setSelectedEvent(null)}>
                  关闭
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
