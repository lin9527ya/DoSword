import { useCallback, useEffect, useState } from "react";
import { Activity, Download } from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText, shortTime } from "../api";
import type { AuditEvent } from "../api";
import { Empty, ErrorBanner, Panel } from "../components/common";

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
  "file.delete": "删除",
  "file.rename": "重命名",
  "file.mkdir": "新建目录",
  "settings.update": "设置变更",
};

export function actionLabel(action: string): string {
  return ACTION_LABELS[action] ?? action;
}

function csvCell(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

export function AuditView() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState<string>("");
  const [outcome, setOutcome] = useState<string>("");
  const [page, setPage] = useState(0);

  const load = useCallback(async (targetPage: number, action: string, result: string) => {
    setLoading(true);
    setError("");
    try {
      const data = await api.listAudit({
        action: action || undefined,
        outcome: result || undefined,
        limit: PAGE_SIZE,
        offset: targetPage * PAGE_SIZE,
      });
      setEvents(data.events);
      setTotal(data.total);
      setPage(targetPage);
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(0, filter, outcome);
  }, [load, filter, outcome]);

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));

  async function exportCsv() {
    const localPath = await save({
      defaultPath: `dosword-audit-${new Date().toISOString().slice(0, 10)}.csv`,
      filters: [{ name: "CSV", extensions: ["csv"] }],
    });
    if (!localPath) return;
    const rows = [
      ["时间", "操作", "结果", "详情", "Workspace", "Shell"],
      ...events.map((event) => [
        event.createdAt,
        actionLabel(event.action),
        event.outcome,
        event.detail,
        event.workspaceId || "",
        event.shellId ?? "",
      ]),
    ];
    const csv = "\uFEFF" + rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
    try {
      const bytes = new TextEncoder().encode(csv);
      await api.writeLocalFile(localPath, b64.encodeBytes(bytes));
    } catch (cause) {
      setError(`导出失败：${errorText(cause)}`);
    }
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">AUDIT TRAIL</p>
          <h1>审计日志</h1>
        </div>
        <div className="top-actions">
          <select className="select" value={outcome} onChange={(event) => setOutcome(event.target.value)}>
            <option value="">全部结果</option>
            <option value="success">success</option>
            <option value="error">error</option>
          </select>
          <select className="select" value={filter} onChange={(event) => setFilter(event.target.value)}>
            <option value="">全部操作</option>
            {Object.entries(ACTION_LABELS).map(([action, label]) => (
              <option key={action} value={action}>
                {label}
              </option>
            ))}
          </select>
          <button className="button secondary" onClick={() => void load(page, filter, outcome)}>
            刷新
          </button>
          <button className="button secondary" onClick={() => void exportCsv()} disabled={events.length === 0}>
            <Download size={16} />
            导出 CSV
          </button>
        </div>
      </header>
      {error && <ErrorBanner message={error} />}
      <Panel eyebrow="EVENT LOG" title={`审计事件（${total}）`}>
        {loading ? (
          <Empty icon={<Activity />} title="正在读取审计日志" />
        ) : events.length === 0 ? (
          <Empty icon={<Activity />} title="暂无审计事件" detail="所有连接、命令与文件操作都会记录在这里。" />
        ) : (
          <>
            <div className="audit-table">
              <div className="audit-head">
                <span>时间</span>
                <span>操作</span>
                <span>结果</span>
                <span>详情</span>
              </div>
              {events.map((event) => (
                <div className="audit-row" key={event.id}>
                  <span className="mono">{shortTime(event.createdAt)}</span>
                  <span className="mono">{actionLabel(event.action)}</span>
                  <span className={`audit-outcome ${event.outcome}`}>{event.outcome}</span>
                  <span className="detail">{event.detail}</span>
                </div>
              ))}
            </div>
            <div className="pagination">
              <button
                className="button compact"
                disabled={page === 0}
                onClick={() => void load(page - 1, filter, outcome)}
              >
                上一页
              </button>
              <span className="pagination-info">
                第 {page + 1} / {pageCount} 页（共 {total} 条）
              </span>
              <button
                className="button compact"
                disabled={page + 1 >= pageCount}
                onClick={() => void load(page + 1, filter, outcome)}
              >
                下一页
              </button>
            </div>
          </>
        )}
      </Panel>
    </>
  );
}
