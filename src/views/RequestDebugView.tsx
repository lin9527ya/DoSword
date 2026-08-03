import { useCallback, useEffect, useMemo, useState } from "react";
import { Braces, Eraser, LoaderCircle, RefreshCw } from "lucide-react";
import { api, errorText, shortTime } from "../api";
import type { RequestRecord } from "../api";
import { Empty, ErrorBanner, Panel } from "../components/common";

const ACTION_LABELS: Record<string, string> = {
  probe: "探测",
  exec: "命令执行",
  list_dir: "浏览目录",
  read_file: "读取文件",
  write_file: "写入文件",
  delete: "删除",
  rename: "重命名",
  mkdir: "新建目录",
  read_chunk: "分块读取",
  write_chunk: "分块写入",
  db_probe: "数据库探测",
  db_query: "数据库查询",
};

export function actionLabel(action: string): string {
  return ACTION_LABELS[action] ?? action;
}

/** 请求调试：进程内环缓冲的协议帧记录（载荷 / 响应，密码已脱敏）。 */
export function RequestDebugView() {
  const [records, setRecords] = useState<RequestRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);
  const [endpointFilter, setEndpointFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setRecords(await api.listRequestLog());
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const endpoints = useMemo(() => [...new Set(records.map((record) => record.endpoint))], [records]);

  const filtered = useMemo(
    () =>
      records.filter(
        (record) =>
          (!endpointFilter || record.endpoint === endpointFilter) &&
          (!actionFilter || record.action === actionFilter),
      ),
    [records, endpointFilter, actionFilter],
  );

  async function clear() {
    setError("");
    try {
      await api.clearRequestLog();
      await load();
    } catch (cause) {
      setError(errorText(cause));
    }
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">PROTOCOL INSPECTOR</p>
          <h1>请求调试</h1>
        </div>
        <div className="top-actions">
          <select className="select" value={endpointFilter} onChange={(event) => setEndpointFilter(event.target.value)}>
            <option value="">全部端点</option>
            {endpoints.map((endpoint) => (
              <option key={endpoint} value={endpoint}>
                {endpoint}
              </option>
            ))}
          </select>
          <select className="select" value={actionFilter} onChange={(event) => setActionFilter(event.target.value)}>
            <option value="">全部操作</option>
            {Object.entries(ACTION_LABELS).map(([action, label]) => (
              <option key={action} value={action}>
                {label}
              </option>
            ))}
          </select>
          <button className="button secondary" onClick={() => void load()}>
            <RefreshCw size={16} />
            刷新
          </button>
          <button className="button secondary" onClick={() => void clear()}>
            <Eraser size={16} />
            清空
          </button>
        </div>
      </header>
      {error && <ErrorBanner message={error} />}
      <Panel eyebrow="FRAME LOG" title={`协议请求（${filtered.length}）`}>
        {loading ? (
          <Empty icon={<LoaderCircle className="spin" />} title="正在读取请求记录" />
        ) : filtered.length === 0 ? (
          <Empty
            icon={<Braces />}
            title="暂无请求记录"
            detail="连接真实网络 Shell 后，每条协议请求（载荷与响应）都会记录在这里。密码已脱敏。"
          />
        ) : (
          <div className="debug-list">
            {filtered.map((record) => (
              <article
                className={`debug-item ${expanded === record.id ? "open" : ""}`}
                key={record.id}
              >
                <button className="debug-head" onClick={() => setExpanded(expanded === record.id ? null : record.id)}>
                  <span className={`debug-status ${record.status < 400 ? "ok" : "err"}`}>
                    {record.status}
                  </span>
                  <span className="debug-action">{actionLabel(record.action)}</span>
                  <code className="debug-endpoint">{record.endpoint}</code>
                  <span className="debug-meta">
                    {shortTime(record.createdAt)} · {record.durationMs} ms
                  </span>
                </button>
                {expanded === record.id && (
                  <div className="debug-body">
                    <div className="debug-block">
                      <h3>载荷（PHP，已脱敏）</h3>
                      <pre>{record.payload}</pre>
                    </div>
                    <div className="debug-block">
                      <h3>响应</h3>
                      <pre>{record.response}</pre>
                    </div>
                  </div>
                )}
              </article>
            ))}
          </div>
        )}
      </Panel>
    </>
  );
}
