import { useCallback, useEffect, useMemo, useState } from "react";
import { Braces, Eraser, LoaderCircle, Play, RefreshCw, Save, Send } from "lucide-react";
import { api, errorText, shortTime } from "../api";
import type { HttpSendResult, RequestRecord } from "../api";
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

type RepeaterState = {
  method: string;
  url: string;
  headers: [string, string][];
  body: string;
};

const TEMPLATE_KEY = "dosword:repeater-templates";

function emptyRequest(): RepeaterState {
  return {
    method: "POST",
    url: "",
    headers: [
      ["Content-Type", "application/x-www-form-urlencoded"],
      ["X-Debug-Key", ""],
    ],
    body: "",
  };
}

/** 请求调试：上半 Repeater（手工构造/重放/模板），下半协议帧日志（只读，可载入）。 */
export function RequestDebugView() {
  const [records, setRecords] = useState<RequestRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);
  const [endpointFilter, setEndpointFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [request, setRequest] = useState<RepeaterState>(emptyRequest);
  const [response, setResponse] = useState<HttpSendResult | null>(null);
  const [sending, setSending] = useState(false);
  const [templates, setTemplates] = useState<{ name: string; request: RepeaterState }[]>([]);
  const [templateName, setTemplateName] = useState("");

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
    try {
      setTemplates(JSON.parse(localStorage.getItem(TEMPLATE_KEY) ?? "[]"));
    } catch {
      setTemplates([]);
    }
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

  async function send() {
    setSending(true);
    setError("");
    try {
      setResponse(
        await api.httpSend({
          method: request.method,
          url: request.url,
          headers: request.headers.filter(([name]) => name.trim() !== ""),
          body: request.body,
        }),
      );
    } catch (cause) {
      setError(errorText(cause));
      setResponse(null);
    } finally {
      setSending(false);
    }
  }

  function loadFromLog(record: RequestRecord) {
    setRequest({
      method: "POST",
      url: record.endpoint,
      headers: [["Content-Type", "application/x-www-form-urlencoded"], ["X-Debug-Key", ""]],
      body: record.payload,
    });
    setResponse(null);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function saveTemplate() {
    const name = templateName.trim() || `模板 ${templates.length + 1}`;
    const next = [...templates.filter((item) => item.name !== name), { name, request }];
    setTemplates(next);
    localStorage.setItem(TEMPLATE_KEY, JSON.stringify(next));
    setTemplateName("");
  }

  function loadTemplate(template: { name: string; request: RepeaterState }) {
    setRequest(structuredClone(template.request));
    setResponse(null);
  }

  function removeTemplate(name: string) {
    const next = templates.filter((item) => item.name !== name);
    setTemplates(next);
    localStorage.setItem(TEMPLATE_KEY, JSON.stringify(next));
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">协议检查器</p>
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

      <Panel eyebrow="重放器" title="手工请求（修改 / 重放 / 模板）">
        <div className="repeater">
          <div className="repeater-request">
            <div className="repeater-row">
              <select
                className="select repeater-method"
                value={request.method}
                onChange={(event) => setRequest((prev) => ({ ...prev, method: event.target.value }))}
              >
                {["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"].map((method) => (
                  <option key={method} value={method}>
                    {method}
                  </option>
                ))}
              </select>
              <input
                className="repeater-url"
                value={request.url}
                onChange={(event) => setRequest((prev) => ({ ...prev, url: event.target.value }))}
                placeholder="https://目标/shell.php"
              />
              <button className="button primary" onClick={() => void send()} disabled={sending || !request.url}>
                {sending ? <LoaderCircle className="spin" size={15} /> : <Send size={15} />}
                发送
              </button>
            </div>
            <div className="repeater-headers">
              {request.headers.map(([name, value], index) => (
                <div className="repeater-row" key={index}>
                  <input
                    className="repeater-hname"
                    value={name}
                    placeholder="请求头"
                    onChange={(event) =>
                      setRequest((prev) => {
                        const headers = prev.headers.map((item, i) => (i === index ? [event.target.value, item[1]] as [string, string] : item));
                        return { ...prev, headers };
                      })
                    }
                  />
                  <input
                    className="repeater-hvalue"
                    value={value}
                    placeholder="值"
                    onChange={(event) =>
                      setRequest((prev) => {
                        const headers = prev.headers.map((item, i) => (i === index ? [item[0], event.target.value] as [string, string] : item));
                        return { ...prev, headers };
                      })
                    }
                  />
                  <button
                    className="button secondary small"
                    onClick={() =>
                      setRequest((prev) => ({ ...prev, headers: prev.headers.filter((_, i) => i !== index) }))
                    }
                  >
                    ×
                  </button>
                </div>
              ))}
              <button
                className="button secondary small"
                onClick={() =>
                  setRequest((prev) => ({ ...prev, headers: [...prev.headers, ["", ""]] }))
                }
              >
                + Header
              </button>
            </div>
            <textarea
              className="repeater-body"
              rows={6}
              value={request.body}
              onChange={(event) => setRequest((prev) => ({ ...prev, body: event.target.value }))}
              placeholder="请求体（formData=... / JSON / 原始字节）"
            />
            <div className="repeater-tools">
              <input
                className="repeater-tpl-name"
                value={templateName}
                onChange={(event) => setTemplateName(event.target.value)}
                placeholder="模板名称"
              />
              <button className="button secondary small" onClick={saveTemplate}>
                <Save size={14} />
                保存模板
              </button>
              {templates.map((template) => (
                <span className="tpl-chip" key={template.name}>
                  <button className="tpl-chip-main" onClick={() => loadTemplate(template)}>
                    {template.name}
                  </button>
                  <button className="tpl-chip-x" onClick={() => removeTemplate(template.name)}>
                    ×
                  </button>
                </span>
              ))}
            </div>
          </div>
          <div className="repeater-response">
            {response ? (
              <>
                <p className={`repeater-status ${response.status < 400 ? "ok" : "err"}`}>
                  {response.status} {response.statusText} · {response.durationMs} ms
                </p>
                <pre className="repeater-resp-headers">
                  {response.headers.map(([name, value]) => `${name}: ${value}`).join("\n")}
                </pre>
                <pre className="repeater-resp-body">{response.body}</pre>
              </>
            ) : (
              <Empty icon={<Play />} title="尚未发送" detail="构造请求后点击「发送」。可从下方日志「载入 Repeater」复用载荷。" />
            )}
          </div>
        </div>
      </Panel>

      <Panel eyebrow="帧日志" title={`协议请求（${filtered.length}）`}>
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
                  <span className="debug-protocol">{record.protocolId.replace("builtin.", "").replace(".v1", "")}</span>
                  <code className="debug-endpoint">{record.endpoint}</code>
                  <span className="debug-meta">
                    {shortTime(record.createdAt)} · {record.durationMs} ms
                  </span>
                </button>
                {expanded === record.id && (
                  <div className="debug-body">
                    <div className="debug-block">
                      <h3>载荷（已脱敏）</h3>
                      <pre>{record.payload}</pre>
                    </div>
                    <div className="debug-block">
                      <h3>响应</h3>
                      <pre>{record.response}</pre>
                    </div>
                    <button className="button secondary small" onClick={() => loadFromLog(record)}>
                      <Send size={13} />
                      载入 Repeater
                    </button>
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
