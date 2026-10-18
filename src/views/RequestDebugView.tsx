import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowLeftRight,
  CheckCircle2,
  Clock,
  Copy,
  Eraser,
  Layers,
  LoaderCircle,
  Play,
  Radio,
  RefreshCw,
  Save,
  Send,
  Terminal,
  Wand2,
  XCircle,
} from "lucide-react";
import { api, errorText, shortTime } from "../api";
import type { HttpSendResult, RequestRecord } from "../api";
import { Empty, ErrorBanner, Metric, Panel } from "../components/common";
import { useToast } from "../components/Toast";

const ACTION_LABELS: Record<string, string> = {
  probe: "探测握手",
  exec: "命令执行",
  list_dir: "浏览目录",
  read_file: "读取文件",
  write_file: "写入文件",
  delete: "删除文件/目录",
  rename: "重命名/移动",
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
      ["User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"],
    ],
    body: "",
  };
}

export function RequestDebugView() {
  const toast = useToast();
  const [records, setRecords] = useState<RequestRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<"repeater" | "logs" | "tools">("repeater");
  const [expanded, setExpanded] = useState<number | null>(null);
  const [endpointFilter, setEndpointFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [request, setRequest] = useState<RepeaterState>(emptyRequest);
  const [response, setResponse] = useState<HttpSendResult | null>(null);
  const [sending, setSending] = useState(false);
  // 默认要求目标命中某个 Workspace 的授权范围；勾选后允许越界（审计记 override）
  const [allowUnscoped, setAllowUnscoped] = useState(false);
  const [templates, setTemplates] = useState<{ name: string; request: RepeaterState }[]>([]);
  const [templateName, setTemplateName] = useState("");
  const [toolInput, setToolInput] = useState("");
  const [toolOutput, setToolOutput] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      setRecords(await api.listRequestLog());
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "加载请求日志失败");
    } finally {
      setLoading(false);
    }
  }, [toast]);

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

  const successCount = useMemo(() => records.filter((r) => r.status >= 200 && r.status < 400).length, [records]);
  const errorCount = useMemo(() => records.filter((r) => r.status >= 400 || r.status === 0).length, [records]);
  const avgLatency = useMemo(() => {
    if (records.length === 0) return "0 ms";
    const sum = records.reduce((acc, r) => acc + (r.durationMs || 0), 0);
    return `${Math.round(sum / records.length)} ms`;
  }, [records]);

  async function clear() {
    try {
      await api.clearRequestLog();
      toast.info("已清空协议帧请求日志");
      await load();
    } catch (cause) {
      toast.error(errorText(cause), "清空失败");
    }
  }

  async function send() {
    if (!request.url.trim()) {
      toast.warning("请输入请求目标 URL");
      return;
    }
    setSending(true);
    setError("");
    try {
      const res = await api.httpSend(
        {
          method: request.method,
          url: request.url,
          headers: request.headers.filter(([name]) => name.trim() !== ""),
          body: request.body,
        },
        allowUnscoped,
      );
      setResponse(res);
      toast.success(`${res.status} ${res.statusText} (${res.durationMs} ms)`, "请求已完成");
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "请求发送失败");
      setResponse(null);
    } finally {
      setSending(false);
    }
  }

  function loadFromLog(record: RequestRecord) {
    setRequest({
      method: "POST",
      url: record.endpoint,
      headers: [
        ["Content-Type", "application/x-www-form-urlencoded"],
        ["User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"],
      ],
      body: record.payload,
    });
    setResponse(null);
    setActiveTab("repeater");
    toast.info("已将日志载荷导入到 Repeater", "载入成功");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function saveTemplate() {
    const name = templateName.trim() || `模板 ${templates.length + 1}`;
    const next = [...templates.filter((item) => item.name !== name), { name, request }];
    setTemplates(next);
    localStorage.setItem(TEMPLATE_KEY, JSON.stringify(next));
    setTemplateName("");
    toast.success(`模板「${name}」已保存`, "保存成功");
  }

  function loadTemplate(template: { name: string; request: RepeaterState }) {
    setRequest(structuredClone(template.request));
    setResponse(null);
    toast.info(`已载入模板「${template.name}」`);
  }

  function removeTemplate(name: string) {
    const next = templates.filter((item) => item.name !== name);
    setTemplates(next);
    localStorage.setItem(TEMPLATE_KEY, JSON.stringify(next));
    toast.info(`已删除模板「${name}」`);
  }

  function copyAsCurl() {
    let curl = `curl -X ${request.method} "${request.url}"`;
    for (const [k, v] of request.headers) {
      if (k.trim()) curl += ` \\\n  -H "${k}: ${v}"`;
    }
    if (request.body && request.method !== "GET" && request.method !== "HEAD") {
      curl += ` \\\n  --data-raw "${request.body.replace(/"/g, '\\"')}"`;
    }
    void navigator.clipboard.writeText(curl);
    toast.success("已生成 cURL 命令并复制到剪贴板", "cURL 导出成功");
  }

  // --- 编码与调试小工具 ---
  function applyTool(type: "urlEncode" | "urlDecode" | "b64Encode" | "b64Decode" | "hexEncode" | "hexDecode") {
    try {
      switch (type) {
        case "urlEncode":
          setToolOutput(encodeURIComponent(toolInput));
          break;
        case "urlDecode":
          setToolOutput(decodeURIComponent(toolInput));
          break;
        case "b64Encode":
          setToolOutput(btoa(unescape(encodeURIComponent(toolInput))));
          break;
        case "b64Decode":
          setToolOutput(decodeURIComponent(escape(atob(toolInput))));
          break;
        case "hexEncode": {
          const bytes = new TextEncoder().encode(toolInput);
          setToolOutput(Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(""));
          break;
        }
        case "hexDecode": {
          const clean = toolInput.replace(/\s+/g, "");
          const bytes = new Uint8Array(clean.length / 2);
          for (let i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
          }
          setToolOutput(new TextDecoder().decode(bytes));
          break;
        }
      }
    } catch (e) {
      setToolOutput(`处理失败: ${String(e)}`);
    }
  }

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">PROTOCOL & REQUEST DEBUGGER</p>
          <h1>请求与协议调试中心</h1>
        </div>
        <div className="top-actions">
          <button
            className={`button ${activeTab === "repeater" ? "primary" : "secondary"}`}
            onClick={() => setActiveTab("repeater")}
          >
            <ArrowLeftRight size={14} />
            HTTP 重放器
          </button>
          <button
            className={`button ${activeTab === "logs" ? "primary" : "secondary"}`}
            onClick={() => setActiveTab("logs")}
          >
            <Radio size={14} />
            底层交互日志 ({records.length})
          </button>
          <button
            className={`button ${activeTab === "tools" ? "primary" : "secondary"}`}
            onClick={() => setActiveTab("tools")}
          >
            <Wand2 size={14} />
            编解码工具箱
          </button>
          <button className="button secondary" onClick={() => void load()} title="刷新日志">
            <RefreshCw size={14} />
            刷新
          </button>
        </div>
      </header>

      {error && <ErrorBanner message={error} />}

      {/* 状态统计卡片 */}
      <section className="metrics">
        <Metric
          label="协议记录帧"
          value={records.length}
          detail="全量通信抓包"
          icon={<Radio size={16} />}
          onClick={() => setActiveTab("logs")}
        />
        <Metric
          label="成功响应"
          value={successCount}
          detail="HTTP 200~399"
          accent
          icon={<CheckCircle2 size={16} />}
        />
        <Metric
          label="异常与失败"
          value={errorCount}
          detail="HTTP 4xx / 5xx / 超时"
          icon={<XCircle size={16} />}
        />
        <Metric
          label="平均往返耗时"
          value={avgLatency}
          detail="通信网络延迟"
          icon={<Clock size={16} />}
        />
        <Metric
          label="关联端点数"
          value={endpoints.length}
          detail="涉及 WebShell 节点"
          icon={<Layers size={16} />}
        />
      </section>

      {activeTab === "tools" && (
        <Panel
          eyebrow="SECURITY TOOLBOX"
          title="常用安全编解码与载荷转换工具"
          actions={
            <button className="button compact secondary" onClick={() => setActiveTab("repeater")}>
              返回重放器
            </button>
          }
        >
          <div style={{ padding: "18px 22px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <span className="eyebrow">输入文本 / 原始载荷</span>
              <textarea
                className="repeater-body"
                rows={7}
                value={toolInput}
                onChange={(e) => setToolInput(e.target.value)}
                placeholder="输入待编码/解码的字符串、SQL 载荷或命令…"
                spellCheck={false}
              />
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                <button className="button compact secondary" onClick={() => applyTool("urlEncode")}>
                  URL 编码
                </button>
                <button className="button compact secondary" onClick={() => applyTool("urlDecode")}>
                  URL 解码
                </button>
                <button className="button compact secondary" onClick={() => applyTool("b64Encode")}>
                  Base64 编码
                </button>
                <button className="button compact secondary" onClick={() => applyTool("b64Decode")}>
                  Base64 解码
                </button>
                <button className="button compact secondary" onClick={() => applyTool("hexEncode")}>
                  HEX 编码
                </button>
                <button className="button compact secondary" onClick={() => applyTool("hexDecode")}>
                  HEX 解码
                </button>
              </div>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span className="eyebrow">转换输出结果</span>
                {toolOutput && (
                  <button
                    className="button compact"
                    onClick={() => {
                      void navigator.clipboard.writeText(toolOutput);
                      toast.success("已复制到剪贴板");
                    }}
                  >
                    <Copy size={12} />
                    复制结果
                  </button>
                )}
              </div>
              <textarea
                className="repeater-body"
                rows={7}
                readOnly
                value={toolOutput}
                placeholder="编解码处理结果将即时呈现在此处…"
                spellCheck={false}
              />
            </div>
          </div>
        </Panel>
      )}

      {activeTab === "repeater" && (
        <Panel
          eyebrow="HTTP REPEATER"
          title="HTTP 发包重放与载荷调试"
          actions={
            <div style={{ display: "flex", gap: 6 }}>
              <button className="button compact secondary" onClick={() => copyAsCurl()}>
                <Terminal size={13} />
                复制 cURL
              </button>
            </div>
          }
        >
          <div className="repeater">
            <div className="repeater-request">
              <div className="repeater-row">
                <select
                  className="select repeater-method"
                  value={request.method}
                  onChange={(event) =>
                    setRequest((prev) => ({ ...prev, method: event.target.value }))
                  }
                >
                  {["POST", "GET", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"].map((method) => (
                    <option key={method} value={method}>
                      {method}
                    </option>
                  ))}
                </select>
                <input
                  className="repeater-url"
                  value={request.url}
                  onChange={(event) =>
                    setRequest((prev) => ({ ...prev, url: event.target.value }))
                  }
                  placeholder="http://192.168.1.100/shell.php"
                  spellCheck={false}
                />
                <button
                  className="button primary"
                  onClick={() => void send()}
                  disabled={sending || !request.url}
                >
                  {sending ? (
                    <LoaderCircle className="spin" size={15} />
                  ) : (
                    <Send size={15} />
                  )}
                  发送请求
                </button>
              </div>

              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  margin: "6px 0 2px",
                  fontSize: 12,
                  color: "var(--muted)",
                }}
                title="默认仅允许命中某个 Workspace 授权范围的目标；越界发送会写入审计"
              >
                <input
                  type="checkbox"
                  checked={allowUnscoped}
                  onChange={(event) => setAllowUnscoped(event.target.checked)}
                />
                允许未授权范围目标（越界发送将记入审计日志）
              </label>

              <div className="repeater-headers">
                {request.headers.map(([name, value], index) => (
                  <div className="repeater-row" key={index}>
                    <input
                      className="repeater-hname"
                      value={name}
                      placeholder="Header 名称"
                      spellCheck={false}
                      onChange={(event) =>
                        setRequest((prev) => {
                          const headers = prev.headers.map((item, i) =>
                            i === index ? ([event.target.value, item[1]] as [string, string]) : item,
                          );
                          return { ...prev, headers };
                        })
                      }
                    />
                    <input
                      className="repeater-hvalue"
                      value={value}
                      placeholder="Header 对应值"
                      spellCheck={false}
                      onChange={(event) =>
                        setRequest((prev) => {
                          const headers = prev.headers.map((item, i) =>
                            i === index ? ([item[0], event.target.value] as [string, string]) : item,
                          );
                          return { ...prev, headers };
                        })
                      }
                    />
                    <button
                      className="icon-button"
                      style={{ width: 28, height: 28 }}
                      onClick={() =>
                        setRequest((prev) => ({
                          ...prev,
                          headers: prev.headers.filter((_, i) => i !== index),
                        }))
                      }
                      title="移除该请求头"
                    >
                      ×
                    </button>
                  </div>
                ))}
                <div>
                  <button
                    className="button secondary compact"
                    onClick={() =>
                      setRequest((prev) => ({ ...prev, headers: [...prev.headers, ["", ""]] }))
                    }
                  >
                    + 添加 Header
                  </button>
                </div>
              </div>

              <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                <span className="eyebrow">请求体载荷 (Request Body)</span>
                <textarea
                  className="repeater-body"
                  rows={8}
                  value={request.body}
                  onChange={(event) =>
                    setRequest((prev) => ({ ...prev, body: event.target.value }))
                  }
                  placeholder="请求体载荷（表单数据 / JSON / Base64）…"
                  spellCheck={false}
                />
              </label>

              <div className="repeater-tools">
                <input
                  className="repeater-tpl-name"
                  value={templateName}
                  onChange={(event) => setTemplateName(event.target.value)}
                  placeholder="模板别名"
                  style={{
                    height: 30,
                    borderRadius: "var(--radius-sm)",
                    border: "1px solid var(--border)",
                    padding: "0 8px",
                    fontSize: 12,
                  }}
                />
                <button className="button secondary compact" onClick={saveTemplate}>
                  <Save size={13} />
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
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                    <p className={`repeater-status ${response.status < 400 ? "ok" : "err"}`}>
                      {response.status} {response.statusText} · 耗时: {response.durationMs} ms
                    </p>
                    <button
                      className="button compact"
                      onClick={() => {
                        void navigator.clipboard.writeText(response.body);
                        toast.success("响应体已复制到剪贴板");
                      }}
                    >
                      <Copy size={13} />
                      复制响应
                    </button>
                  </div>
                  <pre className="repeater-resp-headers">
                    {response.headers.map(([name, value]) => `${name}: ${value}`).join("\n")}
                  </pre>
                  <pre className="repeater-resp-body">{response.body || "（响应体为空）"}</pre>
                </>
              ) : (
                <Empty
                  icon={<Play size={28} />}
                  title="尚未发送请求"
                  detail="构造请求后点击「发送请求」。也可从「底层交互日志」中直接点击「载入 Repeater」复用实际通信载荷。"
                />
              )}
            </div>
          </div>
        </Panel>
      )}

      {activeTab === "logs" && (
        <Panel
          eyebrow="FRAME LOGS"
          title={`协议底层交互日志 (${filtered.length})`}
          actions={
            <div style={{ display: "flex", gap: 8 }}>
              <select
                className="select"
                value={endpointFilter}
                onChange={(event) => setEndpointFilter(event.target.value)}
              >
                <option value="">全部端点</option>
                {endpoints.map((endpoint) => (
                  <option key={endpoint} value={endpoint}>
                    {endpoint}
                  </option>
                ))}
              </select>
              <select
                className="select"
                value={actionFilter}
                onChange={(event) => setActionFilter(event.target.value)}
              >
                <option value="">全部操作</option>
                {Object.entries(ACTION_LABELS).map(([action, label]) => (
                  <option key={action} value={action}>
                    {label}
                  </option>
                ))}
              </select>
              <button className="button secondary compact" onClick={() => void clear()}>
                <Eraser size={13} />
                清空日志
              </button>
            </div>
          }
        >
          {loading ? (
            <Empty icon={<LoaderCircle className="spin" size={24} />} title="正在读取请求记录…" />
          ) : filtered.length === 0 ? (
            <Empty
              icon={<Radio size={28} />}
              title="暂无底层交互日志"
              detail="连接真实网络 Shell 后，每条握手、命令、文件操作协议帧（载荷与回显）都会在此留痕（已做敏感信息脱敏）。"
            />
          ) : (
            <div className="debug-list">
              {filtered.map((record) => (
                <article
                  className={`debug-item ${expanded === record.id ? "open" : ""}`}
                  key={record.id}
                >
                  <button
                    className="debug-head"
                    onClick={() => setExpanded(expanded === record.id ? null : record.id)}
                  >
                    <span className={`debug-status ${record.status < 400 ? "ok" : "err"}`}>
                      {record.status}
                    </span>
                    <span className="debug-action">{actionLabel(record.action)}</span>
                    <span className="debug-protocol">
                      {record.protocolId.replace("builtin.", "").replace(".v1", "")}
                    </span>
                    <code className="debug-endpoint">{record.endpoint}</code>
                    <span className="debug-meta">
                      {shortTime(record.createdAt)} · {record.durationMs} ms
                    </span>
                  </button>
                  {expanded === record.id && (
                    <div className="debug-body">
                      <div className="debug-block">
                        <h3>载荷 (Payload - 脱敏后)</h3>
                        <pre>{record.payload}</pre>
                      </div>
                      <div className="debug-block">
                        <h3>响应回显 (Response)</h3>
                        <pre>{record.response}</pre>
                      </div>
                      <div style={{ display: "flex", justifyContent: "flex-end" }}>
                        <button className="button primary compact" onClick={() => loadFromLog(record)}>
                          <Send size={13} />
                          载入到 Repeater 重放
                        </button>
                      </div>
                    </div>
                  )}
                </article>
              ))}
            </div>
          )}
        </Panel>
      )}
    </>
  );
}
