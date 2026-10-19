import { useCallback, useEffect, useMemo, useState } from "react";
import { BookOpen, CircleSlash, Play, RotateCcw, Save, Trash2 } from "lucide-react";
import { api, errorText } from "../api";
import type { PlaybookReport } from "../api";
import { Panel } from "../components/common";
import { useToast } from "../components/Toast";

const STORAGE_KEY = "dosword:playbook-draft";

const TEMPLATE = `name: smoke
continue_on_error: false
steps:
  - id: conn
    action: connect
    args: { shell_id: "在此填入 Shell ID（总览页可复制）" }
  - id: whoami
    action: exec
    args: { session_id: "\${conn.sessionId}", command: "id" }
    expect:
      contains: "uid="
  # 条件：为假时跳过（skipped=true，不计失败）
  - action: list_dir
    when: { ref: "\${conn.runtime}", equals: "php" }
    args: { session_id: "\${conn.sessionId}", path: "/" }
  - action: disconnect
    args: { session_id: "\${conn.sessionId}" }
`;

/** 动作 → 中文说明（与后端 playbook 动作表一致）。 */
const ACTION_LABELS: Record<string, string> = {
  connect: "建立会话",
  disconnect: "断开会话",
  exec: "执行命令",
  list_dir: "列目录",
  read_file: "读文件",
  write_file: "写文件",
  plugin: "运行插件",
};

export function PlaybookView() {
  const toast = useToast();
  const [yaml, setYaml] = useState<string>(() => localStorage.getItem(STORAGE_KEY) ?? TEMPLATE);
  const [report, setReport] = useState<PlaybookReport | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // 草稿自动落盘：运行前误关页面不至于丢失
  useEffect(() => {
    const timer = window.setTimeout(() => localStorage.setItem(STORAGE_KEY, yaml), 400);
    return () => window.clearTimeout(timer);
  }, [yaml]);

  const run = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    setError("");
    setReport(null);
    try {
      const result = await api.runPlaybook(yaml);
      setReport(result);
      if (result.ok) {
        toast.success(`Playbook「${result.name}」通过（${result.durationMs}ms）`, "运行完成");
      } else {
        const failed = result.steps.find((step) => !step.ok && !step.skipped);
        toast.error(
          failed ? `第 ${failed.index + 1} 步失败：${failed.error ?? "未知原因"}` : "运行未通过",
          "运行失败",
        );
      }
    } catch (cause) {
      const message = errorText(cause);
      setError(message);
      toast.error(message, "运行失败");
    } finally {
      setBusy(false);
    }
  }, [busy, toast, yaml]);

  // Ctrl/Cmd + Enter 运行
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
        event.preventDefault();
        void run();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [run]);

  const summary = useMemo(() => {
    if (!report) return null;
    const total = report.steps.length;
    const skipped = report.steps.filter((step) => step.skipped).length;
    const failed = report.steps.filter((step) => !step.ok && !step.skipped).length;
    return { total, skipped, failed };
  }, [report]);

  return (
    <>
      <header className="topbar">
        <div>
          <p className="eyebrow">AUTOMATION PLAYBOOK</p>
          <h1>剧本编排</h1>
        </div>
        <div className="top-actions">
          <button
            className="button secondary"
            onClick={() => setYaml(TEMPLATE)}
            title="恢复内置示例"
          >
            <RotateCcw size={14} /> 重置模板
          </button>
          <button
            className="button secondary"
            onClick={() => {
              localStorage.setItem(STORAGE_KEY, yaml);
              toast.success("草稿已保存到本地", "已保存");
            }}
          >
            <Save size={14} /> 保存草稿
          </button>
          <button className="button primary" disabled={busy} onClick={() => void run()}>
            <Play size={14} /> {busy ? "运行中…" : "运行 (Ctrl+Enter)"}
          </button>
        </div>
      </header>

      {error && (
        <div className="banner danger" style={{ margin: "0 24px 12px" }}>
          {error}
        </div>
      )}

      <div style={{ display: "grid", gap: 16, padding: "0 24px 24px", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)" }}>
        <Panel eyebrow="YAML" title="剧本定义">
          <div className="settings-body">
            <p style={{ fontSize: 12, color: "var(--muted)", margin: 0 }}>
              动作：{Object.entries(ACTION_LABELS).map(([key, label]) => `${key}（${label}）`).join("、")}
              。变量：<code className="mono">${"${步骤id.字段}"}</code>；断言：<code className="mono">expect.contains / equals</code>；
              条件：<code className="mono">when</code>；循环：<code className="mono">repeat</code> / <code className="mono">foreach</code>。
            </p>
            <textarea
              className="mono"
              spellCheck={false}
              value={yaml}
              onChange={(event) => setYaml(event.target.value)}
              style={{ width: "100%", minHeight: 420, padding: 10, borderRadius: 8, resize: "vertical" }}
            />
          </div>
        </Panel>

        <Panel eyebrow="RESULT" title="运行结果">
          <div className="settings-body">
            {!report && (
              <p style={{ fontSize: 13, color: "var(--muted)" }}>
                <BookOpen size={14} /> 还没有运行记录。填入有效的 Shell ID 后点「运行」。
              </p>
            )}
            {report && summary && (
              <>
                <div style={{ display: "flex", gap: 18, fontSize: 13 }}>
                  <span>
                    名称：<strong>{report.name}</strong>
                  </span>
                  <span style={{ color: report.ok ? "var(--ok, #2e9e5b)" : "var(--danger, #d9534f)" }}>
                    {report.ok ? "通过" : "失败"}
                  </span>
                  <span>耗时：{report.durationMs}ms</span>
                  <span>
                    步骤：{summary.total}（失败 {summary.failed} / 跳过 {summary.skipped}）
                  </span>
                </div>
                <div style={{ display: "grid", gap: 6 }}>
                  {report.steps.map((step) => (
                    <div
                      key={`${step.index}-${step.id ?? step.action}`}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        padding: "6px 8px",
                        borderRadius: 6,
                        border: "1px solid var(--border, rgba(127,127,127,.2))",
                        fontSize: 12,
                      }}
                    >
                      <span className="mono" style={{ width: 28, color: "var(--muted)" }}>
                        {step.index + 1}
                      </span>
                      <span style={{ width: 96 }}>{ACTION_LABELS[step.action] ?? step.action}</span>
                      <span className="mono" style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {step.id ?? ""}
                      </span>
                      <span style={{ width: 64, textAlign: "right", color: "var(--muted)" }}>{step.durationMs}ms</span>
                      <span
                        style={{
                          width: 52,
                          color: step.skipped
                            ? "var(--muted)"
                            : step.ok
                              ? "var(--ok, #2e9e5b)"
                              : "var(--danger, #d9534f)",
                        }}
                      >
                        {step.skipped ? "跳过" : step.ok ? "通过" : "失败"}
                      </span>
                    </div>
                  ))}
                </div>
                {!report.ok && (
                  <div style={{ fontSize: 12, color: "var(--danger, #d9534f)" }}>
                    <CircleSlash size={13} />{" "}
                    {report.steps.find((step) => !step.ok && !step.skipped)?.error ?? "运行未通过"}
                  </div>
                )}
              </>
            )}
            {report && (
              <button
                className="button secondary compact"
                onClick={() => {
                  setReport(null);
                  setError("");
                }}
              >
                <Trash2 size={13} /> 清空结果
              </button>
            )}
          </div>
        </Panel>
      </div>
    </>
  );
}
