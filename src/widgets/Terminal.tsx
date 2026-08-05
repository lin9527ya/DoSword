import { useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { api } from "../api";

/**
 * 基于 xterm.js 的命令终端。
 * HTTP WebShell 无 PTY、非交互流，这里采用行编辑模式：
 * 输入行收集 → Enter 触发执行 → 输出回显。
 */
const HISTORY_KEY = "dosword:term-history";

type ViewMode = "ansi" | "text" | "json" | "hex";

const VIEW_LABELS: Record<ViewMode, string> = {
  ansi: "ANSI",
  text: "文本",
  json: "JSON",
  hex: "HEX",
};

/** 剥离 ANSI 转义序列（文本/JSON 模式用）。 */
function stripAnsi(text: string): string {
  return text
    .replace(/\x1b\][^\x07]*(\x07|\x1b\\)/g, "")
    .replace(/\x1b\[[0-9;?]*[a-zA-Z]/g, "")
    .replace(/\x1b[()][0-9A-Z]/g, "");
}

/** 按查看格式渲染输出文本。 */
function renderOutput(stdout: string, mode: ViewMode): string {
  switch (mode) {
    case "text":
      return stripAnsi(stdout);
    case "json": {
      const stripped = stripAnsi(stdout).trim();
      try {
        const parsed = JSON.parse(stripped);
        return JSON.stringify(parsed, null, 2);
      } catch {
        return stripped;
      }
    }
    case "hex": {
      const bytes = new TextEncoder().encode(stripAnsi(stdout));
      const lines: string[] = [];
      for (let i = 0; i < bytes.length; i += 16) {
        const chunk = Array.from(bytes.slice(i, i + 16));
        const hex = chunk.map((byte) => byte.toString(16).padStart(2, "0")).join(" ");
        const ascii = chunk
          .map((byte) => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : "."))
          .join("");
        lines.push(`${i.toString(16).padStart(8, "0")}  ${hex.padEnd(47)}  ${ascii}`);
      }
      return lines.join("\r\n");
    }
    default:
      return stdout;
  }
}

export function Terminal({
  sessionId,
  currentDir,
  onCwdChange,
}: {
  sessionId: string;
  currentDir?: string;
  onCwdChange?: (cwd: string) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const bufferRef = useRef("");
  const historyRef = useRef<string[]>([]);
  const historyIndexRef = useRef(-1);
  const busyRef = useRef(false);
  const currentDirRef = useRef(currentDir);
  currentDirRef.current = currentDir;
  const [ready, setReady] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>("ansi");
  const viewModeRef = useRef<ViewMode>("ansi");
  viewModeRef.current = viewMode;

  useEffect(() => {
    try {
      historyRef.current = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
    } catch {
      // 历史记录损坏时忽略
    }
  }, []);

  const prompt = () => `dosword@target:${currentDirRef.current ?? "~"}$ `;

  async function run(command: string) {
    if (!command.trim() || busyRef.current) return;
    busyRef.current = true;
    const term = termRef.current;
    if (!term) return;
    term.write(`\r\n`);
    try {
      const output = await api.executeCommand(sessionId, command);
      term.write(renderOutput(output.stdout, viewModeRef.current).replace(/\n$/, "") + "\r\n");
      if (output.cwd) onCwdChange?.(output.cwd);
    } catch (error) {
      term.write(`\x1b[31m${String(error)}\x1b[0m\r\n`);
    } finally {
      busyRef.current = false;
      if (term) {
        term.write(prompt());
        bufferRef.current = "";
        historyIndexRef.current = -1;
      }
    }
  }

  function changeViewMode(next: ViewMode) {
    setViewMode(next);
    const term = termRef.current;
    if (!term) return;
    term.write(`\r\n\x1b[90m[输出格式: ${VIEW_LABELS[next]}——仅影响后续输出]\x1b[0m\r\n${prompt()}`);
  }

  function pushHistory(command: string) {
    const history = historyRef.current;
    history.push(command);
    if (history.length > 500) history.shift();
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch {
      // 忽略存储失败
    }
  }

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const term = new XTerm({
      fontFamily: '"IBM Plex Mono", monospace',
      fontSize: 13,
      // 输出中的 
 自动转 
（否则 ls 等列对齐输出光标不回到行首导致错乱）
      convertEol: true,
      theme: {
        background: "#111310",
        foreground: "#d6d8d2",
        cursor: "#b6d77d",
        selectionBackground: "#33402a",
        black: "#3a3f37",
        green: "#a9d36a",
        brightGreen: "#b6d77d",
        red: "#d47568",
        brightRed: "#e08a7d",
        yellow: "#d0c66a",
        brightYellow: "#dcd27a",
      },
      scrollback: 2000,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(container);
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;
    term.write(prompt());
    setReady(true);

    const resizeObserver = new ResizeObserver(() => fit.fit());
    resizeObserver.observe(container);

    term.onData((data) => {
      const term = termRef.current;
      if (!term) return;
      // 粘贴多行 / 已提交
      if (data === "\r") {
        const command = bufferRef.current;
        if (command.trim()) {
          pushHistory(command);
          historyIndexRef.current = -1;
          term.write(`\r\n`);
          void run(command);
        } else {
          term.write(`\r\n${prompt()}`);
        }
        return;
      }
      // 退格
      if (data === "\x7f") {
        if (bufferRef.current.length > 0) {
          bufferRef.current = bufferRef.current.slice(0, -1);
          term.write("\b \b");
        }
        return;
      }
      // 清空当前输入
      if (data === "\x03") {
        bufferRef.current = "";
        term.write("\r\n" + prompt());
        return;
      }
      // 历史：上/下
      if (data === "\x1b[A" || data === "\x1b[B") {
        const history = historyRef.current;
        if (history.length === 0) return;
        if (data === "\x1b[A") {
          historyIndexRef.current = Math.min(historyIndexRef.current + 1, history.length - 1);
        } else {
          historyIndexRef.current = Math.max(historyIndexRef.current - 1, -1);
        }
        const entry = historyIndexRef.current >= 0 ? history[history.length - 1 - historyIndexRef.current] : "";
        term.write("\r\x1b[K" + prompt() + entry);
        bufferRef.current = entry;
        return;
      }
      // 常规字符（含粘贴）
      if (data.length === 1 && data.charCodeAt(0) >= 0x20) {
        bufferRef.current += data;
        term.write(data);
      } else if (data.length > 1) {
        // 粘贴内容
        const clean = data.replace(/[\r\n]+/g, "");
        bufferRef.current += clean;
        term.write(clean);
      }
    });

    return () => {
      resizeObserver.disconnect();
      term.dispose();
      termRef.current = null;
    };
  }, []);

  return (
    <div className="terminal-wrap">
      <div className="term-toolbar">
        <span className="term-toolbar-label">输出格式</span>
        <select
          className="select term-view-mode"
          value={viewMode}
          onChange={(event) => changeViewMode(event.target.value as ViewMode)}
        >
          <option value="ansi">ANSI 颜色</option>
          <option value="text">普通文本</option>
          <option value="json">JSON</option>
          <option value="hex">HEX</option>
        </select>
      </div>
      <div className="terminal-box" ref={containerRef} data-ready={ready} />
    </div>
  );
}
