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
  active = true,
  onCwdChange,
}: {
  sessionId: string;
  currentDir?: string;
  /** 是否活动（非活动时暂停轮询但保持 PTY 连接，切回不丢历史）。 */
  active?: boolean;
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
  const [ptyId, setPtyId] = useState<string | null>(null);
  const ptyIdRef = useRef<string | null>(null);
  ptyIdRef.current = ptyId;
  const [ptyFailed, setPtyFailed] = useState(false);
  const ptyFailedRef = useRef(false);
  ptyFailedRef.current = ptyFailed;
  const [outputEncoding, setOutputEncoding] = useState<"utf-8" | "gbk">("utf-8");
  const encodingRef = useRef<"utf-8" | "gbk">("utf-8");
  encodingRef.current = outputEncoding;
  const pollTimerRef = useRef<number | null>(null);
  const activeRef = useRef(true);
  activeRef.current = active;

  useEffect(() => {
    try {
      historyRef.current = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
    } catch {
      // 历史记录损坏时忽略
    }
  }, []);

  const prompt = () => `dosword@target:${currentDirRef.current ?? "~"}$ `;

  async function pollPty(id: string) {
    if (!activeRef.current) return;
    try {
      const result = await api.ptyRead(id);
      if (result.data) {
        const bytes = b64decodeToUint8(result.data);
        termRef.current?.write(bytes);
      }
      if (result.closed) {
        if (pollTimerRef.current !== null) {
          window.clearInterval(pollTimerRef.current);
          pollTimerRef.current = null;
        }
        setPtyId(null);
        termRef.current?.write(`\r\n\x1b[31m[交互式会话已断开]\x1b[0m\r\n`);
        if (termRef.current) termRef.current.write(prompt());
      }
    } catch {
      // 轮询失败忽略（下次重试）
    }
  }

  function b64encode(text: string): string {
    return btoa(unescape(encodeURIComponent(text)));
  }

  function b64decodeToUint8(data: string): Uint8Array {
    const binary = atob(data);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  async function run(command: string) {
    if (!command.trim() || busyRef.current) return;
    busyRef.current = true;
    const term = termRef.current;
    if (!term) return;
    term.write(`\r\n`);
    try {
      const output = await api.executeCommand(sessionId, command);
      let display = output.stdout;
      if (output.rawB64 && encodingRef.current === "gbk") {
        const bytes = b64decodeToUint8(output.rawB64);
        try {
          display = new TextDecoder("gbk").decode(bytes);
        } catch {
          display = output.stdout;
        }
      }
      term.write(renderOutput(display, viewModeRef.current).replace(/\n$/, "") + "\r\n");
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
      // 输出换行自动转 CRLF（修复 ls 等列对齐输出错乱）
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
    setReady(true);

    const resizeObserver = new ResizeObserver(() => fit.fit());
    resizeObserver.observe(container);

    // 尝试建立交互式 PTY 会话（失败降级为命令模式）
    void api
      .startPty(sessionId)
      .then((pty) => {
        if (!termRef.current) return;
        setPtyId(pty.ptyId);
        term.write(`\r\n\x1b[90m[交互式会话已建立（PTY），可直接输入命令，如同本地 shell]\x1b[0m\r\n`);
        // 轮询输出
        pollTimerRef.current = window.setInterval(() => {
          void pollPty(pty.ptyId);
        }, 80);
      })
      .catch(() => {
        if (!termRef.current) return;
        ptyFailedRef.current = true;
        setPtyFailed(true);
        term.write(`\r\n\x1b[33m[交互式会话不可用（目标不支持），已降级为命令模式]\x1b[0m\r\n${prompt()}`);
      });

    term.onData((data) => {
      const term = termRef.current;
      if (!term) return;
      // PTY 交互模式：直接转发到目标 shell（由远端回显，本地不回显）
      if (ptyIdRef.current) {
        void api.ptyWrite(ptyIdRef.current, b64encode(data)).catch(() => {});
        return;
      }
      // 命令模式：粘贴多行 / 已提交
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
      if (pollTimerRef.current !== null) {
        window.clearInterval(pollTimerRef.current);
        pollTimerRef.current = null;
      }
      if (ptyIdRef.current) {
        void api.ptyClose(ptyIdRef.current).catch(() => {});
      }
      term.dispose();
      termRef.current = null;
    };
  }, []);

  return (
    <div className="terminal-wrap">
      <div className="term-toolbar">
        {!ptyId && !ptyFailed && (
          <span className="term-toolbar-label">输出编码</span>
        )}
        {!ptyId && !ptyFailed && (
          <select
            className="select term-encoding"
            value={outputEncoding}
            onChange={(event) => setOutputEncoding(event.target.value as "utf-8" | "gbk")}
            title="Windows 目标（chcp 936）输出请选 GBK"
          >
            <option value="utf-8">UTF-8</option>
            <option value="gbk">GBK</option>
          </select>
        )}
        {ptyId ? (
          <span className="term-toolbar-label term-pty-badge">交互式会话（PTY）</span>
        ) : ptyFailed ? (
          <span className="term-toolbar-label term-pty-fail">命令模式（PTY 不可用）</span>
        ) : (
          <>
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
          </>
        )}
      </div>
      <div className="terminal-box" ref={containerRef} data-ready={ready} />
    </div>
  );
}
