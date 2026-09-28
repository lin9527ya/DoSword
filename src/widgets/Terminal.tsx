import { useCallback, useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { Eraser, TerminalSquare, Zap } from "lucide-react";
import { api } from "../api";

const HISTORY_KEY = "dosword:term-history";

type ViewMode = "ansi" | "text" | "json" | "hex";

const QUICK_COMMANDS = [
  { label: "身份与内核", cmd: "whoami && id && uname -a" },
  { label: "网络监听端口", cmd: "netstat -tuln || ss -tuln || netstat -ano" },
  { label: "IP 与网卡配置", cmd: "ip addr || ifconfig || ipconfig /all" },
  { label: "活跃进程列表", cmd: "ps aux || tasklist /svc" },
  { label: "系统用户列表", cmd: "cat /etc/passwd || net user" },
  { label: "磁盘空间", cmd: "df -h || wmic logicaldisk get caption,size,freespace" },
  { label: "SUID 特权文件", cmd: "find / -perm -4000 -type f 2>/dev/null" },
];

function stripAnsi(text: string): string {
  return text
    .replace(/\x1b\][^\x07]*(\x07|\x1b\\)/g, "")
    .replace(/\x1b\[[0-9;?]*[a-zA-Z]/g, "")
    .replace(/\x1b[()][0-9A-Z]/g, "");
}

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

/** 默认标准非交互式终端：输入指令 -> HTTP 传输 -> 即时回显（支持 ANSI、多编码、历史命令） */
export function Terminal({
  sessionId,
  currentDir,
  active = true,
  onCwdChange,
}: {
  sessionId: string;
  currentDir?: string;
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
  const lastSizeRef = useRef({ w: 0, h: 0 });

  const currentDirRef = useRef(currentDir);
  currentDirRef.current = currentDir;

  const sessionIdRef = useRef(sessionId);
  sessionIdRef.current = sessionId;

  const onCwdChangeRef = useRef(onCwdChange);
  onCwdChangeRef.current = onCwdChange;

  const [viewMode, setViewMode] = useState<ViewMode>("ansi");
  const viewModeRef = useRef<ViewMode>("ansi");
  viewModeRef.current = viewMode;

  const [outputEncoding, setOutputEncoding] = useState<"utf-8" | "gbk">("utf-8");
  const encodingRef = useRef<"utf-8" | "gbk">("utf-8");
  encodingRef.current = outputEncoding;

  useEffect(() => {
    try {
      historyRef.current = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
    } catch {
      // 忽略
    }
  }, []);

  const getPrompt = useCallback(() => `dosword@target:${currentDirRef.current ?? "~"}$ `, []);

  function b64decodeToUint8(data: string): Uint8Array {
    const binary = atob(data);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  const runCommand = useCallback(
    async (command: string) => {
      if (!command.trim() || busyRef.current) return;
      busyRef.current = true;
      const term = termRef.current;
      if (!term) return;
      term.write(`\r\n`);
      try {
        const output = await api.executeCommand(sessionIdRef.current, command);
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
        if (output.cwd) {
          currentDirRef.current = output.cwd;
          onCwdChangeRef.current?.(output.cwd);
        }
      } catch (error) {
        term.write(`\x1b[31m${String(error)}\x1b[0m\r\n`);
      } finally {
        busyRef.current = false;
        if (term) {
          term.write(getPrompt());
          bufferRef.current = "";
          historyIndexRef.current = -1;
        }
      }
    },
    [getPrompt],
  );

  const runCommandRef = useRef(runCommand);
  runCommandRef.current = runCommand;

  function pushHistory(command: string) {
    const history = historyRef.current;
    history.push(command);
    if (history.length > 500) history.shift();
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch {
      // 忽略
    }
  }

  function clearScreen() {
    const term = termRef.current;
    if (!term) return;
    term.clear();
    term.write(getPrompt());
  }

  // 严格安全的自适应尺寸调整，防止死循环横向伸展
  const safeFit = useCallback(() => {
    const container = containerRef.current;
    const fit = fitRef.current;
    if (!container || !fit) return;
    const w = container.clientWidth;
    const h = container.clientHeight;
    if (w <= 100 || h <= 100) return;
    if (Math.abs(w - lastSizeRef.current.w) < 4 && Math.abs(h - lastSizeRef.current.h) < 4) {
      return;
    }
    lastSizeRef.current = { w, h };
    try {
      fit.fit();
    } catch {
      // 忽略
    }
  }, []);

  useEffect(() => {
    if (active) {
      const timer = setTimeout(safeFit, 50);
      return () => clearTimeout(timer);
    }
  }, [active, safeFit]);

  // 核心：XTerm 终端实例仅在挂载时初始化一次，绝不因 state 或回调变化而重新销毁
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const term = new XTerm({
      fontFamily: '"JetBrains Mono", "IBM Plex Mono", Consolas, "Fira Code", monospace',
      fontSize: 13,
      lineHeight: 1.45,
      convertEol: true,
      cursorBlink: true,
      cursorStyle: "block",
      theme: {
        background: "#080a0c",
        foreground: "#d4d4d4",
        cursor: "#22c55e",
        black: "#000000",
        red: "#ef4444",
        green: "#22c55e",
        yellow: "#eab308",
        blue: "#3b82f6",
        magenta: "#a855f7",
        cyan: "#06b6d4",
        white: "#f3f4f6",
        brightBlack: "#4b5563",
        brightRed: "#f87171",
        brightGreen: "#4ade80",
        brightYellow: "#fde047",
        brightBlue: "#60a5fa",
        brightMagenta: "#c084fc",
        brightCyan: "#22d3ee",
        brightWhite: "#ffffff",
      },
    });

    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(container);
    termRef.current = term;
    fitRef.current = fit;

    term.write(
      `\x1b[32mDoSword 终端就绪 (非交互命令模式)\x1b[0m  \x1b[90m(支持 ANSI 彩色高亮、目录跟踪、GBK/UTF-8 切换)\x1b[0m\r\n${getPrompt()}`,
    );

    // 使用防抖 ResizeObserver
    let rafId: number | null = null;
    const resizeObserver = new ResizeObserver(() => {
      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(safeFit);
    });
    resizeObserver.observe(container);

    term.onData((data) => {
      const t = termRef.current;
      if (!t) return;
      if (data === "\r") {
        const command = bufferRef.current;
        if (command.trim()) {
          pushHistory(command);
          historyIndexRef.current = -1;
          void runCommandRef.current(command);
        } else {
          t.write(`\r\n${getPrompt()}`);
        }
        return;
      }
      if (data === "\x7f") {
        if (bufferRef.current.length > 0) {
          bufferRef.current = bufferRef.current.slice(0, -1);
          t.write("\b \b");
        }
        return;
      }
      if (data === "\x03") {
        bufferRef.current = "";
        t.write("\r\n" + getPrompt());
        return;
      }
      if (data === "\x0c") {
        clearScreen();
        return;
      }
      if (data === "\x1b[A" || data === "\x1b[B") {
        const history = historyRef.current;
        if (history.length === 0) return;
        if (data === "\x1b[A") {
          historyIndexRef.current = Math.min(historyIndexRef.current + 1, history.length - 1);
        } else {
          historyIndexRef.current = Math.max(historyIndexRef.current - 1, -1);
        }
        const entry =
          historyIndexRef.current >= 0
            ? history[history.length - 1 - historyIndexRef.current]
            : "";
        t.write("\r\x1b[K" + getPrompt() + entry);
        bufferRef.current = entry;
        return;
      }
      if (data.length === 1 && data.charCodeAt(0) >= 0x20) {
        bufferRef.current += data;
        t.write(data);
      } else if (data.length > 1) {
        const clean = data.replace(/[\r\n]+/g, "");
        bufferRef.current += clean;
        t.write(clean);
      }
    });

    return () => {
      if (rafId) cancelAnimationFrame(rafId);
      resizeObserver.disconnect();
      term.dispose();
      termRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="terminal-wrap">
      {/* 终端控制条 */}
      <div className="term-toolbar">
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", minWidth: 0 }}>
          <span className="term-toolbar-label term-pty-fail">
            <TerminalSquare size={12} /> 非交互式命令终端
          </span>

          <span className="term-toolbar-label">编码</span>
          <select
            className="select term-encoding"
            value={outputEncoding}
            onChange={(event) => setOutputEncoding(event.target.value as "utf-8" | "gbk")}
            title="Windows 目标如果出现乱码请选择 GBK"
          >
            <option value="utf-8">UTF-8 (Linux/Mac)</option>
            <option value="gbk">GBK (Windows CMD)</option>
          </select>

          <span className="term-toolbar-label">格式</span>
          <select
            className="select term-view-mode"
            value={viewMode}
            onChange={(event) => setViewMode(event.target.value as ViewMode)}
          >
            <option value="ansi">ANSI 彩色输出</option>
            <option value="text">纯文本 (无 ANSI)</option>
            <option value="json">JSON 格式化</option>
            <option value="hex">十六进制 HEX</option>
          </select>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          <button className="button compact secondary" onClick={clearScreen} title="清空终端屏幕 (Ctrl+L)">
            <Eraser size={13} />
            清屏
          </button>
        </div>
      </div>

      {/* 终端主体窗口容器（包含固定边界与防溢出限制） */}
      <div className="terminal-box" ref={containerRef} />

      {/* 快速侦察指令芯片栏 */}
      <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", paddingTop: 2 }}>
        <span style={{ fontSize: 11, color: "var(--text-faint)", fontWeight: 600, display: "flex", alignItems: "center", gap: 4 }}>
          <Zap size={12} color="var(--accent)" /> 快捷指令:
        </span>
        {QUICK_COMMANDS.map((qc) => (
          <button
            key={qc.cmd}
            className="file-bookmark-chip"
            style={{ fontSize: 11.5, padding: "3px 8px" }}
            onClick={() => {
              const term = termRef.current;
              if (term) {
                term.write(qc.cmd);
                void runCommand(qc.cmd);
              }
            }}
            title={qc.cmd}
          >
            {qc.label}
          </button>
        ))}
      </div>
    </div>
  );
}
