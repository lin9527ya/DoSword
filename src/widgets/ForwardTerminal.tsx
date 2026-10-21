import { useCallback, useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { Eraser, LoaderCircle, Play, Square, Terminal as TermIcon } from "lucide-react";
import { api, b64, errorText } from "../api";
import { useToast } from "../components/Toast";

export function ForwardTerminal({
  sessionId,
  active = true,
}: {
  sessionId: string;
  active?: boolean;
}) {
  const toast = useToast();
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const pollTimerRef = useRef<number | null>(null);
  const pollInFlightRef = useRef(false);
  const failCountRef = useRef(0);
  const offsetRef = useRef<number>(0);
  // 标签隐藏时暂停轮询（见 App.tsx）：输出留在套接字 / 服务端缓冲里，
  // 切回来继续读 —— 既不丢数据，也避免后台标签持续向目标发包
  const activeRef = useRef(active);
  activeRef.current = active;
  const isRunningRef = useRef<boolean>(false);
  const lastSizeRef = useRef({ w: 0, h: 0 });

  const sessionIdRef = useRef(sessionId);
  sessionIdRef.current = sessionId;

  const [running, setRunning] = useState(false);
  const [starting, setStarting] = useState(false);

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

  const pollRead = useCallback(async () => {
    if (!isRunningRef.current) return;
    // in-flight 互斥 + 自递归调度：此前是 80ms setInterval 且无互斥，
    // 单次 RPC 超过 80ms 时会并发叠加、两个请求带同一 offset，
    // 导致终端输出重复回放，晚到的旧响应还会把 offset 写回较小值。
    if (pollInFlightRef.current) return;
    pollInFlightRef.current = true;
    try {
      const res = (await api.runFeaturePlugin(sessionIdRef.current, "super_terminal", {
        action: "read",
        term_id: sessionIdRef.current,
        offset: offsetRef.current,
      })) as { ok?: boolean; dataB64?: string; offset?: number };

      if (res && res.ok) {
        failCountRef.current = 0;
        if (res.dataB64) {
          const text = b64.decodeText(res.dataB64);
          if (text) {
            termRef.current?.write(text.replace(/\r?\n/g, "\r\n"));
          }
        }
        // offset 只允许前进，避免旧响应把读取位置回退造成重复输出
        if (typeof res.offset === "number" && res.offset > offsetRef.current) {
          offsetRef.current = res.offset;
        }
      }
    } catch (cause) {
      failCountRef.current += 1;
      if (failCountRef.current === 5) {
        termRef.current?.write(
          `\r\n\x1b[33m[!] 终端读取连续失败：${errorText(cause)}（继续重试中）\x1b[0m\r\n`,
        );
      }
    } finally {
      pollInFlightRef.current = false;
      if (isRunningRef.current && activeRef.current) {
        pollTimerRef.current = window.setTimeout(() => void pollRead(), 80);
      } else {
        // 隐藏：停掉轮询链；重新可见时由下面的 effect 拉起
        pollTimerRef.current = null;
      }
    }
  }, []);

  // 从隐藏标签切回：恢复轮询（隐藏期间的输出仍在缓冲区里）
  useEffect(() => {
    if (!active || !isRunningRef.current) return;
    if (pollTimerRef.current === null && !pollInFlightRef.current) {
      void pollRead();
    }
  }, [active, pollRead]);

  const sendRawData = useCallback(async (data: string) => {
    if (!isRunningRef.current) return;
    try {
      await api.runFeaturePlugin(sessionIdRef.current, "super_terminal", {
        action: "write",
        term_id: sessionIdRef.current,
        data_b64: b64.encodeText(data),
      });
    } catch {
      // 忽略
    }
  }, []);

  const sendRawDataRef = useRef(sendRawData);
  sendRawDataRef.current = sendRawData;

  const startSession = useCallback(async () => {
    setStarting(true);
    const term = termRef.current;
    try {
      term?.write(`\r\n\x1b[33m[*] 正在通过 WebShell HTTP 隧道初始化交互式伪终端 (PTY)...\x1b[0m\r\n`);
      const res = (await api.runFeaturePlugin(sessionIdRef.current, "super_terminal", {
        action: "start",
        term_id: sessionIdRef.current,
      })) as { ok?: boolean; pid?: number; error?: string };

      if (res && res.ok) {
        offsetRef.current = 0;
        isRunningRef.current = true;
        setRunning(true);
        term?.write(
          `\x1b[32m[+] 交互式 PTY 伪终端已建立 (PID: ${res.pid ?? "auto"})，支持 sudo/su/密码交互及键盘控制\x1b[0m\r\n\r\n`,
        );
        toast.success("交互式终端已启动", "PTY 就绪");

        if (pollTimerRef.current !== null) {
          window.clearTimeout(pollTimerRef.current);
          pollTimerRef.current = null;
        }
        pollInFlightRef.current = false;
        failCountRef.current = 0;
        pollTimerRef.current = window.setTimeout(() => void pollRead(), 80);
      } else {
        term?.write(`\x1b[31m[-] 启动失败: ${res?.error ?? "未知错误"}\x1b[0m\r\n`);
        toast.error(`启动终端失败：${res?.error ?? "目标不支持管道或 proc_open"}`);
      }
    } catch (cause) {
      const msg = errorText(cause);
      term?.write(`\x1b[31m[-] 启动异常: ${msg}\x1b[0m\r\n`);
      toast.error(`启动异常：${msg}`);
    } finally {
      setStarting(false);
    }
  }, [pollRead, toast]);

  const stopSession = useCallback(async () => {
    isRunningRef.current = false;
    setRunning(false);
    if (pollTimerRef.current !== null) {
      window.clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
    const term = termRef.current;
    try {
      await api.runFeaturePlugin(sessionIdRef.current, "super_terminal", {
        action: "stop",
        term_id: sessionIdRef.current,
      });
      term?.write(`\r\n\x1b[33m[!] 交互式终端会话已终止\x1b[0m\r\n`);
      toast.info("交互式终端已终止");
    } catch {
      term?.write(`\r\n\x1b[33m[!] 会话已断开\x1b[0m\r\n`);
    }
  }, [toast]);

  const clearScreen = () => {
    termRef.current?.clear();
  };

  useEffect(() => {
    if (active) {
      const timer = setTimeout(safeFit, 50);
      return () => clearTimeout(timer);
    }
  }, [active, safeFit]);

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
      `\x1b[32mDoSword 交互式终端 (Godzilla SuperTerminal / PTY)\x1b[0m\r\n\x1b[90m点击上方「启动交互终端」建立会话，支持 sudo 密码输入、su 切换、Tab 补全与 PTY 交互控制\x1b[0m\r\n\r\n`,
    );

    let rafId: number | null = null;
    const resizeObserver = new ResizeObserver(() => {
      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(safeFit);
    });
    resizeObserver.observe(container);

    term.onData((data) => {
      const t = termRef.current;
      if (!t) return;

      if (!isRunningRef.current) {
        if (data === "\r") {
          t.write(`\r\n\x1b[33m[!] 请先点击上方「启动交互终端」建立会话\x1b[0m\r\n`);
        }
        return;
      }

      // 运行中：PTY 具备原生终端 Echo 与行规程，按键直接原样送入 PTY 管道
      void sendRawDataRef.current(data);
    });

    return () => {
      if (rafId) cancelAnimationFrame(rafId);
      resizeObserver.disconnect();
      if (pollTimerRef.current !== null) {
        window.clearTimeout(pollTimerRef.current);
        pollTimerRef.current = null;
      }
      if (isRunningRef.current) {
        void api.runFeaturePlugin(sessionIdRef.current, "super_terminal", {
          action: "stop",
          term_id: sessionIdRef.current,
        }).catch(() => {});
      }
      term.dispose();
      termRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="terminal-wrap" style={{ padding: 0 }}>
      <div className="term-toolbar" style={{ padding: "6px 12px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", minWidth: 0 }}>
          <span className={`term-toolbar-label ${running ? "term-pty-badge" : "term-pty-fail"}`}>
            <TermIcon size={13} />
            {running ? "● 交互式 PTY 会话已就绪" : "○ 交互式终端未启动"}
          </span>
          <span style={{ fontSize: 11, color: "var(--text-faint)" }}>
            支持 sudo / su / 密码输入 / Tab 补全
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          {running ? (
            <button className="button compact danger" onClick={() => void stopSession()}>
              <Square size={13} />
              终止终端
            </button>
          ) : (
            <button
              className="button compact primary"
              onClick={() => void startSession()}
              disabled={starting}
            >
              {starting ? <LoaderCircle className="spin" size={13} /> : <Play size={13} />}
              {starting ? "正在建立…" : "启动交互终端"}
            </button>
          )}

          <button className="button compact secondary" onClick={clearScreen} title="清空屏幕">
            <Eraser size={13} />
            清屏
          </button>
        </div>
      </div>

      <div
        className="terminal-box"
        style={{
          height: "calc(100vh - 470px)",
          minHeight: "260px",
          maxHeight: "440px",
        }}
        ref={containerRef}
      />
    </div>
  );
}
