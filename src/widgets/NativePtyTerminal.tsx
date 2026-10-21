import { useCallback, useEffect, useRef, useState } from "react";
import { Terminal as XTerm } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { Eraser, LoaderCircle, Play, Square, Terminal as TermIcon } from "lucide-react";
import { api, b64, errorText } from "../api";
import { useToast } from "../components/Toast";
import { TERM_THEME } from "../lib/termTheme";

/**
 * 本地 PTY 终端：后端在操作机监听随机端口、让目标反弹一个 PTY 回来，
 * 前端把这条 TCP 流桥接到 xterm（与 HTTP 隧道版的 ForwardTerminal 并列）。
 */
export function NativePtyTerminal({
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
  const ptyIdRef = useRef<string>("");
  const pollTimerRef = useRef<number | null>(null);
  const pollInFlightRef = useRef(false);
  // 标签隐藏时暂停轮询（见 App.tsx）：输出留在套接字 / 服务端缓冲里，
  // 切回来继续读 —— 既不丢数据，也避免后台标签持续向目标发包
  const activeRef = useRef(active);
  activeRef.current = active;
  const runningRef = useRef(false);
  const lastSizeRef = useRef({ w: 0, h: 0 });

  const [callbackHost, setCallbackHost] = useState("127.0.0.1");
  const [running, setRunning] = useState(false);
  const [starting, setStarting] = useState(false);
  const [listenPort, setListenPort] = useState<number | null>(null);

  const safeFit = useCallback(() => {
    const container = containerRef.current;
    const fit = fitRef.current;
    if (!container || !fit) return;
    const w = container.clientWidth;
    const h = container.clientHeight;
    if (w <= 100 || h <= 100) return;
    if (Math.abs(w - lastSizeRef.current.w) < 4 && Math.abs(h - lastSizeRef.current.h) < 4) return;
    lastSizeRef.current = { w, h };
    try {
      fit.fit();
    } catch {
      // 忽略
    }
  }, []);

  const pollRead = useCallback(async () => {
    if (!runningRef.current || !ptyIdRef.current) return;
    if (pollInFlightRef.current) return;
    pollInFlightRef.current = true;
    try {
      const res = await api.ptyRead(ptyIdRef.current);
      if (res.data) {
        const bytes = b64.decodeBytes(res.data);
        if (bytes.length > 0) termRef.current?.write(bytes);
      }
      if (res.closed) {
        runningRef.current = false;
        setRunning(false);
        termRef.current?.write(
          `\r\n\x1b[33m[!] PTY 会话已断开${res.error ? `：${res.error}` : ""}\x1b[0m\r\n`,
        );
      }
    } catch (cause) {
      termRef.current?.write(`\r\n\x1b[33m[!] 读取失败：${errorText(cause)}\x1b[0m\r\n`);
    } finally {
      pollInFlightRef.current = false;
      if (runningRef.current && activeRef.current) {
        pollTimerRef.current = window.setTimeout(() => void pollRead(), 80);
      } else {
        // 隐藏：停掉轮询链；重新可见时由下面的 effect 拉起
        pollTimerRef.current = null;
      }
    }
  }, []);

  // 从隐藏标签切回：恢复轮询（隐藏期间的输出仍在缓冲区里）
  useEffect(() => {
    if (!active || !runningRef.current) return;
    if (pollTimerRef.current === null && !pollInFlightRef.current) {
      void pollRead();
    }
  }, [active, pollRead]);

  const sendData = useCallback(async (data: string) => {
    if (!runningRef.current || !ptyIdRef.current) return;
    try {
      await api.ptyWrite(ptyIdRef.current, b64.encodeText(data));
    } catch {
      // 忽略
    }
  }, []);
  const sendDataRef = useRef(sendData);
  sendDataRef.current = sendData;

  const start = useCallback(async () => {
    setStarting(true);
    const term = termRef.current;
    try {
      term?.write(
        `\r\n\x1b[33m[*] 正在本地监听并让目标反弹 PTY（回调 ${callbackHost}）...\x1b[0m\r\n`,
      );
      const res = await api.startPty(sessionId, callbackHost);
      ptyIdRef.current = res.ptyId;
      setListenPort(res.port);
      runningRef.current = true;
      setRunning(true);
      term?.write(
        `\x1b[32m[+] 本地 PTY 已建立（监听端口 ${res.port}）\x1b[0m\r\n\r\n`,
      );
      toast.success("本地 PTY 已建立", "PTY 就绪");
      if (pollTimerRef.current !== null) window.clearTimeout(pollTimerRef.current);
      pollInFlightRef.current = false;
      pollTimerRef.current = window.setTimeout(() => void pollRead(), 80);
    } catch (cause) {
      const message = errorText(cause);
      term?.write(`\x1b[31m[-] 启动失败：${message}\x1b[0m\r\n`);
      toast.error(message, "启动失败");
    } finally {
      setStarting(false);
    }
  }, [callbackHost, pollRead, sessionId, toast]);

  const stop = useCallback(async () => {
    runningRef.current = false;
    setRunning(false);
    if (pollTimerRef.current !== null) {
      window.clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
    const id = ptyIdRef.current;
    ptyIdRef.current = "";
    if (id) {
      try {
        await api.ptyClose(id);
      } catch {
        // 忽略
      }
    }
    termRef.current?.write(`\r\n\x1b[33m[!] 本地 PTY 已关闭\x1b[0m\r\n`);
  }, []);

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
      theme: TERM_THEME,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(container);
    termRef.current = term;
    fitRef.current = fit;

    term.write(
      `\x1b[32mDoSword 本地 PTY（目标反弹接收）\x1b[0m\r\n` +
        `\x1b[90m后端在操作机监听随机端口，目标主动回连；适用于目标可直连本机或已做端口转发的场景。\x1b[0m\r\n\r\n`,
    );

    let rafId: number | null = null;
    const observer = new ResizeObserver(() => {
      if (rafId) cancelAnimationFrame(rafId);
      rafId = requestAnimationFrame(safeFit);
    });
    observer.observe(container);

    term.onData((data) => {
      if (!runningRef.current) return;
      void sendDataRef.current(data);
    });

    return () => {
      observer.disconnect();
      if (rafId) cancelAnimationFrame(rafId);
      if (pollTimerRef.current !== null) window.clearTimeout(pollTimerRef.current);
      runningRef.current = false;
      const id = ptyIdRef.current;
      ptyIdRef.current = "";
      if (id) void api.ptyClose(id).catch(() => {});
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [safeFit]);

  return (
    <div className="panel detail-panel" style={{ padding: 12, display: "grid", gap: 8 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <button
          className="button primary compact"
          onClick={() => void (running ? stop() : start())}
          disabled={starting}
        >
          {starting ? (
            <LoaderCircle className="spin" size={13} />
          ) : running ? (
            <Square size={13} />
          ) : (
            <Play size={13} />
          )}
          {starting ? "启动中…" : running ? "关闭 PTY" : "启动本地 PTY"}
        </button>
        <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
          回调地址
          <input
            value={callbackHost}
            onChange={(event) => setCallbackHost(event.target.value)}
            disabled={running}
            style={{ width: 150 }}
            title="目标从它的网络位置回连本机，必须是目标可达的地址"
          />
        </label>
        {listenPort !== null && (
          <span className="form-note" style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <TermIcon size={12} /> 本地监听 {listenPort}
          </span>
        )}
        <button className="button compact secondary" onClick={() => termRef.current?.clear()}>
          <Eraser size={13} /> 清屏
        </button>
      </div>
      <div
        ref={containerRef}
        style={{
          height: 420,
          borderRadius: "var(--radius-md)",
          overflow: "hidden",
          background: "#080a0c",
        }}
      />
      <div className="form-note">
        回调地址默认 127.0.0.1，仅适用于本机目标或已做端口转发；跨网段需填目标可达的本机地址。
      </div>
    </div>
  );
}
