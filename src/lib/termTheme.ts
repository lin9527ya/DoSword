import type { ITheme } from "@xterm/xterm";

/**
 * 终端配色（`Terminal` / `ForwardTerminal` / `NativePtyTerminal` 共用）。
 *
 * 此前三处各写一份：前两处是完整的 18 色，`NativePtyTerminal` 只写了
 * background / foreground / cursor 三色 —— 同一个应用里 ANSI 输出颜色不一致。
 * 收敛到一处后，三者的配色随这一份一起变。
 */
export const TERM_THEME: ITheme = {
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
};
