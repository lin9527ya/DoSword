// 视图类型定义：桌面应用内用 state 切换，无需路由库。

export type View =
  | { kind: "dashboard" }
  | { kind: "shell"; shellId: string; sessionId?: string }
  | { kind: "sessions" }
  | { kind: "audit" }
  | { kind: "settings" };
