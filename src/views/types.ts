// 视图类型定义：桌面应用内用 state 切换，无需路由库。

export type View =
  | { kind: "dashboard" }
  | { kind: "shell"; shellId: string; sessionId?: string; shellName?: string }
  | { kind: "sessions" }
  | { kind: "debug" }
  | { kind: "files" }
  | { kind: "database" }
  | { kind: "orchestrate" }
  | { kind: "proxyChain" }
  | { kind: "playbook" }
  | { kind: "audit" }
  | { kind: "settings" };

/** 多 Shell 标签页：一次可同时打开多个 Shell 详情。 */
export type ShellTab = {
  id: string;
  shellId: string;
  sessionId?: string;
  name?: string;
};
