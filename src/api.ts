// 与 src-tauri/src/domain.rs 对应的 invoke 封装。
// 类型由 Rust 侧 ts-rs 生成（src/generated/domain.ts），重新生成：pnpm gen:types
import { invoke } from "@tauri-apps/api/core";

import type {
  Workspace,
  ShellProfile,
  AuditFilter,
  AuditPage,
  Dashboard,
  ProbeResult,
  AppSettings,
  ProtocolMeta,
  CommandOutput,
  DirListing,
  FileContent,
  ConnectResult,
  SessionInfo,
  DbConnection,
  DbProbeResult,
  DbQueryResult,
  RequestRecord,
  PluginManifest,
  GenerateShellResult,
  HttpSendResult,
  ImportResult,
  ProxyTestResult,
  FileChunk,
  McpStatus,
  McpCallRecord,
  McpPendingApproval,
  FeatureManifest,
  MemoryShell,
  MemshellCapability,
} from "./generated/domain";

export type * from "./generated/domain";

/** 批量编排的单个目标结果。 */
export type OrchestrationOutcome = {
  shellId: string;
  shellName: string;
  ok: boolean;
  elapsedMs: number;
  output: string;
  error: string;
};

/** 批量编排汇总。 */
export type OrchestrationReport = {
  total: number;
  ok: number;
  failed: number;
  outcomes: OrchestrationOutcome[];
};

/** 已启动的代理链。 */
export type ProxyChainInfo = {
  chainId: string;
  localAddr: string;
  hops?: number;
};

// --- invoke 封装 ---

export const api = {
  dashboard: () => invoke<Dashboard>("dashboard"),
  createWorkspace: (input: {
    name: string;
    authorizationScope: string;
    expiresAt?: string | null;
  }) => invoke<Workspace>("create_workspace", { input }),
  updateWorkspace: (input: {
    id: string;
    name: string;
    authorizationScope: string;
    expiresAt?: string | null;
  }) => invoke<Workspace>("update_workspace", { input }),
  deleteWorkspace: (workspaceId: string) =>
    invoke<void>("delete_workspace", { workspaceId }),
  createShell: (input: {
    workspaceId: string;
    name: string;
    endpoint: string;
    runtime: string;
    protocolId: string;
    password?: string;
    confirmNetwork?: boolean;
    tags?: string[];
    protocolParams?: string;
  }) => invoke<ShellProfile>("create_shell", { input }),
  updateShell: (input: {
    id: string;
    name: string;
    endpoint: string;
    password?: string;
    tags?: string[];
    /** 协议参数（编码方式 / 盐 / session 开关）；省略 = 保持不变。 */
    protocolParams?: string;
  }) => invoke<ShellProfile>("update_shell", { input }),
  deleteShell: (shellId: string) => invoke<void>("delete_shell", { shellId }),
  listProtocols: () => invoke<ProtocolMeta[]>("list_protocols"),
  listPlugins: () => invoke<PluginManifest[]>("list_plugins"),
  listFeaturePlugins: () => invoke<FeatureManifest[]>("list_feature_plugins"),
  runFeaturePlugin: (
    sessionId: string,
    pluginId: string,
    params: Record<string, unknown>,
  ) => invoke<Record<string, unknown>>("run_feature_plugin", { sessionId, pluginId, params }),
  refreshShellStatus: () => invoke<ShellProfile[]>("refresh_shell_status"),
  installPlugin: (content: string) => invoke<void>("install_plugin", { content }),
  installNativePlugin: (sourcePath: string) =>
    invoke<void>("install_native_plugin", { sourcePath }),
  uninstallPlugin: (pluginId: string) => invoke<void>("uninstall_plugin", { pluginId }),
  exportShells: () => invoke<string>("export_shells"),
  backupShells: (backupDir: string) => invoke<string>("backup_shells", { backupDir }),
  importShells: (payload: string, workspaceId: string) =>
    invoke<ImportResult>("import_shells", { payload, workspaceId }),
  readLocalFile: (path: string) => invoke<string>("read_local_file", { path }),
  encodeText: (text: string, encoding: string) =>
    invoke<string>("encode_text", { text, encoding }),
  batchUpdateShells: (
    ids: string[],
    tags?: string[],
    password?: string,
  ) => invoke<number>("batch_update_shells", { ids, tags, password }),
  httpSend: (
    request: {
      method: string;
      url: string;
      headers: [string, string][];
      body: string;
    },
    allowUnscoped?: boolean,
  ) => invoke<HttpSendResult>("http_send", { ...request, allowUnscoped: allowUnscoped ?? false }),
  listEncoders: () => invoke<[string, string][]>("list_encoders"),
  registerCustomEncoder: (stub: string) => invoke<void>("register_custom_encoder", { stub }),
  generateShell: (
    language: string,
    encoderId: string,
    password: string,
    session: boolean,
    salted: boolean,
    /** 传输形态（W2）：请求参数名 / 鉴权头名（仅 NATIVE 系列烘焙进 stub） */
    param?: string,
    header?: string,
  ) =>
    invoke<GenerateShellResult>("generate_shell", {
      language,
      encoderId,
      password,
      session,
      salted,
      param,
      header,
    }),
  listAudit: (filter: AuditFilter) => invoke<AuditPage>("list_audit", { filter }),
  writeLocalFile: (path: string, contentB64: string) =>
    invoke<void>("write_local_file", { path, contentB64 }),
  probeShell: (shellId: string) => invoke<ProbeResult>("probe_shell", { shellId }),
  testConnection: (
    endpoint: string,
    password: string,
    protocolId: string,
    protocolParams?: string,
    runtime?: string,
    allowUnscoped?: boolean,
  ) =>
    invoke<ProbeResult>("test_connection", {
      endpoint,
      password,
      protocolId,
      protocolParams,
      runtime,
      allowUnscoped: allowUnscoped ?? false,
    }),
  getSettings: () => invoke<AppSettings>("get_settings"),
  updateSettings: (input: AppSettings) => invoke<void>("update_settings", { input }),
  connectShell: (shellId: string) => invoke<ConnectResult>("connect_shell", { shellId }),
  disconnectShell: (sessionId: string) => invoke<void>("disconnect_shell", { sessionId }),
  getSessionProbe: (sessionId: string) => invoke<ProbeResult>("get_session_probe", { sessionId }),
  startPty: (sessionId: string, callbackHost?: string | null) =>
    invoke<{ ptyId: string; port: number; callbackHost: string }>("start_pty_session", {
      sessionId,
      callbackHost: callbackHost ?? null,
    }),
  ptyWrite: (ptyId: string, dataB64: string) => invoke<void>("pty_write", { ptyId, dataB64 }),
  ptyRead: (ptyId: string) => invoke<{ data: string; closed: boolean; error?: string }>("pty_read", { ptyId }),
  ptyClose: (ptyId: string) => invoke<void>("pty_close", { ptyId }),
  listSessions: () => invoke<SessionInfo[]>("list_sessions"),
  executeCommand: (sessionId: string, command: string) =>
    invoke<CommandOutput>("execute_command", { sessionId, command }),
  // --- 多跳代理链 ---
  proxyChainStart: (spec: {
    hops: Array<{
      shellId: string;
      host: string;
      port: number;
      username?: string;
      password?: string;
    }>;
    localPort: number;
    targetHost?: string | null;
    targetPort?: number | null;
  }) => invoke<ProxyChainInfo>("proxy_chain_start", { spec }),
  proxyChainStop: (chainId: string) => invoke<void>("proxy_chain_stop", { chainId }),
  proxyChainList: () => invoke<ProxyChainInfo[]>("proxy_chain_list"),

  // --- 批量与多目标编排 ---
  orchestrateRun: (spec: {
    shellIds: string[];
    op: Record<string, unknown>;
    concurrency: number;
    stopOnError: boolean;
    autoConnect: boolean;
    disconnectAfter: boolean;
  }) => invoke<OrchestrationReport>("orchestrate_run", { spec }),

  // --- 内存马（后渗透） ---
  memshellCapabilities: (sessionId: string) =>
    invoke<MemshellCapability[]>("memshell_capabilities", { sessionId }),
  memshellInstall: (
    sessionId: string,
    kind: string,
    options: {
      installDir?: string;
      triggerUrl?: string;
      fpmTarget?: string;
      scriptFilename?: string;
    },
  ) =>
    invoke<MemoryShell>("memshell_install", {
      sessionId,
      kind,
      installDir: options.installDir ?? null,
      triggerUrl: options.triggerUrl ?? null,
      fpmTarget: options.fpmTarget ?? null,
      scriptFilename: options.scriptFilename ?? null,
    }),
  memshellCheck: (handleId: string) => invoke<boolean>("memshell_check", { handleId }),
  memshellUninstall: (handleId: string) => invoke<string>("memshell_uninstall", { handleId }),
  memshellList: (workspaceId?: string, shellId?: string) =>
    invoke<MemoryShell[]>("memshell_list", { workspaceId, shellId }),
  memshellExec: (handleId: string, command: string) =>
    invoke<string>("memshell_exec", { handleId, command }),
  batchListDir: (sessionId: string, paths: string[]) =>
    invoke<Record<string, DirListing>>("batch_list_dir", { sessionId, paths }),
  listDir: (sessionId: string, path: string) =>
    invoke<DirListing>("list_dir", { sessionId, path }),
  readFile: (sessionId: string, path: string) =>
    invoke<FileContent>("read_file", { sessionId, path }),
  writeFile: (sessionId: string, path: string, contentB64: string) =>
    invoke<void>("write_file", { sessionId, path, contentB64 }),
  writeChunk: (sessionId: string, path: string, contentB64: string, offset: number) =>
    invoke<void>("write_chunk", { sessionId, path, contentB64, offset }),
  uploadFile: (sessionId: string, remotePath: string, contentB64: string) =>
    invoke<void>("upload_file", { sessionId, remotePath, contentB64 }),
  downloadFile: (sessionId: string, remotePath: string, localPath: string) =>
    invoke<number>("download_file", { sessionId, remotePath, localPath }),
  deletePath: (sessionId: string, path: string) =>
    invoke<void>("delete_path", { sessionId, path }),
  renamePath: (sessionId: string, from: string, to: string) =>
    invoke<void>("rename_path", { sessionId, from, to }),
  createDir: (sessionId: string, path: string) =>
    invoke<void>("create_dir", { sessionId, path }),
  touchPath: (sessionId: string, path: string, timestamp: number) =>
    invoke<void>("touch_path", { sessionId, path, timestamp }),
  dbProbe: (sessionId: string, connection: DbConnection) =>
    invoke<DbProbeResult>("db_probe", { sessionId, connection }),
  dbQuery: (sessionId: string, connection: DbConnection, sql: string) =>
    invoke<DbQueryResult>("db_query", { sessionId, connection, sql }),
  listRequestLog: (endpoint?: string | null) =>
    invoke<RequestRecord[]>("list_request_log", { endpoint: endpoint ?? null }),
  clearRequestLog: () => invoke<void>("clear_request_log"),
  testProxyUpstream: (proxy?: string | null, timeoutSecs?: number | null, probeUrl?: string | null) =>
    invoke<ProxyTestResult>("test_proxy_upstream", {
      proxy: proxy ?? null,
      timeoutSecs: timeoutSecs ?? null,
      probeUrl: probeUrl ?? null,
    }),
  readChunk: (sessionId: string, path: string, offset: number, length: number) =>
    invoke<FileChunk>("read_chunk", { sessionId, path, offset, length }),

  // --- MCP 服务端 ---
  mcpStatus: () => invoke<McpStatus>("mcp_status"),
  mcpStart: () => invoke<McpStatus>("mcp_start"),
  mcpStop: () => invoke<McpStatus>("mcp_stop"),
  mcpRotateToken: () => invoke<string>("mcp_rotate_token"),
  mcpRecentCalls: (limit?: number) =>
    invoke<McpCallRecord[]>("mcp_recent_calls", { limit: limit ?? null }),
  mcpClearLog: () => invoke<void>("mcp_clear_log"),
  mcpPendingApprovals: () => invoke<McpPendingApproval[]>("mcp_pending_approvals"),
  mcpResolveApproval: (id: string, approve: boolean) =>
    invoke<McpPendingApproval>("mcp_resolve_approval", { id, approve }),
};

// --- Base64 工具（编辑器/上传下载用） ---

export const b64 = {
  encodeBytes(bytes: Uint8Array): string {
    // 分块拼接（每块 8KB），避免 4MB 级逐字节字符串追加卡顿主线程
    const CHUNK = 8192;
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += CHUNK) {
      const end = Math.min(offset + CHUNK, bytes.length);
      binary += String.fromCharCode(...bytes.subarray(offset, end));
    }
    return btoa(binary);
  },
  decodeBytes(value: string): Uint8Array {
    if (!value) return new Uint8Array();
    try {
      const clean = value.replace(/[\s\r\n]+/g, "");
      const binary = atob(clean);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    } catch {
      return new Uint8Array();
    }
  },
  decodeText(value: string, encoding: string = "utf-8"): string {
    try {
      const bytes = this.decodeBytes(value);
      return new TextDecoder(encoding, { fatal: false }).decode(bytes);
    } catch {
      return "";
    }
  },
  encodeText(value: string): string {
    return this.encodeBytes(new TextEncoder().encode(value));
  },
};

// --- 展示辅助 ---

export function shortTime(value?: string | null): string {
  if (!value) return "尚未连接";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/** 将任意错误值转成可读字符串（Tauri invoke 失败会返回字符串）。 */
export function errorText(cause: unknown): string {
  return typeof cause === "string" ? cause : String(cause);
}
