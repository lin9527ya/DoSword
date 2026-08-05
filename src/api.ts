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
} from "./generated/domain";

export type * from "./generated/domain";

// 功能插件类型（ts-rs 生成的 domain.ts 未包含，本地定义）
export type ParamSpec = {
  name: string;
  label: string;
  type: string;
  default: string | number | boolean | null;
  options: string[] | null;
};

export type HttpSendResult = {
  status: number;
  statusText: string;
  headers: [string, string][];
  body: string;
  durationMs: number;
};

export type FeatureManifest = {
  id: string;
  name: string;
  version: string;
  description: string;
  category: string;
  languages: string[];
  params: ParamSpec[];
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
  uninstallPlugin: (pluginId: string) => invoke<void>("uninstall_plugin", { pluginId }),
  exportShells: () => invoke<string>("export_shells"),
  importShells: (payload: string, workspaceId: string) =>
    invoke<{ imported: number; skipped: number }>("import_shells", { payload, workspaceId }),
  readLocalFile: (path: string) => invoke<string>("read_local_file", { path }),
  batchUpdateShells: (
    ids: string[],
    tags?: string[],
    password?: string,
  ) => invoke<number>("batch_update_shells", { ids, tags, password }),
  httpSend: (request: {
    method: string;
    url: string;
    headers: [string, string][];
    body: string;
  }) => invoke<HttpSendResult>("http_send", request),
  listEncoders: () => invoke<[string, string][]>("list_encoders"),
  generateShell: (language: string, encoderId: string, password: string, session: boolean) =>
    invoke<GenerateShellResult>("generate_shell", { language, encoderId, password, session }),
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
  ) =>
    invoke<ProbeResult>("test_connection", {
      endpoint,
      password,
      protocolId,
      protocolParams,
      runtime,
    }),
  getSettings: () => invoke<AppSettings>("get_settings"),
  updateSettings: (input: AppSettings) => invoke<void>("update_settings", { input }),
  connectShell: (shellId: string) => invoke<ConnectResult>("connect_shell", { shellId }),
  disconnectShell: (sessionId: string) => invoke<void>("disconnect_shell", { sessionId }),
  listSessions: () => invoke<SessionInfo[]>("list_sessions"),
  executeCommand: (sessionId: string, command: string) =>
    invoke<CommandOutput>("execute_command", { sessionId, command }),
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
  dbProbe: (sessionId: string, connection: DbConnection) =>
    invoke<DbProbeResult>("db_probe", { sessionId, connection }),
  dbQuery: (sessionId: string, connection: DbConnection, sql: string) =>
    invoke<DbQueryResult>("db_query", { sessionId, connection, sql }),
  listRequestLog: (endpoint?: string | null) =>
    invoke<RequestRecord[]>("list_request_log", { endpoint: endpoint ?? null }),
  clearRequestLog: () => invoke<void>("clear_request_log"),
};

// --- Base64 工具（编辑器/上传下载用） ---

export const b64 = {
  encodeBytes(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  },
  decodeBytes(value: string): Uint8Array {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  },
  decodeText(value: string): string {
    try {
      return new TextDecoder("utf-8").decode(this.decodeBytes(value));
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
