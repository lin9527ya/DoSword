// 与 src-tauri/src/domain.rs 对应的类型定义与 invoke 封装。
import { invoke } from "@tauri-apps/api/core";

// --- 类型 ---

export type Workspace = {
  id: string;
  name: string;
  authorizationScope: string;
  expiresAt?: string;
  createdAt: string;
};

export type ShellProfile = {
  id: string;
  workspaceId: string;
  name: string;
  endpoint: string;
  runtime: string;
  protocolId: string;
  password: string;
  protocolParams: string;
  authorizationAck: boolean;
  status: "unknown" | "online" | "offline" | "error";
  lastConnectedAt?: string;
  createdAt: string;
  tags: string[];
};

export type AuditEvent = {
  id: number;
  workspaceId: string;
  shellId?: string;
  action: string;
  outcome: string;
  detail: string;
  createdAt: string;
};

export type AuditFilter = {
  workspaceId?: string;
  action?: string;
  outcome?: string;
  limit?: number;
  offset?: number;
};

export type AuditPage = {
  total: number;
  events: AuditEvent[];
};

export type Dashboard = {
  workspaces: Workspace[];
  shells: ShellProfile[];
  auditEvents: AuditEvent[];
};

export type ProbeResult = {
  status: string;
  server: string;
  webServer: string;
  runtime: string;
  currentDir: string;
  separator: string;
  message: string;
};

export type AppSettings = {
  httpEnabled: boolean;
  defaultTimeoutSecs: number;
  proxy: string | null;
  maxFileSizeMb: number;
};

export type ProtocolMeta = {
  id: string;
  displayName: string;
  requiresNetwork: boolean;
};

export type CommandOutput = {
  stdout: string;
  durationMs: number;
  cwd?: string;
};

export type FileEntry = {
  name: string;
  path: string;
  isDir: boolean;
  size: number;
  modified: string;
};

export type DirListing = {
  entries: FileEntry[];
};

export type FileContent = {
  name: string;
  size: number;
  contentB64: string;
};

export type ConnectResult = {
  sessionId: string;
  server: string;
  webServer: string;
  runtime: string;
  currentDir: string;
  separator: string;
  message: string;
};

export type SessionInfo = {
  sessionId: string;
  profileId: string;
  server: string;
  lastUsedAt: number;
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
  listAudit: (filter: AuditFilter) => invoke<AuditPage>("list_audit", { filter }),
  writeLocalFile: (path: string, contentB64: string) =>
    invoke<void>("write_local_file", { path, contentB64 }),
  probeShell: (shellId: string) => invoke<ProbeResult>("probe_shell", { shellId }),
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

export function shortTime(value?: string): string {
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
