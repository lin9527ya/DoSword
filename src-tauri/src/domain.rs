use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub authorization_scope: String,
    pub expires_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellProfile {
    pub id: String,
    pub workspace_id: String,
    pub name: String,
    pub endpoint: String,
    pub runtime: String,
    pub protocol_id: String,
    pub password: String,
    /// 协议扩展参数（JSON 字符串，默认 "{}"）。
    pub protocol_params: String,
    pub authorization_ack: bool,
    pub status: String,
    pub last_connected_at: Option<String>,
    pub created_at: String,
    /// 标签列表（DB 中存 JSON 数组字符串）。
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: i64,
    pub workspace_id: String,
    pub shell_id: Option<String>,
    pub action: String,
    pub outcome: String,
    pub detail: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFilter {
    pub workspace_id: Option<String>,
    pub action: Option<String>,
    pub outcome: Option<String>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPage {
    pub total: u64,
    pub events: Vec<AuditEvent>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Dashboard {
    pub workspaces: Vec<Workspace>,
    pub shells: Vec<ShellProfile>,
    pub audit_events: Vec<AuditEvent>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWorkspace {
    pub name: String,
    pub authorization_scope: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateShell {
    pub workspace_id: String,
    pub name: String,
    pub endpoint: String,
    pub runtime: String,
    pub protocol_id: String,
    pub password: Option<String>,
    pub protocol_params: Option<String>,
    /// 用户勾选的"已确认目标位于授权范围内"。
    pub confirm_network: bool,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateWorkspace {
    pub id: String,
    pub name: String,
    pub authorization_scope: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateShell {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub password: Option<String>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResult {
    pub status: String,
    pub server: String,
    pub web_server: String,
    pub runtime: String,
    /// 连接时的当前工作目录。
    pub current_dir: String,
    /// 服务器路径分隔符（"/" 或 "\"）。
    pub separator: String,
    pub message: String,
}

/// 全局应用设置（app_settings 表单行 JSON）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    /// 是否允许发起真实网络请求（安全门总开关，默认关闭）。
    pub http_enabled: bool,
    /// 默认请求超时（秒）。
    pub default_timeout_secs: u64,
    /// HTTP 代理地址（可选）。
    pub proxy: Option<String>,
    /// 单次响应大小上限（MB）。
    pub max_file_size_mb: u64,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            http_enabled: false,
            default_timeout_secs: 10,
            proxy: None,
            max_file_size_mb: 32,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandOutput {
    pub stdout: String,
    pub duration_ms: u64,
    /// 命令执行后的服务器工作目录（终端据此更新提示符）。
    pub cwd: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirListing {
    pub entries: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileContent {
    pub name: String,
    pub size: u64,
    pub content_b64: String,
}

/// 协议注册表对外暴露的元信息（前端下拉用）。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolMeta {
    pub id: String,
    pub display_name: String,
    pub requires_network: bool,
}

/// 连接结果：会话 ID + 环境信息。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectResult {
    pub session_id: String,
    pub server: String,
    pub web_server: String,
    pub runtime: String,
    pub current_dir: String,
    pub separator: String,
    pub message: String,
}

impl ConnectResult {
    pub fn from_probe(session_id: String, probe: ProbeResult) -> Self {
        Self {
            session_id,
            server: probe.server,
            web_server: probe.web_server,
            runtime: probe.runtime,
            current_dir: probe.current_dir,
            separator: probe.separator,
            message: probe.message,
        }
    }
}

/// 活跃会话元信息（供会话列表页展示）。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub session_id: String,
    pub profile_id: String,
    pub server: String,
    pub last_used_at: u64,
}
