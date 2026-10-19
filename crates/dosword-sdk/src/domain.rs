use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub authorization_scope: String,
    pub expires_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
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

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    #[ts(type = "number")]
    pub id: i64,
    pub workspace_id: String,
    pub shell_id: Option<String>,
    pub action: String,
    pub outcome: String,
    pub detail: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct AuditFilter {
    pub workspace_id: Option<String>,
    pub action: Option<String>,
    pub outcome: Option<String>,
    #[ts(type = "number | null")]
    pub limit: Option<u64>,
    #[ts(type = "number | null")]
    pub offset: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct AuditPage {
    #[ts(type = "number")]
    pub total: u64,
    pub events: Vec<AuditEvent>,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct Dashboard {
    pub workspaces: Vec<Workspace>,
    pub shells: Vec<ShellProfile>,
    pub audit_events: Vec<AuditEvent>,
}

#[derive(Debug, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct CreateWorkspace {
    pub name: String,
    pub authorization_scope: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize, TS)]
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

#[derive(Debug, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct UpdateWorkspace {
    pub id: String,
    pub name: String,
    pub authorization_scope: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct UpdateShell {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub password: Option<String>,
    pub tags: Option<Vec<String>>,
    /// 协议参数（JSON 字符串，如 `{"encoder":"native","session":true}`）。
    /// `None` = 保持不变；显式给出则整体替换（编码方式 / session 开关都在这里）。
    #[serde(default)]
    pub protocol_params: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
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
    /// PHP SAPI（fpm-fcgi / cli-server / apache2handler 等）。
    pub php_sapi: String,
    /// 系统架构（php_uname('m')）。
    pub arch: String,
    /// 已加载 PHP 扩展（前 16 个）。
    pub extensions: Vec<String>,
    /// disable_functions 配置原文。
    pub disable_functions: String,
    /// 哥斯拉风格环境详情（OsInfo/CurrentUser/服务器/会话/配置等）。
    pub info: std::collections::HashMap<String, String>,
    /// stub 自报的协议元数据（能力协商）。旧 stub 可能为 None。
    #[serde(default)]
    pub capabilities: Option<TargetCapabilities>,
}

/// 目标 stub 自报的协议元数据：协议版本 + 能力位图 + 载荷形态。
///
/// 参考冰蝎 / 哥斯拉的能力握手：客户端不能假设目标具备某能力。
/// 旧 stub 不上报（`None`）→ 按兼容模式放行但按旧行为处理；
/// 新 stub 上报后可精确判定，缺能力时给出可执行错误而不是莫名失败。
#[derive(Debug, Clone, Serialize, Deserialize, TS, Default)]
#[serde(rename_all = "camelCase")]
pub struct TargetCapabilities {
    /// 协议版本（1 = 旧 stub 未上报；2 = 上报能力位图）
    #[ts(type = "number")]
    pub proto_version: u32,
    /// 能力标识：chunked / stream / db / plugin / exec / memory / gzip
    pub capabilities: Vec<String>,
    /// 载荷形态：file（落地文件）/ memory（内存马）
    pub shell_type: String,
}

impl TargetCapabilities {
    /// 从 probe/connect 返回的 `info` 映射构造。旧 stub 没有 `ProtoVersion` 时返回 None。
    pub fn from_info(info: &std::collections::HashMap<String, String>) -> Option<Self> {
        let proto_version = info
            .get("ProtoVersion")
            .map(|value| value.trim().parse::<u32>().unwrap_or(1))?;
        let mut capabilities = info
            .get("Capabilities")
            .map(|value| {
                value
                    .split(',')
                    .map(|item| item.trim().to_ascii_lowercase())
                    .filter(|item| !item.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        // 旧 stub 只报 ChunkedTransfer 时折算成能力位
        if !capabilities.iter().any(|item| item == "chunked")
            && info.get("ChunkedTransfer").map(String::as_str) == Some("1")
        {
            capabilities.push("chunked".to_string());
        }
        let shell_type = info
            .get("ShellType")
            .cloned()
            .unwrap_or_else(|| "file".to_string());
        Some(Self {
            proto_version,
            capabilities,
            shell_type,
        })
    }

    pub fn supports(&self, capability: &str) -> bool {
        let needle = capability.to_ascii_lowercase();
        self.capabilities.contains(&needle)
    }

    /// 分块读写是否可用（chunked 能力）。
    pub fn supports_chunked(&self) -> bool {
        self.supports("chunked")
    }
}

/// HTTP 手工请求结果（Repeater）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub struct HttpSendResult {
    #[ts(type = "number")]
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    #[ts(type = "number")]
    pub duration_ms: u64,
}

/// Shell 批量导入结果。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    #[ts(type = "number")]
    pub imported: usize,
    #[ts(type = "number")]
    pub skipped: usize,
}

/// 代理连通性测试结果（设置页「测试代理连通性」）。
///
/// `exit_ip` 仅在探测地址返回极短的纯 IP 文本时回填（如 `api.ipify.org`），
/// 其他探测地址一律为 `None`。
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct ProxyTestResult {
    pub ok: bool,
    #[ts(type = "number")]
    pub latency_ms: u64,
    pub message: String,
    pub exit_ip: Option<String>,
}

/// 分块读取结果（MCP `fs_read` 与前端分块预览共用）。
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct FileChunk {
    /// 分块内容（Base64）
    pub data_b64: String,
    /// 本次读取的起始偏移
    #[ts(type = "number")]
    pub offset: u64,
    /// 本次实际读到的字节数（0 表示已在文件尾）
    #[ts(type = "number")]
    pub size: u64,
    /// 是否已到文件尾（`length = 0` 表示整段读完）
    pub eof: bool,
}

/// 全局应用设置（app_settings 表单行 JSON）。
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    /// 是否允许发起真实网络请求（安全门总开关，默认关闭）。
    pub http_enabled: bool,
    /// 默认请求超时（秒）。
    #[ts(type = "number")]
    pub default_timeout_secs: u64,
    /// HTTP 代理地址（可选）。
    pub proxy: Option<String>,
    /// 单次响应大小上限（MB）。
    #[ts(type = "number")]
    pub max_file_size_mb: u64,
    /// 分块传输块大小（MB，上传/下载共用，默认 4）。
    #[ts(type = "number")]
    #[serde(default = "default_chunk_mb")]
    pub chunk_size_mb: u64,
    /// 是否允许 run_code 任意代码执行（插件托管载荷之外的安全闸，默认开）。
    #[serde(default = "default_allow_code")]
    pub allow_arbitrary_code: bool,
    /// 审计日志保留天数（超出自动清理；0 = 不清理，默认 90 天）。
    #[ts(type = "number")]
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u64,
    /// 传输压缩（gzip，目标支持 zlib 时启用，大文件/慢网络加速）。
    #[serde(default = "default_gzip")]
    pub gzip_enabled: bool,
    /// 是否校验 TLS 证书（默认 **false**：被测目标常用自签名证书，
    /// 严格校验会让工具不可用；开启后需目标证书链可信）。
    #[serde(default = "default_tls_verify")]
    pub tls_verify: bool,
    /// 是否允许读写任意本地路径（默认 false：仅限用户目录 / 系统临时目录）。
    /// 影响导入导出、下载保存与备份目录；敏感系统目录始终拒绝。
    #[serde(default = "default_allow_any_path")]
    pub allow_arbitrary_local_paths: bool,

    // —— MCP 服务端（把能力暴露给 AI 客户端） ——
    /// MCP 总开关（默认关闭）。关闭时不监听任何端口。
    #[serde(default)]
    pub mcp_enabled: bool,
    /// MCP 监听端口（仅绑定 127.0.0.1）。
    #[serde(default = "default_mcp_port")]
    pub mcp_port: u16,
    /// 访问令牌（64 位十六进制）。启用时生成，可轮换；等同密码，任何工具输出中不出现。
    #[serde(default)]
    pub mcp_token: String,
    /// 只读工具（列目录/读文件/查询/会话信息），默认开启。
    #[serde(default = "default_true")]
    pub mcp_tier_read: bool,
    /// 写入工具（写文件/建目录/重命名/删除/连接与断开），默认关闭。
    #[serde(default)]
    pub mcp_tier_write: bool,
    /// 执行工具（命令执行/插件执行/生成载荷），默认关闭。
    #[serde(default)]
    pub mcp_tier_exec: bool,
    /// 执行级操作需人在 GUI 二次确认（默认开启）。
    #[serde(default = "default_true")]
    pub mcp_require_confirm: bool,
    /// 每分钟最大调用次数（令牌桶）。
    #[serde(default = "default_mcp_rate")]
    pub mcp_max_calls_per_min: u32,
}

fn default_mcp_port() -> u16 {
    7317
}

fn default_mcp_rate() -> u32 {
    120
}

fn default_true() -> bool {
    true
}

/// MCP 服务运行状态（供设置页展示）。
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct McpStatus {
    pub running: bool,
    pub port: Option<u16>,
    /// 完整端点，如 `http://127.0.0.1:7317/mcp`
    pub endpoint: Option<String>,
    /// 当前启用的工具数量
    #[ts(type = "number")]
    pub tool_count: u32,
    /// 启动时间（Unix 秒）
    #[ts(type = "number | null")]
    pub started_at: Option<u64>,
    /// 最近一次启动失败原因（绑定失败等）
    pub last_error: Option<String>,
}

/// MCP 执行级操作的待确认请求（须由人在设置页批准）。
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct McpPendingApproval {
    pub id: String,
    pub tool: String,
    /// 参数摘要（已脱敏）
    pub summary: String,
    /// 发起时间（Unix 秒）
    #[ts(type = "number")]
    pub requested_at: u64,
}

/// MCP 单次调用记录（设置页「最近调用」用，仅内存环形缓冲）。
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct McpCallRecord {
    #[ts(type = "number")]
    pub at: u64,
    pub tool: String,
    /// read / write / exec
    pub tier: String,
    /// success / denied / error
    pub outcome: String,
    /// 参数摘要（已脱敏）
    pub summary: String,
    #[ts(type = "number")]
    pub duration_ms: u64,
}

fn default_tls_verify() -> bool {
    false
}

fn default_allow_any_path() -> bool {
    false
}

fn default_gzip() -> bool {
    true
}

fn default_chunk_mb() -> u64 {
    4
}

fn default_allow_code() -> bool {
    true
}

fn default_audit_retention_days() -> u64 {
    90
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            http_enabled: false,
            default_timeout_secs: 10,
            proxy: None,
            chunk_size_mb: 4,
            allow_arbitrary_code: true,
            max_file_size_mb: 32,
            audit_retention_days: 90,
            gzip_enabled: true,
            tls_verify: false,
            allow_arbitrary_local_paths: false,
            mcp_enabled: false,
            mcp_port: 7317,
            mcp_token: String::new(),
            mcp_tier_read: true,
            mcp_tier_write: false,
            mcp_tier_exec: false,
            mcp_require_confirm: true,
            mcp_max_calls_per_min: 120,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct CommandOutput {
    pub stdout: String,
    #[ts(type = "number")]
    pub duration_ms: u64,
    /// 命令执行后的服务器工作目录（终端据此更新提示符）。
    pub cwd: Option<String>,
    /// 原始输出字节（base64）——终端 GBK 等非 UTF-8 场景用。
    pub raw_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct DirListing {
    pub entries: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    #[ts(type = "number")]
    pub size: u64,
    pub modified: String,
    /// 权限（八进制字符串，如 "755"）。
    pub perms: String,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct FileContent {
    pub name: String,
    #[ts(type = "number")]
    pub size: u64,
    pub content_b64: String,
}

/// 协议注册表对外暴露的元信息（前端下拉用）。
#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolMeta {
    pub id: String,
    pub display_name: String,
    pub requires_network: bool,
    /// 插件版本（来自插件清单）。
    pub version: String,
    pub description: String,
    /// 能力列表（空 = 全支持）。
    pub capabilities: Vec<String>,
}

/// 连接结果：会话 ID + 环境信息。
#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct ConnectResult {
    pub session_id: String,
    pub server: String,
    pub web_server: String,
    pub runtime: String,
    pub current_dir: String,
    pub separator: String,
    pub message: String,
    pub php_sapi: String,
    pub arch: String,
    pub extensions: Vec<String>,
    pub disable_functions: String,
    pub info: std::collections::HashMap<String, String>,
    /// stub 自报的协议元数据（能力协商）。旧 stub 可能为 None。
    #[serde(default)]
    pub capabilities: Option<TargetCapabilities>,
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
            php_sapi: probe.php_sapi,
            arch: probe.arch,
            extensions: probe.extensions,
            disable_functions: probe.disable_functions,
            capabilities: probe.capabilities,
            info: probe.info,
        }
    }
}

/// 文件传输结果（W4 断点续传）：本次字节数与续传起点。
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct TransferOutcome {
    #[ts(type = "number")]
    pub bytes: u64,
    /// 0 = 从头开始；> 0 = 从该偏移续传。
    #[ts(type = "number")]
    pub resumed_from: u64,
}

/// 活跃会话元信息（供会话列表页展示）。
#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub session_id: String,
    pub profile_id: String,
    pub server: String,
    #[ts(type = "number")]
    pub last_used_at: u64,
    /// 最近一次心跳成功的时间（0 = 尚未心跳）。心跳**不**刷新 `last_used_at`，
    /// 因此空闲会话仍会按 TTL 过期。
    #[ts(type = "number")]
    pub last_heartbeat_at: u64,
    /// 最近一次心跳失败（目标掉线 / 会话失效）。
    pub stale: bool,
}

// --- 数据库管理（V2.0） ---

/// 数据库连接参数。driver 白名单：mysql / pgsql / sqlite（Rust 侧校验）。
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct DbConnection {
    pub driver: String,
    pub host: Option<String>,
    #[ts(type = "number | null")]
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub dbname: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct DbProbeResult {
    pub driver: String,
    pub databases: Vec<String>,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct DbQueryResult {
    pub columns: Vec<String>,
    /// 行数据：值为字符串或 null。
    pub rows: Vec<Vec<Option<String>>>,
    /// 非查询语句的影响行数。
    #[ts(type = "number")]
    pub affected: u64,
    #[ts(type = "number")]
    pub duration_ms: u64,
}

// --- 请求调试器（V2.0） ---

/// 生成的服务端脚本（stub）。
#[derive(Debug, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct GenerateShellResult {
    /// 建议文件名（如 shell_php_xor_base64.php）。
    pub filename: String,
    /// 脚本内容。
    pub content: String,
    /// 加盐密钥派生的盐（未启用时为 None）。登记 Shell 时需一并填入协议参数。
    pub salt: Option<String>,
}

/// 一条协议请求记录（内存环缓冲，仅调试用途，不落盘）。
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct RequestRecord {
    #[ts(type = "number")]
    pub id: u64,
    /// 产生该帧的协议 id（builtin.php.v1 / builtin.jsp.v1 / ...）。
    pub protocol_id: String,
    /// 目标端点。
    pub endpoint: String,
    /// 操作类型（probe / exec / list_dir / read_file / ... / db_probe / db_query）。
    pub action: String,
    pub created_at: String,
    #[ts(type = "number")]
    pub status: u16,
    #[ts(type = "number")]
    pub duration_ms: u64,
    /// base64 解码后的 PHP 载荷（密码已脱敏，截断 2KB）。
    pub payload: String,
    /// 响应体（截断 2KB）。
    pub response: String,
}

/// 内存马句柄。
///
/// 设计约束：**仅凭本记录（endpoint + token + artifact）就应能在一个全新的
/// DoSword 实例上完成卸载**。做不到的形态不允许实现 —— 否则等于给目标留后门。
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct MemoryShell {
    pub id: String,
    pub workspace_id: String,
    /// 关联的 Shell（可为空：Shell 被删除后句柄仍需保留以便卸载）。
    pub shell_id: Option<String>,
    /// 目标运行时：php / jsp。
    pub runtime: String,
    /// 形态：php_fcgi / php_user_ini / java_filter。
    pub kind: String,
    /// 载荷自报的标识（用于存活检测与卸载时精确匹配）。
    pub name: String,
    /// 存活检测与自毁鉴权令牌。**等同密码**，UI 需掩码显示。
    pub token: String,
    /// 注入时的目标端点（全新实例可据此重连并卸载）。
    pub endpoint: String,
    pub install_path: String,
    /// 卸载所需的产物清单（JSON：files[] / previous_content / cleanup[]）。
    pub artifact: String,
    /// active / stale / orphaned / uninstalled
    pub status: String,
    pub installed_at: String,
    pub last_check_at: Option<String>,
    pub last_check_ok: bool,
    #[ts(type = "number")]
    pub uninstall_attempts: i64,
    pub notes: String,
}

/// 某个内存马形态在当前目标上的可行性（由客户端根据 probe 的环境信息本地判定）。
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
pub struct MemshellCapability {
    pub kind: String,
    pub runtime: String,
    pub feasible: bool,
    /// 不可行时的原因（供 UI 直接展示）。
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// TS 类型生成：将全部 DTO 导出为 src/generated/domain.ts，前端 api.ts 复用，
// 避免前后端类型手工重复维护导致的漂移。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod ts_bindings {
    use super::*;
    use ts_rs::TS;

    /// 参与生成的类型清单（保持与前端 API 面一致）。
    fn exported() -> Vec<(&'static str, String)> {
        let types: Vec<(&str, String)> = vec![
            ("Workspace", Workspace::decl()),
            ("ShellProfile", ShellProfile::decl()),
            ("AuditEvent", AuditEvent::decl()),
            ("AuditFilter", AuditFilter::decl()),
            ("AuditPage", AuditPage::decl()),
            ("Dashboard", Dashboard::decl()),
            ("CreateWorkspace", CreateWorkspace::decl()),
            ("CreateShell", CreateShell::decl()),
            ("UpdateWorkspace", UpdateWorkspace::decl()),
            ("UpdateShell", UpdateShell::decl()),
            ("ProbeResult", ProbeResult::decl()),
            ("TargetCapabilities", TargetCapabilities::decl()),
            ("MemoryShell", MemoryShell::decl()),
            ("MemshellCapability", MemshellCapability::decl()),
            ("AppSettings", AppSettings::decl()),
            ("CommandOutput", CommandOutput::decl()),
            ("DirListing", DirListing::decl()),
            ("FileEntry", FileEntry::decl()),
            ("FileContent", FileContent::decl()),
            ("FileChunk", FileChunk::decl()),
            ("ProtocolMeta", ProtocolMeta::decl()),
            ("ConnectResult", ConnectResult::decl()),
            ("SessionInfo", SessionInfo::decl()),
            ("TransferOutcome", TransferOutcome::decl()),
            ("DbConnection", DbConnection::decl()),
            ("DbProbeResult", DbProbeResult::decl()),
            ("DbQueryResult", DbQueryResult::decl()),
            ("RequestRecord", RequestRecord::decl()),
            ("GenerateShellResult", GenerateShellResult::decl()),
            ("HttpSendResult", HttpSendResult::decl()),
            ("ImportResult", ImportResult::decl()),
            ("ProxyTestResult", ProxyTestResult::decl()),
            ("McpStatus", McpStatus::decl()),
            ("McpCallRecord", McpCallRecord::decl()),
            ("McpPendingApproval", McpPendingApproval::decl()),
            ("PluginManifest", crate::plugin::PluginManifest::decl()),
            ("PluginKind", crate::plugin::PluginKind::decl()),
            ("FeatureManifest", crate::plugin::FeatureManifest::decl()),
            ("ParamSpec", crate::plugin::ParamSpec::decl()),
        ];
        types
    }

    #[test]
    fn generate_ts_bindings() {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("cargo 环境变量缺失");
        let out = std::path::Path::new(&manifest).join("../../src/generated/domain.ts");

        let mut content = String::new();
        content.push_str("// AUTO-GENERATED by src-tauri/src/domain.rs (ts-rs) — 请勿手工编辑。\n");
        content.push_str("// 重新生成：pnpm gen:types\n\n");
        for (name, decl) in exported() {
            // ts-rs 声明不带 export 关键字，统一加前缀使其成为 ES 模块
            content.push_str(&format!("export {decl}"));
            content.push('\n');
            // 校验类型名一致性（ts-rs 声明格式为 `type <name> = ...`）
            if !decl.contains(&format!("type {name} =")) {
                panic!("类型 {name} 声明异常：{decl}");
            }
        }

        // 生成 + 一致性校验一体（避免并行测试竞争写同一文件）：
        // 文件缺失时先落盘并要求重跑一次；内容漂移时自动重新生成并报错提示。
        let parent = out.parent().expect("生成目录缺失");
        std::fs::create_dir_all(parent).expect("创建生成目录失败");
        if !out.exists() {
            std::fs::write(&out, &content).expect("写入 domain.ts 失败");
            panic!("首次生成 {}，请再次运行 pnpm gen:types", out.display());
        }
        let current = std::fs::read_to_string(&out).expect("读取 domain.ts 失败");
        if current != content {
            std::fs::write(&out, &content).expect("写入 domain.ts 失败");
            panic!(
                "src/generated/domain.ts 与当前 Rust 类型不一致，已重新生成，请再次运行 pnpm gen:types"
            );
        }
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    use std::collections::HashMap;

    fn info(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn new_stub_reports_version_and_capabilities() {
        let map = info(&[
            ("ProtoVersion", "2"),
            ("Capabilities", "chunked,stream,db,plugin,exec"),
            ("ShellType", "file"),
        ]);
        let caps = TargetCapabilities::from_info(&map).expect("应解析出能力");
        assert_eq!(caps.proto_version, 2);
        assert!(caps.supports_chunked());
        assert!(caps.supports("db"));
        assert!(caps.supports("EXEC"), "能力判定应忽略大小写");
        assert!(!caps.supports("memory"));
        assert_eq!(caps.shell_type, "file");
    }

    #[test]
    fn legacy_stub_without_version_returns_none() {
        // 旧 stub 只报 ChunkedTransfer、不报 ProtoVersion → None（调用方按兼容模式处理）
        let map = info(&[("ChunkedTransfer", "1")]);
        assert!(TargetCapabilities::from_info(&map).is_none());
    }

    #[test]
    fn legacy_chunked_flag_is_folded_into_capabilities() {
        // 有 ProtoVersion 但无 Capabilities 列表时，ChunkedTransfer=1 折算成 chunked 能力位
        let map = info(&[("ProtoVersion", "2"), ("ChunkedTransfer", "1")]);
        let caps = TargetCapabilities::from_info(&map).expect("应解析出能力");
        assert!(caps.supports_chunked());
        assert_eq!(caps.shell_type, "file", "未上报时默认为落地文件型");
    }

    #[test]
    fn capability_list_is_trimmed_and_lowercased() {
        let map = info(&[
            ("ProtoVersion", "2"),
            ("Capabilities", " Chunked , DB ,, "),
            ("ShellType", "memory"),
        ]);
        let caps = TargetCapabilities::from_info(&map).expect("应解析出能力");
        assert_eq!(caps.capabilities, vec!["chunked", "db"]);
        assert_eq!(caps.shell_type, "memory");
    }
}
