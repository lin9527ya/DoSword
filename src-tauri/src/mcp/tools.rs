//! MCP 工具层：把 DoSword 能力包装成 MCP 工具。
//!
//! 三条硬规则：
//! 1. **不重复实现安全闸门**——工具体直接调用既有的 `commands::*`，授权范围、
//!    授权到期、真实网络开关、审计都在同一处生效。
//! 2. **不把凭据交给模型**——Shell 列表走 [`ShellSummary`]（无密码），设置走
//!    `redact_settings`（无令牌、代理已掩码）。
//! 3. **每个调用都过 [`Guard`]**——分级开关、限流、并发、执行级人工确认、
//!    超时、结果截断、审计与调用日志，一次都不漏。

use std::future::Future;
use std::time::{Duration, Instant};

use dosword_sdk::domain::{
    AppSettings, AuditFilter, DbConnection, McpCallRecord, ProbeResult, SessionInfo,
};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ErrorData as McpError};
use schemars::JsonSchema;
use serde::Deserialize;
use tauri::{AppHandle, Manager};

use super::redact::{ShellSummary, redact_settings, truncate_text};
use super::{McpState, now_unix};
use crate::AppState;

/// 工具的能力级别。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    Read,
    Write,
    Exec,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Read => "read",
            Tier::Write => "write",
            Tier::Exec => "exec",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Tier::Read => "只读",
            Tier::Write => "写入",
            Tier::Exec => "执行",
        }
    }

    fn enabled(self, settings: &AppSettings) -> bool {
        match self {
            Tier::Read => settings.mcp_tier_read,
            Tier::Write => settings.mcp_tier_write,
            Tier::Exec => settings.mcp_tier_exec,
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Tier::Read => "请在「设置 → AI / MCP」启用只读级权限",
            Tier::Write => "请在「设置 → AI / MCP」启用写入级权限（会改动目标文件/会话）",
            Tier::Exec => "请在「设置 → AI / MCP」启用执行级权限（可在目标执行任意命令）",
        }
    }
}

/// 工具总数（用于状态展示）。
pub fn tool_count() -> usize {
    super::DoswordMcp::tool_router().list_all().len()
}

impl super::DoswordMcp {
    /// 构造服务器。工具表由宏生成的 `Self::tool_router()` 提供，无需额外字段。
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

// ---------------------------------------------------------------------------
// 统一守卫
// ---------------------------------------------------------------------------

/// 一次工具调用的守卫：进入时校验，退出时记账。
pub struct Guard {
    app: AppHandle,
    tool: &'static str,
    tier: Tier,
    summary: String,
    started: Instant,
    timeout: Duration,
    /// 并发槽位：Drop 时自动释放
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Guard {
    /// 五道闸门：总开关 → 分级 → 限流 → 并发 → 执行级确认。
    pub async fn begin(
        app: &AppHandle,
        tool: &'static str,
        tier: Tier,
        summary: String,
    ) -> Result<Self, CallToolResult> {
        let settings = match read_settings(app) {
            Ok(settings) => settings,
            Err(error) => return Err(denied(app, tool, tier, &summary, &error)),
        };
        if !settings.mcp_enabled {
            return Err(denied(
                app,
                tool,
                tier,
                &summary,
                "MCP 服务未启用：请在「设置 → AI / MCP」中开启",
            ));
        }
        if !tier.enabled(&settings) {
            return Err(denied(
                app,
                tool,
                tier,
                &summary,
                &format!("{}级工具未启用：{}", tier.label(), tier.hint()),
            ));
        }

        let state = app.state::<McpState>();
        if let Err(error) = state.check_rate(settings.mcp_max_calls_per_min) {
            return Err(denied(app, tool, tier, &summary, &error));
        }
        let permit = match state.acquire_slot().await {
            Ok(permit) => permit,
            Err(error) => return Err(denied(app, tool, tier, &summary, &error)),
        };

        // 执行级：默认要求人工确认（一次性批准，120 秒内有效）
        if tier == Tier::Exec
            && settings.mcp_require_confirm
            && !state.consume_approval(tool, &summary)
        {
            let id = state.request_approval(tool, &summary);
            audit(app, tool, "pending", &summary);
            return Err(CallToolResult::error(vec![ContentBlock::text(format!(
                "该操作属于执行级，需要人工确认。\n\
                 请在 DoSword「设置 → AI / MCP → 待确认操作」批准 id：{id}\n\
                 批准后 120 秒内以**完全相同的参数**重试本调用即可执行（批准是一次性的）。"
            ))]));
        }

        Ok(Self {
            app: app.clone(),
            tool,
            tier,
            summary,
            started: Instant::now(),
            // 单次调用上限：设置里的请求超时 + 30 秒余量（命令内部还有各自的 HTTP 超时）
            timeout: Duration::from_secs(settings.default_timeout_secs.max(1) + 30),
            _permit: permit,
        })
    }

    /// 执行并统一收尾（超时 → 截断 → 审计 → 调用日志）。
    pub async fn run<T, F>(self, future: F) -> CallToolResult
    where
        T: serde::Serialize,
        F: Future<Output = Result<T, String>>,
    {
        let timeout = self.timeout;
        let result = match tokio::time::timeout(timeout, future).await {
            Ok(result) => result,
            Err(_) => Err(format!("调用超时（超过 {} 秒）", timeout.as_secs())),
        };
        self.finish(result)
    }

    /// 同步路径（无需等待异步命令时使用）。
    pub fn finish<T: serde::Serialize>(self, result: Result<T, String>) -> CallToolResult {
        let duration_ms = self.started.elapsed().as_millis() as u64;
        let state = self.app.state::<McpState>();

        match result {
            Ok(value) => {
                let text = serde_json::to_string_pretty(&value)
                    .unwrap_or_else(|error| format!("{{\"error\":\"结果序列化失败：{error}\"}}"));
                let (text, truncated) = truncate_text(&text);
                audit(&self.app, self.tool, "success", &self.summary);
                state.record(McpCallRecord {
                    at: now_unix(),
                    tool: self.tool.to_string(),
                    tier: self.tier.as_str().to_string(),
                    outcome: "success".to_string(),
                    summary: self.summary.clone(),
                    duration_ms,
                });
                let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
                if truncated {
                    result.content.push(ContentBlock::text(
                        "（结果超过 256 KiB 已截断：请用偏移/分页参数分批读取）",
                    ));
                }
                result
            }
            Err(message) => {
                audit(
                    &self.app,
                    self.tool,
                    "error",
                    &format!("{}｜{message}", self.summary),
                );
                state.record(McpCallRecord {
                    at: now_unix(),
                    tool: self.tool.to_string(),
                    tier: self.tier.as_str().to_string(),
                    outcome: "error".to_string(),
                    summary: self.summary.clone(),
                    duration_ms,
                });
                CallToolResult::error(vec![ContentBlock::text(message)])
            }
        }
    }
}

fn denied(
    app: &AppHandle,
    tool: &'static str,
    tier: Tier,
    summary: &str,
    message: &str,
) -> CallToolResult {
    audit(app, tool, "denied", &format!("{summary}｜{message}"));
    let state = app.state::<McpState>();
    state.record(McpCallRecord {
        at: now_unix(),
        tool: tool.to_string(),
        tier: tier.as_str().to_string(),
        outcome: "denied".to_string(),
        summary: summary.to_string(),
        duration_ms: 0,
    });
    CallToolResult::error(vec![ContentBlock::text(message.to_string())])
}

fn read_settings(app: &AppHandle) -> Result<AppSettings, String> {
    let state = app.state::<AppState>();
    let database = state
        .database
        .lock()
        .map_err(|_| "数据库锁异常".to_string())?;
    database.get_settings().map_err(|error| error.to_string())
}

fn audit(app: &AppHandle, tool: &str, outcome: &str, detail: &str) {
    let state = app.state::<AppState>();
    if let Ok(database) = state.database.lock() {
        let _ = database.record_audit(
            None,
            None,
            &format!("mcp.{tool}"),
            outcome,
            &truncate_text(detail).0,
        );
    }
}

/// 在阻塞线程上访问 `AppState`（避免同步数据库/文件操作占用 tokio 工作线程）。
async fn with_state<T, F>(app: &AppHandle, work: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&AppState) -> Result<T, String> + Send + 'static,
{
    let app = app.clone();
    tokio::task::spawn_blocking(move || {
        let state = app.state::<AppState>();
        work(&state)
    })
    .await
    .map_err(|error| format!("内部任务失败：{error}"))?
}

/// SQL 级别分类：只读语句走 read 级，其余一律 write 级；多语句一律 write。
fn classify_sql(sql: &str) -> Tier {
    let trimmed = sql.trim_start();
    let lowered = trimmed.to_ascii_lowercase();
    // 多语句（分号后还有内容）无法保证只读，按写处理
    let without_trailing = lowered.trim_end().trim_end_matches(';');
    if without_trailing.contains(';') {
        return Tier::Write;
    }
    const READ_PREFIXES: [&str; 6] = ["select", "show", "explain", "describe", "desc", "pragma"];
    if READ_PREFIXES
        .iter()
        .any(|prefix| without_trailing.starts_with(prefix))
    {
        Tier::Read
    } else {
        Tier::Write
    }
}

// ---------------------------------------------------------------------------
// 参数结构（schema 由 schemars 自动生成）
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NoArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SessionArgs {
    /// 会话 ID（由 `dosword_shell_connect` 或 `dosword_sessions_list` 获得）
    pub session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PathArgs {
    pub session_id: String,
    /// 目标机绝对路径
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadArgs {
    pub session_id: String,
    pub path: String,
    /// 起始偏移（字节），默认 0
    pub offset: Option<u64>,
    /// 读取长度（字节），0 或省略表示读到文件尾
    pub length: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteArgs {
    pub session_id: String,
    pub path: String,
    /// 文件内容（Base64）
    pub content_b64: String,
    /// 写入偏移（字节），0 表示从头覆写，>0 表示追加
    pub offset: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameArgs {
    pub session_id: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TouchArgs {
    pub session_id: String,
    pub path: String,
    /// Unix 时间戳（秒）
    pub timestamp: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DbArgs {
    pub session_id: String,
    /// 数据库连接参数：{ driver: "mysql"|"pgsql"|"sqlite", host, port, username, password, dbname }
    pub connection: serde_json::Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DbQueryArgs {
    pub session_id: String,
    pub connection: serde_json::Value,
    /// SQL 语句；`SELECT`/`SHOW`/`EXPLAIN` 属只读级，其余属写入级
    pub sql: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ExecArgs {
    pub session_id: String,
    /// 目标机 shell 命令
    pub command: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PluginArgs {
    pub session_id: String,
    /// 功能插件 id（见 `dosword_plugins_list`）
    pub plugin_id: String,
    /// 插件参数（结构随插件而定，见插件清单的 params）
    pub params: serde_json::Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StubArgs {
    /// 服务端语言：php / asp / aspx / jsp / python / node
    pub language: String,
    /// 编码器 id（见 `dosword_encoders_list`，默认 `native`）
    pub encoder_id: String,
    /// 连接密码（与后续 connect 使用的一致）
    pub password: String,
    /// 是否生成分阶段（session）载荷
    pub session: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AuditArgs {
    pub workspace_id: Option<String>,
    pub action: Option<String>,
    /// success / error / denied / override / pending
    pub outcome: Option<String>,
    /// 返回条数上限（默认 50，最大 200）
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

fn to_connection(value: &serde_json::Value) -> Result<DbConnection, String> {
    serde_json::from_value(value.clone()).map_err(|error| format!("数据库连接参数不合法：{error}"))
}

// ---------------------------------------------------------------------------
// 工具定义
// ---------------------------------------------------------------------------

#[rmcp::tool_router(vis = "pub(crate)")]
impl super::DoswordMcp {
    // ---- 只读 ----

    #[rmcp::tool(description = "列出所有授权的 Workspace（只读）")]
    async fn dosword_workspaces_list(
        &self,
        Parameters(_args): Parameters<NoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let guard = match Guard::begin(
            &self.app,
            "dosword_workspaces_list",
            Tier::Read,
            "list".into(),
        )
        .await
        {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let result = with_state(&self.app, |state| {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            database
                .list_workspaces()
                .map_err(|error| error.to_string())
        })
        .await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(
        description = "列出已登记的 Shell（只读）。返回结果不含连接密码，仅以 hasPassword 表示是否已配置"
    )]
    async fn dosword_shells_list(
        &self,
        Parameters(_args): Parameters<NoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let guard =
            match Guard::begin(&self.app, "dosword_shells_list", Tier::Read, "list".into()).await {
                Ok(guard) => guard,
                Err(denied) => return Ok(denied),
            };
        let result = with_state(&self.app, |state| {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            let shells = database.list_shells().map_err(|error| error.to_string())?;
            Ok(shells
                .iter()
                .map(ShellSummary::from)
                .collect::<Vec<ShellSummary>>())
        })
        .await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "列出当前活跃会话（只读）")]
    async fn dosword_sessions_list(
        &self,
        Parameters(_args): Parameters<NoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let guard = match Guard::begin(
            &self.app,
            "dosword_sessions_list",
            Tier::Read,
            "list".into(),
        )
        .await
        {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result: Result<Vec<SessionInfo>, String> = crate::commands::list_sessions(app).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "探测某个会话的目标环境信息（只读）")]
    async fn dosword_probe_session(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, McpError> {
        let summary = format!("session={}", args.session_id);
        let guard =
            match Guard::begin(&self.app, "dosword_probe_session", Tier::Read, summary).await {
                Ok(guard) => guard,
                Err(denied) => return Ok(denied),
            };
        let app = self.app.clone();
        let session_id = args.session_id;
        let result: Result<ProbeResult, String> =
            crate::commands::get_session_probe(session_id, app).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "读取全局设置（只读）。MCP 令牌被清空、代理地址已脱敏")]
    async fn dosword_settings_get(
        &self,
        Parameters(_args): Parameters<NoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let guard =
            match Guard::begin(&self.app, "dosword_settings_get", Tier::Read, "get".into()).await {
                Ok(guard) => guard,
                Err(denied) => return Ok(denied),
            };
        let guard_app = self.app.clone();
        let result = with_state(&guard_app, |state| {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            let settings = database.get_settings().map_err(|error| error.to_string())?;
            Ok(redact_settings(&settings))
        })
        .await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "列出可用协议及其能力（只读）")]
    async fn dosword_protocols_list(
        &self,
        Parameters(_args): Parameters<NoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let guard = match Guard::begin(
            &self.app,
            "dosword_protocols_list",
            Tier::Read,
            "list".into(),
        )
        .await
        {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let result = with_state(&self.app, |state| Ok(state.protocols.protocol_metas())).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "列出功能插件及其参数（只读）")]
    async fn dosword_plugins_list(
        &self,
        Parameters(_args): Parameters<NoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let guard = match Guard::begin(&self.app, "dosword_plugins_list", Tier::Read, "list".into())
            .await
        {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let result = with_state(&self.app, |state| {
            let plugins = state
                .feature_plugins
                .lock()
                .map(|registry| registry.list())
                .unwrap_or_default();
            Ok(plugins)
        })
        .await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "列出可用编码器（id + 名称）（只读）")]
    async fn dosword_encoders_list(
        &self,
        Parameters(_args): Parameters<NoArgs>,
    ) -> Result<CallToolResult, McpError> {
        let guard = match Guard::begin(
            &self.app,
            "dosword_encoders_list",
            Tier::Read,
            "list".into(),
        )
        .await
        {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let result: Result<Vec<(String, String)>, String> = with_state(&self.app, |_state| {
            Ok(dosword_sdk::EncoderRegistry::global().list())
        })
        .await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "查询审计日志（只读）。detail 可能包含命令原文，请谨慎外传")]
    async fn dosword_audit_query(
        &self,
        Parameters(args): Parameters<AuditArgs>,
    ) -> Result<CallToolResult, McpError> {
        let filter = AuditFilter {
            workspace_id: args.workspace_id,
            action: args.action,
            outcome: args.outcome,
            limit: Some(args.limit.unwrap_or(50).clamp(1, 200)),
            offset: args.offset,
        };
        let summary = format!("limit={}", filter.limit.unwrap_or(50));
        let guard = match Guard::begin(&self.app, "dosword_audit_query", Tier::Read, summary).await
        {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result = crate::commands::list_audit(filter, app).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "列出目标机目录内容（只读）")]
    async fn dosword_fs_list(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<CallToolResult, McpError> {
        let summary = format!("session={} path={}", args.session_id, args.path);
        let guard = match Guard::begin(&self.app, "dosword_fs_list", Tier::Read, summary).await {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result = crate::commands::list_dir(args.session_id, args.path, app).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(
        description = "按偏移分块读取目标机文件（只读）。length 省略或为 0 表示读到文件尾；返回 Base64"
    )]
    async fn dosword_fs_read(
        &self,
        Parameters(args): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, McpError> {
        let summary = format!(
            "session={} path={} offset={} length={}",
            args.session_id,
            args.path,
            args.offset.unwrap_or(0),
            args.length.unwrap_or(0)
        );
        let guard = match Guard::begin(&self.app, "dosword_fs_read", Tier::Read, summary).await {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result = crate::commands::read_chunk(
            args.session_id,
            args.path,
            args.offset.unwrap_or(0),
            args.length.unwrap_or(0),
            app,
        )
        .await;
        Ok(guard.run(async { result }).await)
    }

    // ---- 写入 ----

    #[rmcp::tool(description = "连接某个已登记的 Shell，返回会话 ID（写入级：会与目标建立会话）")]
    async fn dosword_shell_connect(
        &self,
        Parameters(args): Parameters<ShellIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let summary = format!("shell={}", args.shell_id);
        let guard =
            match Guard::begin(&self.app, "dosword_shell_connect", Tier::Write, summary).await {
                Ok(guard) => guard,
                Err(denied) => return Ok(denied),
            };
        let app = self.app.clone();
        let result = crate::commands::connect_shell(args.shell_id, app).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "断开会话（写入级）")]
    async fn dosword_shell_disconnect(
        &self,
        Parameters(args): Parameters<SessionArgs>,
    ) -> Result<CallToolResult, McpError> {
        let summary = format!("session={}", args.session_id);
        let guard =
            match Guard::begin(&self.app, "dosword_shell_disconnect", Tier::Write, summary).await {
                Ok(guard) => guard,
                Err(denied) => return Ok(denied),
            };
        let app = self.app.clone();
        let result = crate::commands::disconnect_shell(args.session_id, app).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(
        description = "写入目标机文件（写入级）。offset=0 或省略为从头覆写，>0 为追加；内容需 Base64"
    )]
    async fn dosword_fs_write(
        &self,
        Parameters(args): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, McpError> {
        let summary = format!(
            "session={} path={} offset={} bytes={}",
            args.session_id,
            args.path,
            args.offset.unwrap_or(0),
            args.content_b64.len()
        );
        let guard = match Guard::begin(&self.app, "dosword_fs_write", Tier::Write, summary).await {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result = crate::commands::write_chunk(
            args.session_id,
            args.path,
            args.content_b64,
            args.offset.unwrap_or(0),
            app,
        )
        .await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "在目标机创建目录（写入级）")]
    async fn dosword_fs_mkdir(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<CallToolResult, McpError> {
        let summary = format!("session={} path={}", args.session_id, args.path);
        let guard = match Guard::begin(&self.app, "dosword_fs_mkdir", Tier::Write, summary).await {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result = crate::commands::create_dir(args.session_id, args.path, app).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "重命名/移动目标机文件（写入级）")]
    async fn dosword_fs_rename(
        &self,
        Parameters(args): Parameters<RenameArgs>,
    ) -> Result<CallToolResult, McpError> {
        let summary = format!("session={} {} -> {}", args.session_id, args.from, args.to);
        let guard = match Guard::begin(&self.app, "dosword_fs_rename", Tier::Write, summary).await {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result = crate::commands::rename_path(args.session_id, args.from, args.to, app).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "删除目标机文件或目录（写入级，不可恢复）")]
    async fn dosword_fs_delete(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<CallToolResult, McpError> {
        let summary = format!("session={} path={}", args.session_id, args.path);
        let guard = match Guard::begin(&self.app, "dosword_fs_delete", Tier::Write, summary).await {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result = crate::commands::delete_path(args.session_id, args.path, app).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "修改目标机文件时间戳（写入级）")]
    async fn dosword_fs_touch(
        &self,
        Parameters(args): Parameters<TouchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let summary = format!(
            "session={} path={} ts={}",
            args.session_id, args.path, args.timestamp
        );
        let guard = match Guard::begin(&self.app, "dosword_fs_touch", Tier::Write, summary).await {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result =
            crate::commands::touch_path(args.session_id, args.path, args.timestamp, app).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "探测目标机数据库连接（写入级：会建立外部数据库连接）")]
    async fn dosword_db_probe(
        &self,
        Parameters(args): Parameters<DbArgs>,
    ) -> Result<CallToolResult, McpError> {
        let connection = match to_connection(&args.connection) {
            Ok(connection) => connection,
            Err(error) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(error)]));
            }
        };
        let summary = format!(
            "session={} driver={} host={}",
            args.session_id,
            connection.driver,
            connection.host.clone().unwrap_or_default()
        );
        let guard = match Guard::begin(&self.app, "dosword_db_probe", Tier::Write, summary).await {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result = crate::commands::db_probe(args.session_id, connection, app).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(
        description = "在目标机执行 SQL（SELECT/SHOW/EXPLAIN 属只读级，其余语句属写入级）"
    )]
    async fn dosword_db_query(
        &self,
        Parameters(args): Parameters<DbQueryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let connection = match to_connection(&args.connection) {
            Ok(connection) => connection,
            Err(error) => {
                return Ok(CallToolResult::error(vec![ContentBlock::text(error)]));
            }
        };
        let tier = classify_sql(&args.sql);
        let sql_preview: String = args.sql.chars().take(120).collect();
        let summary = format!("session={} sql={}", args.session_id, sql_preview);
        let guard = match Guard::begin(&self.app, "dosword_db_query", tier, summary).await {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result = crate::commands::db_query(args.session_id, connection, args.sql, app).await;
        Ok(guard.run(async { result }).await)
    }

    // ---- 执行 ----

    #[rmcp::tool(description = "在目标机执行 Shell 命令（执行级：默认需要人工在 GUI 中确认）")]
    async fn dosword_exec(
        &self,
        Parameters(args): Parameters<ExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let command_preview: String = args.command.chars().take(120).collect();
        let summary = format!("session={} cmd={}", args.session_id, command_preview);
        let guard = match Guard::begin(&self.app, "dosword_exec", Tier::Exec, summary).await {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result = crate::commands::execute_command(args.session_id, args.command, app).await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(description = "运行功能插件（执行级：插件可能执行任意代码，默认需要人工确认）")]
    async fn dosword_plugin_run(
        &self,
        Parameters(args): Parameters<PluginArgs>,
    ) -> Result<CallToolResult, McpError> {
        let params_preview = truncate_text(&args.params.to_string()).0;
        let summary = format!(
            "session={} plugin={} params={}",
            args.session_id, args.plugin_id, params_preview
        );
        let guard = match Guard::begin(&self.app, "dosword_plugin_run", Tier::Exec, summary).await {
            Ok(guard) => guard,
            Err(denied) => return Ok(denied),
        };
        let app = self.app.clone();
        let result =
            crate::commands::run_feature_plugin(args.session_id, args.plugin_id, args.params, app)
                .await;
        Ok(guard.run(async { result }).await)
    }

    #[rmcp::tool(
        description = "生成服务端 stub 载荷（执行级：产出可上传的 webshell，仅用于授权测试）"
    )]
    async fn dosword_generate_stub(
        &self,
        Parameters(args): Parameters<StubArgs>,
    ) -> Result<CallToolResult, McpError> {
        let summary = format!(
            "language={} encoder={} session={}",
            args.language,
            args.encoder_id,
            args.session.unwrap_or(false)
        );
        let guard =
            match Guard::begin(&self.app, "dosword_generate_stub", Tier::Exec, summary).await {
                Ok(guard) => guard,
                Err(denied) => return Ok(denied),
            };
        let app = self.app.clone();
        let result = crate::commands::generate_shell(
            args.language,
            args.encoder_id,
            args.password,
            args.session.unwrap_or(false),
            app,
        )
        .await;
        Ok(guard.run(async { result }).await)
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ShellIdArgs {
    /// 已登记的 Shell id（见 `dosword_shells_list`）
    pub shell_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回归：工具表由宏生成，漏注册/重名都不会编译报错——必须显式断言。
    #[test]
    fn tool_registry_is_complete_and_unique() {
        let tools = super::super::DoswordMcp::tool_router().list_all();
        let mut names: Vec<String> = tools.iter().map(|tool| tool.name.to_string()).collect();
        names.sort();

        let total = names.len();
        names.dedup();
        assert_eq!(total, names.len(), "工具名必须唯一");

        for expected in [
            "dosword_workspaces_list",
            "dosword_shells_list",
            "dosword_sessions_list",
            "dosword_probe_session",
            "dosword_settings_get",
            "dosword_protocols_list",
            "dosword_plugins_list",
            "dosword_encoders_list",
            "dosword_audit_query",
            "dosword_fs_list",
            "dosword_fs_read",
            "dosword_shell_connect",
            "dosword_shell_disconnect",
            "dosword_fs_write",
            "dosword_fs_mkdir",
            "dosword_fs_rename",
            "dosword_fs_delete",
            "dosword_fs_touch",
            "dosword_db_probe",
            "dosword_db_query",
            "dosword_exec",
            "dosword_plugin_run",
            "dosword_generate_stub",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "缺少工具 {expected}（已注册：{names:?}）"
            );
        }
        assert_eq!(tool_count(), total, "tool_count 应与路由表一致");
    }
    #[test]
    fn sql_classifier_treats_reads_as_read() {
        for sql in [
            "SELECT * FROM users",
            "  select 1",
            "SHOW TABLES",
            "EXPLAIN SELECT 1",
            "DESCRIBE users",
            "PRAGMA table_info(users)",
            "SELECT 1;",
        ] {
            assert_eq!(classify_sql(sql), Tier::Read, "{sql} 应判为只读");
        }
    }

    #[test]
    fn sql_classifier_treats_writes_and_multi_statement_as_write() {
        for sql in [
            "INSERT INTO users VALUES (1)",
            "UPDATE users SET a=1",
            "DELETE FROM users",
            "DROP TABLE users",
            "SELECT 1; DROP TABLE users",
            "select * from a; delete from b",
            "WITH x AS (SELECT 1) SELECT * FROM x",
        ] {
            assert_eq!(classify_sql(sql), Tier::Write, "{sql} 应判为写入");
        }
    }

    #[test]
    fn tier_gate_reads_settings_flags() {
        let settings = AppSettings::default();
        assert!(Tier::Read.enabled(&settings), "只读默认开启");
        assert!(!Tier::Write.enabled(&settings), "写入默认关闭");
        assert!(!Tier::Exec.enabled(&settings), "执行默认关闭");

        let all_on = AppSettings {
            mcp_tier_write: true,
            mcp_tier_exec: true,
            ..AppSettings::default()
        };
        assert!(Tier::Write.enabled(&all_on));
        assert!(Tier::Exec.enabled(&all_on));
    }
}
