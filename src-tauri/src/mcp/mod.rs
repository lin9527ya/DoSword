//! MCP（Model Context Protocol）服务端。
//!
//! 设计要点：
//! - 只绑定 `127.0.0.1`，使用 Streamable HTTP 传输（rmcp 3.x）；Host 校验由 rmcp
//!   内建（`allowed_hosts` 默认仅回环），防 DNS rebinding。
//! - 总开关默认关闭；`Authorization: Bearer <token>` 鉴权；能力按
//!   read / write / exec 三级授权（只读默认开）。
//! - exec 级默认要求**人工确认**：工具返回待批准 id，人在设置页批准后
//!   120 秒内重试才生效（一次性消费）。
//! - 每次工具调用写审计（`mcp.<tool>`）并进内存环形缓冲，供设置页展示。
//! - 不提供任何改写授权登记表（Workspace / Shell 增删改）的工具：
//!   授权范围只能由人在 GUI 里维护。
//!
//! 该模块由 cargo feature `mcp` 控制编译（默认开启）。

pub mod auth;
pub mod redact;
mod server;
mod tools;

pub(crate) use server::DoswordMcp;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dosword_sdk::domain::{AppSettings, McpCallRecord, McpPendingApproval, McpStatus};
use tauri::{AppHandle, Manager};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

/// 「最近调用」环形缓冲容量
pub const LOG_CAPACITY: usize = 200;
/// 待批准请求的有效期：超时后需重新发起
pub const APPROVAL_TTL: Duration = Duration::from_secs(120);
/// 同时执行的工具调用上限
pub const MAX_CONCURRENCY: usize = 4;

struct Runtime {
    port: u16,
    started_at: u64,
    cancel: CancellationToken,
}

struct PendingApproval {
    tool: String,
    summary: String,
    requested_at: Instant,
}

#[derive(Default)]
struct Approvals {
    /// 待人工确认：id → 请求
    pending: HashMap<String, PendingApproval>,
    /// 已批准：`tool|summary` → 批准时间（一次性消费）
    approved: HashMap<String, Instant>,
}

/// MCP 运行状态（Tauri managed state）。
pub struct McpState {
    runtime: Mutex<Option<Runtime>>,
    log: Mutex<VecDeque<McpCallRecord>>,
    last_error: Mutex<Option<String>>,
    /// 限流：最近一分钟内的调用时刻
    rate: Mutex<VecDeque<Instant>>,
    /// 并发闸门
    slots: Arc<Semaphore>,
    approvals: Mutex<Approvals>,
}

impl Default for McpState {
    fn default() -> Self {
        Self::new()
    }
}

impl McpState {
    pub fn new() -> Self {
        Self {
            runtime: Mutex::new(None),
            log: Mutex::new(VecDeque::new()),
            last_error: Mutex::new(None),
            rate: Mutex::new(VecDeque::new()),
            slots: Arc::new(Semaphore::new(MAX_CONCURRENCY)),
            approvals: Mutex::new(Approvals::default()),
        }
    }

    pub fn is_running(&self) -> bool {
        self.runtime
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    pub fn status(&self) -> McpStatus {
        let (running, port, started_at) = match self
            .runtime
            .lock()
            .ok()
            .as_ref()
            .and_then(|guard| guard.as_ref())
        {
            Some(runtime) => (true, Some(runtime.port), Some(runtime.started_at)),
            None => (false, None, None),
        };
        McpStatus {
            running,
            port,
            endpoint: port.map(|port| format!("http://127.0.0.1:{port}/mcp")),
            tool_count: tools::tool_count() as u32,
            started_at,
            last_error: self.last_error.lock().ok().and_then(|guard| guard.clone()),
        }
    }

    /// 启动服务器（若已在运行则先停止再重启）。
    ///
    /// 绑定失败（端口被占用等）会把原因记录到 `last_error`，供设置页展示。
    pub async fn start(&self, app: AppHandle, settings: &AppSettings) -> Result<u16, String> {
        self.stop();

        if settings.mcp_token.trim().is_empty() {
            let message = "MCP 访问令牌为空：请先轮换令牌再启动".to_string();
            self.set_error(Some(message.clone()));
            return Err(message);
        }

        let port = settings.mcp_port;
        let cancel = CancellationToken::new();
        let service = server::build_service(app.clone(), cancel.clone(), settings);
        let router = server::router(service, auth::TokenState::new(settings.mcp_token.clone()));

        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => listener,
            Err(error) => {
                let message = format!("MCP 端口 {port} 绑定失败：{error}");
                self.set_error(Some(message.clone()));
                return Err(message);
            }
        };

        let shutdown = cancel.clone();
        tauri::async_runtime::spawn(async move {
            let served = axum::serve(listener, router)
                .with_graceful_shutdown(async move { shutdown.cancelled().await })
                .await;
            if let Err(error) = served {
                eprintln!("[mcp] 服务异常退出: {error}");
            }
        });

        if let Ok(mut guard) = self.runtime.lock() {
            *guard = Some(Runtime {
                port,
                started_at: now_unix(),
                cancel,
            });
        }
        self.set_error(None);
        Ok(port)
    }

    pub fn stop(&self) {
        if let Ok(mut guard) = self.runtime.lock()
            && let Some(runtime) = guard.take()
        {
            runtime.cancel.cancel();
        }
    }

    pub fn record(&self, record: McpCallRecord) {
        if let Ok(mut guard) = self.log.lock() {
            if guard.len() >= LOG_CAPACITY {
                guard.pop_front();
            }
            guard.push_back(record);
        }
    }

    pub fn recent(&self, limit: usize) -> Vec<McpCallRecord> {
        let guard = match self.log.lock() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        let mut out: Vec<McpCallRecord> = guard.iter().rev().take(limit).cloned().collect();
        out.reverse();
        out
    }

    pub fn clear_log(&self) {
        if let Ok(mut guard) = self.log.lock() {
            guard.clear();
        }
    }

    pub fn set_error(&self, message: Option<String>) {
        if let Ok(mut guard) = self.last_error.lock() {
            *guard = message;
        }
    }

    // ---- 限流与并发 ----

    /// 滑动窗口限流：每分钟最多 `per_min` 次。超限返回可读错误。
    pub fn check_rate(&self, per_min: u32) -> Result<(), String> {
        let per_min = per_min.max(1) as usize;
        let mut guard = match self.rate.lock() {
            Ok(guard) => guard,
            Err(_) => return Ok(()),
        };
        let now = Instant::now();
        while let Some(front) = guard.front() {
            if now.duration_since(*front) >= Duration::from_secs(60) {
                guard.pop_front();
            } else {
                break;
            }
        }
        if guard.len() >= per_min {
            return Err(format!(
                "调用频率超限（每分钟上限 {per_min} 次）：请降低轮询频率，或在设置中提高上限"
            ));
        }
        guard.push_back(now);
        Ok(())
    }

    /// 取得一个并发槽位（最多 [`MAX_CONCURRENCY`] 个工具调用同时进行）。
    pub async fn acquire_slot(&self) -> Result<OwnedSemaphorePermit, String> {
        Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .map_err(|_| "MCP 并发闸门已关闭".to_string())
    }

    // ---- 执行级人工确认 ----

    /// 登记一个待批准请求，返回批准 id。
    pub fn request_approval(&self, tool: &str, summary: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        if let Ok(mut guard) = self.approvals.lock() {
            prune_approvals(&mut guard);
            guard.pending.insert(
                id.clone(),
                PendingApproval {
                    tool: tool.to_string(),
                    summary: summary.to_string(),
                    requested_at: Instant::now(),
                },
            );
        }
        id
    }

    /// 待批准列表（已过期条目自动清理）。
    pub fn pending_approvals(&self) -> Vec<McpPendingApproval> {
        let mut guard = match self.approvals.lock() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        prune_approvals(&mut guard);
        let mut out: Vec<McpPendingApproval> = guard
            .pending
            .iter()
            .map(|(id, pending)| McpPendingApproval {
                id: id.clone(),
                tool: pending.tool.clone(),
                summary: pending.summary.clone(),
                requested_at: now_unix().saturating_sub(pending.requested_at.elapsed().as_secs()),
            })
            .collect();
        out.sort_by_key(|item| item.requested_at);
        out
    }

    /// 批准或拒绝：返回（被处理的请求是否获批）。
    pub fn resolve_approval(
        &self,
        id: &str,
        approve: bool,
    ) -> Result<(McpPendingApproval, bool), String> {
        let mut guard = self
            .approvals
            .lock()
            .map_err(|_| "审批队列锁异常".to_string())?;
        prune_approvals(&mut guard);
        let pending = guard
            .pending
            .remove(id)
            .ok_or_else(|| "待确认请求不存在或已超时，请让 agent 重新发起".to_string())?;
        if approve {
            guard.approved.insert(
                approval_key(&pending.tool, &pending.summary),
                Instant::now(),
            );
        }
        let record = McpPendingApproval {
            id: id.to_string(),
            tool: pending.tool,
            summary: pending.summary,
            requested_at: now_unix().saturating_sub(pending.requested_at.elapsed().as_secs()),
        };
        Ok((record, approve))
    }

    /// 消费一次批准（一次性）：命中则返回 true 并移除。
    pub fn consume_approval(&self, tool: &str, summary: &str) -> bool {
        let mut guard = match self.approvals.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        prune_approvals(&mut guard);
        guard
            .approved
            .remove(&approval_key(tool, summary))
            .is_some()
    }
}

fn approval_key(tool: &str, summary: &str) -> String {
    format!("{tool}|{summary}")
}

fn prune_approvals(approvals: &mut Approvals) {
    let now = Instant::now();
    approvals
        .pending
        .retain(|_, pending| now.duration_since(pending.requested_at) < APPROVAL_TTL);
    approvals
        .approved
        .retain(|_, approved_at| now.duration_since(*approved_at) < APPROVAL_TTL);
}

/// 应用启动时装配 MCP 状态，并在设置允许的情况下自动拉起服务。
pub fn bootstrap(app: AppHandle) {
    app.manage(McpState::new());

    let settings = {
        let state = app.state::<crate::AppState>();
        match state.database.lock() {
            Ok(database) => database.get_settings().ok(),
            Err(_) => None,
        }
    };

    let Some(settings) = settings else { return };
    if !settings.mcp_enabled || settings.mcp_token.is_empty() {
        return;
    }

    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = handle.state::<McpState>();
        if let Err(error) = state.start(handle.clone(), &settings).await {
            eprintln!("[mcp] 启动失败: {error}");
        }
    });
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// 生成 32 字节随机令牌（64 位十六进制）。
///
/// 与连接密码同等级敏感：仅在设置页展示与拷贝，任何 MCP 工具输出中都不出现。
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    if getrandom::fill(&mut bytes).is_err() {
        // 极端情况（无系统随机源）下的兜底：混入时间与计数器，绝不返回空令牌
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (((nanos >> ((index % 16) * 8)) & 0xff) as u8) ^ (index as u8);
        }
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_64_hex_chars() {
        let token = generate_token();
        assert_eq!(token.len(), 64, "令牌应为 32 字节的十六进制表示");
        assert!(
            token.chars().all(|c| c.is_ascii_hexdigit()),
            "令牌应为十六进制"
        );
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(
            generate_token(),
            generate_token(),
            "连续两次生成的令牌不应相同"
        );
    }

    #[test]
    fn log_is_capped_and_ordered() {
        let state = McpState::new();
        for index in 0..(LOG_CAPACITY + 5) {
            state.record(McpCallRecord {
                at: index as u64,
                tool: format!("t{index}"),
                tier: "read".into(),
                outcome: "success".into(),
                summary: String::new(),
                duration_ms: 0,
            });
        }
        let recent = state.recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].tool, format!("t{}", LOG_CAPACITY + 2));
        assert_eq!(recent[2].tool, format!("t{}", LOG_CAPACITY + 4));
    }

    #[test]
    fn status_without_runtime_is_stopped() {
        let status = McpState::new().status();
        assert!(!status.running);
        assert!(status.port.is_none());
        assert!(status.endpoint.is_none());
    }

    #[test]
    fn rate_limit_rejects_after_quota() {
        let state = McpState::new();
        for _ in 0..3 {
            assert!(state.check_rate(3).is_ok());
        }
        let error = state.check_rate(3).unwrap_err();
        assert!(error.contains("调用频率超限"), "{error}");
    }

    #[test]
    fn approval_is_required_then_one_shot() {
        let state = McpState::new();
        // 未批准 → 消费失败
        assert!(!state.consume_approval("dosword_exec", "ls -la"));

        let id = state.request_approval("dosword_exec", "ls -la");
        let pending = state.pending_approvals();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, id);
        assert_eq!(pending[0].tool, "dosword_exec");

        let (resolved, approved) = state.resolve_approval(&id, true).expect("批准");
        assert!(approved);
        assert_eq!(resolved.summary, "ls -la");
        assert!(state.pending_approvals().is_empty());

        // 批准后放行一次
        assert!(state.consume_approval("dosword_exec", "ls -la"));
        // 一次性：第二次不再放行
        assert!(!state.consume_approval("dosword_exec", "ls -la"));
    }

    #[test]
    fn denied_approval_does_not_authorize() {
        let state = McpState::new();
        let id = state.request_approval("dosword_plugin_run", "{\"id\":\"x\"}");
        let (_, approved) = state.resolve_approval(&id, false).expect("拒绝");
        assert!(!approved);
        assert!(!state.consume_approval("dosword_plugin_run", "{\"id\":\"x\"}"));
    }

    #[test]
    fn resolving_unknown_approval_reports_expired() {
        let state = McpState::new();
        let error = state.resolve_approval("not-a-real-id", true).unwrap_err();
        assert!(error.contains("不存在或已超时"), "{error}");
    }
}
