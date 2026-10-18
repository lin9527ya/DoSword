//! MCP（Model Context Protocol）服务端。
//!
//! 设计要点：
//! - 只绑定 `127.0.0.1`，使用 Streamable HTTP 传输（rmcp 3.x）；Host 校验由 rmcp
//!   内建（`allowed_hosts` 默认仅回环），防 DNS rebinding。
//! - 总开关默认关闭；`Authorization: Bearer <token>` 鉴权；能力按
//!   read / write / exec 三级授权（只读默认开）。
//! - 每次工具调用写审计（`mcp.<tool>`）并进内存环形缓冲，供设置页展示。
//! - 不提供任何改写授权登记表（Workspace / Shell 增删改）的工具：
//!   授权范围只能由人在 GUI 里维护。
//!
//! 该模块由 cargo feature `mcp` 控制编译（默认开启）。

mod auth;
mod server;

use std::collections::VecDeque;
use std::sync::Mutex;

use dosword_sdk::domain::{AppSettings, McpCallRecord, McpStatus};
use tauri::{AppHandle, Manager};
use tokio_util::sync::CancellationToken;

/// 「最近调用」环形缓冲容量。
/// P1 起由工具层写入；P0 仅有测试使用，故允许未使用。
#[allow(dead_code)]
const LOG_CAPACITY: usize = 200;

struct Runtime {
    port: u16,
    started_at: u64,
    cancel: CancellationToken,
}

/// MCP 运行状态（Tauri managed state）。
#[derive(Default)]
pub struct McpState {
    runtime: Mutex<Option<Runtime>>,
    log: Mutex<VecDeque<McpCallRecord>>,
    last_error: Mutex<Option<String>>,
}

impl McpState {
    pub fn new() -> Self {
        Self::default()
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
            tool_count: server::tool_count() as u32,
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

    /// 写入一条调用记录（P1 工具层调用）。
    #[allow(dead_code)]
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
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b, "连续两次生成的令牌不应相同");
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
        // 最新的三条，按时间升序
        assert_eq!(recent[0].tool, format!("t{}", LOG_CAPACITY + 2));
        assert_eq!(recent[2].tool, format!("t{}", LOG_CAPACITY + 4));
    }

    #[test]
    fn status_without_runtime_is_stopped() {
        let state = McpState::new();
        let status = state.status();
        assert!(!status.running);
        assert!(status.port.is_none());
        assert!(status.endpoint.is_none());
    }
}
