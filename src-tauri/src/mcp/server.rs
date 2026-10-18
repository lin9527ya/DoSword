//! MCP 服务器实现（rmcp 3.x）。
//!
//! P0 只提供协议骨架：`initialize` / `tools/list`（空）+ 健康检查 + 鉴权 + 优雅停机。
//! 工具在 P1 起按 read / write / exec 三级逐步接入（见 `tools/`）。

use std::sync::Arc;

use dosword_sdk::domain::AppSettings;
use rmcp::ServerHandler;
use rmcp::model::{ServerCapabilities, ServerConfig};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::tower::{
    StreamableHttpServerConfig, StreamableHttpService,
};
use tauri::AppHandle;
use tokio_util::sync::CancellationToken;

use super::auth::TokenState;

/// 请求体上限：MCP 只承载 JSON 指令，1 MiB 足够；二进制内容一律走 base64 分块参数。
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// 当前暴露的工具数量（P0 为 0，P1 起与工具路由表保持一致）。
pub fn tool_count() -> usize {
    0
}

/// DoSword 的 MCP 服务器。
///
/// 只持有 `AppHandle`：每次工具调用都通过它取得 `AppState`，与 Tauri 命令共享
/// 同一份数据库 / 会话 / 审计状态，避免出现第二套真相。
#[derive(Clone)]
pub struct DoswordMcp {
    /// P1 工具层通过它取得 AppState（P0 仅持有）。
    #[allow(dead_code)]
    app: AppHandle,
}

impl DoswordMcp {
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }

    /// 供工具实现取用应用状态（P1 起使用）。
    #[allow(dead_code)]
    pub fn app(&self) -> &AppHandle {
        &self.app
    }
}

impl ServerHandler for DoswordMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}

/// 构建 Streamable HTTP 传输服务。
pub fn build_service(
    app: AppHandle,
    cancel: CancellationToken,
    _settings: &AppSettings,
) -> StreamableHttpService<DoswordMcp, LocalSessionManager> {
    // `StreamableHttpServerConfig` 是 #[non_exhaustive]：只能先取默认值再改字段
    let mut config = StreamableHttpServerConfig::default();
    config.cancellation_token = cancel;
    // 纯请求-响应式工具：优先返回 application/json，客户端实现更省事
    config.json_response = true;
    config.max_request_body_bytes = MAX_REQUEST_BODY_BYTES;
    StreamableHttpService::new(
        move || Ok(DoswordMcp::new(app.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    )
}

/// 组装 HTTP 路由：`/mcp` 需鉴权，`/healthz` 无需（仅用于本机探活，无数据）。
pub fn router(
    service: StreamableHttpService<DoswordMcp, LocalSessionManager>,
    tokens: TokenState,
) -> axum::Router {
    let protected = axum::Router::new().nest_service("/mcp", service).layer(
        axum::middleware::from_fn_with_state(tokens, super::auth::require_bearer),
    );

    axum::Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .merge(protected)
}

async fn healthz() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "ok": true, "app": "dosword" }))
}
