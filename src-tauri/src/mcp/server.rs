//! MCP 服务器实现（rmcp 3.x）。
//!
//! 传输：Streamable HTTP（本地回环）。工具定义在 `tools.rs`，本文件只负责
//! 服务器身份、能力声明与服务装配。

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

/// 请求体上限：MCP 只承载 JSON 指令，1 MiB 足够；文件内容一律走 Base64 分块参数。
const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// DoSword 的 MCP 服务器。
///
/// 只持有 `AppHandle`：每次工具调用都通过它取得 `AppState`，与 Tauri 命令共享
/// 同一份数据库 / 会话 / 审计状态，避免出现第二套真相。
#[derive(Clone)]
pub struct DoswordMcp {
    pub(crate) app: AppHandle,
}

#[rmcp::tool_handler]
impl ServerHandler for DoswordMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, rmcp::model::ErrorData> {
        Ok(rmcp::model::ListResourcesResult::with_all_items(
            super::resources::list_resources(),
        ))
    }

    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResponse, rmcp::model::ErrorData> {
        match super::resources::read_resource(&self.app, &request.uri) {
            Ok(contents) => Ok(rmcp::model::ReadResourceResult::new(contents).into()),
            Err(message) => Err(rmcp::model::ErrorData::resource_not_found(
                message,
                Some(serde_json::json!({ "uri": request.uri })),
            )),
        }
    }

    async fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::ListPromptsResult, rmcp::model::ErrorData> {
        Ok(rmcp::model::ListPromptsResult::with_all_items(
            super::resources::list_prompts(),
        ))
    }

    async fn get_prompt(
        &self,
        request: rmcp::model::GetPromptRequestParams,
        _context: rmcp::service::RequestContext<rmcp::service::RoleServer>,
    ) -> Result<rmcp::model::GetPromptResponse, rmcp::model::ErrorData> {
        match super::resources::get_prompt(&request.name) {
            Some(messages) => Ok(rmcp::model::GetPromptResult::new(messages).into()),
            None => Err(rmcp::model::ErrorData::invalid_params(
                format!("未知提示词：{}", request.name),
                None,
            )),
        }
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
