//! MCP 访问控制：Bearer 令牌鉴权。
//!
//! 传输层只监听回环地址，且 rmcp 的 `allowed_hosts` 默认仅接受
//! `localhost` / `127.0.0.1` / `::1`（防 DNS rebinding）。此处再叠加令牌，
//! 使「本机其它进程」也无法直接驱动 DoSword。

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// 持有期望令牌，供中间件比对。
#[derive(Clone)]
pub struct TokenState(Arc<str>);

impl TokenState {
    pub fn new(token: String) -> Self {
        Self(Arc::from(token))
    }

    pub fn matches(&self, candidate: &str) -> bool {
        constant_time_eq(self.0.as_bytes(), candidate.as_bytes())
    }
}

/// 常量时间字符串比较：避免按字节提前返回造成的时序侧信道。
///
/// 长度不同时直接返回（令牌长度固定为 64 字符，本身不是秘密）。
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Bearer 鉴权中间件。缺失与错误一律返回 401，不区分原因。
pub async fn require_bearer(
    State(tokens): State<TokenState>,
    request: Request,
    next: Next,
) -> Response {
    let candidate = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");

    if candidate.is_empty() || !tokens.matches(candidate) {
        let mut response = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return response;
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_only_identical_bytes() {
        assert!(constant_time_eq(b"abc123", b"abc123"));
        assert!(!constant_time_eq(b"abc123", b"abc124"));
        assert!(!constant_time_eq(b"abc123", b"abc12"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn token_state_accepts_exact_token_only() {
        let state = TokenState::new("deadbeef".to_string());
        assert!(state.matches("deadbeef"));
        assert!(!state.matches("deadbeee"));
        assert!(!state.matches("deadbeef "));
        assert!(!state.matches(""));
        assert!(!state.matches("DEADBEEF"));
    }
}
