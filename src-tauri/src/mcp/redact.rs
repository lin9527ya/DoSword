//! MCP 输出脱敏与裁剪。
//!
//! 这里是「不把凭据交给模型」的最后一道闸门：`dashboard()` / `list_shells()`
//! 返回的 `ShellProfile` **带明文密码**，`AppSettings` **带 MCP 令牌**，
//! 任何直接透传都会让令牌/密码进入模型上下文与客户端日志。

use dosword_sdk::domain::{AppSettings, ShellProfile};

/// 单次工具结果的文本上限（字符安全截断）
pub const MAX_TEXT_BYTES: usize = 256 * 1024;

/// 面向 AI 客户端的 Shell 摘要：**不含密码**。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellSummary {
    pub id: String,
    pub workspace_id: String,
    pub name: String,
    pub endpoint: String,
    pub runtime: String,
    pub protocol_id: String,
    pub status: String,
    pub last_connected_at: Option<String>,
    pub tags: Vec<String>,
    /// 是否已配置连接密码（只暴露「有没有」，不暴露内容）
    pub has_password: bool,
}

impl From<&ShellProfile> for ShellSummary {
    fn from(profile: &ShellProfile) -> Self {
        Self {
            id: profile.id.clone(),
            workspace_id: profile.workspace_id.clone(),
            name: profile.name.clone(),
            endpoint: profile.endpoint.clone(),
            runtime: profile.runtime.clone(),
            protocol_id: profile.protocol_id.clone(),
            status: profile.status.clone(),
            last_connected_at: profile.last_connected_at.clone(),
            tags: profile.tags.clone(),
            has_password: !profile.password.is_empty(),
        }
    }
}

/// 面向 AI 客户端的设置视图：清空令牌、掩码代理地址（可能含账号密码）。
pub fn redact_settings(settings: &AppSettings) -> serde_json::Value {
    let mut value = serde_json::to_value(settings).unwrap_or(serde_json::Value::Null);
    if let Some(object) = value.as_object_mut() {
        object.insert("mcpToken".to_string(), serde_json::json!(""));
        let has_proxy = object
            .get("proxy")
            .map(|proxy| !proxy.is_null())
            .unwrap_or(false);
        if has_proxy {
            object.insert("proxy".to_string(), serde_json::json!("已配置（已脱敏）"));
        }
    }
    value
}

/// 按字符边界截断到 `MAX_TEXT_BYTES`，返回（内容, 是否被截断）。
pub fn truncate_text(text: &str) -> (String, bool) {
    if text.len() <= MAX_TEXT_BYTES {
        return (text.to_string(), false);
    }
    let mut out = String::with_capacity(MAX_TEXT_BYTES + 64);
    for character in text.chars() {
        if out.len() + character.len_utf8() > MAX_TEXT_BYTES {
            break;
        }
        out.push(character);
    }
    out.push_str(&format!("\n…（已截断，原文 {} 字节）", text.len()));
    (out, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_with_password(password: &str) -> ShellProfile {
        ShellProfile {
            id: "shell-1".into(),
            workspace_id: "ws-1".into(),
            name: "测试目标".into(),
            endpoint: "http://192.0.2.10/shell.php".into(),
            runtime: "php".into(),
            protocol_id: "builtin.php.v1".into(),
            password: password.to_string(),
            protocol_params: String::new(),
            authorization_ack: true,
            status: "unknown".into(),
            last_connected_at: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            tags: vec!["lab".into()],
        }
    }

    #[test]
    fn shell_summary_never_contains_password() {
        let profile = profile_with_password("S3CRET-PW");
        let summary = ShellSummary::from(&profile);
        let json = serde_json::to_string(&summary).expect("序列化");
        assert!(!json.contains("S3CRET-PW"), "摘要不得包含密码：{json}");
        assert!(!json.contains("\"password\""), "摘要不得包含 password 字段");
        assert!(summary.has_password, "应通过 hasPassword 暴露「已配置」");
        assert!(json.contains("\"hasPassword\":true"));
    }

    #[test]
    fn redacted_settings_hides_token_and_proxy_credentials() {
        let settings = AppSettings {
            mcp_token: "deadbeefdeadbeef".into(),
            proxy: Some("http://user:pass@127.0.0.1:8080".into()),
            ..AppSettings::default()
        };
        let value = redact_settings(&settings);
        let json = serde_json::to_string(&value).expect("序列化");
        assert!(!json.contains("deadbeef"), "不得泄漏 MCP 令牌：{json}");
        assert!(!json.contains("user:pass"), "不得泄漏代理凭据：{json}");
        assert!(json.contains("已脱敏"), "应标明代理已脱敏");
    }

    #[test]
    fn truncate_is_char_safe_and_marks_truncation() {
        // 构造超过上限的中文文本：每个字符 3 字节，直接按字节切会 panic
        let text = "中".repeat(MAX_TEXT_BYTES / 3 + 10);
        let (out, truncated) = truncate_text(&text);
        assert!(truncated);
        assert!(out.len() <= MAX_TEXT_BYTES + 64, "截断后长度应受控");
        assert!(out.contains("已截断"));
        // 未被截断时原样返回
        let (same, flag) = truncate_text("短文本");
        assert!(!flag);
        assert_eq!(same, "短文本");
    }
}
