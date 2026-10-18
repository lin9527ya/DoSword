//! 请求调试：进程内环缓冲，记录各协议帧（载荷 / 响应），供「请求调试」页查看。
//!
//! 仅调试用途，不落盘；密码在载荷预览中脱敏。PHP 与 JSP/ASP/Python/Node
//! 等所有真实网络协议统一经此模块记录（A1：JSP 系列协议此前不入日志）。

use std::collections::VecDeque;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

use dosword_sdk::domain::RequestRecord;

/// 载荷 / 响应预览截断长度。
const DEBUG_PREVIEW_LEN: usize = 2048;
/// 环缓冲容量。
const DEBUG_LOG_CAP: usize = 200;

static REQUEST_LOG: LazyLock<parking_lot::Mutex<VecDeque<RequestRecord>>> =
    LazyLock::new(|| parking_lot::Mutex::new(VecDeque::with_capacity(DEBUG_LOG_CAP)));
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 记录一条协议请求（由各协议通道的发送函数调用）。
///
/// 脱敏说明：载荷/响应中可能同时出现密码的**多种形态**——原始密码、
/// 表单转义形态（`%26`/`%2B`/`%3D`/`%25`）、PHP 单引号转义形态，以及由密码
/// 派生的 16 位令牌（`X-Debug-Key` 与载荷内 `token`）。全部按长串优先替换。
/// 先脱敏再截断：反序会让跨截断点的密钥残留半截。
#[allow(clippy::too_many_arguments)] // 协议帧字段固定，拆结构体反而增加调用方噪声
pub fn record_request(
    protocol_id: &str,
    action: &str,
    endpoint: &str,
    status: u16,
    duration_ms: u64,
    code: &str,
    response: &str,
    password: &str,
) {
    let secrets = secret_variants(password);
    let mut record = RequestRecord {
        id: REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed),
        protocol_id: protocol_id.to_string(),
        endpoint: endpoint.to_string(),
        action: action.to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        status,
        duration_ms,
        payload: truncate(&redact(code, &secrets)),
        response: truncate(&redact(response, &secrets)),
    };
    record.action = record.action.replace('\n', " ");
    let mut log = REQUEST_LOG.lock();
    if log.len() >= DEBUG_LOG_CAP {
        log.pop_front();
    }
    log.push_back(record);
}

/// 需要脱敏的密文变体（长串优先，避免短变体先命中留下残片）。
fn secret_variants(password: &str) -> Vec<String> {
    if password.is_empty() {
        return Vec::new();
    }
    let mut variants = vec![
        password.to_string(),
        super::transport::form_escape(password),
        super::transport::php_single_quote(password),
    ];
    // 派生令牌：md5(密码) 前 16 位（头鉴权与分阶段载荷内 token 同值）
    let digest = dosword_sdk::encoder::md5_hex(password);
    if digest.len() >= 16 {
        variants.push(digest[..16].to_string());
    }
    variants.sort_by_key(|value| std::cmp::Reverse(value.len()));
    variants.dedup();
    variants
}

fn redact(value: &str, secrets: &[String]) -> String {
    let mut out = value.to_string();
    for secret in secrets {
        out = out.replace(secret.as_str(), "***");
    }
    out
}

fn truncate(value: &str) -> String {
    let mut chars = value.chars();
    let head: String = chars.by_ref().take(DEBUG_PREVIEW_LEN).collect();
    if chars.next().is_some() {
        format!("{head}\n…（已截断）")
    } else {
        head
    }
}

/// 列出请求记录（可选按端点 / 协议过滤），新记录在前。
pub fn list_requests(endpoint: Option<&str>, protocol: Option<&str>) -> Vec<RequestRecord> {
    let log = REQUEST_LOG.lock();
    log.iter()
        .rev()
        .filter(|record| endpoint.is_none_or(|target| record.endpoint == target))
        .filter(|record| protocol.is_none_or(|target| record.protocol_id == target))
        .cloned()
        .collect()
}

/// 清空请求记录。
pub fn clear_requests() {
    REQUEST_LOG.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 回归：脱敏必须覆盖密码的各种转义形态与派生令牌，且先脱敏后截断。
    #[test]
    fn redaction_covers_escaped_forms_and_derived_token() {
        let password = "pa%26ss=1+";
        let token = &dosword_sdk::encoder::md5_hex(password)[..16];
        let escaped = super::super::transport::form_escape(password);
        let quoted = super::super::transport::php_single_quote(password);
        assert_ne!(escaped, password, "该密码应存在转义形态差异");
        let code = format!("pass={password}&token={token}&q={quoted}&k={escaped}");
        let variants = secret_variants(password);

        let redacted = redact(&code, &variants);
        assert!(!redacted.contains(password), "原始密码不应残留：{redacted}");
        assert!(!redacted.contains(token), "派生令牌不应残留：{redacted}");
        assert!(!redacted.contains(&escaped), "转义形态不应残留：{redacted}");
        assert!(
            !redacted.contains(&quoted),
            "引号转义形态不应残留：{redacted}"
        );
        assert!(redacted.contains("***"));

        // 空密码不应产生任何变体（避免 replace("") 异常）
        assert!(secret_variants("").is_empty());
    }

    /// 截断按字符（不是字节），且不会把多字节字符切成半个。
    #[test]
    fn truncate_is_char_safe() {
        let long = "中".repeat(DEBUG_PREVIEW_LEN + 10);
        let out = truncate(&long);
        assert!(out.ends_with("…（已截断）"));
        // 2048 字符 + 换行 + "…（已截断）"
        assert_eq!(out.chars().count(), DEBUG_PREVIEW_LEN + 1 + 6);
    }
}
