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
/// 性能注意（P1）：先对载荷 / 响应做截断，再执行密码脱敏替换——
/// 避免对整块（最大 4MB+ base64）字符串做全量 replace 与分配。
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
    // 载荷脱敏：密码字面量替换为 ***（密码为空时跳过，避免 replace("") 异常）
    let payload = if password.is_empty() {
        truncate(code)
    } else {
        truncate(code).replace(password, "***")
    };
    let mut record = RequestRecord {
        id: REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed),
        protocol_id: protocol_id.to_string(),
        endpoint: endpoint.to_string(),
        action: action.to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        status,
        duration_ms,
        payload,
        response: truncate(response),
    };
    // 响应里可能残留明文密码（如 AUTH_FAIL 回显外的场景），一并脱敏
    record.response = if password.is_empty() {
        record.response
    } else {
        record.response.replace(password, "***")
    };
    let mut log = REQUEST_LOG.lock();
    if log.len() >= DEBUG_LOG_CAP {
        log.pop_front();
    }
    log.push_back(record);
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
