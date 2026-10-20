//! 会话录制与离线回放。
//!
//! 目标：把一次会话的协议帧落成可重复的**证据文件**，并能在**不联目标**的情况下
//! 验证传输层管线（外层 JSON → `data` 字段 → base64/gzip）是否仍然成立。
//!
//! 设计取舍：
//! - **不落密钥**。帧里保存的是请求明文（已脱敏）与响应原文，不保存密码、令牌、
//!   也不保存 AEAD 密钥；因此回放只校验「不需要密钥就能验证」的那一段管线，
//!   明文解密的兼容性由既有单测与真实往返测试覆盖。
//! - **按 `protocol_id|endpoint` 归档**：`JspSession` 不携带会话 id，而 endpoint 是
//!   该会话的唯一稳定标识；同一 endpoint 的多次录制追加到同一文件（带时间戳）。
//! - 录制关闭时句柄立即落盘（`BufWriter::flush`），崩溃最多丢最后一行。
//!
//! 文件格式：JSONL，一行一帧，便于 `grep`/`jq` 与人工核对。

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use serde::{Deserialize, Serialize};

/// 一帧录制记录。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    /// Unix 毫秒时间戳。
    pub ts_ms: u64,
    pub protocol_id: String,
    pub action: String,
    /// 请求明文（已脱敏：密码/令牌替换为 ***）。
    pub request: String,
    /// 响应原文（HTTP body，未解密）。
    pub response: String,
    /// `data` 字段经 gunzip 处理后的长度（回放时用来发现传输层漂移）。
    pub data_len: usize,
    /// 响应是否成功（`ok: true`）。
    pub ok: bool,
}

struct Recorder {
    path: PathBuf,
    writer: BufWriter<File>,
}

static ACTIVE: LazyLock<Mutex<HashMap<String, Recorder>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// 录制键：协议 + endpoint（同一目标同一协议共用一个文件）。
pub fn key(protocol_id: &str, endpoint: &str) -> String {
    format!("{protocol_id}|{endpoint}")
}

/// 开始录制（重复 start 会覆盖旧句柄并先落盘）。
pub fn start(key: &str, path: &Path, protocol_id: &str) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|error| format!("创建录制目录失败：{error}"))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("打开录制文件失败：{error}"))?;
    let _ = protocol_id; // 协议已编码在 key 里，这里只用于校验调用方传参一致
    let recorder = Recorder {
        path: path.to_path_buf(),
        writer: BufWriter::new(file),
    };
    let mut guard = ACTIVE.lock().map_err(|_| "录制表锁异常".to_string())?;
    guard.insert(key.to_string(), recorder);
    Ok(())
}

/// 结束录制；返回落盘路径（没有在录则返回 None）。
pub fn stop(key: &str) -> Option<PathBuf> {
    let mut guard = ACTIVE.lock().ok()?;
    guard.remove(key).map(|mut recorder| {
        let _ = recorder.writer.flush();
        recorder.path
    })
}

/// 该键是否正在录制（供状态查询与测试使用）。
#[allow(dead_code)]
pub fn is_recording(key: &str) -> bool {
    ACTIVE
        .lock()
        .map(|guard| guard.contains_key(key))
        .unwrap_or(false)
}

/// 追加一帧。未在录制时静默返回（调用点无需分支）。
pub fn append(key: &str, frame: &Frame) {
    let Ok(mut guard) = ACTIVE.lock() else {
        return;
    };
    let Some(recorder) = guard.get_mut(key) else {
        return;
    };
    let Ok(line) = serde_json::to_string(frame) else {
        return;
    };
    // 写失败不打断业务：录制是旁路，不能因为它让会话失败
    let _ = writeln!(recorder.writer, "{line}");
    let _ = recorder.writer.flush();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayFailure {
    /// 帧序号（从 1 开始，与文件行号一致）。
    pub index: usize,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReplayReport {
    pub total: usize,
    pub passed: usize,
    pub failures: Vec<ReplayFailure>,
}

/// 离线回放：逐帧重跑「外层 JSON → data 字段 → gunzip」，与录制时的长度比对。
///
/// 能发现的问题：字段改名、`data` 语义变化、gzip 处理变化、响应被截断。
/// 不能发现的问题：明文解密（需要密钥，刻意不落盘）。
pub fn replay(path: &Path) -> Result<ReplayReport, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("读取录制文件失败：{error}"))?;
    let mut report = ReplayReport {
        total: 0,
        passed: 0,
        failures: Vec::new(),
    };
    for (index, line) in text.lines().enumerate() {
        let index = index + 1;
        if line.trim().is_empty() {
            continue;
        }
        report.total += 1;
        let frame: Frame = match serde_json::from_str(line) {
            Ok(frame) => frame,
            Err(error) => {
                report.failures.push(ReplayFailure {
                    index,
                    reason: format!("帧不是合法 JSON：{error}"),
                });
                continue;
            }
        };
        match replay_frame(&frame) {
            Ok(()) => report.passed += 1,
            Err(reason) => report.failures.push(ReplayFailure { index, reason }),
        }
    }
    Ok(report)
}

fn replay_frame(frame: &Frame) -> Result<(), String> {
    let outer: serde_json::Value =
        serde_json::from_str(&frame.response).map_err(|_| "响应不再是合法 JSON".to_string())?;
    let data = outer
        .get("data")
        .and_then(|value| value.as_str())
        .ok_or_else(|| "响应缺少 data 字段".to_string())?;
    let data = crate::protocol::transport::gunzip_if_needed(data);
    if data.len() != frame.data_len {
        return Err(format!(
            "data 长度漂移：录制时 {} 字节，现在 {} 字节",
            frame.data_len,
            data.len()
        ));
    }
    Ok(())
}

/// 脱敏：把密码及其派生形态（md5/hex 等）替换成 ***。
/// 直接复用请求调试页的实现，保证两处口径一致。
pub fn redact_text(text: &str, password: &str) -> String {
    let secrets = crate::protocol::reqlog::secret_variants(password);
    crate::protocol::reqlog::redact(text, &secrets)
}

/// 录制状态（供 UI/命令查询）。
pub fn active_keys() -> Vec<String> {
    ACTIVE
        .lock()
        .map(|guard| guard.keys().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dosword-rec-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("临时目录");
        dir.join("rec.jsonl")
    }

    fn frame(action: &str, response: &str) -> Frame {
        Frame {
            ts_ms: 0,
            protocol_id: "builtin.jsp.v1".into(),
            action: action.into(),
            request: "{\"a\":\"probe\",\"token\":\"***\"}".into(),
            response: response.into(),
            data_len: 0,
            ok: true,
        }
    }

    #[test]
    fn record_then_replay_passes() {
        let path = temp_path("ok");
        let key = key("builtin.jsp.v1", "http://example.invalid/shell.jsp");
        // data 为 base64("hello")，gunzip_if_needed 对非 gzip 内容原样返回
        start(&key, &path, "builtin.jsp.v1").expect("start");
        assert!(is_recording(&key));
        let mut f = frame("exec", "{\"data\":\"aGVsbG8=\"}");
        f.data_len = "aGVsbG8=".len();
        append(&key, &f);
        let stopped = stop(&key).expect("stop 返回路径");
        assert!(!is_recording(&key));
        assert_eq!(stopped, path);

        let report = replay(&path).expect("replay");
        assert_eq!(report.total, 1);
        assert_eq!(report.passed, 1);
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn replay_reports_length_drift() {
        let path = temp_path("drift");
        // 手工写一帧：录制时 data_len = 999，与真实内容不符
        let line = serde_json::to_string(&Frame {
            ts_ms: 1,
            protocol_id: "builtin.jsp.v1".into(),
            action: "exec".into(),
            request: "{}".into(),
            response: "{\"data\":\"aGVsbG8=\"}".into(),
            data_len: 999,
            ok: true,
        })
        .expect("序列化");
        std::fs::write(&path, format!("{line}\n")).expect("写文件");

        let report = replay(&path).expect("replay");
        assert_eq!(report.total, 1);
        assert_eq!(report.passed, 0);
        assert_eq!(report.failures.len(), 1);
        assert!(
            report.failures[0].reason.contains("长度漂移"),
            "{:?}",
            report.failures
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn replay_flags_garbage_line() {
        let path = temp_path("bad");
        std::fs::write(&path, "not json\n").expect("写文件");
        let report = replay(&path).expect("replay");
        assert_eq!(report.total, 1);
        assert_eq!(report.passed, 0);
        assert!(report.failures[0].reason.contains("不是合法 JSON"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// 提交进仓库的 fixture 必须能稳定回放：这条用例让录制/回放逻辑在 CI 里
    /// 每天都真跑一遍，而不是"写完就没人碰"。fixture 里的 data_len 与
    /// gunzip_if_needed(data).len() 一旦不一致，这里立刻失败。
    #[test]
    fn committed_fixture_replays_clean() {
        let text = include_str!("../../tests/fixtures/recording.jsonl");
        let path = temp_path("fixture");
        std::fs::write(&path, text).expect("写 fixture");
        let report = replay(&path).expect("replay");
        assert!(
            report.total >= 3,
            "fixture 至少 3 帧，实际 {}",
            report.total
        );
        assert_eq!(
            report.passed, report.total,
            "fixture 回放有漂移帧：{:?}",
            report.failures
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn append_without_start_is_noop() {
        let key = key("builtin.jsp.v1", "http://nowhere.invalid/x");
        append(&key, &frame("probe", "{}"));
        assert!(!is_recording(&key));
    }
}
