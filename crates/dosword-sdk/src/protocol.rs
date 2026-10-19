//! 协议抽象层：定义 `Protocol` trait、错误类型与会话状态。
//!
//! 协议方法全部是同步的：网络类命令在 Tauri 侧以阻塞线程池执行，
//! 因此可以自由持有 `std::sync::Mutex` 而不会跨越 await。

use std::any::Any;
use std::fmt;

use crate::domain::{
    AppSettings, CommandOutput, DbConnection, DbProbeResult, DbQueryResult, DirListing,
    ProbeResult, ShellProfile,
};

/// 协议层错误。`Display` 输出面向用户的中文消息，命令层直接 `to_string()`。
#[derive(Debug)]
pub enum ProtocolError {
    /// 连接失败、超时、DNS 等传输层问题。
    Network(String),
    /// HTTP 状态码非 2xx。
    HttpStatus(u16, String),
    /// 鉴权失败（密码错误或响应帧缺失 AUTH 标记）。
    AuthFailed(String),
    /// 响应无法按协议帧解析。
    ParseError(String),
    /// 服务器返回了业务错误（ok=false）。
    ServerError(String),
    /// 会话状态与当前协议不匹配（内部不变式被破坏，非用户操作问题）。
    SessionInvalid(String),
    /// 当前协议不支持该操作。
    NotSupported(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Network(detail) => write!(f, "网络错误：{detail}"),
            ProtocolError::HttpStatus(code, detail) => {
                write!(f, "HTTP 状态异常（{code}）：{detail}")
            }
            ProtocolError::AuthFailed(detail) => write!(f, "鉴权失败：{detail}"),
            ProtocolError::ParseError(detail) => write!(f, "响应解析失败：{detail}"),
            ProtocolError::ServerError(detail) => write!(f, "服务器错误：{detail}"),
            ProtocolError::SessionInvalid(detail) => write!(f, "会话状态无效：{detail}"),
            ProtocolError::NotSupported(detail) => write!(f, "操作不受支持：{detail}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// 批量目录列举结果：`(路径, 该路径的结果)`，单项失败不影响其余。
pub type BatchDirResult = Vec<(String, Result<DirListing, String>)>;

/// 一次成功连接后需要保留的会话状态。具体协议将其向下转型回自身类型。
pub trait SessionState: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
}

/// 协议实例本身无状态（连接态保存在 `SessionState` 中），因此要求 `Send + Sync`。
pub trait Protocol: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    /// 是否会产生真实网络流量（前端下拉与安全门据此判断）。
    fn requires_network(&self) -> bool;

    /// 无副作用地探测端点，返回环境信息。
    fn probe(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<ProbeResult, ProtocolError>;

    /// 建立会话，返回可复用的会话状态与首次环境信息。
    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError>;

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError>;

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError>;

    /// 轻量探活（W4 心跳）：会话空闲时调用，失败即认为目标已掉线。
    ///
    /// 默认实现执行一条无副作用命令（所有协议都有命令通道）；
    /// PHP 覆写为更轻的 probe / legacy 探测模板。心跳**不**更新
    /// 会话的 `last_used_at`（TTL 仍由用户交互决定）。
    fn heartbeat(
        &self,
        session: &dyn SessionState,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        self.execute_command(session, "true", settings).map(|_| ())
    }

    /// 多路复用：一次网络往返列举多个目录（W4）。
    ///
    /// 返回 `(path, Result<DirListing, String>)`：单项失败不影响其余。
    /// 默认返回 `NotSupported`，调用方回退到逐个列举；支持批量分发的协议
    /// （如 PHP 的 NATIVE / 分阶段通道）覆写本方法。
    fn batch_list_dir(
        &self,
        _session: &dyn SessionState,
        _paths: &[String],
        _settings: &AppSettings,
    ) -> Result<BatchDirResult, ProtocolError> {
        Err(ProtocolError::NotSupported(
            "该协议不支持多路复用（批量列举）".into(),
        ))
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError>;

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError>;

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError>;

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError>;

    /// 执行一段目标语言代码（功能插件通道）。默认协议不支持；
    /// PHP 协议以「临时文件部署 + HTTP 请求」实现，JSP/ASP 待协议实现后补齐。
    fn run_code(
        &self,
        _session: &dyn SessionState,
        _language: &str,
        _code: &str,
        _settings: &AppSettings,
    ) -> Result<String, ProtocolError> {
        Err(ProtocolError::NotSupported(
            "该协议不支持代码执行通道".to_string(),
        ))
    }

    /// 新建目录（递归创建中间目录）。默认不支持，协议按需覆盖。
    /// 修改文件/目录的修改时间戳（秒级 epoch）。
    fn touch_path(
        &self,
        _session: &dyn SessionState,
        _path: &str,
        _timestamp: u64,
        _settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::NotSupported("touch_path".into()))
    }

    fn create_dir(
        &self,
        _session: &dyn SessionState,
        _path: &str,
        _settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::NotSupported("当前协议不支持新建目录".into()))
    }

    /// 读取文件指定区间（offset 起 length 字节；length=0 表示读到文件尾）。
    /// 默认实现基于完整读取后切片，支持随机访问的协议应覆盖为 fseek 实现。
    fn read_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        offset: u64,
        length: u64,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        let whole = self.read_file(session, path, settings)?;
        let (start, end) = chunk_range(whole.len(), offset, length);
        Ok(whole[start..end].to_vec())
    }

    /// 在指定偏移处写入内容（offset=0 且文件不存在时创建，否则以 r+b 追加/覆写）。
    /// 默认实现为完整读改写；支持随机访问的协议应覆盖为 fseek 实现。
    fn write_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        offset: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        // 读失败必须区分对待：原实现对**任何**读失败都 `unwrap_or_default()`，
        // 把「读不到」当成空文件，随后只写入新块 —— 远端文件被零填充 + 单块覆盖。
        // 规则：
        //   offset == 0 → 调用方本就要从头写，读不到即按新建文件处理（无数据可丢）；
        //   offset  > 0 → 必须读到原内容才能拼接，读失败一律上抛（绝不零填充）。
        let mut whole = if tolerate_missing_on_write(offset) {
            self.read_file(session, path, settings).unwrap_or_default()
        } else {
            self.read_file(session, path, settings)?
        };
        let start = usize::try_from(offset)
            .map_err(|_| ProtocolError::NotSupported("写入偏移超出本机寻址范围".into()))?;
        let end = start
            .checked_add(content.len())
            .ok_or_else(|| ProtocolError::NotSupported("写入区间溢出".into()))?;
        if end > whole.len() {
            whole.resize(end, 0);
        }
        whole[start..end].copy_from_slice(content);
        self.write_file(session, path, &whole, settings)
    }

    /// 探测数据库连接并列出数据库（默认不支持，协议按需覆盖）。
    fn db_probe(
        &self,
        _session: &dyn SessionState,
        _connection: &DbConnection,
        _settings: &AppSettings,
    ) -> Result<DbProbeResult, ProtocolError> {
        Err(ProtocolError::NotSupported(
            "当前协议不支持数据库操作".into(),
        ))
    }

    /// 执行 SQL（查询返回列与行，非查询返回影响行数）。
    fn db_query(
        &self,
        _session: &dyn SessionState,
        _connection: &DbConnection,
        _sql: &str,
        _settings: &AppSettings,
    ) -> Result<DbQueryResult, ProtocolError> {
        Err(ProtocolError::NotSupported(
            "当前协议不支持数据库操作".into(),
        ))
    }
}

/// 计算分块读取的字节区间（字符安全、无溢出）。
///
/// 独立成函数以便单测：`offset + length` 在极端值下会回绕，
/// 直接切片会 panic 或读到错误区间。
fn chunk_range(total_len: usize, offset: u64, length: u64) -> (usize, usize) {
    let start = usize::try_from(offset).unwrap_or(usize::MAX).min(total_len);
    let end = if length == 0 {
        total_len
    } else {
        usize::try_from(length)
            .ok()
            .and_then(|length| start.checked_add(length))
            .unwrap_or(usize::MAX)
            .min(total_len)
    };
    (start, end)
}

/// 写入时若读不到原文件，是否可以按「新建文件」处理。
///
/// 只有 `offset == 0`（从头写）可以容忍——此时没有任何既有内容会被丢弃；
/// `offset > 0` 必须读到原内容才能拼接，容忍就会把远端文件零填充后覆盖。
fn tolerate_missing_on_write(offset: u64) -> bool {
    offset == 0
}

#[cfg(test)]
mod chunk_tests {
    use super::*;

    #[test]
    fn chunk_range_handles_overflow_and_bounds() {
        // 常规区间
        assert_eq!(chunk_range(100, 10, 20), (10, 30));
        // length = 0 表示读到尾
        assert_eq!(chunk_range(100, 10, 0), (10, 100));
        // 偏移越界 → 空区间，不 panic
        assert_eq!(chunk_range(100, 500, 10), (100, 100));
        // u64::MAX 偏移不得回绕
        assert_eq!(chunk_range(100, u64::MAX, 10), (100, 100));
        // 偏移 + 长度溢出 → 截到文件尾
        assert_eq!(chunk_range(100, 90, u64::MAX), (90, 100));
        // 空文件
        assert_eq!(chunk_range(0, 0, 0), (0, 0));
    }

    #[test]
    fn only_zero_offset_tolerates_missing_source() {
        assert!(tolerate_missing_on_write(0), "offset=0 可视为新建文件");
        assert!(!tolerate_missing_on_write(1), "offset>0 必须读到原内容");
        assert!(!tolerate_missing_on_write(u64::MAX));
    }
}
