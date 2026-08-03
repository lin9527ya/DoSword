//! 协议抽象层：定义 `Protocol` trait、错误类型、会话状态与内置协议注册表。
//!
//! 协议方法全部是同步的：网络类命令在 Tauri 侧以 `#[tauri::command(async)]`
//! 调度到阻塞线程池执行，因此可以自由持有 `std::sync::Mutex` 而不会跨越 await。

mod mock;
pub mod php;
mod transport;

use std::any::Any;
use std::collections::HashMap;
use std::fmt;

use crate::domain::{
    AppSettings, CommandOutput, DbConnection, DbProbeResult, DbQueryResult, DirListing,
    ProbeResult, ProtocolMeta, ShellProfile,
};

pub const MOCK_PROTOCOL_ID: &str = "builtin.mock.v1";

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
            ProtocolError::NotSupported(detail) => write!(f, "操作不受支持：{detail}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

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

    /// 新建目录（递归创建中间目录）。默认不支持，协议按需覆盖。
    fn create_dir(
        &self,
        _session: &dyn SessionState,
        _path: &str,
        _settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::NotSupported(
            "当前协议不支持新建目录".into(),
        ))
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
        let start = (offset as usize).min(whole.len());
        let end = if length == 0 {
            whole.len()
        } else {
            (start + (length as usize)).min(whole.len())
        };
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
        let mut whole = self
            .read_file(session, path, settings)
            .unwrap_or_default();
        let start = offset as usize;
        if start + content.len() > whole.len() {
            whole.resize(start + content.len(), 0);
        }
        whole[start..start + content.len()].copy_from_slice(content);
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

/// 内置协议注册表。
pub struct ProtocolRegistry {
    map: HashMap<&'static str, Box<dyn Protocol>>,
}

impl ProtocolRegistry {
    /// 注册所有内置协议。
    pub fn builtin() -> Self {
        let mut map: HashMap<&'static str, Box<dyn Protocol>> = HashMap::new();
        let mock = mock::MockProtocol;
        let php = php::PhpProtocol;
        map.insert(mock.id(), Box::new(mock));
        map.insert(php.id(), Box::new(php));
        Self { map }
    }

    pub fn get(&self, id: &str) -> Option<&dyn Protocol> {
        self.map.get(id).map(|boxed| boxed.as_ref())
    }

    /// 供前端"创建 Shell"下拉使用的协议清单，按 id 稳定排序。
    pub fn list(&self) -> Vec<ProtocolMeta> {
        let mut metas: Vec<ProtocolMeta> = self
            .map
            .values()
            .map(|protocol| ProtocolMeta {
                id: protocol.id().to_string(),
                display_name: protocol.display_name().to_string(),
                requires_network: protocol.requires_network(),
            })
            .collect();
        metas.sort_by(|a, b| a.id.cmp(&b.id));
        metas
    }
}
