//! 协议注册：内置插件与示例插件统一经 dosword-sdk 的 `PluginRegistry` 注册。
//!
//! 宿主负责安全门：授权检查、审计、会话管理在命令层完成；
//! 插件只实现 `Protocol` 能力，即自动纳入既有安全模型。

pub mod jsp;
pub mod mock;
pub mod php;
pub mod recorder;
pub mod reqlog;
pub mod transport;

use dosword_sdk::domain::ProtocolMeta;
use dosword_sdk::{PluginManifest, PluginRegistry, ProtocolPlugin};

pub const MOCK_PROTOCOL_ID: &str = "builtin.mock.v1";

/// 测试辅助：轮询等待本地 HTTP 服务就绪。
///
/// 替代「spawn 后固定 sleep」—— CI runner 负载高时，python3 / node / php 起的
/// mock server 可能超过固定等待时间才 `listen`，表现为
/// `Network("error sending request")` 的假失败。返回 false 表示超时仍未就绪，
/// 调用方应打印原因并跳过，而不是断言失败。
#[cfg(test)]
pub(crate) fn wait_http_ready(port: u16, timeout_ms: u64) -> bool {
    use std::io::{Read, Write};
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    while std::time::Instant::now() < deadline {
        if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
            // 发一个最简请求：比裸 TCP 连接更贴近真实使用，
            // 也避免服务端收到半开连接后继续等待请求行
            if stream
                .write_all(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                .is_ok()
            {
                let mut buf = [0u8; 64];
                // 有响应即说明已就绪（状态码不重要，404/501 都算）
                if matches!(stream.read(&mut buf), Ok(n) if n > 0) {
                    return true;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

/// 测试辅助：轮询等待本地 TCP 服务就绪（非 HTTP 协议用，如 redis mock）。
///
/// 注意：仅适用于「可接受多次连接」的服务。只 `accept()` 一次的监听器
/// （如 REV_LISTENER）不能用探活，应由服务端写就绪标记文件供轮询。
#[cfg(test)]
pub(crate) fn wait_tcp_ready(port: u16, timeout_ms: u64) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

/// 协议注册表（包装 SDK 插件注册表，注册内置插件与第三方插件）。
pub struct ProtocolRegistry {
    inner: PluginRegistry,
}

impl ProtocolRegistry {
    /// 注册全部内置插件（mock / php）与示例插件（echo）。
    pub fn builtin() -> Self {
        let mut inner = PluginRegistry::new();
        for plugin in [
            Box::new(mock::MockProtocol) as Box<dyn ProtocolPlugin>,
            Box::new(php::PhpProtocol),
            Box::new(jsp::JspProtocol),
            Box::new(jsp::AspNetProtocol),
            Box::new(jsp::AspProtocol),
            Box::new(jsp::PythonProtocol),
            Box::new(jsp::NodeProtocol),
            Box::new(dosword_plugin_echo::EchoProtocol),
        ] {
            inner.register(plugin).expect("内置插件注册失败（id 冲突）");
        }
        Self { inner }
    }

    pub fn get(&self, id: &str) -> Option<&dyn ProtocolPlugin> {
        self.inner.get(id)
    }

    /// 协议下拉元信息（含 requires_network）。
    pub fn protocol_metas(&self) -> Vec<ProtocolMeta> {
        self.inner.protocol_metas()
    }

    /// 插件清单（设置页「插件」面板）。
    pub fn plugin_manifests(&self) -> Vec<PluginManifest> {
        self.inner.list()
    }
}
