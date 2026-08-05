//! 协议注册：内置插件与示例插件统一经 dosword-sdk 的 `PluginRegistry` 注册。
//!
//! 宿主负责安全门：授权检查、审计、会话管理在命令层完成；
//! 插件只实现 `Protocol` 能力，即自动纳入既有安全模型。

pub mod jsp;
pub mod mock;
pub mod php;
pub mod transport;

use dosword_sdk::domain::ProtocolMeta;
use dosword_sdk::{PluginManifest, PluginRegistry, ProtocolPlugin};

pub const MOCK_PROTOCOL_ID: &str = "builtin.mock.v1";

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
            Box::new(dosword_plugin_echo::EchoProtocol),
        ] {
            inner
                .register(plugin)
                .expect("内置插件注册失败（id 冲突）");
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
