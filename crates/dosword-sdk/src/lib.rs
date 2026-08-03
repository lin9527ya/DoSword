//! DoSword 协议 SDK。
//!
//! 纯接口库（零 tauri 依赖）：协议插件实现 [`plugin::ProtocolPlugin`]
//! 后即可接入宿主，授权检查 / 审计 / 会话管理由宿主自动完成。

pub mod domain;
pub mod plugin;
pub mod protocol;

pub use plugin::{PluginKind, PluginManifest, PluginRegistry, ProtocolPlugin};
pub use protocol::{Protocol, ProtocolError, SessionState};
