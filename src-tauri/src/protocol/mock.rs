//! 内置的 Mock 协议（第一阶段默认）。

use std::any::Any;

use dosword_sdk::domain::{AppSettings, CommandOutput, DirListing, ProbeResult, ShellProfile};
use dosword_sdk::{PluginKind, PluginManifest, ProtocolPlugin};
use dosword_sdk::{Protocol, ProtocolError, SessionState};

/// Mock 协议的会话状态（目前为空结构，占位）。
pub struct MockSession;

impl SessionState for MockSession {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Mock 协议实例。
pub struct MockProtocol;

impl ProtocolPlugin for MockProtocol {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: super::MOCK_PROTOCOL_ID.to_string(),
            name: self.display_name().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            kind: PluginKind::Protocol,
            description: "本地 Mock 协议：不产生任何网络流量，用于验证工作流。".to_string(),
            capabilities: vec!["terminal".to_string()],
        }
    }
}

impl Protocol for MockProtocol {
    fn id(&self) -> &'static str {
        super::MOCK_PROTOCOL_ID
    }

    fn display_name(&self) -> &'static str {
        "Mock 协议（本地测试）"
    }

    fn requires_network(&self) -> bool {
        false
    }

    fn probe(
        &self,
        profile: &ShellProfile,
        _settings: &AppSettings,
    ) -> Result<ProbeResult, ProtocolError> {
        Ok(ProbeResult {
            status: "online".to_string(),
            server: "Mock Linux 6.x".to_string(),
            web_server: "DoSword Local Test Endpoint".to_string(),
            runtime: profile.runtime.clone(),
            current_dir: "/".to_string(),
            separator: "/".to_string(),
            message: "本次探测未向远端发送请求，仅用于验证本地工作流。".to_string(),

            php_sapi: "".to_string(),
            arch: "".to_string(),
            extensions: vec![],
            disable_functions: "".to_string(),
            info: std::collections::HashMap::new(),
        })
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        _settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        let session: Box<dyn SessionState> = Box::new(MockSession);
        let result = self.probe(profile, _settings)?;
        Ok((session, result))
    }

    fn execute_command(
        &self,
        _session: &dyn SessionState,
        command: &str,
        _settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        let stdout = format!("Mock 执行成功：{command}");
        Ok(CommandOutput {
            stdout,
            duration_ms: 0,
            cwd: None,
            raw_b64: None,
        })
    }

    fn list_dir(
        &self,
        _session: &dyn SessionState,
        _path: &str,
        _settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        Ok(DirListing { entries: vec![] })
    }

    fn read_file(
        &self,
        _session: &dyn SessionState,
        _path: &str,
        _settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        Err(ProtocolError::NotSupported(
            "Mock 协议不支持文件操作".to_string(),
        ))
    }

    fn write_file(
        &self,
        _session: &dyn SessionState,
        _path: &str,
        _content: &[u8],
        _settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::NotSupported(
            "Mock 协议不支持文件操作".to_string(),
        ))
    }

    fn delete_path(
        &self,
        _session: &dyn SessionState,
        _path: &str,
        _settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::NotSupported(
            "Mock 协议不支持文件操作".to_string(),
        ))
    }

    fn rename_path(
        &self,
        _session: &dyn SessionState,
        _from: &str,
        _to: &str,
        _settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::NotSupported(
            "Mock 协议不支持文件操作".to_string(),
        ))
    }
}
