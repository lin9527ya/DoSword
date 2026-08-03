//! DoSword 示例协议插件：ECHO 协议。
//!
//! 演示第三方协议接入 SDK 的三步：
//!   1. crate 依赖 `dosword-sdk`
//!   2. 实现 [`Protocol`]（本文件）并附带 [`ProtocolPlugin`] 清单
//!   3. 在宿主 `src-tauri/src/protocol/mod.rs` 注册一行
//!
//! 协议行为（与 php 协议同构，用于演示帧协议的最小实现）：
//!   - 服务端 stub：`<?php echo 'OK';`（任意回显端点即可）
//!   - 客户端 POST `k`（密码）与 `x`（base64 载荷）到端点，
//!     服务器把 `{NONCE}{业务JSON base64}{NONCE}` 原样回显；
//!   - 命令执行 = 回显（探测返回固定环境信息），文件/数据库操作不支持。

use std::any::Any;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use dosword_sdk::domain::{
    AppSettings, CommandOutput, DirListing, ProbeResult, ShellProfile,
};
use dosword_sdk::{PluginKind, PluginManifest, Protocol, ProtocolError, ProtocolPlugin, SessionState};

pub const ECHO_PROTOCOL_ID: &str = "dev.echo.v1";

/// ECHO 协议会话状态：持有专用 HTTP 客户端。
pub struct EchoSession {
    pub endpoint: String,
    pub password: String,
    pub client: reqwest::blocking::Client,
}

impl SessionState for EchoSession {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// ECHO 协议实例（无状态单例）。
pub struct EchoProtocol;

/// 载荷模板：回显任意内容，nonce 帧包裹。
const TEMPLATE_FRAME: &str = r#"echo '{NONCE}'.'{PAYLOAD}'.'{NONCE}';"#;

fn build_client(settings: &AppSettings) -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(settings.default_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("DoSword/1.0 (echo-plugin)")
        .build()
        .expect("构建 HTTP 客户端失败")
}

impl EchoProtocol {
    /// 发送一次请求：服务器把 nonce 帧原样回显。
    fn send_frame(
        &self,
        session: &EchoSession,
        payload: &str,
        _settings: &AppSettings,
    ) -> Result<serde_json::Value, ProtocolError> {
        // 8 字节随机 nonce
        let nonce: String = (0..8).map(|_| format!("{:02x}", rand_byte())).collect();
        let code = TEMPLATE_FRAME
            .replace("{NONCE}", &nonce)
            .replace("{PAYLOAD}", payload);

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("k", &session.password)
            .append_pair("x", &B64.encode(code))
            .finish();

        let response = session
            .client
            .post(&session.endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .map_err(|error| ProtocolError::Network(error.to_string()))?;
        if !response.status().is_success() {
            return Err(ProtocolError::HttpStatus(
                response.status().as_u16(),
                response.status().canonical_reason().unwrap_or("").to_string(),
            ));
        }
        let bytes = response
            .bytes()
            .map_err(|error| ProtocolError::ParseError(error.to_string()))?;
        let text = String::from_utf8_lossy(&bytes);
        if text.contains("AUTH_FAIL") {
            return Err(ProtocolError::AuthFailed(
                "密码错误，服务器拒绝鉴权".to_string(),
            ));
        }
        // 定位 nonce 帧
        let start = text.find(&nonce).ok_or_else(|| {
            ProtocolError::ParseError("响应中未找到协议帧".to_string())
        })?;
        let tail = &text[start + nonce.len()..];
        let end = tail.find(&nonce).ok_or(ProtocolError::ParseError(
            "协议帧不完整".to_string(),
        ))?;
        let payload_b64 = &tail[..end];
        let decoded = B64
            .decode(payload_b64)
            .map_err(|_| ProtocolError::ParseError("帧内容不是合法 Base64".to_string()))?;
        let value: serde_json::Value = serde_json::from_slice(&decoded)
            .map_err(|_| ProtocolError::ParseError("帧内容不是合法 JSON".to_string()))?;
        if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            let message = value
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("未知错误");
            return Err(ProtocolError::ServerError(message.to_string()));
        }
        Ok(value)
    }
}

/// 伪随机字节（演示用；正式插件建议用 getrandom）。
fn rand_byte() -> u8 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    (nanos & 0xff) as u8
}

impl ProtocolPlugin for EchoProtocol {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: ECHO_PROTOCOL_ID.to_string(),
            name: self.display_name().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            kind: PluginKind::Protocol,
            description: "示例插件：ECHO 帧协议（演示 SDK 三步接入，仅命令回显）。".to_string(),
            capabilities: vec!["terminal".to_string()],
        }
    }
}

impl Protocol for EchoProtocol {
    fn id(&self) -> &'static str {
        ECHO_PROTOCOL_ID
    }

    fn display_name(&self) -> &'static str {
        "ECHO 协议（示例插件）"
    }

    fn requires_network(&self) -> bool {
        true
    }

    fn probe(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<ProbeResult, ProtocolError> {
        let session = EchoSession {
            endpoint: profile.endpoint.clone(),
            password: profile.password.clone(),
            client: build_client(settings),
        };
        // 用 ok 帧验证端点与密码（帧往返即成功）
        let probe_payload = serde_json::json!({"ok": true, "data": {}});
        self.send_frame(
            &session,
            &B64.encode(probe_payload.to_string().as_bytes()),
            settings,
        )?;
        Ok(ProbeResult {
            status: "online".to_string(),
            server: "ECHO Mock Server".to_string(),
            web_server: "任意回显端点".to_string(),
            runtime: profile.runtime.clone(),
            current_dir: "/".to_string(),
            separator: "/".to_string(),
            message: "ECHO 协议探测成功（端点可回显 nonce 帧）。".to_string(),
        })
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        let probe = self.probe(profile, settings)?;
        let session: Box<dyn SessionState> = Box::new(EchoSession {
            endpoint: profile.endpoint.clone(),
            password: profile.password.clone(),
            client: build_client(settings),
        });
        Ok((session, probe))
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        let echo = session
            .as_any()
            .downcast_ref::<EchoSession>()
            .expect("会话类型不匹配");
        let payload = serde_json::json!({"ok": true, "data": {"stdout": command}});
        let start = Instant::now();
        let value = self.send_frame(echo, &B64.encode(payload.to_string().as_bytes()), settings)?;
        let duration_ms = start.elapsed().as_millis() as u64;
        let stdout = value
            .pointer("/data/stdout")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Ok(CommandOutput {
            stdout,
            duration_ms,
            cwd: None,
        })
    }

    fn list_dir(
        &self,
        _session: &dyn SessionState,
        _path: &str,
        _settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        Err(ProtocolError::NotSupported(
            "ECHO 示例插件不支持文件操作".to_string(),
        ))
    }

    fn read_file(
        &self,
        _session: &dyn SessionState,
        _path: &str,
        _settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        Err(ProtocolError::NotSupported(
            "ECHO 示例插件不支持文件操作".to_string(),
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
            "ECHO 示例插件不支持文件操作".to_string(),
        ))
    }

    fn delete_path(
        &self,
        _session: &dyn SessionState,
        _path: &str,
        _settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        Err(ProtocolError::NotSupported(
            "ECHO 示例插件不支持文件操作".to_string(),
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
            "ECHO 示例插件不支持文件操作".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use serde_json::json;

    use super::*;

    fn settings() -> AppSettings {
        AppSettings {
            http_enabled: true,
            default_timeout_secs: 5,
            proxy: None,
            max_file_size_mb: 32,
        }
    }

    fn profile(endpoint: &str) -> ShellProfile {
        ShellProfile {
            id: "test".into(),
            workspace_id: "ws".into(),
            name: "echo".into(),
            endpoint: endpoint.into(),
            runtime: "php".into(),
            protocol_id: ECHO_PROTOCOL_ID.into(),
            status: "unknown".into(),
            last_connected_at: None,
            created_at: "2026-01-01".into(),
            password: "secret".into(),
            protocol_params: "{}".into(),
            authorization_ack: true,
            tags: vec![],
        }
    }

    /// 假服务器：解析 `k`/`x`，回显 nonce 帧（x 解码后含 nonce 与业务载荷）。
    fn spawn_fake_server() -> (String, std::sync::mpsc::Receiver<(String, String)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = Vec::new();
                let mut temp = [0u8; 8192];
                loop {
                    match stream.read(&mut temp) {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&temp[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let request = String::from_utf8_lossy(&buf);
                let body_start = request
                    .find("\r\n\r\n")
                    .map(|i| i + 4)
                    .unwrap_or(request.len());
                let body = &request[body_start.min(request.len())..];
                let params: Vec<(String, String)> =
                    url::form_urlencoded::parse(body.as_bytes())
                        .map(|(k, v)| (k.into_owned(), v.into_owned()))
                        .collect();
                let k = params
                    .iter()
                    .find(|(key, _)| key == "k")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                let x = params
                    .iter()
                    .find(|(key, _)| key == "x")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                let code =
                    String::from_utf8(B64.decode(&x).unwrap_or_default()).unwrap_or_default();
                let _ = tx.send((k.clone(), code.clone()));

                // 从载荷提取 nonce：echo '{NONCE}'.'{PAYLOAD}'.'{NONCE}';
                let nonce = code
                    .split("echo '")
                    .nth(1)
                    .and_then(|part| part.split('\'').next())
                    .unwrap_or("abababab")
                    .to_string();
                let payload = code
                    .split("'.'")
                    .nth(1)
                    .and_then(|part| part.split("'.'").next())
                    .unwrap_or("")
                    .to_string();

                let body = if k == "secret" {
                    format!("{nonce}{payload}{nonce}")
                } else {
                    "AUTH_FAIL".to_string()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (format!("http://{addr}"), rx)
    }

    #[test]
    fn manifest_is_present() {
        let manifest = EchoProtocol.manifest();
        assert_eq!(manifest.id, ECHO_PROTOCOL_ID);
        assert_eq!(manifest.kind, PluginKind::Protocol);
        assert!(manifest.supports("terminal"));
        assert!(!manifest.supports("files"));
    }

    #[test]
    fn probe_and_exec_round_trip() {
        let (url, rx) = spawn_fake_server();
        let proto = EchoProtocol;
        let settings = settings();
        let profile = profile(&url);

        let probe = proto.probe(&profile, &settings).expect("探测应成功");
        assert_eq!(probe.status, "online");
        let (k, _) = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("应收到请求");
        assert_eq!(k, "secret");

        let (session, _) = proto.connect(&profile, &settings).unwrap();
        let output = proto
            .execute_command(session.as_ref(), "whoami", &settings)
            .expect("执行应成功");
        assert_eq!(output.stdout, "whoami");
    }

    #[test]
    fn wrong_password_auth_fail() {
        let (url, _rx) = spawn_fake_server();
        let proto = EchoProtocol;
        let mut profile = profile(&url);
        profile.password = "wrong".into();
        let result = proto.probe(&profile, &settings());
        assert!(
            matches!(result, Err(ProtocolError::AuthFailed(_))),
            "密码错误应报鉴权失败"
        );
    }

    #[test]
    fn unsupported_ops_return_not_supported() {
        let proto = EchoProtocol;
        let result = proto.list_dir(&EchoSession {
            endpoint: "http://t".into(),
            password: "s".into(),
            client: build_client(&settings()),
        }, "/", &settings());
        assert!(matches!(result, Err(ProtocolError::NotSupported(_))));
    }
}
