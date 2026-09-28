//! 协议层共享的 reqwest 工具（支持 blocking 同步 + async 异步双栈）。
//!
//! 当前命令层以 `#[tauri::command(async)]` + `spawn_blocking` 调度同步网络，
//! 因此默认使用 blocking client；`build_client_async` 为后续异步化演进预留，
//! 允许协议层逐步迁移至 `async/await` 而无需一次性重构 `Protocol` trait。

use std::time::Duration;

use reqwest::blocking::Client;

use dosword_sdk::domain::AppSettings;

/// 依据全局设置构建 HTTP 客户端（blocking）。
/// 重定向策略固定为 `none()`：防止密码参数随 301/302 泄露到其他主机。
pub fn build_client(settings: &AppSettings) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(settings.default_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("DoSword/1.0")
        .cookie_store(true)
        .danger_accept_invalid_certs(true);
    if let Some(proxy) = settings.proxy.as_deref().filter(|value| !value.is_empty())
        && let Ok(proxy) = reqwest::Proxy::all(proxy)
    {
        builder = builder.proxy(proxy);
    }
    builder.build().expect("构建 HTTP 客户端失败")
}

/// 快速表单转义（P2）：base64 载荷只需转义 + 与 =；密码等短值额外转义 &（防参数注入）。
/// 相比 url::form_urlencoded 的全量百分号编码，避免对每块（最大 4MB+）载荷
/// 做一次全串遍历与分配；正斜杠在 PHP 表单解析中原样保留，百分号不出现在 base64 中。
pub fn form_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("%26"),
            '+' => out.push_str("%2B"),
            '=' => out.push_str("%3D"),
            c => out.push(c),
        }
    }
    out
}

/// PHP 单引号字符串转义（S3）：密码含 `'`/`\` 时防止载荷语法破坏或鉴权被改写。
pub fn php_single_quote(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}

/// JSON 字符串值转义（嵌入 PHP/Java 双引号字符串字面量；含控制字符处理）。
pub fn json_str(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// gzip：压缩载荷文本（base64 载荷 gzip 后再 base64），目标无 zlib 时保持原样由 stub 兜底。
/// 仅对 >1KB 载荷压缩且压缩后更小才使用，避免小包膨胀与 mock 兼容问题。
pub fn gzip_payload(payload: &str, enabled: bool) -> String {
    if !enabled || payload.len() < 1024 {
        return payload.to_string();
    }
    use base64::Engine;
    use std::io::Write;
    let bytes = match base64::engine::general_purpose::STANDARD.decode(payload) {
        Ok(bytes) => bytes,
        Err(_) => return payload.to_string(),
    };
    if bytes.len() < 512 {
        return payload.to_string();
    }
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    if encoder.write_all(&bytes).is_err() {
        return payload.to_string();
    }
    match encoder.finish() {
        Ok(compressed) => {
            if compressed.len() >= bytes.len() {
                return payload.to_string();
            }
            base64::engine::general_purpose::STANDARD.encode(compressed)
        }
        Err(_) => payload.to_string(),
    }
}

/// gzip：响应文本若为 gzip 字节则解压（按魔数 1f 8b 判断），否则原样返回。
pub fn gunzip_if_needed(text: &str) -> String {
    use base64::Engine;
    use std::io::Read;
    let bytes = match base64::engine::general_purpose::STANDARD.decode(text) {
        Ok(bytes) => bytes,
        Err(_) => return text.to_string(),
    };
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        return text.to_string();
    }
    let mut decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut out = Vec::new();
    if decoder.read_to_end(&mut out).is_err() {
        return text.to_string();
    }
    base64::engine::general_purpose::STANDARD.encode(out)
}

/// S10：流式读取响应（上限 max_bytes+1），避免恶意目标撑爆内存。
pub fn read_limited<R: std::io::Read>(reader: R, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut buf = Vec::new();
    reader.take(max_bytes + 1).read_to_end(&mut buf)?;
    Ok(buf)
}

/// 异步 HTTP 客户端（预留：协议层 async 化后使用，配置与 blocking 版本保持一致）。
#[allow(dead_code)]
pub fn build_client_async(settings: &AppSettings) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(settings.default_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("DoSword/1.0")
        .cookie_store(true)
        .danger_accept_invalid_certs(true);
    if let Some(proxy) = settings.proxy.as_deref().filter(|value| !value.is_empty())
        && let Ok(proxy) = reqwest::Proxy::all(proxy)
    {
        builder = builder.proxy(proxy);
    }
    builder.build().expect("构建异步 HTTP 客户端失败")
}

/// 异步流式读取（async 版本，与 read_limited 语义一致）。
#[allow(dead_code)]
pub async fn read_limited_async(
    response: reqwest::Response,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("读取响应失败：{e}"))?;
    if bytes.len() > max_bytes as usize {
        return Err(format!("响应超过大小上限（{}MB）", max_bytes / 1024 / 1024));
    }
    Ok(bytes.to_vec())
}
