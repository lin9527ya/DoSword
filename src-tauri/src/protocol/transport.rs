//! 协议层共享的阻塞 reqwest 工具。
//!
//! 网络类命令在 Tauri 侧以 `#[tauri::command(async)]` 调度到阻塞线程池，
//! 因此这里使用 blocking client 且无需 async runtime。

use std::time::Duration;

use reqwest::blocking::Client;

use dosword_sdk::domain::AppSettings;

/// 依据全局设置构建 HTTP 客户端。
/// 重定向策略固定为 `none()`：防止密码参数随 301/302 泄露到其他主机。
pub fn build_client(settings: &AppSettings) -> Client {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(settings.default_timeout_secs))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("DoSword/1.0")
        .cookie_store(true);
    if let Some(proxy) = settings.proxy.as_deref().filter(|value| !value.is_empty()) {
        if let Ok(proxy) = reqwest::Proxy::all(proxy) {
            builder = builder.proxy(proxy);
        }
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
pub fn gzip_payload(payload: &str, enabled: bool) -> String {
    if !enabled {
        return payload.to_string();
    }
    use base64::Engine;
    use std::io::Write;
    let bytes = match base64::engine::general_purpose::STANDARD.decode(payload) {
        Ok(bytes) => bytes,
        Err(_) => return payload.to_string(),
    };
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    if encoder.write_all(&bytes).is_err() {
        return payload.to_string();
    }
    match encoder.finish() {
        Ok(compressed) => base64::engine::general_purpose::STANDARD.encode(compressed),
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
