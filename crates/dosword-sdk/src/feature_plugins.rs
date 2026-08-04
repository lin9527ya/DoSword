//! 内置功能插件（通用 + 语言专用）。
//!
//! 通用插件（languages 为空）：能力与语言无关（命令型走协议命令通道，
//! 代码型按语言模板生成载荷）。
//! 语言专用插件（category = "php" 等）：特定语言能力（环境检测 / bypass 等）。

use crate::domain::AppSettings;
use crate::plugin::{FeatureManifest, FeaturePlugin, ParamSpec};
use crate::protocol::{Protocol, ProtocolError, SessionState};

/// 从参数 JSON 取字符串值。
fn param_str(params: &serde_json::Value, name: &str, default: &str) -> String {
    params
        .get(name)
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

fn param_int(params: &serde_json::Value, name: &str, default: u32) -> u32 {
    params
        .get(name)
        .and_then(|v| v.as_u64())
        .unwrap_or(default as u64) as u32
}

fn param_bool(params: &serde_json::Value, name: &str, default: bool) -> bool {
    params
        .get(name)
        .and_then(|v| v.as_bool())
        .unwrap_or(default)
}

fn run_command(
    protocol: &dyn Protocol,
    session: &dyn SessionState,
    command: &str,
    settings: &AppSettings,
) -> Result<serde_json::Value, ProtocolError> {
    let output = protocol.execute_command(session, command, settings)?;
    Ok(serde_json::json!({
        "ok": true,
        "command": command,
        "stdout": output.stdout,
    }))
}

/// 按语言返回进程列表命令（通用：多语言命令模板）。
fn process_command(language: &str) -> &'static str {
    match language {
        "aspnet" => "tasklist /FO CSV 2>nul",
        _ => "ps -eo pid,user,pcpu,pmem,cmd --sort=-pcpu 2>/dev/null | head -60 || ps aux 2>/dev/null | head -60",
    }
}

/// 进程详情（通用）。
pub struct ProcessesPlugin;

impl FeaturePlugin for ProcessesPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "processes".into(),
            name: "进程详情".into(),
            version: "1.0.0".into(),
            description: "列出目标进程（通用，按语言选择 ps/tasklist 命令）。".into(),
            category: "general".into(),
            languages: vec![],
            params: vec![],
        }
    }

    fn execute(
        &self,
        protocol: &dyn Protocol,
        session: &dyn SessionState,
        runtime: &str,
        _params: &serde_json::Value,
        settings: &AppSettings,
    ) -> Result<serde_json::Value, ProtocolError> {
        run_command(protocol, session, process_command(runtime), settings)
    }
}

/// PHP 端口扫描载荷（串行 fsockopen，超时 1s，可扫多端口）。
fn php_port_scan_code(host: &str, ports: &[u32], timeout: u32) -> String {
    let ports_php: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
    format!(
        r#"<?php
set_time_limit(0);
error_reporting(0);
$host = {host_php};
$ports = array({ports_php});
$timeout = {timeout};
$open = array();
foreach ($ports as $p) {{
    $s = @fsockopen($host, $p, $errno, $errstr, $timeout);
    if ($s) {{ $open[] = $p; fclose($s); }}
}}
echo json_encode(array('host' => $host, 'open' => $open, 'scanned' => count($ports)));
"#,
        host_php = serde_json::to_string(host).unwrap_or_else(|_| "\"\"".to_string()),
        ports_php = ports_php.join(","),
        timeout = timeout,
    )
}

/// 端口扫描（通用：PHP 代码型载荷；JSP/ASP 待协议实现后补模板）。
pub struct PortScanPlugin;

impl FeaturePlugin for PortScanPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "port_scan".into(),
            name: "端口扫描".into(),
            version: "1.0.0".into(),
            description: "扫描目标主机开放端口（基于目标语言的 socket 载荷）。".into(),
            category: "general".into(),
            languages: vec![],
            params: vec![
                ParamSpec {
                    name: "host".into(),
                    label: "目标主机".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("127.0.0.1")),
                    options: None,
                },
                ParamSpec {
                    name: "ports".into(),
                    label: "端口列表".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("21,22,80,443,3306,3389,6379,8080")),
                    options: None,
                },
                ParamSpec {
                    name: "timeout".into(),
                    label: "连接超时（秒）".into(),
                    param_type: "int".into(),
                    default: Some(serde_json::json!(1)),
                    options: None,
                },
            ],
        }
    }

    fn execute(
        &self,
        protocol: &dyn Protocol,
        session: &dyn SessionState,
        runtime: &str,
        params: &serde_json::Value,
        settings: &AppSettings,
    ) -> Result<serde_json::Value, ProtocolError> {
        let language = runtime;
        let host = param_str(params, "host", "127.0.0.1");
        let ports_text = param_str(params, "ports", "21,22,80,443");
        let ports: Vec<u32> = ports_text
            .split(|c: char| c == ',' || c == ' ' || c == '\n')
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.trim().parse::<u32>().ok())
            .take(128)
            .collect();
        if ports.is_empty() {
            return Err(ProtocolError::ParseError("端口列表为空".to_string()));
        }
        let timeout = param_int(params, "timeout", 1).clamp(1, 10);
        match language {
            "php" => {
                let code = php_port_scan_code(&host, &ports, timeout);
                let output = protocol.run_code(session, "php", &code, settings)?;
                let parsed: serde_json::Value = serde_json::from_str(&output)
                    .map_err(|_| ProtocolError::ParseError(format!("载荷输出非 JSON：{output}")))?;
                Ok(parsed)
            }
            other => Err(ProtocolError::NotSupported(format!(
                "端口扫描暂不支持运行时 {other}（待协议实现后补载荷模板）"
            ))),
        }
    }
}

/// PHP 环境检测载荷（PHP 专用：disable_functions / open_basedir / 关键能力）。
fn php_env_code() -> &'static str {
    r#"<?php
error_reporting(0);
function probe_fn($name) {
    if (!function_exists($name)) return 'missing';
    if (in_array($name, array_map('trim', explode(',', ini_get('disable_functions'))))) return 'disabled';
    return 'available';
}
$df = ini_get('disable_functions');
$ob = ini_get('open_basedir');
$checks = array();
foreach (array('shell_exec','exec','system','passthru','popen','proc_open','dl','mail','fsockopen','curl_init','file_put_contents','putenv','pcntl_exec') as $f) {
    $checks[$f] = probe_fn($f);
}
echo json_encode(array(
    'php_version' => PHP_VERSION,
    'sapi' => php_sapi_name(),
    'disable_functions' => $df === false ? '' : $df,
    'open_basedir' => $ob === false ? '' : $ob,
    'safe_mode' => ini_get('safe_mode'),
    'upload_tmp_dir' => ini_get('upload_tmp_dir'),
    'functions' => $checks,
    'uname' => @php_uname('a'),
    'cwd' => getcwd(),
));
"#
}

/// PHP 环境检测（PHP 专用）。
pub struct PhpEnvPlugin;

impl FeaturePlugin for PhpEnvPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "php_env".into(),
            name: "PHP 环境检测".into(),
            version: "1.0.0".into(),
            description: "检测 PHP 禁用函数 / open_basedir / 关键能力（bypass 前置评估）。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: vec![],
        }
    }

    fn execute(
        &self,
        protocol: &dyn Protocol,
        session: &dyn SessionState,
        runtime: &str,
        _params: &serde_json::Value,
        settings: &AppSettings,
    ) -> Result<serde_json::Value, ProtocolError> {
        if runtime != "php" {
            return Err(ProtocolError::NotSupported(format!(
                "PHP 环境检测仅支持 php 运行时（当前 {runtime}）"
            )));
        }
        let output = protocol.run_code(session, "php", php_env_code(), settings)?;
        serde_json::from_str(&output)
            .map_err(|_| ProtocolError::ParseError(format!("载荷输出非 JSON：{output}")))
    }
}

/// ZIP 压缩（通用：PHP ZipArchive 载荷）。
fn php_zip_code(source: &str, target: &str) -> String {
    format!(
        r#"<?php
error_reporting(0);
$src = {source};
$dst = {target};
if (!class_exists('ZipArchive')) {{ echo json_encode(array('ok' => false, 'error' => 'no ZipArchive')); exit; }}
$zip = new ZipArchive();
if ($zip->open($dst, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {{ echo json_encode(array('ok' => false, 'error' => 'open failed')); exit; }}
if (is_dir($src)) {{
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS));
    $count = 0;
    foreach ($it as $f) {{
        $real = $f->getRealPath();
        if ($real === false) continue;
        $rel = substr($real, strlen(rtrim($src, '/\\')) + 1);
        $zip->addFile($real, str_replace('\\', '/', $rel));
        $count++;
    }}
}} elseif (is_file($src)) {{
    $zip->addFile($src, basename($src));
    $count = 1;
}} else {{ $count = 0; }}
$zip->close();
echo json_encode(array('ok' => true, 'target' => $dst, 'entries' => $count));
"#,
        source = serde_json::to_string(source).unwrap_or_else(|_| "\"\"".to_string()),
        target = serde_json::to_string(target).unwrap_or_else(|_| "\"\"".to_string()),
    )
}

/// ZIP 压缩（通用）。
pub struct ZipPlugin;

impl FeaturePlugin for ZipPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "zip".into(),
            name: "ZIP 压缩".into(),
            version: "1.0.0".into(),
            description: "将目标目录/文件打包为 ZIP（PHP ZipArchive 载荷）。".into(),
            category: "general".into(),
            languages: vec![],
            params: vec![
                ParamSpec {
                    name: "source".into(),
                    label: "源路径".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!(".")),
                    options: None,
                },
                ParamSpec {
                    name: "target".into(),
                    label: "ZIP 输出路径".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("/tmp/backup.zip")),
                    options: None,
                },
            ],
        }
    }

    fn execute(
        &self,
        protocol: &dyn Protocol,
        session: &dyn SessionState,
        runtime: &str,
        params: &serde_json::Value,
        settings: &AppSettings,
    ) -> Result<serde_json::Value, ProtocolError> {
        let language = runtime;
        match language {
            "php" => {
                let source = param_str(params, "source", ".");
                let target = param_str(params, "target", "/tmp/backup.zip");
                let code = php_zip_code(&source, &target);
                let output = protocol.run_code(session, "php", &code, settings)?;
                serde_json::from_str(&output).map_err(|_| {
                    ProtocolError::ParseError(format!("载荷输出非 JSON：{output}"))
                })
            }
            other => Err(ProtocolError::NotSupported(format!(
                "ZIP 压缩暂不支持运行时 {other}（待协议实现后补载荷模板）"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::FeaturePluginRegistry;

    #[test]
    fn builtin_manifests_valid() {
        for manifest in FeaturePluginRegistry::builtin().list() {
            assert!(!manifest.id.is_empty());
            assert!(!manifest.name.is_empty());
            assert!(manifest.category == "general" || manifest.category == "php");
        }
    }

    #[test]
    fn port_scan_php_code_generates() {
        let code = php_port_scan_code("127.0.0.1", &[80, 443], 1);
        assert!(code.contains("fsockopen"));
        assert!(code.contains("80"));
        assert!(code.contains("127.0.0.1"));
    }
}
