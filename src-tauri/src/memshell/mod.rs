//! 内存马（payload installer）后端。
//!
//! **准入约束（硬性）**：`install` 产出的句柄必须足以在**一个全新的 DoSword
//! 实例**上完成 `uninstall`（句柄里要能重建出 endpoint / token / 产物清单）。
//! 做不到的形态一律不实现 —— 否则等于给目标留后门。
//!
//! 当前仅实现 PHP：
//! - `php_user_ini`：写入 `.user.ini` 的 `auto_prepend_file` + 一个载荷文件，
//!   请求时自动加载。持久、可卸载（载荷自带自毁入口 + 句柄可还原原文件）。
//!
//! Java 内存马需要先给 JSP 协议补 `run_code` 通道（当前 stub 是固定分发），
//! 且存在 classloader 回收陷阱，另行排期。

pub mod php;

use dosword_sdk::domain::ProbeResult;

/// 操作头：ping / exec / uninstall。
pub const OP_HEADER: &str = "X-DSW-OP";
/// 令牌头：与载荷内嵌令牌做常量时间比较。
pub const TOKEN_HEADER: &str = "X-DSW-TOKEN";
/// 命令头：base64 后的命令（仅 exec）。
pub const CMD_HEADER: &str = "X-DSW-CMD";

pub const KIND_PHP_USER_INI: &str = "php_user_ini";

/// 判定 `php_user_ini` 在当前目标上是否可行。纯本地计算，不发网络请求。
///
/// `.user.ini` 由 CGI/FastCGI SAPI 解析；`php -S`（cli-server）**不支持**
/// （已实测），因此必须排除。`user_ini.filename` 为空表示该特性被禁用。
pub fn php_user_ini_preconditions(info: &ProbeResult) -> Result<(), String> {
    let sapi = info
        .info
        .get("PHP_SAPI")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    if sapi.is_empty() {
        return Err("目标未上报 PHP_SAPI".to_string());
    }
    if !sapi.contains("fpm") && !sapi.contains("cgi") {
        return Err(format!(
            "当前 SAPI 为 {sapi}，.user.ini 仅在 CGI/FastCGI 下生效（php -S 不支持）"
        ));
    }
    let ini_name = info
        .info
        .get("user_ini_filename")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if ini_name.is_empty() {
        return Err("目标禁用了 user_ini（user_ini.filename 为空）".to_string());
    }
    if document_root(info).is_none() {
        return Err("目标未上报 DOCUMENT_ROOT".to_string());
    }
    Ok(())
}

/// 目标的 web 根目录（`DOCUMENT_ROOT` / `FileRoot`）。
pub fn document_root(info: &ProbeResult) -> Option<String> {
    info.info
        .get("DOCUMENT_ROOT")
        .or_else(|| info.info.get("FileRoot"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// 目标是否已经存在无法卸载的残留（调用方据此拒绝再次注入）。
pub fn has_orphan(shells: &[dosome_dto::MemoryShell]) -> bool {
    shells.iter().any(|item| item.status == "orphaned")
}

/// 让 storage 层与命令层共用同一类型。
pub mod dosome_dto {
    pub use dosword_sdk::domain::MemoryShell;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_with(sapi: &str, ini: &str, root: &str) -> ProbeResult {
        let mut info = std::collections::HashMap::new();
        if !sapi.is_empty() {
            info.insert("PHP_SAPI".to_string(), sapi.to_string());
        }
        if !ini.is_empty() {
            info.insert("user_ini_filename".to_string(), ini.to_string());
        }
        if !root.is_empty() {
            info.insert("DOCUMENT_ROOT".to_string(), root.to_string());
        }
        ProbeResult {
            status: String::new(),
            server: String::new(),
            web_server: String::new(),
            runtime: "php".to_string(),
            current_dir: String::new(),
            separator: "/".to_string(),
            message: String::new(),
            php_sapi: sapi.to_string(),
            arch: String::new(),
            extensions: Vec::new(),
            disable_functions: String::new(),
            info,
            capabilities: None,
        }
    }

    #[test]
    fn user_ini_requires_fpm_or_cgi() {
        // php -S 的 cli-server 不支持 .user.ini —— 实测确认，必须拒绝
        let err = php_user_ini_preconditions(&probe_with("cli-server", ".user.ini", "/var/www"))
            .unwrap_err();
        assert!(err.contains("CGI/FastCGI"), "{err}");
    }

    #[test]
    fn user_ini_accepts_fpm_and_cgi() {
        assert!(
            php_user_ini_preconditions(&probe_with("fpm-fcgi", ".user.ini", "/var/www")).is_ok()
        );
        assert!(php_user_ini_preconditions(&probe_with("cgi-fcgi", ".user.ini", "/srv")).is_ok());
    }

    #[test]
    fn user_ini_rejects_disabled_feature_and_missing_root() {
        let err = php_user_ini_preconditions(&probe_with("fpm-fcgi", "", "/var/www")).unwrap_err();
        assert!(err.contains("user_ini"), "{err}");
        let err = php_user_ini_preconditions(&probe_with("fpm-fcgi", ".user.ini", "")).unwrap_err();
        assert!(err.contains("DOCUMENT_ROOT"), "{err}");
    }
}
