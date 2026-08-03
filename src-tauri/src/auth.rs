//! 授权边界校验：Workspace 过期检查与授权范围（scope）匹配。
//!
//! 所有校验都在后端执行，前端展示的只是结果。scope 语法：
//! - 以逗号、中文顿号、空格或分号分隔的多个条目
//! - 支持：精确 host（`example.com`）、后缀通配（`*.example.com`）、
//!   IPv4/IPv6 字面量、CIDR（`10.0.0.0/8`）、裸通配（`*`）
//! - 无法解析的条目按"人工已确认"放行，审计中注明无法自动校验

use chrono::{DateTime, Local};
use url::Url;

use crate::domain::{ShellProfile, Workspace};
use crate::storage::Database;

/// 检查 Shell 所属 Workspace 的授权状态。
/// 返回 Err 表示授权过期或不存在。
pub fn check_workspace_authorized(
    workspace: Option<&Workspace>,
) -> Result<(), String> {
    let workspace = workspace.ok_or("Shell 所属的 Workspace 不存在，已禁止操作")?;
    if let Some(expires_at) = &workspace.expires_at {
        let expires = DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| "授权到期时间格式异常，已按禁止处理".to_string())?;
        let now = Local::now();
        if now > expires.with_timezone(&Local) {
            return Err(format!(
                "授权已于 {} 过期，禁止继续操作",
                expires_at
            ));
        }
    }
    Ok(())
}

/// 检查 endpoint 是否落在授权范围内，返回 (是否允许, 校验方式说明)。
pub fn scope_allows(scope: &str, url: &Url) -> (bool, String) {
    let host = match url.host_str() {
        Some(host) => host.to_lowercase(),
        None => return (false, "端点缺少主机名".to_string()),
    };
    // 提取 IP 字面量（用于 CIDR 匹配）
    let ip_addr = match url.host() {
        Some(url::Host::Ipv4(addr)) => Some(std::net::IpAddr::V4(addr)),
        Some(url::Host::Ipv6(addr)) => Some(std::net::IpAddr::V6(addr)),
        _ => None,
    };
    let host_trimmed = host.trim_end_matches('.');

    for token in scope
        .split(|c: char| c == ',' || c == '，' || c == ' ' || c == ';' || c == '\n')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let token = token.to_lowercase();
        // 裸通配
        if token == "*" {
            return (true, "通配授权".to_string());
        }
        // CIDR（IPv4/IPv6）
        if let Ok(network) = token.parse::<ipnet::IpNet>() {
            if let Some(addr) = ip_addr {
                if network.contains(&addr) {
                    return (true, format!("CIDR 范围 {token}"));
                }
            }
            continue;
        }
        // 后缀通配 *.example.com
        if let Some(suffix) = token.strip_prefix("*.") {
            if host_trimmed == suffix || host_trimmed.ends_with(&format!(".{suffix}")) {
                return (true, format!("域名后缀 {suffix}"));
            }
            continue;
        }
        // 精确 host
        if host_trimmed == token {
            return (true, format!("精确主机 {token}"));
        }
    }
    (false, format!("目标主机 {host} 不在授权范围 {scope} 内"))
}

/// 完整授权检查：Workspace 存在 + 未过期 + endpoint 在授权范围内。
/// 返回 Ok(校验说明) 表示放行。
pub fn require_authorized(
    db: &Database,
    shell: &ShellProfile,
) -> Result<String, String> {
    let workspace = db
        .workspace(&shell.workspace_id)
        .map_err(|error| format!("读取授权信息失败：{error}"))?;
    check_workspace_authorized(workspace.as_ref())?;

    let endpoint = Url::parse(&shell.endpoint)
        .map_err(|_| "Shell 端点解析失败，已按禁止处理".to_string())?;
    let (allowed, reason) = scope_allows(&workspace.unwrap().authorization_scope, &endpoint);
    if !allowed {
        return Err(format!("目标不在授权范围内：{reason}"));
    }
    Ok(reason)
}

/// 会话内的轻量复查：只检查 Workspace 是否过期（不重复做 scope 匹配）。
pub fn require_session_alive(db: &Database, shell: &ShellProfile) -> Result<(), String> {
    let workspace = db
        .workspace(&shell.workspace_id)
        .map_err(|error| format!("读取授权信息失败：{error}"))?;
    check_workspace_authorized(workspace.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::CreateWorkspace;
    use crate::storage::Database;

    fn db_with_workspace(scope: &str, expires_at: Option<String>) -> Database {
        let mut db = Database::open(":memory:").unwrap();
        db.create_workspace(CreateWorkspace {
            name: "Lab".into(),
            authorization_scope: scope.into(),
            expires_at,
        })
        .unwrap();
        db
    }

    fn shell_for(db: &Database, endpoint: &str) -> ShellProfile {
        let workspace = db.dashboard().unwrap().workspaces.into_iter().next().unwrap();
        ShellProfile {
            id: "s".into(),
            workspace_id: workspace.id,
            name: "s".into(),
            endpoint: endpoint.into(),
            runtime: "php".into(),
            protocol_id: "builtin.php.v1".into(),
            password: "".into(),
            protocol_params: "{}".into(),
            authorization_ack: true,
            status: "unknown".into(),
            last_connected_at: None,
            created_at: "2026-01-01".into(),
            tags: vec![],
        }
    }

    #[test]
    fn exact_host_matches() {
        assert_eq!(
            scope_allows("example.com", &Url::parse("http://example.com/shell.php").unwrap()).0,
            true
        );
        assert_eq!(
            scope_allows("example.com", &Url::parse("http://other.com/shell.php").unwrap()).0,
            false
        );
    }

    #[test]
    fn suffix_wildcard_matches() {
        assert_eq!(
            scope_allows("*.example.com", &Url::parse("http://sub.example.com/a.php").unwrap()).0,
            true
        );
        assert_eq!(
            scope_allows("*.example.com", &Url::parse("http://example.com/a.php").unwrap()).0,
            true,
            "裸域也应匹配 *. 后缀"
        );
        assert_eq!(
            scope_allows("*.example.com", &Url::parse("http://evil-example.com/a.php").unwrap()).0,
            false,
            "不应匹配相似后缀"
        );
    }

    #[test]
    fn cidr_matches() {
        assert_eq!(
            scope_allows("10.0.0.0/8", &Url::parse("http://10.1.2.3/a.php").unwrap()).0,
            true
        );
        assert_eq!(
            scope_allows("10.0.0.0/8", &Url::parse("http://192.168.1.1/a.php").unwrap()).0,
            false
        );
    }

    #[test]
    fn wildcard_allows_everything() {
        assert_eq!(
            scope_allows("*", &Url::parse("http://anything.example/x.php").unwrap()).0,
            true
        );
    }

    #[test]
    fn multiple_tokens_separated_by_commas() {
        assert_eq!(
            scope_allows("10.0.0.0/8, *.corp.example; localhost", &Url::parse("http://svc.corp.example/a.php").unwrap()).0,
            true
        );
    }

    #[test]
    fn expired_workspace_is_rejected() {
        let db = db_with_workspace(
            "localhost",
            Some("2000-01-01T00:00:00+08:00".into()),
        );
        let shell = shell_for(&db, "http://localhost/a.php");
        let result = require_authorized(&db, &shell);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("过期"));
    }

    #[test]
    fn valid_workspace_approves() {
        let db = db_with_workspace("localhost", None);
        let shell = shell_for(&db, "http://localhost/a.php");
        assert!(require_authorized(&db, &shell).is_ok());
    }

    #[test]
    fn out_of_scope_rejected() {
        let db = db_with_workspace("localhost", None);
        let shell = shell_for(&db, "http://10.20.30.40/a.php");
        let result = require_authorized(&db, &shell);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("不在授权范围内"));
    }
}
