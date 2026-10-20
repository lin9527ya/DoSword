//! Java 内存马的**前置通道**（尚未接入安装流程）。
//!
//! 已实现的只是「一次性页面部署 → 带 token 调用 → 立即删除」所需的模板与路径规划：
//! 它证明了「我们能往目标放一个只认 `X-DSW-TOKEN` 的临时页面，并在用完后删掉」。
//!
//! **为什么到此为止**：真正的 Java Filter 内存马必须把一个 **已编译的 Filter 类字节码**
//! 注入 `StandardContext`（`FilterDef` 需要 `javax.servlet.Filter` 的实例，运行期无法凭空
//! 造出实现类，必须自定义 `ClassLoader.defineClass` 加载内嵌字节码）。这带来三个硬性前置：
//! 1. 构建期用 javac 生成 `.class` 并内嵌（需要 JDK 与产物版本管理）；
//! 2. 卸载必须在**全新实例**上也能完成（`MemoryShell` 需记录 filter 名、类名、context 路径），
//!    否则等于给目标留后门；
//! 3. 必须有真实 Tomcat 容器做 E2E（注册/存活/卸载/残留清理），本机无容器。
//!
//! 在 1–3 达成之前，本模块**不会**出现在 `memshell_capabilities` 里，也不会被安装流程调用。
#![allow(dead_code)] // 前置通道：接入安装流程前无人调用，接入后删除本行
/// 形态标识（与 `MemoryShell.kind`、文档中的 java_filter 对齐）。
pub const KIND_JAVA_FILTER: &str = "java_filter";

/// 临时页面的文件名：由 token 派生，避免可预测的名字被第三方先行占用。
pub fn page_name(token: &str) -> String {
    let digest = dosword_sdk::encoder::md5_hex(token);
    format!("dsw_{}.jsp", &digest[..12])
}

/// 临时页面的落地路径。
pub fn page_path(dir: &str, name: &str) -> String {
    let trimmed = dir.trim_end_matches('/');
    if trimmed.is_empty() {
        format!("/{name}")
    } else {
        format!("{trimmed}/{name}")
    }
}

/// JSP 字面量转义（只用于模板占位符替换，不参与 HTML 输出）。
fn literal_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => {}
            _ => out.push(ch),
        }
    }
    out
}

const PROBE_PAGE: &str = r#"<%--
  DoSword 临时页面：仅用于验证「一次性部署 → 带 token 调用 → 立即删除」通路。
  不含注入逻辑；令牌比较走逐字符异或累加，避免提前返回泄露前缀。
--%>
<%@ page import="java.io.File" %>
<%@ page contentType="application/json;charset=UTF-8" %>
<%
    String expected = "__TOKEN__";
    String provided = request.getHeader("X-DSW-TOKEN");
    if (provided == null) provided = "";
    int diff = expected.length() ^ provided.length();
    int n = Math.min(expected.length(), provided.length());
    for (int i = 0; i < n; i++) {
        diff |= expected.charAt(i) ^ provided.charAt(i);
    }
    response.setHeader("Cache-Control", "no-store");
    if (diff != 0) {
        response.setStatus(403);
        out.print("{\"ok\":false,\"error\":\"token\"}");
        return;
    }
    String op = request.getParameter("op");
    if (op == null) op = "ping";
    if ("remove".equals(op)) {
        File self = new File(application.getRealPath(request.getServletPath()));
        boolean removed = self != null && self.exists() && self.delete();
        out.print("{\"ok\":" + removed + ",\"removed\":" + removed + "}");
        return;
    }
    out.print("{\"ok\":true,\"filter\":\"__FILTER__\"}");
%>
"#;

/// 渲染一次性页面：只认 `X-DSW-TOKEN`，支持 `op=ping` 与 `op=remove`。
///
/// 该页面**不做注入**（注入需要内嵌字节码，见模块注释），只做：
/// - `ping`：返回 `{"ok":true,"filter":"<name>"}`，用于验证「部署→调用」通路；
/// - `remove`：删除自身文件，返回 `{"ok":true,"removed":true}`，用于验证「用完即删」。
pub fn build_probe_page(token: &str, filter_name: &str) -> String {
    PROBE_PAGE
        .replace("__TOKEN__", &literal_escape(token))
        .replace("__FILTER__", &literal_escape(filter_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_name_is_derived_and_stable() {
        let a = page_name("token-aaaa");
        let b = page_name("token-bbbb");
        assert_ne!(a, b, "不同 token 必须得到不同文件名");
        assert!(a.starts_with("dsw_") && a.ends_with(".jsp"), "{a}");
        // 同 token 稳定：全新实例也能算出同一个名字去清理
        assert_eq!(a, page_name("token-aaaa"));
    }

    #[test]
    fn page_path_handles_trailing_slash() {
        assert_eq!(
            page_path("/opt/tomcat/webapps/ROOT", "dsw_x.jsp"),
            "/opt/tomcat/webapps/ROOT/dsw_x.jsp"
        );
        assert_eq!(
            page_path("/opt/tomcat/webapps/ROOT/", "dsw_x.jsp"),
            "/opt/tomcat/webapps/ROOT/dsw_x.jsp"
        );
        assert_eq!(page_path("", "dsw_x.jsp"), "/dsw_x.jsp");
    }

    #[test]
    fn probe_page_has_token_gate_and_remove_op() {
        let jsp = build_probe_page("s3cr3t-token", "dswF1");
        assert!(jsp.contains("s3cr3t-token"), "令牌必须内嵌用于比较");
        assert!(jsp.contains("X-DSW-TOKEN"), "必须只认自定义头");
        assert!(jsp.contains("\"remove\".equals(op)"), "必须支持自删除");
        assert!(jsp.contains("dswF1"), "filter 名必须可用于卸载定位");
        // 不含注入逻辑：这是本轮刻意的边界
        assert!(
            !jsp.contains("addFilterMap"),
            "尚未实现注入，不能出现踏脚石"
        );
        assert!(!jsp.contains("defineClass"), "尚未实现注入，不能出现踏脚石");
        // 令牌比较不能是 equals（避免时序与前缀泄露）
        assert!(!jsp.contains("expected.equals(provided)"));
        assert!(jsp.contains("diff |= expected.charAt(i) ^ provided.charAt(i)"));
        // 占位符必须被替换干净
        assert!(!jsp.contains("__TOKEN__"));
        assert!(!jsp.contains("__FILTER__"));
    }

    #[test]
    fn probe_page_escapes_dangerous_literals() {
        let jsp = build_probe_page("a\"b\\c", "f\"1");
        assert!(jsp.contains("a\\\"b\\\\c"), "双引号与反斜杠必须转义");
        assert!(jsp.contains("f\\\"1"));
    }
}
