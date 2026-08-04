#!/usr/bin/env python3
"""DoSword 开发辅助：按标准 PHP 协议应答的本地假 Shell 服务器。

用于在没有 PHP 环境的机器上联调 UI（探测 / 连接 / 文件 / 命令）。
响应行为是"模拟"的，不会真正执行命令或读写文件——命令返回固定回显，
文件操作落在 --root 指定的临时目录上（真实读写，便于验证文件功能）。

用法:
    python3 scripts/mock_shell.py [--port 18080] [--password secret] [--root /tmp/mock-root]

在 DoSword 中登记 Shell:
    Endpoint: http://127.0.0.1:18080/shell.php
    协议:     标准 PHP WebShell（类蚁剑）
    密码:     secret（与 --password 一致）
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sqlite3
import sys
import secrets
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

PASSWORD = "secret"
ROOT = ""


def decode_param(value: str) -> str:
    return base64.b64decode(value.encode()).decode("utf-8", errors="replace")


def looks_plain(raw: bytes) -> bool:
    """明文载荷特征：@ini_set / DswSesInit 特征串，或以 { 开头且为合法 JSON。
    （避免 AES/流密码密文首字节恰为 0x7b 时误判为 b64 明文）"""
    if b"@ini_set" in raw or b"DswSesInit" in raw:
        return True
    if raw[:1] == b"{":
        try:
            json.loads(raw)
            return True
        except Exception:
            return False
    return False


def decode_payload_mode(x: str) -> tuple:
    """解码载荷并返回 (明文, 编码方式)。mode: "b64"|"xor"|"aes-ecb"|"aes-cbc"|"des-ecb"。"""
    raw = base64.b64decode(x)
    if looks_plain(raw):
        return raw.decode("utf-8", errors="replace"), "b64"
    key = hashlib.md5(PASSWORD.encode()).hexdigest().encode()
    xored = bytes(c ^ key[i % len(key)] for i, c in enumerate(raw))
    if looks_plain(xored):
        return xored.decode("utf-8", errors="replace"), "xor"
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding

        schemes = [
            (algorithms.AES(key), "aes-ecb", None),
            (algorithms.AES(key), "aes-cbc", modes.CBC(key[16:])),
        ]
        for algo, name, mode_obj in schemes:
            try:
                dec = Cipher(algo, mode_obj or modes.ECB()).decryptor()
                padded = dec.update(raw) + dec.finalize()
                unpadder = sym_padding.PKCS7(algo.block_size).unpadder()
                restored = unpadder.update(padded) + unpadder.finalize()
                if looks_plain(restored):
                    return restored.decode("utf-8", errors="replace"), name
            except Exception:
                continue
    except ImportError:
        pass
    try:
        from Crypto.Cipher import DES as PyDes

        dec = PyDes.new(key[:8], PyDes.MODE_ECB)
        restored = dec.decrypt(raw)
        pad_len = restored[-1]
        if pad_len <= 8:
            restored = restored[:-pad_len]
        if looks_plain(restored):
            return restored.decode("utf-8", errors="replace"), "des-ecb"
    except (ImportError, ValueError):
        pass
    # CHACHA20：载荷 = nonce[12] + 密钥流异或（key = md5 hex ASCII 32B，请求 counter=0）
    try:
        from Crypto.Cipher import ChaCha20

        if len(raw) > 12:
            nonce = raw[:12]
            ck = hashlib.md5(PASSWORD.encode()).hexdigest().encode()
            dec = ChaCha20.new(key=ck, nonce=nonce)
            restored = dec.decrypt(raw[12:])
            if looks_plain(restored):
                return restored.decode("utf-8", errors="replace"), "chacha20"
    except (ImportError, ValueError, TypeError):
        pass
    # RABBIT：载荷 = iv[8] + 密钥流异或（key = md5 16B，请求 skip=0）
    if len(raw) > 8:
        iv = raw[:8]
        rk = hashlib.md5(PASSWORD.encode()).digest()
        restored = rabbit_stream(rk, iv, 0, raw[8:])
        if looks_plain(restored):
            return restored.decode("utf-8", errors="replace"), "rabbit"
    raise ValueError("无法识别的载荷编码")


def decode_payload(x: str) -> str:
    """解码客户端载荷。注意：CHAR/OBFUSCATE 载荷不经 base64（stub 直接 eval），
    其余编码器（base64/xor/aes/des）经 base64。特征串 @ini_set 判断。"""
    # 1) 明文混淆载荷（CHAR / OBFUSCATE）
    if "array_map('chr',array(" in x:
        numbers = x.rsplit("array(", 1)[1].split(")")[0]
        restored = bytes(int(n) for n in numbers.split(",") if n.strip())
        if b"@ini_set" in restored:
            return restored.decode("utf-8", errors="replace")
    if "strrev('" in x:
        reversed_b64 = x.split("strrev('")[1].split("')")[0]
        restored = base64.b64decode(reversed_b64[::-1])
        if b"@ini_set" in restored:
            return restored.decode("utf-8", errors="replace")

    # 2) base64 载荷（裸 / XOR / AES / DES）
    raw = base64.b64decode(x)
    key = hashlib.md5(PASSWORD.encode()).hexdigest().encode()
    if b"@ini_set" in raw:
        return raw.decode("utf-8", errors="replace")
    xored = bytes(c ^ key[i % len(key)] for i, c in enumerate(raw))
    if b"@ini_set" in xored or xored[:1] == b"{" or b"DswSesInit" in xored:
        # 协议代码 / Godzilla 分阶段参数（JSON）/ 分阶段初始化（处理器代码）
        return xored.decode("utf-8", errors="replace")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding

        hex_key = hashlib.md5(PASSWORD.encode()).hexdigest().encode()
        schemes = [
            (algorithms.AES(hex_key[:16]), "aes-ecb"),
            (algorithms.AES(hex_key[:16]), "aes-cbc"),
            (algorithms.DES(hex_key[:8]), "des-ecb"),
        ]
        for algo, name in schemes:
            try:
                if name == "aes-cbc":
                    dec = Cipher(algo, modes.CBC(hex_key[16:])).decryptor()
                else:
                    dec = Cipher(algo, modes.ECB()).decryptor()
                padded = dec.update(raw) + dec.finalize()
                unpadder = sym_padding.PKCS7(algo.block_size).unpadder()
                restored = unpadder.update(padded) + unpadder.finalize()
                if b"@ini_set" in restored:
                    return restored.decode("utf-8", errors="replace")
            except Exception:
                continue
    except ImportError:
        pass
    raise ValueError("无法识别的载荷编码")


def grab_int(code: str, pattern: str) -> int:
    match = re.search(pattern, code)
    return int(match.group(1)) if match else 0


def handle_code(code: str) -> dict:
    """模拟服务端 eval 的执行结果。返回 (ok, data 或 error)。"""
    # 解析客户端载荷里的参数字面量
    def grab(pattern: str) -> str:
        match = re.search(pattern, code)
        return decode_param(match.group(1)) if match else ""

    if "shell_exec" in code:
        cmd = grab(r"\$c=base64_decode\('([^']+)'\)")
        return {"ok": True, "data": {"stdout": base64.b64encode(
            f"[mock] 已执行：{cmd}\n真实输出需 PHP 环境".encode()
        ).decode()}}
    if "scandir" in code:
        path = grab(r"\$p=base64_decode\('([^']+)'\)")
        entries = []
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                full = os.path.join(path, name)
                entries.append({
                    "name": name,
                    "path": full,
                    "is_dir": os.path.isdir(full),
                    "size": 0 if os.path.isdir(full) else os.path.getsize(full),
                    "mtime": int(os.path.getmtime(full)),
                })
        return {"ok": True, "data": {"entries": entries}}
    if "file_get_contents" in code:
        path = grab(r"\$p=base64_decode\('([^']+)'\)")
        try:
            with open(path, "rb") as fh:
                return {"ok": True, "data": base64.b64encode(fh.read()).decode()}
        except OSError:
            return {"ok": False, "error": "读取文件失败"}
    if "fopen($p,'rb')" in code:
        # 分块读取（fseek 定位）
        path = grab(r"\$p=base64_decode\('([^']+)'\)")
        off = grab_int(code, r"\$off=(\d+)")
        length = grab_int(code, r"\$len=(\d+)")
        try:
            with open(path, "rb") as fh:
                fh.seek(off)
                data = fh.read(length) if length > 0 else fh.read()
            return {"ok": True, "data": base64.b64encode(data).decode()}
        except OSError:
            return {"ok": False, "error": "读取文件失败"}
    if "r+b" in code:
        # 分块写入（fopen r+b / w+b）
        path = grab(r"\$p=base64_decode\('([^']+)'\)")
        data = grab(r"\$d=base64_decode\('([^']+)'\)")
        off = grab_int(code, r"\$off=(\d+)")
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "r+b" if os.path.exists(path) else "wb") as fh:
                fh.seek(off)
                fh.write(data.encode("utf-8"))
            return {"ok": True, "data": {"bytes": len(data)}}
        except OSError:
            return {"ok": False, "error": "写入文件失败"}
    if "file_put_contents" in code:
        path = grab(r"\$p=base64_decode\('([^']+)'\)")
        data = grab(r"\$d=base64_decode\('([^']+)'\)")
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(data.encode("utf-8"))
            return {"ok": True, "data": {"bytes": len(data)}}
        except OSError:
            return {"ok": False, "error": "写入文件失败"}
    if "rmdir" in code or "unlink" in code:
        path = grab(r"\$p=base64_decode\('([^']+)'\)")
        try:
            if os.path.isdir(path):
                os.rmdir(path)
            else:
                os.unlink(path)
            return {"ok": True, "data": {}}
        except OSError:
            return {"ok": False, "error": "删除失败（目录非空或权限不足）"}
    if "rename" in code:
        src = grab(r"\$f=base64_decode\('([^']+)'\)")
        dst = grab(r"\$t=base64_decode\('([^']+)'\)")
        try:
            os.rename(src, dst)
            return {"ok": True, "data": {}}
        except OSError:
            return {"ok": False, "error": "重命名失败"}
    if "mkdir" in code:
        path = grab(r"\$p=base64_decode\('([^']+)'\)")
        try:
            os.makedirs(path, exist_ok=True)
            return {"ok": True, "data": {}}
        except OSError:
            return {"ok": False, "error": "创建目录失败（权限不足或已存在）"}
    if "new PDO" in code:
        # 数据库操作：sqlite 用 python sqlite3 真实执行（mysql/pgsql 仅回显连接成功）
        dsn = grab(r"\$dsn=base64_decode\('([^']+)'\)")
        if "$dbh->query($sql)" in code:
            sql = grab(r"\$sql=base64_decode\('([^']+)'\)")
            try:
                if dsn.startswith("sqlite:"):
                    conn = sqlite3.connect(dsn[len("sqlite:"):])
                    cursor = conn.execute(sql)
                    if sql.lstrip().lower().startswith(("select", "show", "desc", "pragma", "with")):
                        columns = [desc[0] for desc in cursor.description or []]
                        rows = [[None if v is None else str(v) for v in row] for row in cursor.fetchall()[:1000]]
                        return {"ok": True, "data": {"columns": columns, "rows": rows, "affected": 0}}
                    conn.commit()
                    return {"ok": True, "data": {"columns": [], "rows": [], "affected": cursor.rowcount}}
                return {"ok": True, "data": {"columns": ["notice"], "rows": [["[mock] 非 sqlite 驱动不做真实执行"]], "affected": 0}}
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "error": f"数据库操作失败：{exc}"}
        # 探测：连接 + 列出数据库
        if dsn.startswith("sqlite:"):
            path = dsn[len("sqlite:"):]
            return {"ok": True, "data": {"driver": "sqlite", "databases": [path]}}
        return {"ok": True, "data": {"driver": "mysql", "databases": ["information_schema", "mysql"]}}
    # 默认视为环境信息探测
    return {
        "ok": True,
        "data": {
            "server": "Mock Linux 6.x (mock_shell.py)",
            "web_server": "Python http.server",
            "php_version": "8.2.0 (模拟)",
            "current_dir": ROOT,
            "separator": "/",
        },
    }


def xor_bytes(data: bytes) -> bytes:
    """按密码 md5 派生密钥做 XOR（与客户端一致）。"""
    key = hashlib.md5(PASSWORD.encode()).hexdigest().encode()
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def xor_encrypt_text(text: str) -> bytes:
    """加密文本响应（base64(XOR)），与 xor_body/xor_session stub 的 pack 一致。"""
    return base64.b64encode(xor_bytes(text.encode()))


def native_handle(req: dict) -> str:
    """NATIVE 分发模拟：返回纯 JSON 结果（无帧）。"""
    action = req.get("a", "")
    if action == "probe":
        return json.dumps({"ok": True, "data": {
            "server": "Mock Linux 6.x (mock_shell.py)", "web_server": "Python http.server",
            "php_version": "8.2.0 (模拟)", "current_dir": ROOT, "separator": "/"}})
    if action == "exec":
        return json.dumps({"ok": True, "data": {
            "stdout": base64.b64encode(f"[mock] 已执行：{req.get('c', '')}".encode()).decode(),
            "cwd": ROOT}})
    if action == "list":
        entries = []
        path = str(req.get("p", ROOT))
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                full = os.path.join(path, name)
                entries.append({"name": name, "path": full, "is_dir": os.path.isdir(full),
                                "size": 0 if os.path.isdir(full) else os.path.getsize(full),
                                "mtime": int(os.path.getmtime(full))})
        return json.dumps({"ok": True, "data": {"entries": entries}})
    return json.dumps({"ok": False, "error": f"mock 暂不支持操作：{action}"})


def encrypt_native_des(text: str) -> str:
    """DES-ECB 加密（pycryptodome）。"""
    try:
        from Crypto.Cipher import DES as PyDes

        key = hashlib.md5(PASSWORD.encode()).hexdigest().encode()[:8]
        pad_len = 8 - (len(text.encode()) % 8)
        padded = text.encode() + bytes([pad_len]) * pad_len
        enc = PyDes.new(key, PyDes.MODE_ECB)
        return base64.b64encode(enc.encrypt(padded)).decode()
    except ImportError:
        return base64.b64encode(text.encode()).decode()


def rabbit_stream(key: bytes, iv: bytes, skip: int, data: bytes) -> bytes:
    """Rabbit（RFC 4503）密钥流异或，纯 Python 参考实现（与 SDK/PHP 同规格）。"""
    M32 = 0xFFFFFFFF
    k = []
    for i in range(8):
        k.append((key[14 - 2 * i] << 8) | key[15 - 2 * i])
    x = [0] * 8
    c = [0] * 8
    for j in range(8):
        if j % 2 == 0:
            x[j] = ((k[(j + 1) % 8] << 16) | k[j]) & M32
            c[j] = ((k[(j + 4) % 8] << 16) | k[(j + 5) % 8]) & M32
        else:
            x[j] = ((k[(j + 5) % 8] << 16) | k[(j + 4) % 8]) & M32
            c[j] = ((k[j] << 16) | k[(j + 1) % 8]) & M32
    aa = [0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3]
    b = 0

    def rc():
        nonlocal b
        for j in range(8):
            t = c[j] + aa[j] + b
            b = (t >> 32) & M32
            c[j] = t & M32

    def g(u, v):
        s = (u + v) & M32
        sq = s * s
        return (sq & M32) ^ ((sq >> 32) & M32)

    def rx():
        gs = [g(x[j], c[j]) for j in range(8)]
        x[0] = (gs[0] + ((gs[7] << 16) | (gs[7] >> 16)) + ((gs[6] << 16) | (gs[6] >> 16))) & M32
        x[1] = (gs[1] + ((gs[0] << 8) | (gs[0] >> 24)) + gs[7]) & M32
        x[2] = (gs[2] + ((gs[1] << 16) | (gs[1] >> 16)) + ((gs[0] << 16) | (gs[0] >> 16))) & M32
        x[3] = (gs[3] + ((gs[2] << 8) | (gs[2] >> 24)) + gs[1]) & M32
        x[4] = (gs[4] + ((gs[3] << 16) | (gs[3] >> 16)) + ((gs[2] << 16) | (gs[2] >> 16))) & M32
        x[5] = (gs[5] + ((gs[4] << 8) | (gs[4] >> 24)) + gs[3]) & M32
        x[6] = (gs[6] + ((gs[5] << 16) | (gs[5] >> 16)) + ((gs[4] << 16) | (gs[4] >> 16))) & M32
        x[7] = (gs[7] + ((gs[6] << 8) | (gs[6] >> 24)) + gs[5]) & M32

    for _ in range(4):
        rc(); rx()
    for j in range(8):
        c[j] = (c[j] ^ x[(j + 4) % 8]) & M32
    iv0 = int.from_bytes(iv[4:8], "big")
    iv1 = int.from_bytes(iv[0:4], "big")
    mh = ((iv1 & 0xFFFF0000) | ((iv0 >> 16) & 0xFFFF)) & M32
    ml = (((iv1 & 0xFFFF) << 16) | (iv0 & 0xFFFF)) & M32
    c[0] ^= iv0; c[1] ^= mh; c[2] ^= iv1; c[3] ^= ml
    c[4] ^= iv0; c[5] ^= mh; c[6] ^= iv1; c[7] ^= ml
    for _ in range(4):
        rc(); rx()
    ks = b""
    need = skip + len(data)
    while len(ks) < need:
        rc(); rx()
        w = [
            (x[0] & 0xFFFF) ^ (x[5] >> 16),
            (x[0] >> 16) ^ (x[3] & 0xFFFF),
            (x[2] & 0xFFFF) ^ (x[7] >> 16),
            (x[2] >> 16) ^ (x[5] & 0xFFFF),
            (x[4] & 0xFFFF) ^ (x[1] >> 16),
            (x[4] >> 16) ^ (x[7] & 0xFFFF),
            (x[6] & 0xFFFF) ^ (x[3] >> 16),
            (x[6] >> 16) ^ (x[1] & 0xFFFF),
        ]
        for i in range(7, -1, -1):
            ks += bytes([(w[i] >> 8) & 0xFF, w[i] & 0xFF])
    return bytes(d ^ kk for d, kk in zip(data, ks[skip:skip + len(data)]))


def encrypt_native_mode(text: str, mode: str) -> str:
    """按请求的编码方式加密 NATIVE 响应（data 字段内容）。"""
    if mode == "xor":
        return xor_encrypt_text(text).decode()
    if mode in ("aes-ecb", "aes-cbc"):
        try:
            from Crypto.Cipher import AES

            key = hashlib.md5(PASSWORD.encode()).hexdigest().encode()
            pad = 16 - (len(text.encode()) % 16)
            padded = text.encode() + bytes([pad]) * pad
            if mode == "aes-cbc":
                iv = hashlib.md5(PASSWORD.encode()).hexdigest().encode()[16:]
                enc = AES.new(key, AES.MODE_CBC, iv)
            else:
                enc = AES.new(key, AES.MODE_ECB)
            return base64.b64encode(enc.encrypt(padded)).decode()
        except (ImportError, ValueError, TypeError):
            return base64.b64encode(text.encode()).decode()
    if mode == "chacha20":
        try:
            from Crypto.Cipher import ChaCha20

            nonce = secrets.token_bytes(12)
            ck = hashlib.md5(PASSWORD.encode()).hexdigest().encode()
            enc = ChaCha20.new(key=ck, nonce=nonce)
            return base64.b64encode(nonce + enc.encrypt(text.encode())).decode()
        except (ImportError, ValueError, TypeError):
            return base64.b64encode(text.encode()).decode()
    if mode == "rabbit":
        iv = secrets.token_bytes(8)
        rk = hashlib.md5(PASSWORD.encode()).digest()
        return base64.b64encode(iv + rabbit_stream(rk, iv, 64, text.encode())).decode()
    if mode in ("aes-ecb", "aes-cbc", "des-ecb"):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding as sym_padding

            key = hashlib.md5(PASSWORD.encode()).hexdigest().encode()
            if mode == "aes-ecb":
                cipher = Cipher(algorithms.AES(key[:16]), modes.ECB())
            elif mode == "aes-cbc":
                cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(key[16:]))
            else:
                return encrypt_native_des(text)
            padder = sym_padding.PKCS7(cipher.algorithm.block_size).padder()
            padded = padder.update(text.encode()) + padder.finalize()
            enc = cipher.encryptor()
            return base64.b64encode(enc.update(padded) + enc.finalize()).decode()
        except ImportError:
            return base64.b64encode(text.encode()).decode()
    return base64.b64encode(text.encode()).decode()


def session_handle(req: dict) -> str:
    """模拟 Godzilla 分阶段载荷的 run()：exec / probe / list 基础操作。"""
    action = req.get("a", "")
    nonce = str(req.get("n", "abababab"))
    if action == "probe":
        out = {
            "ok": True,
            "data": {
                "server": "Mock Linux 6.x (mock_shell.py)",
                "web_server": "Python http.server",
                "php_version": "8.2.0 (模拟)",
                "current_dir": ROOT,
                "separator": "/",
            },
        }
    elif action == "exec":
        cmd = str(req.get("c", ""))
        out = {
            "ok": True,
            "data": {
                "stdout": base64.b64encode(f"[mock] 已执行：{cmd}".encode()).decode(),
                "cwd": ROOT,
            },
        }
    elif action == "list":
        entries = []
        path = str(req.get("p", ROOT))
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                full = os.path.join(path, name)
                entries.append({
                    "name": name, "path": full, "is_dir": os.path.isdir(full),
                    "size": 0 if os.path.isdir(full) else os.path.getsize(full),
                    "mtime": int(os.path.getmtime(full)),
                })
        out = {"ok": True, "data": {"entries": entries}}
    else:
        out = {"ok": False, "error": f"mock 暂不支持 session 操作：{action}"}
    return nonce + base64.b64encode(json.dumps(out).encode()).decode() + nonce


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(raw_body)
        # 标准参数（k/x）、业务伪装参数（token/data）与 body 直传（php_stream）均支持
        k = params.get("k", [""])[0] or params.get("token", [""])[0]
        x = params.get("x", [""])[0] or params.get("data", [""])[0]
        fd = params.get("formData", [""])[0]
        if fd != "":
            # NATIVE 分发：formData 参数 + X-Debug-Key 头鉴权（模拟）
            status, body = self.handle_native(fd)
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        elif x == "" and k == "":
            # body 直传模式（php_stream）：无表单参数，stub 无鉴权
            x = raw_body
            body = self.handle_payload(x)
        elif k != PASSWORD:
            body = b"AUTH_FAIL"
        else:
            body = self.handle_payload(x)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_payload(self, x: str) -> bytes:
        """区分协议代码（xor_body 等）、分阶段载荷（session 模式）与 NATIVE 分发并应答。"""
        # 识别请求编码方式：XOR 密文或明文 base64（决定 session 响应加密方式）
        mode = "b64"
        try:
            plain, mode = decode_payload_mode(x)
        except Exception:
            plain = ""
        if "DswSesInit" in plain:
            # 初始化：处理器代码存入会话（模拟），按请求编码返回 ok
            self.server.session_handler = plain
            return self.encrypt("ok", mode)
        if plain.startswith("{") and '"a"' in plain:
            try:
                req = json.loads(plain)
                if isinstance(req, dict) and "a" in req:
                    return self.encrypt(session_handle(req), mode)
            except Exception:
                pass
        # 普通协议代码（表单参数或 body 直传的 xor_body 等）
        code = plain
        result = handle_code(code)
        # 提取客户端 nonce 帧标记
        nonce = "abababab"
        match = re.search(r"echo '([0-9a-f]{8,})'", code)
        if match:
            nonce = match.group(1)
        payload = base64.b64encode(json.dumps(result).encode()).decode()
        return f"{nonce}{payload}{nonce}".encode()

    def handle_native(self, fd: str):
        """NATIVE 分发模拟：返回 (status, body)。鉴权失败 404，成功返回 XOR 加密 JSON。"""
        token = self.headers.get("X-Debug-Key", "")
        if token != hashlib.md5(PASSWORD.encode()).hexdigest()[:16]:
            return 404, b""
        try:
            plain, mode = decode_payload_mode(fd)
            req = json.loads(plain)
        except Exception:
            req, mode = {}, "b64"
        if not isinstance(req, dict):
            req = {}
        out = native_handle(req)
        enc = encrypt_native_mode(out, mode)
        return 200, json.dumps({"data": enc, "code": 200}).encode()

    @staticmethod
    def encrypt(text: str, mode: str) -> bytes:
        """按请求编码方式加密 session 响应。"""
        if mode == "xor":
            return xor_encrypt_text(text)
        if mode in ("aes-ecb", "aes-cbc", "des-ecb"):
            return encrypt_native_mode(text, mode).encode()
        return base64.b64encode(text.encode())

    def log_message(self, fmt, *args):  # noqa: A003
        sys.stderr.write("[mock-shell] %s\n" % (fmt % args))


def main():
    global PASSWORD, ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--password", default="secret")
    parser.add_argument("--root", default=None, help="文件操作的根目录（默认临时目录）")
    args = parser.parse_args()

    PASSWORD = args.password
    ROOT = os.path.abspath(args.root) if args.root else tempfile.mkdtemp(prefix="dosword-mock-")
    os.makedirs(ROOT, exist_ok=True)

    print(f"Mock Shell 已启动：http://127.0.0.1:{args.port}/shell.php")
    print(f"密码：{PASSWORD}    文件根目录：{ROOT}")
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
