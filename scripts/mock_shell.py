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
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

PASSWORD = "secret"
ROOT = ""


def decode_param(value: str) -> str:
    return base64.b64decode(value.encode()).decode("utf-8", errors="replace")


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
        if x == "" and k == "":
            # body 直传模式（php_stream）：无表单参数，stub 无鉴权
            x = raw_body

        if k != PASSWORD and not (k == "" and x != ""):
            # 仅当存在密码参数且不匹配时拒绝；body 直传模式（php_stream）无鉴权
            body = b"AUTH_FAIL"
        else:
            body = self.handle_payload(x)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_payload(self, x: str) -> bytes:
        """区分协议代码（xor_body 等）与分阶段载荷（xor_session）并应答。"""
        # Godzilla 分阶段载荷：请求体为 XOR 密文，解密后可能是处理器（含 INIT 标记）
        # 或操作参数（JSON {a, n}）
        try:
            plain = decode_payload(x)
        except Exception:
            plain = ""
        if "DswSesInit" in plain:
            # 初始化：处理器代码存入会话（模拟），返回加密的 ok
            self.server.session_handler = plain
            return xor_encrypt_text("ok")
        if plain.startswith("{") and '"a"' in plain:
            try:
                req = json.loads(plain)
                if isinstance(req, dict) and "a" in req:
                    return xor_encrypt_text(session_handle(req))
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
