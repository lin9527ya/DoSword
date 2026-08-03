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
    if b"@ini_set" in xored:
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


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        params = parse_qs(self.rfile.read(length).decode("utf-8"))
        # 标准参数（k/x）与业务伪装参数（token/data）均支持
        k = params.get("k", [""])[0] or params.get("token", [""])[0]
        x = params.get("x", [""])[0] or params.get("data", [""])[0]

        if k != PASSWORD:
            body = b"AUTH_FAIL"
        else:
            try:
                code = decode_payload(x)
            except Exception:
                code = ""
            result = handle_code(code)
            # 提取客户端 nonce 帧标记
            nonce = "abababab"
            match = re.search(r"echo '([0-9a-f]{8,})'", code)
            if match:
                nonce = match.group(1)
            payload = base64.b64encode(json.dumps(result).encode()).decode()
            body = f"{nonce}{payload}{nonce}".encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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
