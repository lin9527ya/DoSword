import { useEffect, useState } from "react";
import { Copy, Dices, Download, LoaderCircle, Sparkles } from "lucide-react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText } from "../api";
import type { GenerateShellResult } from "../api";
import { Dialog } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { isNativeEncoder, supportsSessionMode } from "../shells/encoders";

const LANGUAGES: { value: string; label: string }[] = [
  { value: "php", label: "PHP (.php)" },
  { value: "jsp", label: "JSP (.jsp)" },
  { value: "aspx", label: "ASP.NET C# (.aspx)" },
  { value: "asp", label: "ASP VBScript (.asp)" },
  { value: "python", label: "Python (.py / WSGI)" },
  { value: "node", label: "Node.js (.js / Express)" },
];

export function GenerateShellDialog({
  onClose,
}: {
  onClose: () => void;
}) {
  const toast = useToast();
  const [language, setLanguage] = useState("php");
  const [encoders, setEncoders] = useState<[string, string][]>([]);
  const [encoderId, setEncoderId] = useState("native");
  const [password, setPassword] = useState("pass123");
  // 分阶段载荷（Godzilla session 模式）：处理器只注入一次，后续只传参数。
  // 必须与连接端的 session 配置一致，故显式暴露而不是写死。
  const [sessionMode, setSessionMode] = useState(false);
  // 加盐派生：stub 用 salt:password 派生密钥与令牌，登记 Shell 时需填入同一个盐
  const [salted, setSalted] = useState(false);
  // 传输形态（W2）：参数名 / 鉴权头名烘焙进 NATIVE stub，登记 Shell 时必须一致
  const [param, setParam] = useState("");
  const [header, setHeader] = useState("");
  const [result, setResult] = useState<GenerateShellResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    void api.listEncoders().then(setEncoders).catch(() => {});
  }, []);

  function generateRandomPassword() {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let pwd = "";
    for (let i = 0; i < 12; i++) {
      pwd += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    setPassword(pwd);
  }

  async function generate() {
    if (!password.trim()) {
      toast.warning("请填写连接密码（用于派生 XOR 加密密钥）");
      return;
    }
    setBusy(true);
    setError("");
    setCopied(false);
    try {
      const res = await api.generateShell(
        language,
        encoderId,
        password,
        sessionMode,
        salted,
        param.trim() || undefined,
        header.trim() || undefined,
      );
      setResult(res);
      toast.success(`Webshell 代码生成完毕 (${res.filename})`, "生成成功");
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "生成失败");
    } finally {
      setBusy(false);
    }
  }

  async function saveFile() {
    if (!result) return;
    try {
      const localPath = await save({ defaultPath: result.filename });
      if (!localPath) return;
      await api.writeLocalFile(localPath, b64.encodeText(result.content));
      toast.success(`文件已保存至 ${localPath}`, "保存成功");
    } catch (cause) {
      toast.error(`保存失败：${errorText(cause)}`);
    }
  }

  async function copyContent() {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.content);
      setCopied(true);
      toast.info("代码内容已成功复制到剪贴板");
    } catch {
      toast.error("复制失败");
    }
  }

  return (
    <Dialog title="生成 WebShell 服务端 Stub" onClose={onClose}>
      <div className="generate-form">
        {error && <p className="form-note error">{error}</p>}
        
        <label>
          目标语言与环境
          <select value={language} onChange={(event) => setLanguage(event.target.value)}>
            {LANGUAGES.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </label>

        <label>
          加密/编码器模板
          <select value={encoderId} onChange={(event) => setEncoderId(event.target.value)}>
            {encoders.map(([id, displayName]) => (
              <option key={id} value={id}>
                {displayName}
              </option>
            ))}
          </select>
        </label>

        <label>
          连接鉴权密码 (派生 XOR 混淆密钥)
          <div style={{ display: "flex", gap: 8 }}>
            <input
              type="text"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="自定义鉴权密钥 (例如 pass123)"
              style={{ flex: 1 }}
            />
            <button
              type="button"
              className="button secondary compact"
              onClick={generateRandomPassword}
              title="生成高强度随机密码"
            >
              <Dices size={14} />
              随机
            </button>
          </div>
        </label>

        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input
            type="checkbox"
            checked={sessionMode && supportsSessionMode(encoderId)}
            disabled={!supportsSessionMode(encoderId)}
            onChange={(event) => setSessionMode(event.target.checked)}
            style={{ width: "auto", margin: 0 }}
          />
          生成分阶段载荷（session 模式）
        </label>
        <p className="form-note" style={{ marginTop: -4 }}>
          {supportsSessionMode(encoderId)
            ? "Godzilla 风格：处理器只注入一次，后续请求只传参数。登记 Shell 时需在表单里勾选同名开关；普通 stub 请保持关闭。"
            : `${encoderId} 不使用分阶段载荷${isNativeEncoder(encoderId) ? "（NATIVE 自带内置分发）" : "（请求体直传）"}，生成的始终是普通 stub。`}
        </p>

        {isNativeEncoder(encoderId) && !sessionMode && (
          <>
            <label>
              请求参数名（可选）
              <input
                value={param}
                onChange={(event) => setParam(event.target.value)}
                placeholder="formData"
              />
              <span className="field-hint">
                NATIVE stub 的请求参数名；留空 = 默认 formData。登记 Shell 时需填入同一个值。
              </span>
            </label>
            <label>
              鉴权头名（可选）
              <input
                value={header}
                onChange={(event) => setHeader(event.target.value)}
                placeholder="X-Debug-Key"
              />
              <span className="field-hint">
                NATIVE stub 的鉴权请求头；留空 = 默认 X-Debug-Key。登记 Shell 时需填入同一个值。
              </span>
            </label>
          </>
        )}

        <label style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <input
            type="checkbox"
            checked={salted}
            onChange={(event) => setSalted(event.target.checked)}
            style={{ width: "auto", margin: 0 }}
          />
          加盐密钥派生（salt:password）
        </label>
        <p className="form-note" style={{ marginTop: -4 }}>
          开启后每次生成的 stub 使用随机盐派生密钥与鉴权令牌，能抵抗针对 stub 的弱口令爆破；
          但登记 Shell 时**必须把生成的盐填进「密钥盐」字段**，否则无法连接。
        </p>

        <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 4 }}>
          <button className="button primary" onClick={() => void generate()} disabled={busy}>
            {busy ? <LoaderCircle className="spin" size={14} /> : <Sparkles size={14} />}
            {busy ? "正在生成…" : "立即生成 Stub"}
          </button>
        </div>

        {result && (
          <div className="generate-result">
            <div className="generate-result-head">
              <code>{result.filename}</code>
              <div style={{ display: "flex", gap: 6 }}>
                <button className="button compact secondary" onClick={() => void copyContent()}>
                  <Copy size={13} />
                  {copied ? "已复制" : "复制代码"}
                </button>
                <button className="button compact primary" onClick={() => void saveFile()}>
                  <Download size={13} />
                  保存文件
                </button>
              </div>
            </div>

            {result.salt && (
              <div
                style={{
                  padding: "8px 12px",
                  border: "1px solid var(--warning, #d29922)",
                  borderRadius: "var(--radius-md)",
                  background: "color-mix(in srgb, var(--warning, #d29922) 10%, transparent)",
                  fontSize: 12,
                }}
              >
                <strong>密钥盐：</strong>
                <code className="mono">{result.salt}</code>
                <button
                  className="button compact secondary"
                  style={{ marginLeft: 8 }}
                  onClick={() => {
                    void navigator.clipboard.writeText(result.salt ?? "");
                    toast.info("盐已复制");
                  }}
                >
                  复制
                </button>
                <div className="form-note" style={{ marginTop: 4 }}>
                  登记该 Shell 时，把此盐填入「密钥盐」字段（或协议参数
                  <code>{" "}{`{"encoder":"..." ,"salt":"${result.salt}"}`} </code>）。
                  盐丢失后该 stub 无法再连接。
                </div>
              </div>
            )}

            <pre>{result.content}</pre>

            <div style={{ padding: "8px 12px", background: "var(--panel-2)", borderRadius: "var(--radius-md)", fontSize: 11.5 }}>
              <p style={{ color: "var(--text-dim)", lineHeight: 1.55 }}>
                💡 <strong>部署说明：</strong>
                将生成的代码部署至授权测试环境后，在 DoSword 中「登记 Shell」并填入相同语言、密码与编码器即可建立安全连接通道。
              </p>
            </div>
          </div>
        )}
      </div>
    </Dialog>
  );
}
