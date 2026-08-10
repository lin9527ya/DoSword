import { useState } from "react";
import { Save, X } from "lucide-react";
import { api, b64, errorText } from "../api";
import type { FileEntry } from "../api";

type Encoding = "utf-8" | "gbk" | "hex";

function decodeByEncoding(contentB64: string, encoding: Encoding): string {
  const bytes = b64.decodeBytes(contentB64);
  if (encoding === "hex") {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  try {
    return new TextDecoder(encoding === "gbk" ? "gbk" : "utf-8", { fatal: false }).decode(bytes);
  } catch {
    return b64.decodeText(contentB64);
  }
}

/** 文件编辑器：UTF-8 / GBK / HEX 编码读写。 */
export function FileEditor({
  sessionId,
  entry,
  onClose,
  onSaved,
}: {
  sessionId: string;
  entry: FileEntry & { contentB64?: string };
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const [encoding, setEncoding] = useState<Encoding>("utf-8");
  const [content, setContent] = useState(() =>
    entry.contentB64 ? decodeByEncoding(entry.contentB64, "utf-8") : "",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  function switchEncoding(next: Encoding) {
    if (!entry.contentB64) return;
    setContent(decodeByEncoding(entry.contentB64, next));
    setEncoding(next);
  }

  async function saveFile() {
    setBusy(true);
    setError("");
    try {
      let payload: string;
      if (encoding === "utf-8") {
        payload = b64.encodeText(content);
      } else if (encoding === "gbk") {
        payload = await api.encodeText(content, "gbk");
      } else {
        const hex = content.replace(/[\s:]+/g, "");
        if (hex.length % 2 !== 0) throw new Error("HEX 内容长度必须为偶数");
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i += 1) {
          const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
          if (Number.isNaN(byte)) throw new Error(`HEX 包含非法字符：${hex.slice(i * 2, i * 2 + 2)}`);
          bytes[i] = byte;
        }
        payload = b64.encodeBytes(bytes);
      }
      await api.writeFile(sessionId, entry.path, payload);
      await onSaved();
      onClose();
    } catch (cause) {
      setError(errorText(cause));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="editor-backdrop" onMouseDown={onClose}>
      <section className="editor" onMouseDown={(event) => event.stopPropagation()}>
        <div className="editor-head">
          <strong>{entry.name}</strong>
          <span className="mono muted">{entry.path}</span>
          <div className="editor-actions">
            <select
              className="select editor-encoding"
              value={encoding}
              onChange={(event) => switchEncoding(event.target.value as Encoding)}
              title="切换编码会重新按编码解码文件内容（未保存的修改将丢失）"
            >
              <option value="utf-8">UTF-8</option>
              <option value="gbk">GBK</option>
              <option value="hex">HEX</option>
            </select>
            {error && <span className="editor-error">{error}</span>}
            <button className="button compact primary" onClick={() => void saveFile()} disabled={busy}>
              <Save size={14} />
              {busy ? "保存中…" : "保存"}
            </button>
            <button className="icon-button" onClick={onClose}>
              <X size={15} />
            </button>
          </div>
        </div>
        <div className="editor-body-wrap">
          {encoding !== "hex" && (
            <div className="editor-gutter" aria-hidden>
              {Array.from({ length: Math.max(1, content.split("\n").length) }, (_, index) => (
                <span key={index}>{index + 1}</span>
              ))}
            </div>
          )}
          <textarea
            className="editor-body"
            value={content}
            onChange={(event) => setContent(event.target.value)}
            onScroll={(event) => {
              const target = event.currentTarget;
              const gutter = target.parentElement?.querySelector(".editor-gutter");
              if (gutter) gutter.scrollTop = target.scrollTop;
            }}
            spellCheck={false}
            placeholder={encoding === "hex" ? "十六进制字节（自动忽略空格与冒号）" : undefined}
            onKeyDown={(event) => {
              if ((event.ctrlKey || event.metaKey) && event.key === "s") {
                event.preventDefault();
                void saveFile();
              }
            }}
          />
        </div>
      </section>
    </div>
  );
}
