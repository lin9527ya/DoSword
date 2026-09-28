import { useEffect, useMemo, useRef, useState } from "react";
import { Copy, Save, X } from "lucide-react";
import { api, b64, errorText } from "../api";
import type { FileEntry } from "../api";
import { useToast } from "../components/Toast";

type Encoding = "utf-8" | "gbk" | "hex";

function decodeByEncoding(contentB64: string, encoding: Encoding): string {
  if (!contentB64) return "";
  const bytes = b64.decodeBytes(contentB64);
  if (encoding === "hex") {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(" ");
  }
  try {
    return new TextDecoder(encoding === "gbk" ? "gbk" : "utf-8", { fatal: false }).decode(bytes);
  } catch {
    return b64.decodeText(contentB64, encoding);
  }
}

/** 现代代码与文件编辑器：UTF-8 / GBK / HEX 编码读写，精准行号同步，Ctrl+S 保存。 */
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
  const toast = useToast();
  const [encoding, setEncoding] = useState<Encoding>("utf-8");
  const [content, setContent] = useState(() =>
    entry.contentB64 ? decodeByEncoding(entry.contentB64, "utf-8") : "",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const gutterRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (entry.contentB64 !== undefined) {
      setContent(decodeByEncoding(entry.contentB64, encoding));
    }
  }, [entry.contentB64, encoding]);

  const lineCount = useMemo(() => Math.max(1, content.split("\n").length), [content]);

  function switchEncoding(next: Encoding) {
    if (!entry.contentB64) return;
    setContent(decodeByEncoding(entry.contentB64, next));
    setEncoding(next);
    toast.info(`已切换至 ${next.toUpperCase()} 编码重新解析`);
  }

  const handleScroll = () => {
    if (textareaRef.current && gutterRef.current) {
      gutterRef.current.scrollTop = textareaRef.current.scrollTop;
    }
  };

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
        if (hex.length % 2 !== 0) throw new Error("HEX 字节长度必须为偶数");
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < bytes.length; i += 1) {
          const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
          if (Number.isNaN(byte)) {
            throw new Error(`HEX 包含非法字符: ${hex.slice(i * 2, i * 2 + 2)}`);
          }
          bytes[i] = byte;
        }
        payload = b64.encodeBytes(bytes);
      }
      await api.writeFile(sessionId, entry.path, payload);
      toast.success(`文件「${entry.name}」保存成功`, "保存成功");
      await onSaved();
      onClose();
    } catch (cause) {
      const msg = errorText(cause);
      setError(msg);
      toast.error(msg, "保存失败");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dialog-backdrop" onMouseDown={onClose}>
      <section className="editor" onMouseDown={(event) => event.stopPropagation()}>
        <div className="editor-head">
          <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
            <strong style={{ whiteSpace: "nowrap" }}>{entry.name}</strong>
            <span className="mono muted" style={{ fontSize: 11.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {entry.path}
            </span>
          </div>

          <div className="editor-actions">
            <span style={{ fontSize: 11, color: "var(--text-faint)", whiteSpace: "nowrap" }}>
              {lineCount} 行 · {content.length} 字符
            </span>
            <select
              className="select editor-encoding"
              value={encoding}
              onChange={(event) => switchEncoding(event.target.value as Encoding)}
              title="切换字符编码（未保存的编辑将丢弃）"
            >
              <option value="utf-8">UTF-8</option>
              <option value="gbk">GBK</option>
              <option value="hex">HEX</option>
            </select>
            {error && <span className="editor-error">{error}</span>}
            <button
              className="button compact secondary"
              onClick={() => {
                void navigator.clipboard.writeText(content);
                toast.success("内容已复制到剪贴板");
              }}
              title="复制全部内容"
            >
              <Copy size={13} />
              复制
            </button>
            <button
              className="button compact primary"
              onClick={() => void saveFile()}
              disabled={busy}
              title="保存修改 (Ctrl+S)"
            >
              <Save size={13} />
              {busy ? "保存中…" : "保存 (Ctrl+S)"}
            </button>
            <button className="icon-button" onClick={onClose} title="关闭编辑器 (Esc)">
              <X size={15} />
            </button>
          </div>
        </div>

        <div className="editor-body-wrap">
          {encoding !== "hex" && (
            <div className="editor-gutter" ref={gutterRef} aria-hidden>
              {Array.from({ length: lineCount }, (_, i) => (
                <div key={i + 1} className="gutter-line">
                  {i + 1}
                </div>
              ))}
            </div>
          )}
          <textarea
            ref={textareaRef}
            className="editor-body"
            value={content}
            onChange={(event) => setContent(event.target.value)}
            onScroll={handleScroll}
            spellCheck={false}
            placeholder={encoding === "hex" ? "十六进制字节（例如 48 65 6c 6c 6f）" : undefined}
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
