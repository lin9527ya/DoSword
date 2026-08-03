import { useState } from "react";
import { Save, X } from "lucide-react";
import { api, b64, errorText } from "../api";
import type { FileEntry } from "../api";

/** 文件编辑器：读取 → 编辑 → 保存（UTF-8）。 */
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
  const [content, setContent] = useState(() =>
    entry.contentB64 ? b64.decodeText(entry.contentB64) : "",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function saveFile() {
    setBusy(true);
    setError("");
    try {
      await api.writeFile(sessionId, entry.path, b64.encodeText(content));
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
        <textarea
          className="editor-body"
          value={content}
          onChange={(event) => setContent(event.target.value)}
          spellCheck={false}
          onKeyDown={(event) => {
            if ((event.ctrlKey || event.metaKey) && event.key === "s") {
              event.preventDefault();
              void saveFile();
            }
          }}
        />
      </section>
    </div>
  );
}
