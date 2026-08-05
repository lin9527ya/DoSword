import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowUp,
  File,
  FilePenLine,
  Folder,
  FolderPlus,
  LoaderCircle,
  RefreshCw,
  Trash2,
  Upload,
  Download,
} from "lucide-react";
import { ask, save } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText, formatSize } from "../api";
import type { FileEntry } from "../api";
import { Dialog } from "../components/Dialog";
import { Empty, ErrorBanner } from "../components/common";
import { FileEditor } from "./FileEditor";

const UPLOAD_CHUNK = 4 * 1024 * 1024;

export function FileManager({ sessionId, startDir, separator }: { sessionId: string; startDir: string; separator: string }) {
  const [path, setPath] = useState(startDir || separator || "/");
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState<(FileEntry & { contentB64?: string }) | null>(null);
  const [createName, setCreateName] = useState<string | null>(null);
  const [createKind, setCreateKind] = useState<"file" | "dir" | null>(null);
  const [renaming, setRenaming] = useState<FileEntry | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [uploading, setUploading] = useState<{ name: string; sent: number; total: number } | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const uploadRef = useRef<HTMLInputElement>(null);

  const load = useCallback(
    async (dir: string) => {
      setLoading(true);
      setError("");
      try {
        const listing = await api.listDir(sessionId, dir);
        const sorted = [...listing.entries].sort((a, b) => {
          if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
          return a.name.localeCompare(b.name);
        });
        setEntries(sorted);
      } catch (cause) {
        setError(errorText(cause));
      } finally {
        setLoading(false);
      }
    },
    [sessionId],
  );

  useEffect(() => {
    void load(path);
  }, [path, load]);

  const join = (name: string) => (path.endsWith(separator) ? path + name : path + separator + name);

  async function openEntry(entry: FileEntry) {
    if (entry.isDir) {
      setPath(entry.path);
    } else {
      setError("");
      try {
        const content = await api.readFile(sessionId, entry.path);
        setEditing({ ...entry, contentB64: content.contentB64 });
      } catch (cause) {
        setError(errorText(cause));
      }
    }
  }

  async function createEntry() {
    if (!createName || !createKind) return;
    const target = join(createName);
    setError("");
    try {
      if (createKind === "dir") {
        await api.createDir(sessionId, target);
      } else {
        await api.writeFile(sessionId, target, b64.encodeText(""));
      }
      setCreateName(null);
      setCreateKind(null);
      await load(path);
    } catch (cause) {
      setError(errorText(cause));
    }
  }

  async function removeEntry(entry: FileEntry) {
    const confirmed = await ask(
      `确定删除「${entry.name}」？${entry.isDir ? "（目录必须为空）" : ""}`,
      { title: "删除确认", kind: "warning", okLabel: "删除", cancelLabel: "取消" },
    );
    if (!confirmed) return;
    setError("");
    try {
      await api.deletePath(sessionId, entry.path);
      await load(path);
    } catch (cause) {
      setError(errorText(cause));
    }
  }

  function startRename(entry: FileEntry) {
    setRenaming(entry);
    setRenameValue(entry.name);
  }

  async function submitRename() {
    const entry = renaming;
    if (!entry) return;
    const name = renameValue.trim();
    if (!name || name === entry.name) {
      setRenaming(null);
      return;
    }
    const parent = entry.path.slice(0, entry.path.length - entry.name.length);
    setRenaming(null);
    setError("");
    try {
      await api.renamePath(sessionId, entry.path, parent + name);
      await load(path);
    } catch (cause) {
      setError(errorText(cause));
    }
  }

  async function downloadEntry(entry: FileEntry) {
    if (entry.isDir) {
      setError("暂不支持目录下载");
      return;
    }
    setError("");
    try {
      const localPath = await save({ defaultPath: entry.name });
      if (!localPath) return;
      await api.downloadFile(sessionId, entry.path, localPath);
    } catch (cause) {
      setError(errorText(cause));
    }
  }

  async function uploadFiles(files: FileList | null) {
    if (!files) return;
    setError("");
    for (const file of Array.from(files)) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const total = bytes.length;
      try {
        // 大文件分块上传，避免单请求过大
        for (let offset = 0; offset < total; offset += UPLOAD_CHUNK) {
          const end = Math.min(offset + UPLOAD_CHUNK, total);
          setUploading({ name: file.name, sent: end, total });
          await api.writeChunk(
            sessionId,
            join(file.name),
            b64.encodeBytes(bytes.slice(offset, end)),
            offset,
          );
        }
      } catch (cause) {
        setUploading(null);
        setError(`上传 ${file.name} 失败：${errorText(cause)}`);
        return;
      }
    }
    setUploading(null);
    await load(path);
  }

  const crumbs = path.split(separator).filter(Boolean);

  return (
    <div
      className={`file-manager ${dragActive ? "drag-active" : ""}`}
      onDragOver={(event) => {
        event.preventDefault();
        event.dataTransfer.dropEffect = "copy";
        setDragActive(true);
      }}
      onDragLeave={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
          setDragActive(false);
        }
      }}
      onDrop={(event) => {
        event.preventDefault();
        setDragActive(false);
        void uploadFiles(event.dataTransfer.files);
      }}
    >
      <ErrorBanner message={error} />
      {dragActive && (
        <div className="drop-overlay">
          <Upload size={28} />
          释放以上传到当前目录
        </div>
      )}
      <div className="file-toolbar">
        <div className="breadcrumb">
          <button className="crumb" onClick={() => setPath(separator)}>
            {separator}
          </button>
          {crumbs.map((crumb, index) => (
            <span key={index} className="crumb-group">
              <span className="crumb-sep">{separator}</span>
              <button
                className="crumb"
                onClick={() => setPath(separator + crumbs.slice(0, index + 1).join(separator))}
              >
                {crumb}
              </button>
            </span>
          ))}
          <input
            className="crumb-input"
            defaultValue={path}
            onKeyDown={(event) => {
              if (event.key === "Enter") setPath((event.target as HTMLInputElement).value);
            }}
            onBlur={(event) => setPath(event.target.value)}
            spellCheck={false}
          />
        </div>
        <div className="file-actions">
          <button className="button compact" onClick={() => setPath(startDir)} title="回到初始目录">
            <ArrowUp size={15} />
          </button>
          <button className="button compact" onClick={() => void load(path)} title="刷新">
            <RefreshCw size={15} />
          </button>
          <button className="button compact" onClick={() => { setCreateKind("file"); setCreateName("新文件.txt"); }} title="新建文件">
            <FilePenLine size={15} />
          </button>
          <button className="button compact" onClick={() => { setCreateKind("dir"); setCreateName("新目录"); }} title="新建目录">
            <FolderPlus size={15} />
          </button>
          <button className="button compact" onClick={() => uploadRef.current?.click()} title="上传">
            <Upload size={15} />
          </button>
          <input
            ref={uploadRef}
            type="file"
            multiple
            hidden
            onChange={(event) => void uploadFiles(event.target.files)}
          />
        </div>
      </div>

      {createName !== null && (
        <div className="inline-create">
          <input
            autoFocus
            defaultValue={createName}
            onKeyDown={(event) => {
              if (event.key === "Enter") void createEntry();
              if (event.key === "Escape") setCreateName(null);
            }}
            onBlur={() => { setCreateName(null); setCreateKind(null); }}
          />
        </div>
      )}

      {uploading && (
        <div className="upload-progress">
          <span className="upload-progress-name">
            上传中：{uploading.name}（{formatSize(uploading.sent)} / {formatSize(uploading.total)}）
          </span>
          <div className="upload-progress-bar">
            <div
              className="upload-progress-fill"
              style={{ width: `${(uploading.sent / Math.max(1, uploading.total)) * 100}%` }}
            />
          </div>
        </div>
      )}

      {loading ? (
        <Empty icon={<LoaderCircle className="spin" />} title="正在读取目录" />
      ) : entries.length === 0 ? (
        <Empty icon={<Folder />} title="空目录" />
      ) : (
        <div className="file-table">
          <div className="file-head">
            <span>名称</span>
            <span>大小</span>
            <span>修改时间</span>
            <span>操作</span>
          </div>
          {entries.map((entry) => (
            <div className="file-row" key={entry.path}>
              <button className="file-name" onDoubleClick={() => void openEntry(entry)}>
                {entry.isDir ? <Folder size={16} /> : <File size={16} />}
                <span>{entry.name}</span>
              </button>
              <span className="mono">{entry.isDir ? "—" : formatSize(entry.size)}</span>
              <span className="mono muted">{entry.modified}</span>
              <span className="file-ops">
                <button className="icon-button" title="下载" onClick={() => void downloadEntry(entry)}>
                  <Download size={14} />
                </button>
                <button className="icon-button" title="重命名" onClick={() => startRename(entry)}>
                  <FilePenLine size={14} />
                </button>
                <button className="icon-button danger" title="删除" onClick={() => void removeEntry(entry)}>
                  <Trash2 size={14} />
                </button>
              </span>
            </div>
          ))}
        </div>
      )}

      {renaming && (
        <Dialog title={`重命名「${renaming.name}」`} onClose={() => setRenaming(null)}>
          <div className="dialog-form">
            <input
              autoFocus
              value={renameValue}
              onChange={(event) => setRenameValue(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") void submitRename();
                if (event.key === "Escape") setRenaming(null);
              }}
              spellCheck={false}
            />
          </div>
          <div className="dialog-actions">
            <button className="button secondary" onClick={() => setRenaming(null)}>
              取消
            </button>
            <button className="button primary" onClick={() => void submitRename()}>
              重命名
            </button>
          </div>
        </Dialog>
      )}

      {editing && (
        <FileEditor
          sessionId={sessionId}
          entry={editing}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            await load(path);
          }}
        />
      )}
    </div>
  );
}
