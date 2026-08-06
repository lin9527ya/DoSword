import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowUp,
  Clipboard,
  ClipboardPaste,
  Copy,
  File,
  FileArchive,
  FileAudio,
  FileCode2,
  FilePenLine,
  FileText,
  FileVideo,
  Folder,
  FolderPlus,
  Image,
  LoaderCircle,
  RefreshCw,
  Scissors,
  Search,
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
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [sortBy, setSortBy] = useState<"name" | "size" | "modified">("name");
  const [sortDir, setSortDir] = useState<1 | -1>(1);
  const [search, setSearch] = useState("");
  const [clipboard, setClipboard] = useState<{ kind: "copy" | "move"; paths: string[] } | null>(null);
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
    setSelected(new Set());
  }, [path, load]);

  const join = (name: string) => (path.endsWith(separator) ? path + name : path + separator + name);

  const visible = useMemo(() => {
    let list = entries;
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter((e) => e.name.toLowerCase().includes(q));
    }
    const sorted = [...list].sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      let r = 0;
      if (sortBy === "size") r = a.size - b.size;
      else if (sortBy === "modified") r = (a.modified ?? "").localeCompare(b.modified ?? "");
      else r = a.name.localeCompare(b.name);
      return r * sortDir;
    });
    return sorted;
  }, [entries, search, sortBy, sortDir]);

  function toggleSelect(name: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  function toggleSelectAll() {
    if (selected.size === visible.length) setSelected(new Set());
    else setSelected(new Set(visible.map((e) => e.name)));
  }

  async function removeMany() {
    const names = Array.from(selected);
    if (names.length === 0) return;
    const confirmed = await ask(
      `确定删除选中的 ${names.length} 项？${names.length > 1 ? "（目录必须为空）" : ""}`,
      { title: "批量删除确认", kind: "warning", okLabel: "删除", cancelLabel: "取消" },
    );
    if (!confirmed) return;
    setError("");
    let failed = 0;
    for (const name of names) {
      try {
        await api.deletePath(sessionId, join(name));
      } catch {
        failed++;
      }
    }
    setSelected(new Set());
    await load(path);
    if (failed > 0) setError(`批量删除完成，${failed} 项失败`);
  }

  async function copyToClipboard(kind: "copy" | "move") {
    const names = Array.from(selected);
    if (names.length === 0) return;
    setClipboard({ kind, paths: names.map(join) });
    setError(kind === "copy" ? `已复制 ${names.length} 项（可在任意目录粘贴）` : `已剪切 ${names.length} 项（可在任意目录粘贴）`);
  }

  async function pasteHere() {
    if (!clipboard) return;
    setError("");
    let failed = 0;
    let moved = 0;
    for (const srcPath of clipboard.paths) {
      const name = srcPath.split(/[\\/]/).pop() ?? "";
      const target = join(name);
      if (srcPath === target) continue;
      try {
        if (clipboard.kind === "move") {
          await api.renamePath(sessionId, srcPath, target);
          moved++;
        } else {
          const content = await api.readFile(sessionId, srcPath);
          await api.writeFile(sessionId, target, content.contentB64);
        }
      } catch {
        failed++;
      }
    }
    setClipboard(null);
    await load(path);
    if (failed > 0) setError(`粘贴完成：成功 ${moved || clipboard.paths.length - failed} 项，失败 ${failed} 项`);
  }

  function entryIcon(entry: FileEntry) {
    if (entry.isDir) return <Folder size={16} />;
    const ext = entry.name.split(".").pop()?.toLowerCase() ?? "";
    if (["png", "jpg", "jpeg", "gif", "webp", "bmp", "svg", "ico"].includes(ext)) return <Image size={16} />;
    if (["zip", "tar", "gz", "bz2", "7z", "rar", "xz"].includes(ext)) return <FileArchive size={16} />;
    if (["php", "js", "ts", "py", "java", "c", "cpp", "go", "rs", "html", "css", "json", "sh", "sql", "rb", "pl", "xml", "yml", "yaml"].includes(ext))
      return <FileCode2 size={16} />;
    if (["txt", "md", "log", "ini", "conf", "env"].includes(ext)) return <FileText size={16} />;
    if (["mp3", "wav", "flac", "ogg", "m4a"].includes(ext)) return <FileAudio size={16} />;
    if (["mp4", "avi", "mkv", "mov", "webm"].includes(ext)) return <FileVideo size={16} />;
    return <File size={16} />;
  }

  function toggleSort(key: "name" | "size" | "modified") {
    if (sortBy === key) setSortDir((d) => (d === 1 ? -1 : 1));
    else {
      setSortBy(key);
      setSortDir(1);
    }
  }

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
        <div className="file-tool-actions">
          <div className="file-search">
            <Search size={14} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="搜索…"
              spellCheck={false}
            />
          </div>
          <button className="file-tool-btn" onClick={() => setPath(startDir)} title="回到初始目录">
            <ArrowUp size={15} />
          </button>
          <button className="file-tool-btn" onClick={() => void load(path)} title="刷新">
            <RefreshCw size={15} />
          </button>
          <span className="file-tool-divider" />
          <button className="file-tool-btn" onClick={() => { setCreateKind("file"); setCreateName("新文件.txt"); }} title="新建文件">
            <FilePenLine size={15} />
          </button>
          <button className="file-tool-btn" onClick={() => { setCreateKind("dir"); setCreateName("新目录"); }} title="新建目录">
            <FolderPlus size={15} />
          </button>
          <button className="file-tool-btn" onClick={() => uploadRef.current?.click()} title="上传文件">
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
      <div className="file-batchbar">
        <span className="file-batch-count">
          {selected.size > 0 ? `已选 ${selected.size} 项` : clipboard ? `剪贴板：${clipboard.paths.length} 项` : "批量操作"}
        </span>
        <div className="file-batch-actions">
          {visible.length > 0 && (
            <button className="file-tool-btn" onClick={toggleSelectAll} title="全选 / 取消全选">
              <Clipboard size={14} />
              {selected.size === visible.length ? "取消全选" : "全选"}
            </button>
          )}
          {clipboard && (
            <button className="file-tool-btn" onClick={() => void pasteHere()} title="粘贴到当前目录">
              <ClipboardPaste size={14} />
              粘贴
            </button>
          )}
          {selected.size > 0 && (
            <>
              <button className="file-tool-btn" onClick={() => void copyToClipboard("copy")} title="复制选中项">
                <Copy size={14} />
                复制
              </button>
              <button className="file-tool-btn" onClick={() => void copyToClipboard("move")} title="剪切选中项">
                <Scissors size={14} />
                剪切
              </button>
              <button className="file-tool-btn danger" onClick={() => void removeMany()} title="批量删除选中项">
                <Trash2 size={14} />
                删除
              </button>
            </>
          )}
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
      ) : visible.length === 0 ? (
        <Empty icon={<Search />} title="无匹配项" />
      ) : (
        <div className="file-table">
          <div className="file-head">
            <span className="file-check-col">
              <input type="checkbox" checked={selected.size === visible.length} onChange={toggleSelectAll} />
            </span>
            <span className="file-sortable" onClick={() => toggleSort("name")} title="按名称排序">
              名称{sortBy === "name" ? (sortDir === 1 ? " ↑" : " ↓") : ""}
            </span>
            <span className="file-sortable" onClick={() => toggleSort("size")} title="按大小排序">
              大小{sortBy === "size" ? (sortDir === 1 ? " ↑" : " ↓") : ""}
            </span>
            <span className="file-sortable" onClick={() => toggleSort("modified")} title="按修改时间排序">
              修改时间{sortBy === "modified" ? (sortDir === 1 ? " ↑" : " ↓") : ""}
            </span>
            <span>操作</span>
          </div>
          {visible.map((entry) => (
            <div className={`file-row ${selected.has(entry.name) ? "selected" : ""}`} key={entry.path}>
              <span className="file-check-col">
                <input
                  type="checkbox"
                  checked={selected.has(entry.name)}
                  onChange={() => toggleSelect(entry.name)}
                />
              </span>
              <button
                className="file-name"
                onDoubleClick={() => void openEntry(entry)}
                onClick={() => toggleSelect(entry.name)}
              >
                {entryIcon(entry)}
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
