import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  Bookmark,
  Calendar,
  CheckSquare,
  ChevronsLeft,
  ChevronsRight,
  Clipboard,
  ClipboardPaste,
  Copy,
  Download,
  Eye,
  EyeOff,
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
  KeyRound,
  LoaderCircle,
  Pencil,
  RefreshCw,
  Scissors,
  Search,
  TerminalSquare,
  Trash2,
  Upload,
} from "lucide-react";
import { ask, save } from "@tauri-apps/plugin-dialog";
import { api, b64, errorText, formatSize } from "../api";
import type { FileEntry } from "../api";
import { Dialog } from "../components/Dialog";
import { Empty, UpwardPageSizeSelect } from "../components/common";
import { FileEditor } from "./FileEditor";
import { useToast } from "../components/Toast";

const LINUX_BOOKMARKS = [
  { label: "Web 根目录", path: "/var/www/html" },
  { label: "临时目录 (/tmp)", path: "/tmp" },
  { label: "配置目录 (/etc)", path: "/etc" },
  { label: "系统日志 (/var/log)", path: "/var/log" },
  { label: "用户目录 (/home)", path: "/home" },
  { label: "Root 根目录", path: "/root" },
];

const WINDOWS_BOOKMARKS = [
  { label: "IIS 根目录", path: "C:\\inetpub\\wwwroot" },
  { label: "Win 临时目录", path: "C:\\Windows\\Temp" },
  { label: "用户目录", path: "C:\\Users" },
  { label: "Program Files", path: "C:\\Program Files" },
  { label: "系统盘根目录", path: "C:\\" },
];

export function FileManager({
  sessionId,
  startDir,
  separator,
}: {
  sessionId: string;
  startDir: string;
  separator: string;
}) {
  const toast = useToast();
  const [path, setPath] = useState(startDir || separator || "/");
  const [history, setHistory] = useState<string[]>([startDir || separator || "/"]);
  const [historyIdx, setHistoryIdx] = useState(0);
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState<(FileEntry & { contentB64?: string }) | null>(null);
  const [createName, setCreateName] = useState<string | null>(null);
  const [createKind, setCreateKind] = useState<"file" | "dir" | null>(null);
  const [uploading, setUploading] = useState<{ name: string; sent: number; total: number } | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [sortBy, setSortBy] = useState<"name" | "size" | "modified">("name");
  const [sortDir, setSortDir] = useState<1 | -1>(1);
  const [search, setSearch] = useState("");
  const [clipboard, setClipboard] = useState<{ kind: "copy" | "move"; paths: string[] } | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; entry: FileEntry | null } | null>(null);

  // 弹窗状态
  const [moveTarget, setMoveTarget] = useState<FileEntry | null>(null);
  const [moveValue, setMoveValue] = useState("");
  const [renameTarget, setRenameTarget] = useState<FileEntry | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const [touchTarget, setTouchTarget] = useState<FileEntry | null>(null);
  const [touchDateTime, setTouchDateTime] = useState("");
  const [chmodTarget, setChmodTarget] = useState<FileEntry | null>(null);
  const [chmodValue, setChmodValue] = useState("0755");
  const [execTarget, setExecTarget] = useState<FileEntry | null>(null);
  const [execValue, setExecValue] = useState("");
  const [execOutput, setExecOutput] = useState("");

  // 路径输入与编辑模式
  const [isEditingPath, setIsEditingPath] = useState(false);
  const [pathInput, setPathInput] = useState(path);

  // 分页状态
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(100);
  const [jumpPageInput, setJumpPageInput] = useState("");
  const uploadRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setPathInput(path);
    setIsEditingPath(false);
  }, [path]);

  const isWindows = separator === "\\" || path.includes(":\\") || /^[a-zA-Z]:/.test(path);
  const bookmarks = isWindows ? WINDOWS_BOOKMARKS : LINUX_BOOKMARKS;

  useEffect(() => {
    if (!contextMenu) return;
    const close = () => setContextMenu(null);
    window.addEventListener("click", close);
    window.addEventListener("blur", close);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("blur", close);
    };
  }, [contextMenu]);

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
        setError("");
      } catch (cause) {
        const msg = errorText(cause);
        setError(msg);
        toast.error(`路径「${dir}」无法访问: ${msg}`, "目录访问异常");
      } finally {
        setLoading(false);
      }
    },
    [sessionId, toast],
  );

  const navigateTo = useCallback(
    (newPath: string) => {
      if (newPath === path) return;
      setHistory((prev) => [...prev.slice(0, historyIdx + 1), newPath]);
      setHistoryIdx((prev) => prev + 1);
      setPath(newPath);
    },
    [path, historyIdx],
  );

  const goBack = () => {
    if (historyIdx > 0) {
      setHistoryIdx(historyIdx - 1);
      setPath(history[historyIdx - 1]);
    }
  };

  const goForward = () => {
    if (historyIdx < history.length - 1) {
      setHistoryIdx(historyIdx + 1);
      setPath(history[historyIdx + 1]);
    }
  };

  useEffect(() => {
    void load(path);
    setSelected(new Set());
    setPage(0);
  }, [path, load]);

  const join = (name: string) => {
    const sep = isWindows ? "\\" : "/";
    if (path.endsWith("/") || path.endsWith("\\")) {
      return path + name;
    }
    return path + sep + name;
  };

  const visible = useMemo(() => {
    let list = entries;
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(
        (e) =>
          e.name.toLowerCase().includes(q) ||
          e.perms.toLowerCase().includes(q) ||
          (e.modified || "").toLowerCase().includes(q),
      );
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

  const pageCount = pageSize === 0 ? 1 : Math.max(1, Math.ceil(visible.length / pageSize));
  const pageEntries = pageSize === 0 ? visible : visible.slice(page * pageSize, (page + 1) * pageSize);

  function handleJumpPage() {
    const target = parseInt(jumpPageInput.trim(), 10);
    if (!Number.isNaN(target) && target >= 1 && target <= pageCount) {
      setPage(target - 1);
      setJumpPageInput("");
    } else {
      toast.warning(`请输入 1 到 ${pageCount} 之间的有效页码`);
    }
  }

  function toggleSelect(name: string, event?: React.MouseEvent) {
    if (event?.shiftKey) {
      setSelected(new Set(visible.map((e) => e.name)));
      return;
    }
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
    if (failed > 0) {
      toast.warning(`删除完成，其中 ${failed} 项删除失败`);
    } else {
      toast.success(`已删除 ${names.length} 个文件/目录`, "删除成功");
    }
  }

  function copyToClipboard(kind: "copy" | "move") {
    const paths = Array.from(selected).map(join);
    setClipboard({ kind, paths });
    setSelected(new Set());
    toast.info(`已${kind === "copy" ? "复制" : "剪切"} ${paths.length} 项到剪贴板`);
  }

  async function pasteHere() {
    if (!clipboard) return;
    let success = 0;
    let failed = 0;
    for (const srcPath of clipboard.paths) {
      const baseName = srcPath.split(/[\\/]/).pop() ?? "item";
      const destPath = join(baseName);
      try {
        if (clipboard.kind === "move") {
          await api.renamePath(sessionId, srcPath, destPath);
          success++;
        } else {
          const content = await api.readFile(sessionId, srcPath);
          await api.writeFile(sessionId, destPath, content.contentB64);
          success++;
        }
      } catch {
        failed++;
      }
    }
    await load(path);
    setClipboard(null);
    toast.success(`操作完成：成功 ${success} 项，失败 ${failed} 项`, "粘贴完成");
  }

  const goParent = () => {
    if (isWindows) {
      const parts = path.split("\\").filter(Boolean);
      if (parts.length <= 1) {
        navigateTo("C:\\");
      } else {
        parts.pop();
        navigateTo(parts.join("\\") || "C:\\");
      }
    } else {
      const parts = path.split("/").filter(Boolean);
      if (parts.length <= 1) {
        navigateTo("/");
      } else {
        parts.pop();
        navigateTo("/" + parts.join("/"));
      }
    }
  };

  const crumbs = useMemo(() => {
    if (!path) return [];
    const sep = isWindows ? "\\" : "/";
    return path.split(sep).filter((p) => p.length > 0 && p !== ".");
  }, [path, isWindows]);

  function entryIcon(entry: FileEntry) {
    if (entry.isDir) return <Folder size={15} color="var(--accent)" />;
    const ext = entry.name.split(".").pop()?.toLowerCase() ?? "";
    if (["php", "jsp", "asp", "aspx", "py", "js", "ts", "sh", "bat", "ps1", "sql", "json", "xml", "html", "css"].includes(ext))
      return <FileCode2 size={15} color="var(--info)" />;
    if (["zip", "tar", "gz", "tgz", "rar", "7z", "war", "jar"].includes(ext))
      return <FileArchive size={15} color="var(--warn)" />;
    if (["png", "jpg", "jpeg", "gif", "ico", "svg", "webp"].includes(ext))
      return <Image size={15} color="var(--ok)" />;
    if (["txt", "log", "md", "cfg", "ini", "conf", "env"].includes(ext))
      return <FileText size={15} color="var(--text-dim)" />;
    if (["mp4", "mkv", "avi", "mov"].includes(ext)) return <FileVideo size={15} color="var(--info)" />;
    if (["mp3", "wav", "flac"].includes(ext)) return <FileAudio size={15} color="var(--info)" />;
    return <File size={15} color="var(--text-faint)" />;
  }

  function permsToRwx(perms: string): string {
    if (!perms) return "—";
    const oct = perms.slice(-3);
    const map = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"];
    return oct
      .split("")
      .map((digit) => map[parseInt(digit, 10)] ?? "---")
      .join("");
  }

  async function openEntry(entry: FileEntry) {
    if (entry.isDir) {
      navigateTo(entry.path);
    } else {
      try {
        const content = await api.readFile(sessionId, entry.path);
        setEditing({ ...entry, contentB64: content.contentB64 });
      } catch (cause) {
        toast.error(`读取文件失败：${errorText(cause)}`);
      }
    }
  }

  async function createEntry() {
    if (!createName || !createKind) return;
    const target = join(createName);
    try {
      if (createKind === "dir") {
        await api.createDir(sessionId, target);
        toast.success(`已创建目录 ${createName}`);
      } else {
        await api.writeFile(sessionId, target, b64.encodeText(""));
        toast.success(`已创建文件 ${createName}`);
      }
      setCreateName(null);
      setCreateKind(null);
      await load(path);
    } catch (cause) {
      toast.error(`创建失败：${errorText(cause)}`);
    }
  }

  async function uploadFiles(files: FileList | null) {
    if (!files || files.length === 0) return;
    // 大文件分块缓冲：按 4MB 聚合浏览器小块，减少 HTTP 往返（与后端 chunk_size_mb 对齐）
    const CHUNK = 4 * 1024 * 1024;
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const target = join(file.name);
      try {
        const total = file.size;
        let sent = 0;
        setUploading({ name: file.name, sent: 0, total });
        const reader = file.stream().getReader();
        let buf = new Uint8Array(0);
        const flush = async (data: Uint8Array) => {
          if (data.length === 0) return;
          const chunkB64 = b64.encodeBytes(data);
          await api.writeChunk(sessionId, target, chunkB64, sent);
          sent += data.length;
          setUploading({ name: file.name, sent, total });
        };
        while (true) {
          const { done, value } = await reader.read();
          if (done) {
            if (buf.length > 0) await flush(buf);
            break;
          }
          // 聚合小块至 CHUNK
          const next = new Uint8Array(buf.length + value.length);
          next.set(buf, 0);
          next.set(value, buf.length);
          buf = next;
          while (buf.length >= CHUNK) {
            const slice = buf.slice(0, CHUNK);
            await flush(slice);
            buf = buf.slice(CHUNK);
          }
        }
        toast.success(`文件 ${file.name} 上传完成`);
      } catch (cause) {
        toast.error(`上传 ${file.name} 失败：${errorText(cause)}`);
      } finally {
        setUploading(null);
      }
    }
    await load(path);
  }

  async function downloadEntry(entry: FileEntry) {
    try {
      const savePath = await save({ defaultPath: entry.name });
      if (!savePath) return;
      await api.downloadFile(sessionId, entry.path, String(savePath));
      toast.success(`文件已下载至 ${savePath}`, "下载完成");
    } catch (cause) {
      toast.error(`下载失败：${errorText(cause)}`);
    }
  }

  // 隐藏 / 取消隐藏文件
  async function toggleHideItem(entry: FileEntry, hide: boolean) {
    try {
      if (isWindows) {
        const cmd = hide ? `attrib +h "${entry.path}"` : `attrib -h "${entry.path}"`;
        await api.executeCommand(sessionId, cmd);
        toast.success(hide ? `已为「${entry.name}」添加 Windows 隐藏属性 (+H)` : `已取消「${entry.name}」Windows 隐藏属性 (-H)`);
      } else {
        const newName = hide ? `.${entry.name}` : entry.name.replace(/^\.+/, "");
        const newPath = join(newName);
        await api.renamePath(sessionId, entry.path, newPath);
        toast.success(hide ? `已设置为 Linux 隐藏文件 (.${entry.name})` : `已取消「${entry.name}」Linux 隐藏`);
      }
      await load(path);
    } catch (cause) {
      toast.error(`操作失败: ${errorText(cause)}`);
    }
  }

  function openContextMenu(event: React.MouseEvent, entry: FileEntry) {
    event.preventDefault();
    event.stopPropagation();
    setContextMenu({ x: event.clientX, y: event.clientY, entry });
  }

  function toggleSort(key: "name" | "size" | "modified") {
    if (sortBy === key) setSortDir((d) => (d === 1 ? -1 : 1));
    else {
      setSortBy(key);
      setSortDir(1);
    }
  }

  return (
    <div
      className={`file-manager ${dragActive ? "drag-active" : ""}`}
      style={{ position: "relative", flex: 1, minHeight: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}
      onDragOver={(e) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(true);
      }}
      onDragLeave={(e) => {
        e.preventDefault();
        e.stopPropagation();
        // 仅当离开当前容器范围时清除
        if (!e.currentTarget.contains(e.relatedTarget as Node)) {
          setDragActive(false);
        }
      }}
      onDrop={(e) => {
        e.preventDefault();
        e.stopPropagation();
        setDragActive(false);
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          void uploadFiles(e.dataTransfer.files);
        }
      }}
      onContextMenu={(e) => {
        if ((e.target as HTMLElement).closest(".file-row")) return;
        openContextMenu(e, { name: "", path, isDir: true, size: 0, modified: "", perms: "" });
      }}
    >
      {/* 拖拽上传覆盖层 */}
      {dragActive && (
        <div className="drop-overlay">
          <Upload size={36} />
          <span>松开鼠标立即上传文件至当前目录</span>
          <span style={{ fontSize: 12, color: "var(--text-dim)" }}>
            目标路径: {path}
          </span>
        </div>
      )}

      {/* 路径与全局导航工具栏 */}
      <div className="file-toolbar">
        <div style={{ display: "flex", gap: 4 }}>
          <button className="file-tool-btn" disabled={historyIdx <= 0} onClick={goBack} title="后退">
            <ArrowLeft size={14} />
          </button>
          <button className="file-tool-btn" disabled={historyIdx >= history.length - 1} onClick={goForward} title="前进">
            <ArrowRight size={14} />
          </button>
          <button className="file-tool-btn" onClick={goParent} title="返回上一级目录">
            <ArrowUp size={14} />
          </button>
        </div>

        {isEditingPath ? (
          <div className="breadcrumb editing" style={{ flex: 1 }}>
            <input
              autoFocus
              className="crumb-input-full"
              value={pathInput}
              onChange={(event) => setPathInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  const target = pathInput.trim() || (isWindows ? "C:\\" : "/");
                  navigateTo(target);
                  setIsEditingPath(false);
                }
                if (event.key === "Escape") {
                  setPathInput(path);
                  setIsEditingPath(false);
                }
              }}
              onBlur={() => {
                const target = pathInput.trim();
                if (target && target !== path) {
                  navigateTo(target);
                }
                setIsEditingPath(false);
              }}
              placeholder={isWindows ? "C:\\" : "/"}
              spellCheck={false}
            />
          </div>
        ) : (
          <div
            className="breadcrumb"
            onClick={(event) => {
              if ((event.target as HTMLElement).tagName !== "BUTTON") {
                setPathInput(path);
                setIsEditingPath(true);
              }
            }}
            title="点击空白处可直接输入路径"
          >
            <button
              className="crumb"
              onClick={(e) => {
                e.stopPropagation();
                navigateTo(isWindows ? "C:\\" : "/");
              }}
            >
              {isWindows ? "C:\\" : "/"}
            </button>
            {crumbs.map((crumb, index) => {
              const isFirstWinDrive = isWindows && index === 0 && crumb.endsWith(":");
              if (isFirstWinDrive) return null;
              const targetPath = isWindows
                ? crumbs.slice(0, index + 1).join("\\")
                : "/" + crumbs.slice(0, index + 1).join("/");
              return (
                <span key={index} style={{ display: "inline-flex", alignItems: "center" }}>
                  <span className="crumb-sep">{isWindows ? "\\" : "/"}</span>
                  <button
                    className="crumb"
                    onClick={(e) => {
                      e.stopPropagation();
                      navigateTo(targetPath);
                    }}
                  >
                    {crumb}
                  </button>
                </span>
              );
            })}
            <button
              className="crumb-edit-trigger"
              onClick={(e) => {
                e.stopPropagation();
                setPathInput(path);
                setIsEditingPath(true);
              }}
              title="切换为文本输入模式"
            >
              <Pencil size={11} />
            </button>
          </div>
        )}

        <div className="file-tool-actions">
          <div className="file-search">
            <Search size={13} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="搜索当前目录…"
              spellCheck={false}
            />
          </div>
          <button className="file-tool-btn" onClick={() => void load(path)} title="刷新">
            <RefreshCw size={14} />
          </button>
          <span className="file-tool-divider" />
          <button
            className="file-tool-btn"
            onClick={() => {
              setCreateKind("file");
              setCreateName("new_script.php");
            }}
            title="新建文件"
          >
            <FilePenLine size={14} />
            新建文件
          </button>
          <button
            className="file-tool-btn"
            onClick={() => {
              setCreateKind("dir");
              setCreateName("new_folder");
            }}
            title="新建目录"
          >
            <FolderPlus size={14} />
            新建目录
          </button>
          <button
            className="file-tool-btn primary"
            onClick={() => uploadRef.current?.click()}
            title="上传文件 (支持拖拽上传)"
          >
            <Upload size={14} />
            上传
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

      {/* 快速常用目录书签栏（自适应操作系统预设） */}
      <div className="file-bookmarks-bar">
        <Bookmark size={13} color="var(--text-faint)" />
        <span style={{ fontSize: 11, color: "var(--text-faint)", fontWeight: 600 }}>
          {isWindows ? "WIN 常用书签:" : "LINUX 常用书签:"}
        </span>
        {bookmarks.map((bm) => (
          <button
            key={bm.path}
            className="file-bookmark-chip"
            onClick={() => navigateTo(bm.path)}
            title={bm.path}
          >
            {bm.label}
          </button>
        ))}
      </div>

      {/* 批量与剪贴板工具条 */}
      <div className="file-batchbar">
        <span>
          {selected.size > 0
            ? `已选 ${selected.size} 项 (共 ${visible.length} 项)`
            : clipboard
              ? `剪贴板: ${clipboard.paths.length} 项 (${clipboard.kind === "copy" ? "复制" : "剪切"})`
              : `当前目录共 ${visible.length} 项 (支持直接拖放本地文件上传)`}
        </span>
        <div className="file-batch-actions">
          {visible.length > 0 && (
            <button className="file-tool-btn" onClick={toggleSelectAll}>
              <CheckSquare size={13} />
              {selected.size === visible.length ? "取消全选" : "全选"}
            </button>
          )}
          {clipboard && (
            <button className="file-tool-btn primary" onClick={() => void pasteHere()}>
              <ClipboardPaste size={13} />
              粘贴到此处
            </button>
          )}
          {selected.size > 0 && (
            <>
              <button className="file-tool-btn" onClick={() => void copyToClipboard("copy")}>
                <Copy size={13} />
                复制
              </button>
              <button className="file-tool-btn" onClick={() => void copyToClipboard("move")}>
                <Scissors size={13} />
                剪切
              </button>
              <button className="file-tool-btn danger" onClick={() => void removeMany()}>
                <Trash2 size={13} />
                批量删除
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
            onBlur={() => {
              setCreateName(null);
              setCreateKind(null);
            }}
          />
        </div>
      )}

      {uploading && (
        <div className="upload-progress">
          <span className="upload-progress-name">
            正在分块上传: {uploading.name} ({formatSize(uploading.sent)} / {formatSize(uploading.total)})
          </span>
          <div className="upload-progress-bar">
            <div
              className="upload-progress-fill"
              style={{
                width: `${(uploading.sent / Math.max(1, uploading.total)) * 100}%`,
              }}
            />
          </div>
        </div>
      )}

      {loading ? (
        <Empty icon={<LoaderCircle className="spin" size={24} />} title="正在检索目录内容…" />
      ) : error ? (
        <div style={{ padding: "40px 20px", display: "flex", flexDirection: "column", alignItems: "center", gap: 12 }}>
          <Empty
            icon={<Folder size={32} />}
            title="目录不存在或在当前系统不兼容"
            detail={`目标服务器回显异常: ${error}。请检查路径是否与当前操作系统匹配。`}
            action={
              <div style={{ display: "flex", gap: 10, marginTop: 8 }}>
                <button className="button primary compact" onClick={goParent}>
                  <ArrowUp size={13} />
                  返回上一级
                </button>
                <button
                  className="button secondary compact"
                  onClick={() => navigateTo(startDir || (isWindows ? "C:\\" : "/"))}
                >
                  返回初始根目录
                </button>
              </div>
            }
          />
        </div>
      ) : entries.length === 0 ? (
        <Empty icon={<Folder size={28} />} title="空目录" detail="可拖拽文件至此处上传，或点击上方新建文件。" />
      ) : visible.length === 0 ? (
        <Empty icon={<Search size={28} />} title="未匹配到相关文件" detail="尝试更换搜索词或清除筛选。" />
      ) : (
        <div className="file-table" style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
          <div className="file-head">
            <span className="file-check-col">
              <input
                type="checkbox"
                checked={selected.size === visible.length && visible.length > 0}
                onChange={toggleSelectAll}
              />
            </span>
            <span className="file-sortable" onClick={() => toggleSort("name")}>
              名称 {sortBy === "name" ? (sortDir === 1 ? "↑" : "↓") : ""}
            </span>
            <span className="file-sortable" onClick={() => toggleSort("size")}>
              大小 {sortBy === "size" ? (sortDir === 1 ? "↑" : "↓") : ""}
            </span>
            <span className="file-sortable" onClick={() => toggleSort("modified")}>
              修改时间 {sortBy === "modified" ? (sortDir === 1 ? "↑" : "↓") : ""}
            </span>
            <span>权限 (Perms)</span>
          </div>

          <div style={{ flex: 1, overflowY: "auto", minHeight: 0 }}>
            {pageEntries.map((entry) => (
              <div
                className={`file-row ${selected.has(entry.name) ? "selected" : ""}`}
                key={entry.path}
                onClick={(e) => toggleSelect(entry.name, e)}
                onContextMenu={(event) => openContextMenu(event, entry)}
              >
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
                  title={`双击打开: ${entry.name}`}
                >
                  {entryIcon(entry)}
                  <span>{entry.name}</span>
                </button>
                <span className="mono file-size-col">
                  {entry.isDir ? "—" : formatSize(entry.size)}
                </span>
                <span className="mono muted">{entry.modified}</span>
                <span
                  className="mono muted file-perms"
                  title={entry.perms ? `八进制: ${entry.perms}` : undefined}
                >
                  {permsToRwx(entry.perms)}
                </span>
              </div>
            ))}
          </div>

          {/* 分页与跳转栏 */}
          <div className="file-pager">
            <div className="file-pager-info">
              共 <strong>{visible.length}</strong> 项
              {selected.size > 0 && <span>（已选 {selected.size} 项）</span>}
            </div>

            <div className="file-pager-controls">
              <button
                className="button compact secondary"
                disabled={page === 0}
                onClick={() => setPage(0)}
                title="第一页"
              >
                <ChevronsLeft size={13} />
              </button>
              <button
                className="button compact secondary"
                disabled={page === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
              >
                上一页
              </button>
              <span className="pagination-info" style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
                第 <strong>{page + 1}</strong> / {pageCount} 页
              </span>
              <button
                className="button compact secondary"
                disabled={page + 1 >= pageCount}
                onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
              >
                下一页
              </button>
              <button
                className="button compact secondary"
                disabled={page + 1 >= pageCount}
                onClick={() => setPage(pageCount - 1)}
                title="最后一页"
              >
                <ChevronsRight size={13} />
              </button>
            </div>

            <div className="file-pager-jump">
              <span style={{ fontSize: 11, color: "var(--text-faint)" }}>每页:</span>
              <UpwardPageSizeSelect
                value={pageSize}
                onChange={(val) => {
                  setPageSize(val);
                  setPage(0);
                }}
                unit="条"
              />

              <span style={{ fontSize: 11, color: "var(--text-faint)", marginLeft: 6 }}>跳至:</span>
              <input
                className="file-pager-input"
                value={jumpPageInput}
                onChange={(e) => setJumpPageInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleJumpPage();
                }}
                placeholder={String(page + 1)}
              />
              <button className="button compact secondary" onClick={handleJumpPage}>
                跳转
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 右键上下文菜单 */}
      {contextMenu && (
        <div
          className="file-context-menu"
          style={{
            left: contextMenu.x,
            top: contextMenu.y,
            transform: `translate(${contextMenu.x > window.innerWidth - 220 ? "-100%" : "0"}, ${contextMenu.y > window.innerHeight - 340 ? "-100%" : "0"})`,
          }}
          onContextMenu={(event) => event.preventDefault()}
        >
          {contextMenu.entry && contextMenu.entry.name ? (
            <>
              <button
                className="file-context-item"
                onClick={() => {
                  setContextMenu(null);
                  void openEntry(contextMenu.entry!);
                }}
              >
                <Folder size={14} /> {contextMenu.entry.isDir ? "进入目录" : "打开 / 编辑"}
              </button>
              <span className="file-context-sep" />
              <button
                className="file-context-item"
                onClick={() => {
                  void navigator.clipboard.writeText(contextMenu.entry!.name);
                  toast.success("已复制文件名");
                  setContextMenu(null);
                }}
              >
                <Copy size={14} /> 复制文件名
              </button>
              <button
                className="file-context-item"
                onClick={() => {
                  void navigator.clipboard.writeText(contextMenu.entry!.path);
                  toast.success("已复制完整路径");
                  setContextMenu(null);
                }}
              >
                <Clipboard size={14} /> 复制完整路径
              </button>

              <span className="file-context-sep" />
              <button
                className="file-context-item"
                onClick={() => {
                  setRenameTarget(contextMenu.entry);
                  setRenameValue(contextMenu.entry!.name);
                  setContextMenu(null);
                }}
              >
                <Pencil size={14} /> 重命名
              </button>
              <button
                className="file-context-item"
                onClick={() => {
                  setTouchTarget(contextMenu.entry);
                  const now = new Date();
                  const defaultTime = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")} ${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;
                  setTouchDateTime(defaultTime);
                  setContextMenu(null);
                }}
              >
                <Calendar size={14} /> 修改时间 (Touch)
              </button>
              <button
                className="file-context-item"
                onClick={() => {
                  setChmodTarget(contextMenu.entry);
                  setChmodValue(contextMenu.entry!.perms ? `0${contextMenu.entry!.perms.slice(-3)}` : "0755");
                  setContextMenu(null);
                }}
              >
                <KeyRound size={14} /> 修改权限 (Chmod)
              </button>

              {/* 隐藏 / 取消隐藏 */}
              {contextMenu.entry.name.startsWith(".") ? (
                <button
                  className="file-context-item"
                  onClick={() => {
                    setContextMenu(null);
                    void toggleHideItem(contextMenu.entry!, false);
                  }}
                >
                  <Eye size={14} /> 取消隐藏 ({isWindows ? "attrib -h" : "Linux"})
                </button>
              ) : (
                <button
                  className="file-context-item"
                  onClick={() => {
                    setContextMenu(null);
                    void toggleHideItem(contextMenu.entry!, true);
                  }}
                >
                  <EyeOff size={14} /> 隐藏此项 ({isWindows ? "attrib +h" : "Linux"})
                </button>
              )}

              <button
                className="file-context-item"
                onClick={() => {
                  setMoveTarget(contextMenu.entry);
                  setMoveValue(contextMenu.entry!.path);
                  setContextMenu(null);
                }}
              >
                <Scissors size={14} /> 移动到…
              </button>
              <button
                className="file-context-item"
                onClick={() => {
                  setExecTarget(contextMenu.entry);
                  setExecValue(`cat "${contextMenu.entry!.path}"`);
                  setContextMenu(null);
                }}
              >
                <TerminalSquare size={14} /> 在此路径执行…
              </button>

              <span className="file-context-sep" />
              {!contextMenu.entry.isDir && (
                <button
                  className="file-context-item"
                  onClick={() => {
                    setContextMenu(null);
                    void downloadEntry(contextMenu.entry!);
                  }}
                >
                  <Download size={14} /> 下载文件
                </button>
              )}
              <button
                className="file-context-item danger"
                onClick={() => {
                  setContextMenu(null);
                  void (async () => {
                    const ok = await ask(`确定删除「${contextMenu.entry!.name}」？`, {
                      title: "删除确认",
                      kind: "warning",
                      okLabel: "删除",
                      cancelLabel: "取消",
                    });
                    if (!ok) return;
                    try {
                      await api.deletePath(sessionId, contextMenu.entry!.path);
                      toast.success(`已删除 ${contextMenu.entry!.name}`);
                      await load(path);
                    } catch (cause) {
                      toast.error(`删除失败：${errorText(cause)}`);
                    }
                  })();
                }}
              >
                <Trash2 size={14} /> 删除
              </button>
            </>
          ) : (
            <>
              <button
                className="file-context-item"
                onClick={() => {
                  setContextMenu(null);
                  void load(path);
                }}
              >
                <RefreshCw size={14} /> 刷新当前目录
              </button>
              <button
                className="file-context-item"
                onClick={() => {
                  setContextMenu(null);
                  setCreateKind("file");
                  setCreateName("new_file.php");
                }}
              >
                <FilePenLine size={14} /> 新建文件
              </button>
              <button
                className="file-context-item"
                onClick={() => {
                  setContextMenu(null);
                  setCreateKind("dir");
                  setCreateName("new_folder");
                }}
              >
                <FolderPlus size={14} /> 新建目录
              </button>
              {clipboard && (
                <button
                  className="file-context-item"
                  onClick={() => {
                    setContextMenu(null);
                    void pasteHere();
                  }}
                >
                  <ClipboardPaste size={14} /> 粘贴到此处
                </button>
              )}
            </>
          )}
        </div>
      )}

      {/* 弹窗：重命名 */}
      {renameTarget && (
        <Dialog title={`重命名「${renameTarget.name}」`} onClose={() => setRenameTarget(null)}>
          <div className="dialog-form">
            <label>
              新名称
              <input
                autoFocus
                value={renameValue}
                onChange={(e) => setRenameValue(e.target.value)}
                placeholder="输入新的文件名或目录名"
                spellCheck={false}
              />
            </label>
            <div className="dialog-actions">
              <button className="button secondary" onClick={() => setRenameTarget(null)}>
                取消
              </button>
              <button
                className="button primary"
                onClick={async () => {
                  if (!renameValue.trim()) return;
                  const newPath = join(renameValue.trim());
                  try {
                    await api.renamePath(sessionId, renameTarget.path, newPath);
                    toast.success(`已重命名为 ${renameValue.trim()}`);
                    setRenameTarget(null);
                    await load(path);
                  } catch (e) {
                    toast.error(`重命名失败: ${errorText(e)}`);
                  }
                }}
              >
                确认重命名
              </button>
            </div>
          </div>
        </Dialog>
      )}

      {/* 弹窗：修改时间 (Touch) */}
      {touchTarget && (
        <Dialog title={`修改时间戳「${touchTarget.name}」`} onClose={() => setTouchTarget(null)}>
          <div className="dialog-form">
            <label>
              目标修改时间 (YYYY-MM-DD HH:mm:ss)
              <input
                value={touchDateTime}
                onChange={(e) => setTouchDateTime(e.target.value)}
                placeholder="2024-01-01 12:00:00"
                spellCheck={false}
              />
            </label>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 4 }}>
              <button
                type="button"
                className="button compact secondary"
                onClick={() => {
                  const now = new Date();
                  setTouchDateTime(
                    `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")} ${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`,
                  );
                }}
              >
                当前时间 (现在)
              </button>
              <button
                type="button"
                className="button compact secondary"
                onClick={() => setTouchDateTime("2024-01-01 08:30:00")}
              >
                设为 2024-01-01
              </button>
              <button
                type="button"
                className="button compact secondary"
                onClick={() => setTouchDateTime("2023-06-15 14:20:00")}
              >
                设为 2023-06-15
              </button>
            </div>
            <div className="dialog-actions" style={{ marginTop: 12 }}>
              <button className="button secondary" onClick={() => setTouchTarget(null)}>
                取消
              </button>
              <button
                className="button primary"
                onClick={async () => {
                  try {
                    const parsed = new Date(touchDateTime.replace(/-/g, "/"));
                    let ts = Math.floor(parsed.getTime() / 1000);
                    if (Number.isNaN(ts)) {
                      ts = Math.floor(Date.now() / 1000);
                    }
                    await api.touchPath(sessionId, touchTarget.path, ts);
                    toast.success(`已更新「${touchTarget.name}」修改时间`);
                    setTouchTarget(null);
                    await load(path);
                  } catch (e) {
                    // 尝试 fallback 执行 touch 命令
                    try {
                      await api.executeCommand(sessionId, `touch -d "${touchDateTime}" "${touchTarget.path}"`);
                      toast.success(`已通过 touch 命令更新时间`);
                      setTouchTarget(null);
                      await load(path);
                    } catch {
                      toast.error(`修改时间失败: ${errorText(e)}`);
                    }
                  }
                }}
              >
                确认修改时间
              </button>
            </div>
          </div>
        </Dialog>
      )}

      {/* 弹窗：修改权限 (Chmod) */}
      {chmodTarget && (
        <Dialog title={`修改权限 (Chmod)「${chmodTarget.name}」`} onClose={() => setChmodTarget(null)}>
          <div className="dialog-form">
            <label>
              八进制权限码 (如 0755 / 0644 / 0777)
              <input
                value={chmodValue}
                onChange={(e) => setChmodValue(e.target.value)}
                placeholder="0755"
                spellCheck={false}
              />
            </label>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 4 }}>
              <button
                type="button"
                className="button compact secondary"
                onClick={() => setChmodValue("0755")}
              >
                0755 (目录/可执行)
              </button>
              <button
                type="button"
                className="button compact secondary"
                onClick={() => setChmodValue("0644")}
              >
                0644 (标准文件)
              </button>
              <button
                type="button"
                className="button compact secondary"
                onClick={() => setChmodValue("0777")}
              >
                0777 (完全可写)
              </button>
              <button
                type="button"
                className="button compact secondary"
                onClick={() => setChmodValue("0400")}
              >
                0400 (只读保护)
              </button>
            </div>
            <div className="dialog-actions" style={{ marginTop: 14 }}>
              <button className="button secondary" onClick={() => setChmodTarget(null)}>
                取消
              </button>
              <button
                className="button primary"
                onClick={async () => {
                  const mode = chmodValue.trim();
                  try {
                    const res = await api.executeCommand(sessionId, `chmod ${mode} "${chmodTarget.path}"`);
                    const out = (res.stdout || "").toLowerCase();
                    if (out.includes("permission denied") || out.includes("operation not permitted") || out.includes("不允许的操作")) {
                      toast.error("权限不足：当前 Web 账户无权修改该文件权限位 (Permission Denied)，请检查文件属主");
                    } else {
                      toast.success(`已将「${chmodTarget.name}」权限修改为 ${mode}`);
                      setChmodTarget(null);
                      await load(path);
                    }
                  } catch (e) {
                    const msg = errorText(e);
                    if (msg.includes("Permission denied") || msg.includes("Operation not permitted")) {
                      toast.error("权限不足：当前 Web 账户权限不足 (Permission Denied)");
                    } else {
                      toast.error(`修改权限异常: ${msg}`);
                    }
                  }
                }}
              >
                确认修改权限
              </button>
            </div>
          </div>
        </Dialog>
      )}

      {/* 弹窗：移动到 */}
      {moveTarget && (
        <Dialog title={`移动「${moveTarget.name}」`} onClose={() => setMoveTarget(null)}>
          <div className="dialog-form">
            <label>
              目标绝对路径
              <input
                value={moveValue}
                onChange={(e) => setMoveValue(e.target.value)}
                placeholder="/var/www/html/new_name.php"
                spellCheck={false}
              />
            </label>
            <div className="dialog-actions">
              <button className="button secondary" onClick={() => setMoveTarget(null)}>
                取消
              </button>
              <button
                className="button primary"
                onClick={async () => {
                  try {
                    await api.renamePath(sessionId, moveTarget.path, moveValue.trim());
                    toast.success("移动完成");
                    setMoveTarget(null);
                    await load(path);
                  } catch (e) {
                    toast.error(`移动失败: ${errorText(e)}`);
                  }
                }}
              >
                确认移动
              </button>
            </div>
          </div>
        </Dialog>
      )}

      {/* 弹窗：执行命令 */}
      {execTarget && (
        <Dialog title="执行命令" onClose={() => setExecTarget(null)}>
          <div className="dialog-form">
            <label>
              命令
              <input
                value={execValue}
                onChange={(e) => setExecValue(e.target.value)}
                spellCheck={false}
              />
            </label>
            {execOutput && (
              <pre className="repeater-resp-body" style={{ maxHeight: 200, overflow: "auto" }}>
                {execOutput}
              </pre>
            )}
            <div className="dialog-actions">
              <button className="button secondary" onClick={() => setExecTarget(null)}>
                关闭
              </button>
              <button
                className="button primary"
                onClick={async () => {
                  try {
                    const res = await api.executeCommand(sessionId, execValue);
                    setExecOutput(res.stdout || "（无回显）");
                  } catch (e) {
                    toast.error(`执行失败: ${errorText(e)}`);
                  }
                }}
              >
                执行
              </button>
            </div>
          </div>
        </Dialog>
      )}

      {/* 文件编辑器 */}
      {editing && (
        <FileEditor
          sessionId={sessionId}
          entry={editing}
          onClose={() => setEditing(null)}
          onSaved={() => load(path)}
        />
      )}
    </div>
  );
}
