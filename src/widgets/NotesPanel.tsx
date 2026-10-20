import { useEffect, useMemo, useRef, useState } from "react";
import { ask } from "@tauri-apps/plugin-dialog";
import {
  BookOpen,
  Clock,
  Copy,
  Download,
  FileEdit,
  FileText,
  Key,
  Network,
  Plus,
  Save,
  Search,
  Sparkles,
  Trash2,
  View,
} from "lucide-react";
import { useToast } from "../components/Toast";

interface NotesPanelProps {
  sessionId?: string;
  shellId: string;
  shellName: string;
}

type ViewMode = "split" | "edit" | "preview";

interface KnowledgeSnippet {
  id: string;
  title: string;
  category: "bypass" | "proxy" | "privesc" | "recon" | "plugin";
  tags: string[];
  content: string;
}

const KNOWLEDGE_BASE: KnowledgeSnippet[] = [
  {
    id: "bypass-df-summary",
    title: "Disable Functions 常见绕过方法对照",
    category: "bypass",
    tags: ["PHP", "Bypass", "提权"],
    content: `#### Disable Functions 绕过策略对照
- **Syscall / 替代函数**：优先检查 \`popen\`, \`proc_open\`, \`shell_exec\`, \`passthru\`, \`system\`, \`exec\` 是否有遗漏。
- **FFI 直接调用 (PHP 7.4+)**：需 \`ffi.enable=true\`，使用 \`FFI::cdef()\` 直接调用 \`libc.so.6\` 的 \`system()\` 或 \`popen()\`。
- **pcntl_exec 进程派生**：当 \`pcntl_fork\` 与 \`pcntl_exec\` 可用时，在子进程直接执行 \`/bin/sh\` 并将输出重定向。
- **LD_PRELOAD 动态库劫持**：通过 \`putenv('LD_PRELOAD=/path/evil.so')\` 劫持 \`mail()\` 或 \`error_log()\` 触发 \`getuid()\` 劫持。
- **PHP-FPM FastCGI 通信**：向 \`127.0.0.1:9000\` 或 Unix Domain Socket 发送 FastCGI 协议报文，设置 \`PHP_VALUE=auto_prepend_file\`。
- **Windows COM 扩展**：利用 \`new COM("WScript.Shell")\` 调用 \`Exec()\` 或 \`Run()\`。`,
  },
  {
    id: "proxy-modes-guide",
    title: "网络代理与内网穿透三模指南",
    category: "proxy",
    tags: ["Proxy", "Socks5", "转发", "LCX"],
    content: `#### 网络代理三种模式选型
1. **Socks5 代理 (\`socks_proxy\`)**：
   - 目标主机开放监听端口（默认 1080），支持 RFC 1929 认证；
   - 配合攻击机 Proxychains / Proxifier 进行全端口动态内网流量转发。
2. **正向端口转发 (\`port_forward\`)**：
   - 靶机监听本地端口（如 8888），透明转发至指定内网主机及端口（如 \`192.168.1.50:3389\`）；
   - 适合靶机作为双网卡跳板机的直接端口映射。
3. **反向端口映射 LCX (\`port_map\`)**：
   - 严苛出站防火墙（不开放任何入站端口）环境下的首选方案；
   - 靶机主动外联攻击机公网 VPS 端口，并桥接本地或内网目标服务。`,
  },
  {
    id: "linux-privesc-quick",
    title: "Linux 提权与特权排查速查",
    category: "privesc",
    tags: ["Linux", "提权", "SUID", "Sudo"],
    content: `#### Linux 提权核心检查项
\`\`\`bash
# 1. 查看 sudo 权限
sudo -l

# 2. 查找 SUID 特权可执行文件
find / -perm -4000 -type f 2>/dev/null

# 3. 检查计划任务与 Crontab
cat /etc/crontab /etc/cron.*/* 2>/dev/null
crontab -l

# 4. 检查具备可写权限的敏感文件
find / -writable ! -user $(whoami) -type f 2>/dev/null

# 5. 内核版本与发行版
uname -a && cat /etc/os-release
\`\`\``,
  },
  {
    id: "win-recon-quick",
    title: "Windows 内网快速搜集指令",
    category: "recon",
    tags: ["Windows", "内网", "域管"],
    content: `#### Windows 内网常用信息搜集
\`\`\`cmd
whoami /all
net user
net localgroup administrators
netstat -ano | findstr LISTENING
tasklist /svc
systeminfo
ipconfig /all
route print
arp -a
net view /domain
\`\`\``,
  },
  {
    id: "plugins-tips",
    title: "DoSword 插件开发与热装载规范",
    category: "plugin",
    tags: ["Plugin", "SDK", "规范"],
    content: `#### DoSword .plugin 插件规范
- **清单格式**：JSON 结构，包含 \`id\`, \`name\`, \`version\`, \`category\`, \`params\`, \`execution\`
- **参数占位符**：在代码载荷中使用 \`{{param_name}}\` 进行动态变量注入
- **返回规范**：PHP 脚本统一通过 \`echo json_encode(array('ok' => true, 'output_text' => ...))\` 输出，SDK 会自动解析为美观表格与视图。`,
  },
];

export function NotesPanel({ shellId, shellName }: NotesPanelProps) {
  const toast = useToast();
  const STORAGE_KEY = `dosword:notes:${shellId}`;
  
  const [content, setContent] = useState<string>(() => {
    return (
      localStorage.getItem(STORAGE_KEY) ??
      `# 渗透操作记录 — ${shellName}\n\n> 创建时间：${new Date().toLocaleString()}\n\n### [${new Date().toLocaleTimeString()}] 会话初始化\n- 目标主机已连接，环境已就绪。\n`
    );
  });

  const [viewMode, setViewMode] = useState<ViewMode>("split");
  const [searchQuery, setSearchQuery] = useState("");
  const [activeCategory, setActiveCategory] = useState<string>("all");
  const [isSaved, setIsSaved] = useState(true);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // 自动防抖保存
  useEffect(() => {
    setIsSaved(false);
    const timer = setTimeout(() => {
      try {
        localStorage.setItem(STORAGE_KEY, content);
        setIsSaved(true);
      } catch {
        // ignore
      }
    }, 600);
    return () => clearTimeout(timer);
  }, [content, STORAGE_KEY]);

  function saveManually() {
    try {
      localStorage.setItem(STORAGE_KEY, content);
      setIsSaved(true);
      toast.success("操作笔记已保存", "持久化成功");
    } catch (e) {
      toast.error("保存失败：" + String(e));
    }
  }

  function insertText(text: string) {
    const el = textareaRef.current;
    if (!el) {
      setContent((prev) => prev + "\n" + text);
      return;
    }
    const start = el.selectionStart;
    const end = el.selectionEnd;
    const current = el.value;
    const next = current.substring(0, start) + text + current.substring(end);
    setContent(next);
    setTimeout(() => {
      el.focus();
      el.setSelectionRange(start + text.length, start + text.length);
    }, 50);
  }

  function insertTimestamp() {
    const now = new Date();
    const timeStr = now.getFullYear() + "-" +
      String(now.getMonth() + 1).padStart(2, "0") + "-" +
      String(now.getDate()).padStart(2, "0") + " " +
      String(now.getHours()).padStart(2, "0") + ":" +
      String(now.getMinutes()).padStart(2, "0") + ":" +
      String(now.getSeconds()).padStart(2, "0");
    insertText(`\n### [${timeStr}] 操作记录\n- **执行操作**：\n- **返回结果**：\n- **下一步行动**：\n`);
    toast.info("已插入时间戳操作日志模板");
  }

  function insertCredTemplate() {
    insertText(`\n#### 🔑 凭据与发现资产清单
| 类型 | 目标/服务 | 账号 | 密码/Hash | 权限级别 | 备注 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| MySQL | 127.0.0.1:3306 | root | pass123 | DBA | 本地数据库 |
| SSH | 192.168.1.20:22 | admin | id_rsa | 运维用户 | 内网跳板 |
`);
    toast.info("已插入凭据记录表格");
  }

  function insertAssetTemplate() {
    insertText(`\n#### 🌐 内网主机与拓扑资产
- **目标 IP**：
- **开放端口**：
- **存活服务**：
- **漏洞点**：
`);
    toast.info("已插入资产记录模板");
  }

  function copyAll() {
    void navigator.clipboard.writeText(content).then(() => {
      toast.success("已复制全文到剪贴板");
    });
  }

  function exportMarkdown() {
    const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `notes_${shellName.replace(/[^a-zA-Z0-9_\u4e00-\u9fa5]/g, "_")}_${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("笔记已导出为 Markdown 文件");
  }

  async function clearNotes() {
    // 用应用内确认框而不是原生 confirm：原生框在 Tauri webview 里样式不可控，
    // 且与其他确认（删除 Shell / Workspace）交互不一致
    const confirmed = await ask("确定要清空当前 Shell 的操作笔记吗？", {
      title: "清空笔记",
      kind: "warning",
      okLabel: "清空",
      cancelLabel: "取消",
    });
    if (!confirmed) return;
    setContent(`# 渗透操作记录 — ${shellName}\n\n`);
    toast.info("笔记已重置");
  }

  const filteredSnippets = useMemo(() => {
    return KNOWLEDGE_BASE.filter((item) => {
      const matchCat = activeCategory === "all" || item.category === activeCategory;
      const matchQuery =
        !searchQuery ||
        item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.tags.some((t) => t.toLowerCase().includes(searchQuery.toLowerCase())) ||
        item.content.toLowerCase().includes(searchQuery.toLowerCase());
      return matchCat && matchQuery;
    });
  }, [activeCategory, searchQuery]);

  return (
    <div className="notes-panel">
      {/* 顶部工具栏 */}
      <div className="notes-toolbar">
        <div className="notes-toolbar-left">
          <span className="notes-title-tag">
            <FileText size={15} />
            操作备忘与知识库
          </span>
          <span className={`save-status-indicator ${isSaved ? "saved" : "unsaved"}`}>
            {isSaved ? "● 已自动保存" : "○ 正在保存…"}
          </span>
        </div>

        <div className="notes-toolbar-actions">
          <button className="button compact secondary" onClick={insertTimestamp} title="插入时间戳与操作日志模版">
            <Clock size={13} />
            插入时间戳日志
          </button>
          <button className="button compact secondary" onClick={insertCredTemplate} title="插入凭据记录表格">
            <Key size={13} />
            凭据记录单
          </button>
          <button className="button compact secondary" onClick={insertAssetTemplate} title="插入内网资产模板">
            <Network size={13} />
            资产记录单
          </button>

          <div className="notes-divider-v" />

          {/* 模式切换 */}
          <div className="button-group compact">
            <button
              className={`button compact ${viewMode === "edit" ? "primary" : "secondary"}`}
              onClick={() => setViewMode("edit")}
              title="仅编辑器"
            >
              <FileEdit size={13} />
              编辑
            </button>
            <button
              className={`button compact ${viewMode === "split" ? "primary" : "secondary"}`}
              onClick={() => setViewMode("split")}
              title="双栏对比"
            >
              <View size={13} />
              双栏
            </button>
            <button
              className={`button compact ${viewMode === "preview" ? "primary" : "secondary"}`}
              onClick={() => setViewMode("preview")}
              title="仅预览"
            >
              <BookOpen size={13} />
              预览
            </button>
          </div>

          <div className="notes-divider-v" />

          <button className="icon-button" onClick={saveManually} title="手动立即保存">
            <Save size={14} />
          </button>
          <button className="icon-button" onClick={copyAll} title="复制全部内容">
            <Copy size={14} />
          </button>
          <button className="icon-button" onClick={exportMarkdown} title="导出为 .md 文件">
            <Download size={14} />
          </button>
          <button className="icon-button danger" onClick={() => void clearNotes()} title="清空笔记">
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* 主体双栏区域 */}
      <div className="notes-body">
        {/* 左侧：知识库速查与注入 */}
        <aside className="notes-sidebar">
          <div className="notes-sidebar-header">
            <div className="notes-sidebar-title">
              <Sparkles size={14} color="var(--accent)" />
              <span>插件知识库与速查卡片</span>
            </div>
            <div className="notes-search-box">
              <Search size={13} />
              <input
                type="text"
                placeholder="搜索知识/命令/绕过…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <div className="notes-category-tabs">
              {[
                { id: "all", label: "全部" },
                { id: "bypass", label: "绕过" },
                { id: "proxy", label: "代理" },
                { id: "privesc", label: "提权" },
                { id: "recon", label: "信息" },
              ].map((tab) => (
                <button
                  key={tab.id}
                  className={`notes-category-btn ${activeCategory === tab.id ? "active" : ""}`}
                  onClick={() => setActiveCategory(tab.id)}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          <div className="notes-snippets-list">
            {filteredSnippets.map((snippet) => (
              <div className="notes-snippet-card" key={snippet.id}>
                <div className="notes-snippet-top">
                  <strong>{snippet.title}</strong>
                  <button
                    className="button compact primary notes-inject-btn"
                    onClick={() => {
                      insertText(`\n${snippet.content}\n`);
                      toast.success(`已插入「${snippet.title}」到笔记`);
                    }}
                    title="将本知识卡片内容注入到笔记"
                  >
                    <Plus size={12} />
                    插入笔记
                  </button>
                </div>
                <div className="notes-snippet-tags">
                  {snippet.tags.map((t) => (
                    <span key={t} className="notes-tag">
                      {t}
                    </span>
                  ))}
                </div>
                <div className="notes-snippet-preview">
                  <pre>{snippet.content.substring(0, 140)}…</pre>
                </div>
              </div>
            ))}
          </div>
        </aside>

        {/* 右侧：编辑器与预览 */}
        <main className={`notes-main view-${viewMode}`}>
          {(viewMode === "edit" || viewMode === "split") && (
            <div className="notes-editor-pane">
              <textarea
                ref={textareaRef}
                className="notes-textarea"
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="在此记录渗透过程、提取的凭据、内网资产与插件执行心得（支持 Markdown 语法）…"
                spellCheck={false}
              />
            </div>
          )}

          {(viewMode === "preview" || viewMode === "split") && (
            <div className="notes-preview-pane">
              <div className="notes-preview-content">
                <MarkdownSimpleRenderer content={content} />
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

/**
 * 极简但美观的 Markdown 渲染器，解析常见标题、加粗、代码块、列表与表格
 */
function MarkdownSimpleRenderer({ content }: { content: string }) {
  const lines = useMemo(() => content.split("\n"), [content]);

  return (
    <div className="markdown-render">
      {lines.map((line, idx) => {
        const trimmed = line.trim();
        if (!trimmed) {
          return <div key={idx} style={{ height: "8px" }} />;
        }
        if (trimmed.startsWith("# ")) {
          return <h1 key={idx}>{trimmed.substring(2)}</h1>;
        }
        if (trimmed.startsWith("## ")) {
          return <h2 key={idx}>{trimmed.substring(3)}</h2>;
        }
        if (trimmed.startsWith("### ")) {
          return <h3 key={idx}>{trimmed.substring(4)}</h3>;
        }
        if (trimmed.startsWith("#### ")) {
          return <h4 key={idx}>{trimmed.substring(5)}</h4>;
        }
        if (trimmed.startsWith("> ")) {
          return <blockquote key={idx}>{trimmed.substring(2)}</blockquote>;
        }
        if (trimmed.startsWith("- ")) {
          return (
            <li key={idx} className="md-list-item">
              <FormattedInline text={trimmed.substring(2)} />
            </li>
          );
        }
        if (trimmed.startsWith("```")) {
          return null; // 忽略围栏行
        }
        if (trimmed.startsWith("|") && trimmed.endsWith("|")) {
          return (
            <div key={idx} className="md-table-line">
              <code>{trimmed}</code>
            </div>
          );
        }
        return (
          <p key={idx} className="md-paragraph">
            <FormattedInline text={line} />
          </p>
        );
      })}
    </div>
  );
}

function FormattedInline({ text }: { text: string }) {
  // 简易解析 **加粗** 与 `代码`
  const parts = text.split(/(\*\*.*?\*\*|`.*?`)/g);
  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith("**") && part.endsWith("**")) {
          return <strong key={i}>{part.slice(2, -2)}</strong>;
        }
        if (part.startsWith("`") && part.endsWith("`")) {
          return <code key={i}>{part.slice(1, -1)}</code>;
        }
        return <span key={i}>{part}</span>;
      })}
    </>
  );
}
