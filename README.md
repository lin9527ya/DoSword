# DoSword

[![CI](https://github.com/lin9527ya/DoSword/actions/workflows/ci.yml/badge.svg)](https://github.com/lin9527ya/DoSword/actions/workflows/ci.yml)

DoSword 是一个面向授权安全测试环境的现代化 WebShell 管理客户端（Tauri 2 + React 19 + SQLite）。

> **仅限授权使用**：请在拥有书面授权的渗透测试项目、自有资产或 CTF / 教学环境中使用。
> 使用者须自行承担合规责任。安全问题的上报方式与已知设计取舍见 [SECURITY.md](SECURITY.md)。

## 当前里程碑（第二阶段）

- Workspace 与授权范围登记、到期检查，支持删除/编辑（级联清理会话）
- Shell Profile 本地持久化（SQLite，**含密码明文**——工具惯例，keyring 加密留待后续），支持标签、删除/编辑
  > ⚠️ 连接密码与导出的 Shell JSON / 备份文件均为**明文**，请像对待私钥一样保管
  > `~/.local/share/io.dosword.desktop/dosword.sqlite3` 与所有导出文件
- 审计日志贯穿所有操作（连接 / 命令 / 文件 / 设置），分页查询与 CSV 导出
- **标准 PHP WebShell 协议**（类蚁剑）：探测、连接、命令执行、文件浏览/读写/上传/下载/删除/重命名/建目录
- **编码方式：NATIVE 内置功能分发系列**（同一骨架，载荷加密可选）
  - 功能函数（命令/文件/数据库）直接内置在 stub（业务化命名），
    客户端按操作名 md5 哈希分发调用（stub 仅含哈希数字比较）
  - 敏感函数（file_get_contents/scandir/openssl_decrypt 等）**尽量**经
    crc32b 符号表查表调用（哥斯拉式符号表，运行时从 get_defined_functions() 解析）
    > ⚠️ **诚实声明（勿轻信"零检出"）**：新生成的 stub（NATIVE / AEAD / session /
    > legacy）已不含 `eval(`、命令执行函数名（含降级候选数组）、`base64_*`、
    > 文件操作与 gzip 函数名等高危明文特征 —— 它们经**随代码自带**的 crc32b
    > 符号表在运行时解析（内部辅助函数也用中性命名）。但仍有明文：请求参数名与
    > `$_POST[...]`、`json_encode`/`json_decode`、`hash('crc32b')`、环境信息函数
    > （`ini_get`/`getenv`/`php_uname` 等）、SQL/DSN 字符串，以及
    > `__DEC__('密文','密钥')` 的第二个参数 —— **XOR 密钥就写在文件里**，
    > 一条 `php -r` 即可还原全部字符串。另：stub 内嵌 `md5(密码)` 与其前 16 位令牌，
    > **拿到 stub 即等于拿到会话密钥**。已部署的旧 stub 保持原有特征，
    > 需重新生成并上传才会更新。
    > 且 `__DEC__('密文','密钥')` 的第二参就把 XOR 密钥写在文件里，
    > 所谓"XOR 加密嵌入"不具备抗提取能力（一条 `php -r` 即可还原全部字符串）。
    > 另：stub 内嵌 `md5(密码)` 与其前 16 位令牌——**拿到 stub 即等于拿到会话密钥**，
    > 请像对待私钥一样保管 stub 文件。
    > 抗查杀能力取决于目标环境的具体规则，本项目不承诺任何免杀效果。
  - 自定义 HTTP 头鉴权（X-Debug-Key；JSP 用 servlet 报文头原名，ASPX 兼容两种键名）
  - 请求参数业务化 formData；载荷/响应全程加密，**加密方式可选**：
    - `native`：XOR 循环加密（md5 派生密钥，默认）
    - `native_aes_ecb` / `native_aes_cbc`：AES-**256**（密钥=md5 hex 全部
      32 字节，CBC 用 md5 后 16 字节作 IV，cipher 名与密钥 XOR 嵌入）
    - `native_des`：DES-ECB（密钥=md5 前 8 字节）
- **现代流密码自实现变体（NATIVE 骨架 + 纯 PHP 算法）**：
  - `native_chacha20`：ChaCha20（RFC 8439，TLS 1.3/SSH/WireGuard 标准流密码）
    密钥 = 密码 md5 hex ASCII（256 位），nonce 12 字节随载荷明文携带；
    请求 counter=0 / 响应 counter=1（响应使用**全新随机 nonce**，避免与请求
    密钥流重叠），载荷 `b64(nonce+密文)`
  - `native_rabbit`：Rabbit（RFC 4503，eSTREAM 最终推荐流密码）
    密钥 = 密码 md5（128 位），IV 8 字节随载荷携带；请求密钥流偏移 0 /
    响应偏移 64 字节且**响应使用全新随机 IV**（平方运算 16 位拆分，任意 PHP int 位宽精确）
  - 与 native 系列一致：功能函数内置分发（md5 哈希）、crc32b 符号表、
    X-Debug-Key 头鉴权、formData 参数
  - 算法在 Rust SDK 与 PHP stub 内各自纯实现（无 openssl/mcrypt），
    以 RFC 官方向量互验（ChaCha20 块/加密向量、Rabbit 密钥/IV 向量）
  - 要求 64 位 PHP（32 位位运算不可靠）
- **OPSEC 业务伪装**：PHP stub 整体形如正常业务文件（「会话状态查询接口」），
  webshell 功能隐藏在业务函数中（函数名带随机前缀防与站点业务函数冲突）；
  敏感函数名（base64_decode / openssl_decrypt）完全不在代码中出现——运行时
  经 crc32b 哈希查表从 get_defined_functions() 解析（哥斯拉式符号表）；
  cipher 名（AES-128-ECB / DES-ECB）以 XOR 十六进制嵌入、运行时解密；
  eval 用大小写混合 + 随机纯字母注释分隔（`eVaL/*rvnd*/(...)`，`eval(` 连续
  字符串不存在），且 eval 经业务函数包裹 + 局部变量中转（防语义级查杀如 D盾
  的「内藏 Eval 后门」）；file_get_contents / php://input / 解码函数全部经
  crc32b 符号表查表调用与字符串拆分，stub 无明文敏感特征；参数为业务语义
  token/data；密钥由连接密码运行时派生
  > PHP 依赖分档：NATIVE 系列兼容 **PHP 5.3+**（`native_aes_*` / `native_des` 需 openssl 扩展）；
  > `native_chacha20` / `native_rabbit` 需 **64 位 PHP**（纯 PHP 实现，32 位位运算不可靠）；
  > `native_aead` 需 **PHP 7.1+ / 64 位 / openssl 支持 aes-256-gcm**
  > （`hash_hkdf` + `openssl_encrypt`）；gzip 传输压缩需目标有 zlib
  > `native_aead` 的**非 PHP** 依赖：JSP 需 JDK 8+（`javax.crypto` GCM）；
  > ASPX 需 .NET Framework 4.5+ 或 .NET 6+（纯托管 GCM 实现，不依赖 Windows 专有 API）；
  > Python 需 `cryptography`；Node 需 12+（`hkdfSync` / `aes-256-gcm`）；
  > **经典 ASP（VBScript）无内置 AES-GCM，`native_aead` 不支持**
- **编码方式：16 种**（生成 Webshell 与登记 Shell 都从这里选，两处必须一致）
  - NATIVE 内置分发系列（7）：`native`（XOR，默认）、`native_aes_ecb`、`native_aes_cbc`、
    `native_des`、`native_chacha20`、`native_rabbit`、`native_aead`
  - 经典/兼容形态（8）：`base64`、`xor_base64`、`char`、`php_obfuscate`、`php_stream`、
    `xor_body`、`des`、`xor_session`（哥斯拉式分阶段载荷）
  - `custom`：用户上传 stub 模板（须按契约实现：表单参数 `k` = 密码、`x` = `base64(XOR(代码, md5(密码)))`）
- **三条通道功能对齐**（同一个 Shell 换编码方式不再少功能）
  - NATIVE 内置分发：stub 落地，命令/文件/数据库等 12 项功能内置，敏感函数经 crc32b 符号表调用
  - 分阶段载荷（session）：处理器一次注入、后续只传参数；**由客户端每次连接注入**，
    因此能力始终与客户端同版本
  - legacy 逐请求：代码逐请求下发，兼容既有 stub
  - 三者共用同一份 PHP 实现（`crates/dosword-sdk/src/php_impl.rs`）：
    命令函数降级链（`shell_exec` → `exec` → `system`/`passthru` → `popen`，全部被禁用时给出明确错误）、
    6 个数据库驱动（mysql / pgsql / sqlite / mssql / oracle / redis）、
    目录列举单次 `stat()` 合并
  - **OPSEC 对齐**：session 处理器与 legacy 逐请求代码里的敏感函数名
    （命令执行五函数、`base64_*`、`file_get_contents`/`file_put_contents`、
    `scandir`、`unlink`/`rmdir`/`rename`/`mkdir`/`touch`、`fopen`/`fseek`/`fread`/`fwrite`/`fclose`、
    `stream_socket_client`、`preg_split`、`gzdecode`/`gzencode`、`eval`）
    全部改经**随代码自带**的 crc32b 运行时符号表调用（运行时从
    `get_defined_functions()` 反查），代码里只出现哈希与索引；
    `eval` 用大小写混合 + 随机注释分隔。符号表内嵌在处理器/载荷里，
    不依赖目标上已部署 stub 的版本。
  - gzip 传输压缩：NATIVE 与分阶段载荷通道都在**明文层**（加密之前）压缩，
    能真正收回 base64 的 33% 膨胀；NATIVE 需新 stub 上报 `gzip_plain`，
    请求为 `{"z":1,"d":"base64(gzip(内层 JSON))"}`、响应在加密前 gzip
    （客户端按魔数识别，无需额外标记）。旧 stub（未上报 `gzip_plain`）
    继续走原有的密文层压缩路径，行为不变。
    **legacy 通道不压缩** —— 请求由目标上已部署的 stub 解包，旧 stub 不会 gunzip
- **能力协商**：stub 上报 `ProtoVersion` / `Capabilities` / `ShellType`；
  客户端**只在 stub 明确上报且缺项时**拒绝（旧 stub 不上报 → 保持旧行为），
  错误提示「请用当前版本重新生成并上传 stub」而不是发出去必然失败
- **传输形态可配（Transport Profile）**：每 Shell 可在 `protocol_params.transport` 指定
  请求参数名 / 鉴权头名（NATIVE 系列；须与 stub 一致，生成 stub 时同样可配）、
  附加查询串（如 `?v=1`）、额外请求头、以及表单体随机填充字节。
  参数名/头名严格校验（拒绝 CRLF/头注入），非法配置在保存 Shell 时就拒绝；
  未配置时行为与历史版本完全一致。
- **会话层（W4）**
  - **心跳**：会话页每 45s 对全部活跃会话轻量探活，掉线标记 `STALE`；
    心跳不刷新 TTL（空闲会话仍按 4h 过期）
  - **多路复用**：NATIVE / 分阶段通道支持一次往返执行多个逻辑调用；
    批量目录浏览优先走该通道（legacy 通道自动回退到 4 线程并行逐个拉取）
  - **断点续传**：上传按「会话 + 远端路径 + 源文件大小/修改时间」记录检查点，
    中断重试从断点继续（远端长度不符则自动从头开始）；下载先写 `<目标>.dswpart`，
    远端大小未变时续传，完成后原子改名
  - **背压**：每会话一个令牌桶（PTY 轮询与文件分块共享，容量 120 / 每秒补充 40），
    超限返回明确错误或空轮询，避免 agent 高频请求打满目标
- **扩展与自动化（W6）**
  - **WASM 沙箱插件**：插件目录下的 `<name>.wasm` + 同名 `<name>.wasm.json` 清单。
    插件只能调用**声明过**的宿主能力（`fs.read` 限于插件目录内、`http`、`exec`），
    未声明的导入在实例化阶段即失败；每次执行新建 Store，燃料 5×10⁷、内存上限 64 MiB，
    宿主调用 10s 超时 / 1 MiB 结果上限。设置页「插件」可直接安装 `.wasm`
    （同目录需有清单），卸载会同时清理模块与清单。
  - **Playbook**：YAML 描述批量操作（connect / disconnect / exec / list_dir / read_file /
    write_file / db_probe / db_query / plugin），支持 `${步骤id.字段}` 变量（含内嵌插值）
    与 `contains` / `equals` 断言；**条件** `when`（真值 / equals / not_equals，`!` 取反）
    与**循环** `repeat: N` / `foreach: { source, as }`（结果聚合为 `iterations`）；
    失败默认中止，`continue_on_error` 可覆盖。动作用的是与 GUI/MCP 相同的服务层
    （授权复查与审计一致），不依赖 MCP 服务是否开启。
  - **CLI**：`dosword-cli` 复用桌面端同一服务层与数据目录，子命令
    `shells` / `exec` / `fs ls|read|write` / `db query` / `playbook run` / `stub generate`，
    全部支持 `--json`；高级参数 `--proxy` / `--timeout` / `--tls-verify`（仅本次进程，
    不写回设置）与 `stub generate --out <file>`。
- **生成 Webshell**：PHP / ASP / ASPX / JSP / Python / Node 六种语言 × 编码器生成服务端 stub
  > 语言可用性（实测口径）：PHP 全功能；Python（CGI）与 Node 可用；
  > JSP / ASPX 的 stub 已通过**编译与密码学互操作验证**（javac / dotnet 实机编译运行，
  > 覆盖 native 与 native_aead 两种编码），但**页面级集成未在真实容器（Tomcat / IIS）
  > 中验证**，勿用于真实评估；经典 ASP 未验证且 `native_aead` 不支持。
  > 详见 `docs/优化拓展方案.md` 的「已知缺口」一节。
- 分块上传下载（块大小可配，默认 4MB；`read/write` 走偏移读取 + 顺序追加写），上传带进度条
  > 需要**用当前版本重新生成并上传 stub**：旧 stub 未上报 `ChunkedTransfer` 能力，
  > 客户端会明确报错而不是退化为"整文件返回/从头覆写"
- **数据库管理**（PDO / JDBC / Python / Node）：连接探测、数据库/表浏览、SQL 执行、结果网格
- **请求调试**（协议帧检查器）：进程内环缓冲记录每条协议载荷与响应，密码与派生令牌自动脱敏
- 本地 Mock 协议（默认）：不产生任何网络流量
- 命令终端（xterm.js，多 Tab、cwd 追踪、历史持久化）、文件管理器、设置页、审计页
- 命令层异步化（阻塞线程池），网络操作不冻结 UI、多会话互不阻塞

安全姿态（三层防线 + 可配置加固）：

1. 真实网络协议**默认关闭**，需在「设置」中二次确认后开启；关闭时会**强制断开**全部活跃会话
2. 创建 HTTP Shell 时必须勾选「我已确认目标位于授权范围内」
3. 后端校验 endpoint 落在 Workspace 授权范围内（精确主机 / `*.suffix` / CIDR / 通配），每次操作复查授权到期；
   请求调试与「测试连接」同样受联合范围约束，越界需显式勾选覆盖并记入审计
4. 「设置 → 安全门禁」可配置：**校验 TLS 证书**（默认关闭，见 SECURITY.md）、
   **允许任意本地路径**（默认仅限用户目录/临时目录）、**允许 run_code 任意代码执行**

## 使用真实 PHP 协议

### 1. 生成服务端 stub（到授权目标）

总览 → 生成 Webshell：选择语言（PHP/ASP/ASPX/JSP/Python/Node）、编码方式
（默认 `native`，可选 AES/ChaCha20/Rabbit 等）与连接密码，生成脚本内容并可保存。
上传到目标站点（如 `shell.php`）。stub 不保存明文密码——内嵌的是密码的 md5
派生密钥（**等价于密码本身，务必保管好 stub**），客户端与 stub 自动一致。

### 2. 开启真实网络

设置 → 真实网络协议 → 开启（二次确认）→ 保存。

### 3. 登记 Shell

总览 → 登记 Shell：选择「标准 PHP WebShell（类蚁剑）」，填写 Endpoint 与连接密码，
并选择与 stub 一致的**编码方式 / 密钥盐 / 分阶段载荷（session）开关**——这三项在
「编辑 Shell」里同样可改（改完请重连，已建立的会话仍用旧通道）。勾选授权确认。

### 4. 连接与操作

连接后可在详情页进行文件管理与命令执行。所有操作都会写入审计日志。

> JSP / ASP.NET / 经典 ASP 的**客户端协议已实现**（`builtin.jsp.v1` / `builtin.aspnet.v1` /
> `builtin.asp.v1`）。JSP / ASPX 的 stub 现在有编译与密码学互操作测试兜底（见「生成 Webshell」
> 一节），但页面级集成仍未在真实容器（Tomcat / IIS）上验证，勿用于真实评估。

## 无 PHP 环境联调

仓库提供模拟服务器（按 PHP 协议应答，文件操作落在本地临时目录）：

```bash
python3 scripts/mock_shell.py --port 18080 --password secret
```

在 DoSword 中登记 `http://127.0.0.1:18080/shell.php`（协议选 PHP、密码 `secret`）即可联调全部功能。

## MCP 集成（把能力交给 AI 客户端）

DoSword 可作为 **MCP（Model Context Protocol）服务器**，把 Shell 管理能力暴露给
Claude Desktop / Cursor / 自研 agent。**默认关闭**，且只监听 `127.0.0.1`。

> ⚠️ 开启 MCP 等于把你手上有授权的 WebShell 交给一个模型来调用。能力按级别授权，
> 执行级默认需要人工确认，所有调用都写审计。详见 [SECURITY.md](SECURITY.md)。

### 启用

1. 「设置 → AI / MCP」→ 勾选「启用 MCP 服务」（令牌首次会自动生成）。
2. 保存设置；页签顶部会显示 `运行中 · http://127.0.0.1:7317/mcp · N 个工具`。
3. 点「复制 JSON」，粘到客户端配置里（Claude Desktop：`claude_desktop_config.json`；
   Cursor：`mcp.json`）：

```json
{
  "mcpServers": {
    "dosword": {
      "url": "http://127.0.0.1:7317/mcp",
      "headers": { "Authorization": "Bearer <在设置页复制的令牌>" }
    }
  }
}
```

### 能力分级（默认值）

| 级别 | 默认 | 工具 |
|---|---|---|
| 只读 | **开** | `dosword_workspaces_list`、`dosword_shells_list`（**不含密码**，仅 `hasPassword`）、`dosword_sessions_list`、`dosword_probe_session`、`dosword_settings_get`（令牌已清空、代理已脱敏）、`dosword_protocols_list`、`dosword_plugins_list`、`dosword_encoders_list`、`dosword_audit_query`、`dosword_fs_list`、`dosword_fs_read`（偏移分块）、`dosword_memshell_list/check/capabilities`、`dosword_proxy_chain_list`、`dosword_heartbeat_sessions` |
| 写入 | 关 | `dosword_shell_connect`/`_disconnect`、`dosword_fs_write`（支持追加偏移）、`dosword_fs_mkdir`/`_rename`/`_delete`/`_touch`、`dosword_db_probe`、`dosword_db_query`（`SELECT`/`SHOW`/`EXPLAIN` 自动按只读处理，其余按写入）、`dosword_proxy_chain_start/stop` |
| 执行 | 关 | `dosword_exec`、`dosword_plugin_run`、`dosword_generate_stub`、`dosword_memshell_install/uninstall`、`dosword_run_playbook` |

**不通过 MCP 暴露**：Workspace / Shell 的增删改、插件安装、修改设置、本地文件读写、
`http_send` 原始请求、PTY。授权登记表只能由人在 GUI 里维护——agent 无法给自己扩权。

### 执行级人工确认

默认开启。执行级工具被调用时不会立即执行，而是返回待批准 id 并在设置页出现
「待确认操作」；点「批准」后 **120 秒内、参数完全一致**的重试才会执行（一次性消费，
再次调用需再次批准）。这样「模型想执行什么」始终由人过目。

### 资源与提示词

除工具外还提供只读**资源**（客户端可主动引用/附加到上下文）与一个**指引提示词**：

| 资源 | 内容 |
|---|---|
| dosword://shells | 已登记 Shell 的脱敏摘要（无密码，仅 hasPassword） |
| dosword://sessions | 活跃会话（sessionId / profileId / server / lastUsedAt） |
| dosword://audit/recent | 最近 20 条审计事件（含命令原文，请谨慎外传） |

提示词 dosword_guidance：说明授权边界、三级权限、执行级确认流程与安全用法。

### 观测

- 每次调用写审计 `mcp.<tool>`（含 `denied` / `pending` / `error`），可在「审计轨迹」按 `mcp.` 过滤。
- 「最近调用」表（时间/工具/级别/结果/耗时）保留最近 200 条，仅内存，不落盘。
- 限流默认 120 次/分、并发 4、单次请求体 ≤1 MiB、结果文本超 256 KiB 自动截断。

### 关闭

取消勾选「启用 MCP 服务」并保存 → 端口立即释放，客户端断开。若要彻底不编译该模块：

```bash
cargo build -p dosword --no-default-features   # 去掉 mcp feature 与 rmcp/axum 依赖树
```

## 剧本（Playbook）与内存马

### 剧本：把一串操作写成 YAML

「剧本编排」页可直接编辑并运行（Ctrl/Cmd+Enter），结果按步骤展示通过 / 跳过 / 失败与耗时。
CLI 侧等价命令是 `dosword-cli playbook run <file>`。

```yaml
name: smoke
continue_on_error: false
steps:
  - id: conn
    action: connect
    args: { shell_id: "shell-1" }
  - id: whoami
    action: exec
    args: { session_id: "${conn.sessionId}", command: "id" }
    expect: { contains: "uid=" }
  - action: list_dir
    when: { ref: "${conn.runtime}", equals: "php" }   # 条件为假 → skipped
    args: { session_id: "${conn.sessionId}", path: "/" }
  - action: disconnect
    args: { session_id: "${conn.sessionId}" }
```

- 动作：`connect` / `disconnect` / `exec` / `list_dir` / `read_file` / `write_file` / `plugin`
- 变量：`${步骤id.字段路径}`（如 `${conn.sessionId}`）、循环变量 `${item.字段}`
- 断言：`expect.contains` / `expect.equals`；条件：`when`；循环：`repeat` / `foreach`
- 每次运行写审计 `playbook.run`；失败步骤会带上后端错误原文

### 内存马（PHP）

支持两种形态，均带**卸载**与存活检测（无卸载能力的形态不予实现）：

| 形态 | 机制 | 说明 |
|---|---|---|
| `user_ini` | `.user.ini` + `auto_prepend_file` | 需要可写目录；落地一个 PHP 文件并在同目录写 `.user.ini` |
| `php_fcgi` | 直连 FPM（FastCGI） | 零落盘，需能直连 `host:port` 与目标脚本名 |

- 入口：Shell 详情页「内存马」页签，或 MCP 的 `dosword_memshell_*`（执行级，默认需人工确认）
- 先查形态：打开页签会自动探测（MCP 侧为 `dosword_memshell_capabilities`）
- **卸载**会清理落地文件与 `.user.ini` 中的条目；注入/卸载都写审计

## 开发

```bash
source "$HOME/.cargo/env"
pnpm install
pnpm tauri dev
```

Linux 打包还需要：

```bash
sudo apt-get install librsvg2-dev libayatana-appindicator3-dev patchelf
```

## 检查

```bash
pnpm check          # TypeScript 类型检查
pnpm check:ipc      # IPC 契约：前端 invoke 名 ↔ 后端 generate_handler! 注册
pnpm lint           # ESLint（含 react-hooks 规则）
pnpm build          # 前端构建
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo test --workspace                                # 含真实 PHP 往返测试（需本机有 php）
DOSWORD_REQUIRE_PHP=1 cargo test --workspace           # 缺 php 直接失败（CI 使用，防"跳过＝假绿"）
```

## 跨平台构建

```bash
./scripts/build.sh linux      # Linux 安装包（deb / appimage / rpm）
./scripts/build.sh windows    # 在 Linux 上交叉编译 Windows 安装包（nsis）
./scripts/build.sh all        # 两个平台依次构建
./scripts/build.sh check      # 仅运行质量检查（cargo test + pnpm check）
```

- Windows 交叉编译依赖 `mingw-w64`（Ubuntu/Debian：`sudo apt install gcc-mingw-w64-x86-64`），rust target 由脚本自动安装
- Linux 打包依赖 `librsvg2-dev libayatana-appindicator3-dev patchelf`（缺失时 appimage 会失败，deb 仍可用）
- 产物目录：全部最终产物统一输出到 `target/release-artifacts/`
  （独立二进制 dosword-linux-x86_64 / dosword-windows-x86_64.exe + 各平台安装包）

## 数据库

SQLite 位于 `app_data_dir/dosword.sqlite3`（Linux: `~/.local/share/io.dosword.desktop/`）。
通过 `PRAGMA user_version` 管理迁移，旧版本数据库启动时自动无损升级（当前 v4）。

## 前端类型生成

`src/api.ts` 的类型由 Rust DTO 经 ts-rs 生成（`src/generated/domain.ts`），修改 `crates/dosword-sdk/src/domain.rs` 后运行：

```bash
pnpm gen:types
```

`cargo test` 也会校验生成文件与当前 Rust 类型一致，漂移时自动重新生成并报错。

## 协议 SDK / 插件

协议体系已插件化：`crates/dosword-sdk` 是纯接口库（零 tauri 依赖），第三方协议以 workspace crate 接入。

### 三步接入新协议

1. 新建 crate 并依赖 SDK：

```toml
[dependencies]
dosword-sdk = { path = "../dosword-sdk" }
```

2. 实现 `Protocol`（13 个操作，不支持的可省略用默认 `NotSupported`）+ `ProtocolPlugin::manifest`（清单含 id/版本/描述/能力列表）：

```rust
use dosword_sdk::{Protocol, ProtocolPlugin, PluginKind, PluginManifest};

pub struct MyProtocol;
impl ProtocolPlugin for MyProtocol {
    fn manifest(&self) -> PluginManifest {
        PluginManifest {
            id: "my.v1".into(), name: "我的协议".into(), version: "0.1.0".into(),
            kind: PluginKind::Protocol, description: "...".into(),
            capabilities: vec!["terminal".into()],   // files / database / terminal
        }
    }
}
impl Protocol for MyProtocol { /* ... */ }
```

3. 宿主注册一行（`src-tauri/src/protocol/mod.rs`）：`Box::new(my_protocol::MyProtocol)` 加入 `builtin()` 数组。

接入后自动获得：授权范围校验、审计日志、会话管理、请求调试记录、前端 Tab 按 `capabilities` 显隐。完整示例见 `crates/dosword-plugin-echo`（ECHO 帧协议，含测试）。

> 动态加载（插件目录 + dlopen）为 v2 演进，注册表接口已预留，插件代码无需改动。

## 路线图

- ✅ V1.0：Shell / File / Terminal / 审计分页 / CRUD / 标签 / 分块传输
- ✅ 数据库管理模块：PDO 三驱动、SQL 执行与浏览（mysql/pgsql 需目标 PHP 有对应 PDO 驱动）
- ✅ 请求调试：协议帧记录与检查（环缓冲 200 条，密码脱敏）
- ✅ 协议 SDK / 插件系统：dosword-sdk + 示例插件（动态加载为 v2 演进）
- ✅ Workspace 增强：到期状态徽章、按 Workspace 筛选、批量探测
- V2.0：动态加载插件 ✅（脚本型 .plugin JSON + 二进制 .so/.dll dlopen）

## 二进制插件（Native .plugin）
- 导出宏 `export_dosword_plugin!(MyPlugin)`：unit struct 实现 `NativePlugin`，
  编译为 cdylib（crate-type = ["cdylib"]）即可被宿主 dlopen
- 运行时校验 ABI 魔数/版本；安装复制到数据目录 plugins/*.native.so，
  启动自动扫描加载；卸载删除文件并释放
- v1 约定：execute 为纯逻辑（runtime + 参数 JSON → JSON），
  需要命令/代码通道的插件请用脚本型 .plugin

## 功能插件清单（内置 37 个 + 外部 .plugin）

**功能（feature）**：进程详情、系统信息、端口扫描、ZIP 压缩、WebShell 扫描、
文件搜索、网络信息、用户枚举、PHP 环境检测、凭据枚举（仅检查存在性、不读内容）、
代码执行（P_Eval_Code）、ByPassOpenBasedir（symlink+glob）、Bypass 环境检测

**系统运维（feature）**：计划任务（Linux crontab / Windows schtasks）、
服务管理（systemctl / service / sc）、结束进程（kill -9 / taskkill）、
远程下载（URL 落盘，curl 降级）

**网络代理（feature）**：Socks5（RFC1929 认证 + pcntl 常驻）、端口转发、
端口映射（LCX 反向桥接）、HTTP 代理、综合调度壳

**Bypass 向量库（loader，10 个独立向量，手动选择测试）**：
直接系统调用 / FFI / pcntl_exec / LD_PRELOAD / COM(Windows) / 老版本 eval /
dl 动态加载 / FPM 未授权 / GCONV_PATH / pcntl 反弹

**加载器（loader）**：
- 虚拟终端（反弹 Shell）：fsockopen + proc_open 反弹 /bin/bash 到攻击机
  （后台驻留可选）；本地 `nc -lvnp PORT` 接收
- 交互式终端（linpty）：script 分配 PTY 的完全交互式反弹 shell
  （支持 su 用户切换 / vim / top）；本地用 PTY 方式接收：
  `socat TCP-LISTEN:PORT,reuseaddr,fork EXEC:'bash',pty,stderr,setsid,sigint,sane`

**加密器（crypto）**：加解密工具（AES-256-CBC / MD5-XOR 文本）

**加载器（loader）**：代码加载器（任意 PHP 代码执行 + 可选落盘持久化）

> 插件类型（kind）在清单中声明；前端按 功能/加密器/加载器 分组展示；
> 非 PHP 运行时的通用插件自动降级为命令型（/dev/tcp 扫描、zip 命令等）
- V3.0（部分）：大型 Shell 库（分页）、自动备份（远程同步·本地版）✅；
  团队共享经「导出/导入 + 备份文件」协作；高速索引=搜索过滤
- **JSP / ASP.NET 协议**（builtin.jsp.v1 / builtin.aspnet.v1）：
  - 与 PHP native 相同载荷协议（formData XOR 密文 + X-Debug-Key 头 +
    md5 哈希分发），stub 为 Java（javax.servlet）与 C#（aspx），
    命令 / 文件 / 探测（手动 JSON，无第三方依赖）
  - 生成 Webshell 支持 jsp / aspx / asp（XOR 载荷）；经典 ASP（VBScript）
    协议 builtin.asp.v1 已可用（命令/文件；操作分发用字符串比较免 MD5，
    base64 纯 VBScript 实现，文件 I/O 用 FSO + ADODB.Stream）
