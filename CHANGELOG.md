# 更新日志

本项目所有值得注意的变更都记录在此文件。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 新增（AEAD 多语言，2026-10-20）

- **JSP / ASP.NET / Python / Node 的 AEAD stub**（编码器 `native_aead` 不再只有 PHP）。
  四者与 PHP 版逐字节互操作：HKDF-SHA256（盐 `dosword/aead/v2`、info `dsw2`）派生密钥、
  AES-256-GCM、帧 `base64(nonce[12] ‖ seq[8] ‖ ct ‖ tag[16])`、
  AAD `"dsw2" ‖ 方向 ‖ seq`、连接 sid = nonce 前 8 字节，按 sid 维护防重放窗口。
  - JSP：`javax.crypto` GCM（`GCMParameterSpec`，128 位 tag），`DSW_SEEN` 按 sid 记序号
  - ASPX：**纯托管**实现（ECB 原语 + CTR + GHASH + GCM tag），.NET Framework 与 .NET 6+
    均可运行——不使用 `AesCryptoServiceProvider` / `RNGCryptoServiceProvider`
    （在 .NET Core / Linux 上抛 PlatformNotSupported）
  - Python：`cryptography` 的 `AESGCM`（缺失时给出明确错误），防重放状态按 sid 落临时目录；
    解码失败返回**可解密的错误帧**，不再 404 / 空响应（此前表现为客户端 JSON 解析失败）
  - Node：原生 `crypto` 的 `hkdfSync` + `aes-256-gcm`
  - IKM（`SHA256(密码)` 的十六进制）与 PHP 一致以 **XOR 形式嵌入**，stub 中不出现明文
  - 经典 ASP（VBScript）无内置 AES-GCM：`native_aead` 明确拒绝并说明原因
- 客户端：`src-tauri/src/protocol/jsp.rs` 按编码器选择载荷编码器
  （`native` → XOR、`native_aead` → `AeadSession`），AEAD 会话状态随连接建立。
- 测试：
  - Node / Python：真实服务端到端往返（连接 / 命令 / 文件 / 分块）+ 重放拒绝
  - JSP / ASPX：**密码学互操作**测试——把 stub 的 `<%! %>` / `<script runat="server">`
    声明块与页面脚本片段抽出，用 `javac` / `dotnet` 编译成普通程序运行，验证
    「Java/C# 解 Rust 帧、Rust 解 Java/C# 帧、重放被拒」，无需 servlet 容器 / IIS
  - JSP / ASPX 的 NATIVE（XOR）变体做编译期校验（与 AEAD 变体共用同一模板）
  - SDK：AEAD 语言矩阵测试（四种语言可生成、经典 ASP 拒绝、IKM 不明文）

### 修复（AEAD 多语言，2026-10-20）

同批工作中暴露的 JSP / ASPX 模板缺陷——此前**没有任何测试能发现**（无容器、无编译检查）：

- JSP 声明块反斜杠被双重转义（生成的 Java 根本无法编译）、
  `String out` 遮蔽 JSP 隐式 `out` 对象、声明块末尾多一个右花括号
- ASPX 声明块反斜杠双重转义；NATIVE 变体的 `\n` 未转义为真实换行（语句挤在一行）
- JSP / ASPX 的 `separator` 字段转义错误，产出**非法 JSON**（探针响应解析失败）
- ASPX 的 GCM 计数器从 0 起算（应为 J0+1），导致 tag 校验通过但明文是乱码

### 新增（2026-10-20）

- **文件管理器压缩 / 解压入口**：右键菜单新增「压缩为 ZIP」与「解压到此处」
  （仅 .zip 条目显示），走既有的插件机制：
  - 压缩复用内置 `zip` 插件（PHP ZipArchive / 非 PHP 系统 `zip`）
  - 新增内置 `unzip` 插件：PHP 侧逐条目校验后解压，**拒绝绝对路径与 `..` 条目**
    （zip-slip），跳过数回传并在前端明确提示「有 N 个条目被跳过」，避免
    「看着成功但少文件」；非 PHP 走系统 `unzip`，路径参数照旧过 `validate_path_arg`
  - 测试：`unzip_payload_guards_against_path_traversal`（载荷含两类穿越判定与转义）、
    `unzip_non_php_command_validates_paths`（shell 元字符被拒）、
    `real_php_zip_and_unzip_plugins`（真实 PHP：打包 → 解压 → 内容校验，且断言正常
    归档的跳过数为 0）；本机 php 无 ZipArchive 时显式跳过而非误报失败

### 性能与规模化（2026-10-20）

- **Shell 库改为服务端分页 + 过滤**（此前每次打开看板/详情都拉全量 Shell，含明文密码）：
  - `dashboard()` 不再返回全量 `shells`，改为 `shellStats` 聚合（总数 / 在线数 /
    最近连接时间 / 全部标签 / 各 Workspace 计数）；迁移 v8 补
    `idx_shell_workspace_created` 支撑「按 Workspace 过滤 + 按创建时间倒序翻页」
  - 新增 `query_shells`（关键字匹配 name/endpoint/runtime/tags + Workspace/标签/状态过滤，
    排序 `created_at DESC, id` 保证翻页不重不漏；通配符按字面量转义），返回**无密码**的
    `ShellSummary` 分页结果
  - 新增 `get_shell`（编辑表单按 id 取完整配置）、`list_shell_summaries`（目标选择器）
  - 前端：看板列表改服务端分页（关键字 250ms 防抖、筛选变化回第一页、越界页自动收敛、
    批量探测按同一组条件从服务端取回并说明 500 上限）；4 个选择器视图与 Shell 详情页
    不再拉看板
- **锁序修正**：`connect_shell_impl` / `disconnect_shell_impl` / `run_feature_plugin`
  三处曾在持全局会话锁期间访问数据库（`disconnect` 与 `plugin.run` 更是在锁内写审计 +
  fsync）。改为短锁取参、锁外写库，并把「两把锁不得同时持有」写进 `AppState` 文档。

### 工程化（2026-10-20）

- **前端接入 vitest**（此前零测试）：`vitest.config.ts`（jsdom 环境，与生产构建配置分离）+
  `pnpm test` / `pnpm test:watch`，CI 前端 job 增加「前端单测」步骤。
  首批 3 个文件 36 个用例：
  - `src/shells/encoders.test.ts` —— 编码方式分类（与后端 `session_mode_for` 同义）、
    `protocol_params` 的容错解析与生成（默认值不写入、参数名/头名只对 NATIVE 生效、
    额外请求头去空白与 CRLF 处理）、build↔parse 往返
  - `src/theme.test.ts` —— 主题读取/回落/`data-theme` 写入
  - `src/components/common.test.tsx` —— 错误边界（捕获后不白屏、重试恢复）、
    Metric 数字补零、ErrorBanner 空消息不渲染、向上展开的每页条数选择器交互
- **发布流程工具链钉版本**：`release.yml` 原用浮动的 `dtolnay/rust-toolchain@stable`
  （注释还写着「版本来自 rust-toolchain.toml」，但 `@stable` 会绕过它），现与 ci.yml /
  `rust-toolchain.toml` 统一为 `1.98.1`；三处一起升级的约定已写进 `rust-toolchain.toml`。

### 新增

- **MCP 服务端**（`src-tauri/src/mcp/`，cargo feature `mcp` 默认开启）：把 DoSword 能力
  以 MCP 工具暴露给 Claude Desktop / Cursor 等 AI 客户端
  - 传输：Streamable HTTP，仅绑定 `127.0.0.1`，Host 校验限定回环（防 DNS rebinding），
    请求体上限 1 MiB，`CancellationToken` 优雅停机
  - 鉴权：`Authorization: Bearer <64 hex>`，常量时间比较；令牌由 getrandom 生成、
    可轮换、UI 掩码、任何工具输出中不出现
  - 能力分级：read（默认开）/ write / exec（默认关），逐级在设置页授权
  - 执行级**人工确认**：返回待批准 id，GUI 批准后 120 秒内同参数重试才生效（一次性）
  - 23 个工具：Workspace/Shell/会话/设置/协议/插件/编码器/审计查询、目录列表、
    偏移分块读文件、会话连接与断开、写文件/建目录/重命名/删除/改时间戳、
    数据库探测与查询（含只读语句自动分级）、命令执行、插件运行、生成 stub
  - 治理：每次调用写审计 `mcp.<tool>`（success/denied/error/pending）、最近调用环形缓冲
    （设置页可见）、滑动窗口限流（默认 120 次/分）、并发 4、单调用超时、结果 256 KiB 截断
  - 脱敏：Shell 列表改 `ShellSummary`（无密码，仅 `hasPassword`）、设置视图清空
    `mcpToken` 并掩码代理地址
  - 新增命令：`mcp_status/start/stop/rotate_token/recent_calls/clear_log/
    pending_approvals/resolve_approval`；设置页新增「AI / MCP」页签
    （状态、端口、令牌、三级开关、确认模式、客户端配置一键复制、待确认操作、调用日志）
  - 新增底层命令 `read_chunk`（与 `write_chunk` 对称的偏移读，返回 `FileChunk`）
  - 资源与提示词：`dosword://shells` / `dosword://sessions` / `dosword://audit/recent`
    三个只读资源（经脱敏层、审计详情截断）与提示词 `dosword_guidance`
    （授权边界、三级权限、执行级确认流程、安全用法）；`get_info` 已宣告 resources/prompts 能力
  - 明确不暴露：Workspace/Shell 增删改、插件安装、改设置、本地文件读写、`http_send`、PTY
  - MCP 工具面补全（P2）：工具数 23 → 33 —— 内存马 `memshell_list/check/capabilities`（只读）、
    `memshell_install/uninstall`（执行级）、`proxy_chain_list`（只读）、`proxy_chain_start/stop`（写入级）、
    `heartbeat_sessions`（只读）、`run_playbook`（执行级）；README 工具表同步更新
  - `cargo build --no-default-features` 可完全裁掉 MCP 模块与 rmcp/axum 依赖树

### 修复（PHP 通道对齐，2026-10-19）

PHP 侧此前是「三条通道、三套能力」：同一个目标换个编码方式就少一半功能。
本轮把三条通道对齐到同一份实现，并把每个编码器纳入真实 `php -S` 往返测试
（测试随即暴露出下列**实际缺陷**，不是理论风险）：

- **8 个 legacy 编码器（`base64` / `xor_base64` / `char` / `php_obfuscate` /
  `php_stream` / `xor_body` / `des` / `xor_session`）全部不可用**：
  `business_php_stub` 与 `xor_body` 模板各有一段「执行器降级」覆盖 `$_g[0]`，
  而该槽位属于调用方传入的第一个符号（`base64_decode` / `openssl_decrypt`）——
  解包时去调用 `shell_exec(密文)`，响应恒为 `{"code":200,"rule_size":0}`，
  客户端报「响应中未找到协议帧」。（session 模板此前修过同一个坑，这两处漏了。）
- **legacy 通道没有分块能力**：legacy 的 probe 不返回 `info` 表 → `ChunkedTransfer`
  取不到 → 分块上传/下载一律被拒（旧 stub 上的大文件传输等于不可用）。
- **数据库能力三条通道不一致**：legacy 只列 mysql/pgsql 的库且**显式拒绝 redis**，
  分阶段通道只有 mysql/pgsql/sqlite（无 mssql/oracle/redis）。现统一 6 驱动，
  由 stub 端实现（`php_impl::PHP_DB_PROBE_IMPL` / `PHP_DB_QUERY_IMPL`）。
- **命令降级链只有 NATIVE 有**：session / legacy 硬用 `@shell_exec`，
  目标禁用 `shell_exec` 时命令通道直接死。现三条通道共用 `PHP_EXEC_IMPL`
  （`shell_exec` → `exec` → `system`/`passthru` → `popen`；全部被禁用时返回
  明确错误而不是静默空输出）。legacy 通道同时补上 `cd` 前缀与 cwd 跟踪。
- **能力协商只上报不使用**：`session_probe` 的 `capabilities` 恒为 `None`，
  客户端只看 `ChunkedTransfer` 一个标志。现 `db` / `exec` / `gzip` / `chunked`
  统一走 `require_capability()`：旧 stub（未上报）保持 v1 行为，
  明确上报但缺项时精确拒绝并提示重新生成 stub。
- **登记/编辑 Shell 无法设置 `session:true`**：生成器有「分阶段载荷」开关且提示
  "需与连接端一致"，登记表单却没有该字段，`update_shell` 也不接受协议参数 ——
  生成 session stub 后按 UI 登记必然连不上（只有 `xor_session` 编码器能进该通道）。
  现表单可改编码方式 / 盐 / session，`update_shell` 支持协议参数，
  并在保存时校验未注册的 encoder id。
- **前端数据库「预览」硬编码反引号 + `LIMIT`**：pgsql / mssql / oracle 上点表名必报错。
  现按驱动分派标识符引号与分页语法（MSSQL `TOP 100` / Oracle `FETCH FIRST 100 ROWS ONLY`）。
- **gzip 压缩位置修正**：NATIVE 通道原先把 gzip 放在**加密之后** —— 密文是高频熵
  数据，只有 XOR 变体因周期性偶有收益，AES / ChaCha20 / Rabbit 下几乎压不动，
  「gzip 传输压缩」设置形同虚设。现改为**加密前**压缩：请求走
  `{"z":1,"d":"base64(gzip(内层 JSON))"}` 信封、响应在加密前 gzip（客户端按魔数识别）。
  新增能力位 `gzip_plain` 区分新语义；旧 stub 继续走原密文层压缩路径，行为不变。
- **P1 的目录列表 `stat` 合并只在 legacy 模板生效**：默认 NATIVE 与 session 仍是每项
  `is_dir` + `filesize` + `filemtime` + `fileperms` 四次调用。现三条通道统一单次
  `stat()`（`is_dir` 由 `mode` 判定），顺带消除 stub 里明文的 `fileperms(`。
- **session / legacy 通道的敏感函数名全部改经运行时符号表**：命令执行五函数、
  `base64_*`、文件读写/列举/删除/重命名/建目录/改时间戳、`fopen`/`fseek`/`fread`/
  `fwrite`/`fclose`、`stream_socket_client`、`preg_split`、`gzdecode`/`gzencode`
  以及 `eval` —— 代码里只出现 crc32b 哈希与索引，运行时从 `get_defined_functions()`
  反查；符号表随处理器/载荷自带，不依赖目标上已部署 stub 的版本（旧 stub 也没有新索引）。
  回归测试：`session_handler_and_shared_impl_have_no_plain_sensitive_names`、
  `legacy_channel_payloads_have_no_plain_sensitive_names`（后者从请求调试环缓冲
  取真实载荷断言）。
- 分阶段载荷的 gzip 改为**明文层**压缩（`{"n":..,"z":1,"d":base64(gzip(请求))}`）：
  密文层压缩对高熵密文收益接近零，而 base64 载荷的 33% 膨胀可以被真正收回。

### 新增（扩展与自动化 W6 · 延伸）

- **WASM 插件 UI 安装入口**：设置页「插件」可选择 `.wasm` 安装（要求同目录下有
  同名 `.wasm.json` 清单），安装前完成 id / 能力白名单 / 模块解析校验；
  卸载时同时清理 `<id>.wasm` 与 `<id>.wasm.json`；安装写审计 `plugin.install`。
- **Playbook 条件与循环**：
  - `when: { ref, equals?, not_equals? }`（`ref` 支持 `!` 取反）为假时跳过该步骤，
    报告新增 `skipped` 字段；
  - `repeat: N` 与 `foreach: { source, as }`（source 可为 `${...}` 或内联数组），
    结果聚合为 `{"iterations":[...]}`，断言逐轮检查；上限 1000；
  - 变量替换支持内嵌插值（`echo ${item.name}`）与无点引用（`${item}`）。
- **CLI 高级参数**：`--proxy <url>` / `--timeout <secs>` / `--tls-verify` 通过
  运行期设置覆盖生效（不写回数据库，AppState 新增 `settings_override`）；
  `stub generate --out <file>`；`--json` 输出补充 `bytes` / `path`。
- 测试：`when` 跳过/真值/取反、`repeat` 聚合、`foreach` 绑定循环变量与非法 source、
  设置覆盖只影响 `effective_settings` 不写库。

### 新增（扩展与自动化 W6）

- **WASM 沙箱插件**（cargo feature `wasm`，默认开启）：插件目录下的
  `<name>.wasm` + 同名 `.wasm.json` 清单，由 wasmtime 运行。
  - 能力声明制：`fs.read`（限于插件目录内，防目录穿越）/ `http` / `exec`；
    未声明的导入**不链接**，插件在实例化阶段即失败（link-time denial）
  - 资源限制：每次执行新建 Store（状态隔离），燃料 5×10⁷、内存 64 MiB、
    宿主调用 10s 超时 / 1 MiB 结果上限
  - ABI：`memory` + `dsw_alloc` + `dsw_execute(req_ptr, req_len) -> i64`
  - `--no-default-features` 可完全裁掉 wasmtime/cranelift 依赖树
- **Playbook**：YAML 描述的批量操作序列（connect / disconnect / exec / list_dir /
  read_file / write_file / db_probe / db_query / plugin），支持 `${步骤id.字段}`
  变量替换与 `contains` / `equals` 断言；失败默认中止。动作复用命令层服务函数，
  授权范围复查、到期检查、审计与 GUI 完全一致，不依赖 MCP 服务开启。
  新增命令 `run_playbook` 与 `PlaybookReport` / `PlaybookStepReport` DTO。
- **CLI**：新增 `dosword-cli`（与桌面端同一 crate，链接同一服务层），
  子命令 `shells` / `exec` / `fs ls|read|write` / `db query` / `playbook run` /
  `stub generate`，支持 `--data-dir`（默认与桌面端一致）与 `--json`。
- 测试：WASM 插件执行 / 未声明能力拒绝 / 声明后放行 / 未知能力拒绝 / `fs.read`
  目录穿越拒绝；Playbook 解析、变量替换、JSON 子集断言、mock 协议端到端
  （connect → exec → list_dir → disconnect）与断言失败中止。

### 新增（会话层 W4）

- **心跳**：新增 `heartbeat_sessions` 命令，对全部活跃会话轻量探活
  （PHP：NATIVE / 分阶段走 `probe`，legacy 走探测模板；其它协议执行无副作用命令）。
  `SessionInfo` 增加 `lastHeartbeatAt` / `stale`；会话页每 45s 自动探活，
  掉线显示 `STALE`。心跳**不**刷新 `last_used_at`（TTL 语义不变）。
- **多路复用**：NATIVE stub 与分阶段处理器新增 `batch` 分发（单次调用与批量共用
  `__RUN__` / `<prefix>once` 分发器）；批量目录浏览优先一次往返取回全部未缓存路径。
  legacy 通道明确返回 `NotSupported`，命令层回退到原有的 4 线程并行拉取。
  新能力位 `batch`（旧 stub 不上报 → 自动回退）。
- **断点续传**：上传新增 `upload_begin` / `upload_finish` —— 按
  「会话 + 远端路径 + 源文件大小/修改时间」记录检查点，并用远端文件长度校验断点；
  下载改为写 `<目标>.dswpart` + 远端大小校验，完成后原子替换，
  `download_file` 返回 `TransferOutcome { bytes, resumedFrom }`。
- **背压**：每会话一个令牌桶（容量 120、每秒补充 40），PTY 读写与分块读写/
  上传下载**共享**；PTY 读超限返回空轮询（前端按节奏重试），写与文件操作返回
  明确错误，避免自动重试风暴。
- 测试：`real_php_heartbeat_round_trip`（三通道探活 + 目标下线后失败）、
  `real_php_batch_list_dir_round_trip`（逐项容错 + legacy 明确不支持）、
  `heartbeat_marks_stale_and_does_not_touch_last_used`、
  `token_bucket_throttles_and_refills`、`split_parent_handles_posix_and_windows_paths`。

### 新增（PHP）

- **W2 传输形态可配（Transport Profile）**：每 Shell 可在 `protocol_params.transport`
  配置请求参数名 / 鉴权头名（NATIVE 系列，须与 stub 一致）、附加查询串、
  额外请求头、表单体随机填充字节。
  - SDK 新增 `StubOptions` + `PayloadEncoder::stub_with`（默认转调 `stub`）：
    `native*` / `native_aead` 把参数名与头名烘焙进 stub；默认值即历史行为
  - 客户端三条通道统一应用查询串与额外头；NATIVE/legacy 表单体支持随机填充
  - 严格校验：参数名须为 PHP 标识符、头名须为 HTTP token（拒绝 CRLF 注入）、
    查询串须以 `?`/`&` 开头且不含空白与 `#`、填充 ≤ 4096；保存时就报错
  - 生成器与登记/编辑表单都暴露这些字段；MCP `dosword_generate_stub` 同步支持
  - 测试：`stub_with_custom_param_and_header`、`stub_options_validate_rejects_bad_values`、
    `transport_profile_validation`、`real_php_transport_profile_round_trip`
    （自定义参数名/头名连通；不匹配时必须连不上）
- `crates/dosword-sdk/src/php_impl.rs`：三条通道共用的 PHP 实现片段
  （命令 / 目录列举 / 数据库探测与查询 / redis RESP 辅助 / 环境信息表），
  由 `session_handler_matches_native_capabilities` 测试守住与 NATIVE stub 的一致性。
- 分阶段载荷与 legacy 通道的 probe 现返回完整 `info` 表：能力协商之外，
  内存马前置判定（`PHP_SAPI` / `user_ini_filename` / `DOCUMENT_ROOT`）在
  session / legacy 通道上此前也拿不到数据。
- 测试：`real_php_native_gzip_plain_round_trip`（NATIVE 明文层 gzip，开/关）、
  `gzip_plain_envelope_round_trips`（信封构造与还原）；
  `real_php_all_encoders_round_trip` 改为遍历注册表全部编码器并跑
  命令/目录/整文件读写/偏移分块；`real_php_session_variants_round_trip` 补上
  `xor_session`（原数组里没有它，判断分支是死代码）；新增
  `real_php_db_round_trip_on_all_channels`（三条通道 × redis mock）、
  `session_handler_is_valid_php`（`php -l`）、
  `legacy_stubs_do_not_clobber_symbol_slot_zero`（回归守卫）。

### 修复（阻断级）

- **分块上传/下载对全部可选编码器均不可用**：`read_chunk`/`write_chunk` 缺少
  NATIVE/分阶段通道分支，走 legacy `k/x` 帧被 stub 以 404 拒绝；现已改走内置功能
  分发并支持 `o`/`l` 偏移与长度，配合 `ChunkedTransfer` 能力协商与下载护栏
  （返回块大于请求长度立即中止，避免旧 stub 造成无限追加写满磁盘）
- **进程级 panic 修复**：插件参数摘要 `&s[..64]` 与上传分块 `&content_b64[a..b]`
  按字节切 UTF-8 会 panic，而 release 构建 `panic = "abort"` 会终止整个进程并
  丢失全部会话；现改为按字符截断 / 显式报错
- **JSP stub 无法编译**：`DSW_mkdir` 缺少闭合花括号（后续方法被声明进方法体），
  且 md5 派发常量（最大 4294967295）被写成 Java int 字面量；现补花括号并加 `L` 后缀
- **JSP/ASPX 鉴权头名不匹配**：stub 查 CGI 形式 `HTTP_X_DEBUG_KEY`，客户端发
  `X-Debug-Key`，导致每个请求 404；JSP 改用 servlet 报文头原名，ASPX 兼容两种键名
- **ASP stub 运行期错误**：`Option Explicit` 下 `DoExec` 使用未声明的 `fso`；
  `StrToBytes("")` 触发 `ReDim arr(-1)` 使空输出命令整体失败；相对 `cd` 的分隔符
  字面量为空串导致拼出 `C:\wwwsub`
- **NATIVE 编码器的 session 模式错配**：`session: true` 会让客户端用分阶段通道
  向只认 `formData` 的 NATIVE stub 发裸密文请求体（恒定失败），现对 `native*` 忽略该开关
- **缺失命令 `test_proxy_upstream`**：前端调用、后端从未实现，设置页「测试代理连通性」
  100% 失败；现已实现（可配置探测地址，返回出口 IP 与耗时，写审计）
- 其他：`form_escape` 未转义 `%`（密码含 `%41` 时服务端解出不同字节 → 鉴权恒失败）；
  `chmod` 权限码来自远端 `perms` 且未校验（可注入命令）；交互式 PTY 把**目标自身**的
  127.0.0.1 当回调地址（远程目标必然超时）

### 安全

- **NATIVE 落地 stub 去除高危明文特征**：命令执行降级链不再出现候选函数数组，
  `__CMD__` 改为按 crc32b 符号表索引（0/20/21/22/23）探测与分发；
  `@exec(`/`@popen(`/`@passthru(`、`@eval($c)`、明文 `base64_*`、
  `@stat(`/`@touch(`/`@chdir(`、`is_dir(`、`stream_get_contents(`、`@pclose(`、
  `gzdecode`/`gzencode` 全部改为符号表调用；内部辅助函数改为中性命名
  （apply/index/load/save/clear/relocate/ensure/state/dsn/query/rule/bulk/dispatch）。
  符号表索引 20-30 为新增槽位，旧 stub 不受影响。
  回归：`native_stub_has_no_plain_sensitive_functions`（7 个变体逐一断言）+
  `real_php_exec_fallback_when_shell_exec_disabled`（禁用 shell_exec 后仍能降级执行）。
- 授权门补齐：`run_feature_plugin` 走 `session_ctx`（补到期与真实网络开关复查）、
  `pty_write/read/close` 校验归属会话存活、`get_session_probe` 补到期检查、
  自动重连前重跑授权检查、**关闭真实网络时强制断开全部会话并清理 PTY**
- `http_send` 与「测试连接」增加 Workspace **联合授权范围**校验（此前只检查全局开关，
  可打 127.0.0.1 / 169.254.169.254 等任意主机），越界需显式勾选覆盖并记 `override` 审计
- 本地路径策略改为跨平台实现：拒绝 UNC/设备路径与 ADS，按路径组件拒绝系统目录，
  默认仅允许用户主目录与临时目录（此前仅拒 POSIX 前缀，Windows 上等于没有校验），
  并给本地文件读取加大小上限
- 新增设置项 `tls_verify`（默认关闭，保持既有行为）与 `allow_arbitrary_local_paths`
  （默认 false）；`update_settings` 增加范围钳位与代理地址校验（原为静默直连）
- 响应读取统一流式限长（`session_post`、`run_code` 降级通道、`http_send`），
  避免恶意目标用超大响应撑爆内存（OOM abort）
- `run_code` 降级通道的临时脚本在**所有**返回路径上删除（原读取失败会残留可执行载荷）
- 请求日志脱敏覆盖密码的表单/引号转义形态与派生令牌，并改为「先脱敏后截断」；
  审计中的 URL 去掉 query（可能含密码）；移除遗留的调试 `eprintln!`
- 流密码变体（ChaCha20/Rabbit）响应改用**全新随机 IV/nonce**：
  原实现复用请求 IV，响应与请求密钥流重叠（两段密文异或即两段明文异或）
- 分阶段处理器错误分支补 nonce 帧（原被误判为「响应中未找到协议帧」）

### 变更

- `update_shell` 支持更新协议参数（编码方式 / 密钥盐 / session 开关）：
  此前 `protocol_params` 只能在创建时写入，用户重新生成 stub 换了编码器后
  只能删掉重建 Shell。变更写审计。
- 前端新增 `src/shells/encoders.ts`：编码方式 → 通道能力（是否支持 session）的
  单一来源，生成器与登记表单共用，消除「生成器能勾 session、登记表单没这个字段」。
- 前端质量门禁：新增 ESLint（含 `react-hooks` 规则）与 `pnpm check:ipc`
  （前端 `invoke` 名 ↔ 后端 `generate_handler!` 双向核对），均接入 CI
- CI：`cargo test` 增加 `DOSWORD_REQUIRE_PHP=1`，缺 php 时失败而非静默跳过（消除假绿）
- 出门修复：主内容区恢复滚动（此前 6 个视图超屏内容被裁且翻页按钮不可达）、
  分页随筛选收敛、全局快捷键不再抢输入框/终端按键、关闭标签页时断开会话、
  交互式终端轮询加 in-flight 互斥与失败提示、备份目录不再逐字符触发全量备份、
  Shell 详情页不再重复拉取 dashboard/listProtocols、`ShellProfile` DTO 补全生成

### 文档

- README：编码方式清单更新为 16 个（原写"XOR_BASE64 或 BASE64"）、补三条通道能力对齐
  与能力协商说明、PHP 依赖按编码器分档（5.3+ / 64 位 / PHP 7.1+ 与 openssl-gcm）、
  登记 Shell 一节补「编码方式/盐/session 可编辑」、订正「JSP/ASPX/ASP 客户端协议规划中」
  （客户端协议已实现，缺的是真实容器验证）。
- `docs/优化拓展方案.md`：新增「2026-10-19 本轮已修复」一节（含 8 项实际缺陷），
  并订正此前高估/过期的条目（编码器注册、请求调试、批量 API 接线、Rabbit 差分测试）。
- `docs/现代化方案.md`：W1/W3/W5 标记为已完成，W2/W4/W6 仍待做。
- README 订正与实现不符的声明：NATIVE stub 实际含明文 `@eval($c)` 与命令函数数组，
  XOR 密钥直接内嵌（不构成抗提取混淆），AES 为 256 位；分块传输需重新生成 stub；
  JSP/ASPX/ASP 当前不可端到端使用（**勿用于真实评估**）
- SECURITY.md 增补：stub 泄露＝密钥泄露、TLS 可选开启、本地路径策略、
  插件信任边界、审计含操作原文

## [0.1.0] - 2026-08-14

首个可用版本：授权范围内的 WebShell 生命周期管理客户端（Tauri 2 + React 19 + SQLite）。

### 新增

**授权与工作区**

- Workspace 登记与授权范围管理（精确主机 / `*.suffix` / CIDR / 裸通配）
- 授权到期检查与状态徽章、按 Workspace 筛选、批量探测
- 三层安全防线：真实网络协议默认关闭（需二次确认开启）、创建 Shell 需勾选授权确认、
  后端每次操作复查授权范围与到期时间

**协议与编码器**

- 标准 PHP WebShell 协议（类蚁剑）：探测 / 命令执行 / 文件浏览读写上传下载删除重命名建目录
- `NATIVE` 内置功能分发系列：功能函数内置于 stub 且经 md5 哈希分发，
  敏感函数经 crc32b 符号表查表调用，stub 无明文敏感函数与 `eval`
- 载荷加密变体：`native`（XOR）、`native_aes_ecb` / `native_aes_cbc`（AES-256）、`native_des`
- 自实现现代流密码变体：`native_chacha20`（RFC 8439）、`native_rabbit`（RFC 4503），
  在 Rust SDK 与 PHP stub 内各自纯实现并以 RFC 官方向量互验
- 业务伪装 OPSEC：stub 形如正常业务文件，功能隐藏在业务化命名的函数中
- JSP（`builtin.jsp.v1`）、ASP.NET（`builtin.aspnet.v1`）、经典 ASP（`builtin.asp.v1`）协议
- Python / Node stub 生成；MSSQL / Oracle / Redis 数据库驱动

**插件体系**

- 协议插件化：`crates/dosword-sdk` 为纯接口库（零 tauri 依赖），三步接入新协议
- 脚本型 `.plugin` 动态加载（JSON 清单 + 命令型/代码型执行定义）
- 二进制 `.plugin` 动态加载（Rust cdylib + `dlopen`，含 ABI 魔数与版本校验）
- 12 个内置功能插件：进程详情、端口扫描、ZIP 压缩、WebShell 扫描、Socks/HTTP 代理、
  文件搜索、网络信息、用户枚举、PHP 环境检测、代码执行、ByPassOpenBasedir、Bypass 向量库
- Bypass 向量库：9 个独立向量（禁用命令函数场景的降级链与 eval 通道）
- 虚拟终端（反弹 Shell）与交互式终端（linpty，支持 `su` / `vim` / `top`）

**界面**

- 命令终端（xterm.js，多 Tab、cwd 跟踪、历史持久化、GBK 编码、输出格式切换）
- 文件管理器（权限列、右键菜单、GBK/HEX 编辑、拖拽上传、分块传输与进度条）
- 数据库管理（PDO / 三驱动，连接探测、库表浏览、SQL 执行、结果网格、分页）
- 请求调试：协议帧环缓冲记录与检查（200 条，密码自动脱敏）
- 审计日志：连接 / 命令 / 文件 / 设置全量记录，分页查询与 CSV 导出
- 明亮 / 暗色主题系统

### 安全

- 安全加固 S1–S16：默认关闭任意代码执行、`run_code` eval 主通道收敛、密码转义、
  路径约束、授权门、PTY 级联、审计、流式限长、注入修复、加盐密钥派生

### 性能

- P1–P16：JSP 系列分块传输、插件锁外执行、批量操作并行、会话上下文与缓存优化
- 命令层异步化（阻塞线程池），网络操作不冻结 UI、多会话互不阻塞
- gzip 传输压缩（`native` 变体）

### 已知限制

- Shell 连接密码以明文存储于本地 SQLite（工具惯例，keyring 加密待后续版本），
  导出的 Shell JSON 与备份文件同样含明文密码
- Shell 列表单次最多 500 条（`query_shells` 上限）；批量探测同样以 500 为上限并在
  超过时于提示中说明
- 导入/导出仍是同步路径（`import_shells` 全程持库锁逐条事务；`export_shells` /
  `get_settings` 为同步命令）
- 前端测试覆盖有限：vitest 已接入，当前覆盖编码器/协议参数、主题、共享组件；
  各视图与 `FileManager` / `Terminal` 等大组件仍无测试

[未发布]: https://github.com/lin9527ya/DoSword/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lin9527ya/DoSword/releases/tag/v0.1.0
