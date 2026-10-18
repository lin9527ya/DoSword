# 更新日志

本项目所有值得注意的变更都记录在此文件。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

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

- 前端质量门禁：新增 ESLint（含 `react-hooks` 规则）与 `pnpm check:ipc`
  （前端 `invoke` 名 ↔ 后端 `generate_handler!` 双向核对），均接入 CI
- CI：`cargo test` 增加 `DOSWORD_REQUIRE_PHP=1`，缺 php 时失败而非静默跳过（消除假绿）
- 出门修复：主内容区恢复滚动（此前 6 个视图超屏内容被裁且翻页按钮不可达）、
  分页随筛选收敛、全局快捷键不再抢输入框/终端按键、关闭标签页时断开会话、
  交互式终端轮询加 in-flight 互斥与失败提示、备份目录不再逐字符触发全量备份、
  Shell 详情页不再重复拉取 dashboard/listProtocols、`ShellProfile` DTO 补全生成

### 文档

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
- 前端尚无自动化测试

[未发布]: https://github.com/lin9527ya/DoSword/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lin9527ya/DoSword/releases/tag/v0.1.0
