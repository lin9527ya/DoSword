# 更新日志

本项目所有值得注意的变更都记录在此文件。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 新增

- 插件工作室（Plugin Studio）：可视化编辑与调试 `.plugin` 清单
- 全局文件视图与全局数据库视图
- 转发终端（ForwardTerminal）与笔记面板（NotesPanel）
- 状态栏与统一 Toast 通知组件

### 安全

- 修复插件 id 路径穿越：`validate_plugin_id` 统一校验安装与卸路径，拒绝 `..`、路径分隔符、
  绝对路径与前导点（`crates/dosword-sdk/src/plugin.rs`）
- 协议会话 downcast 失败不再 `panic`：release 构建开启了 `panic = "abort"`，
  原 `.expect("会话类型不匹配")` 会导致整个应用崩溃并丢失全部活动会话；
  现返回 `ProtocolError::SessionInvalid`（25 处生产路径）
- 移除 `base.css` 对 Google Fonts CDN 的 `@import`（应用 CSP 为 `default-src 'self'`，
  该请求本就被拦截，属无效代码且构成不必要的外连面）
- 修正 `auth.rs` 模块注释：原文写「无法解析的条目按人工已确认放行」，与实现相反。
  实际语义为**失败即拒绝**（fail-closed）

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
