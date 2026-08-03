# DoSword

DoSword 是一个面向授权安全测试环境的现代化 WebShell 管理客户端（Tauri 2 + React 19 + SQLite）。

## 当前里程碑（第二阶段）

- Workspace 与授权范围登记、到期检查，支持删除/编辑（级联清理会话）
- Shell Profile 本地持久化（SQLite，含密码明文——工具惯例，keyring 加密留待后续），支持标签、删除/编辑
- 审计日志贯穿所有操作（连接 / 命令 / 文件 / 设置），分页查询与 CSV 导出
- **标准 PHP WebShell 协议**（类蚁剑）：探测、连接、命令执行、文件浏览/读写/上传/下载/删除/重命名/建目录
- **编码器体系**（哥斯拉风格，8 种）：
  - `base64` 经典裸编码 / `xor_base64` 异或混淆 + Base64
  - `aes128_ecb` / `aes128_cbc` / `des` 自加密（密钥由密码 md5 派生并内嵌 stub，载荷为密文）
  - `char` 字符数组混淆 / `php_obfuscate` base64+反转混淆（无密钥，混淆在载荷内）
  - `php_stream` 零敏感函数 stub（`INCLUDE("php://filter/...php://input")` 一行，需 allow_url_include=On）
  - `xor_body` Godzilla 风格请求体 XOR 直传（`file_get_contents('php://input')`，默认配置可用）
- **OPSEC 业务伪装**：PHP stub 整体形如正常业务文件（「会话状态查询接口」），
  webshell 功能隐藏在业务函数中（函数名带随机前缀防与站点业务函数冲突）；
  敏感函数名（base64_decode / openssl_decrypt）完全不在代码中出现——运行时
  经 crc32b 哈希查表从 get_defined_functions() 解析（哥斯拉式符号表）；
  cipher 名（AES-128-ECB / DES-ECB）以 XOR 十六进制嵌入、运行时解密；
  eval 用大小写混淆 EvAl；参数为业务语义 token/data；密钥由连接密码运行时
  派生；兼容 PHP 5.3+（自加密编码器需 openssl 扩展）
- **生成 Webshell**：PHP / ASP / ASPX / JSP 四种语言 × 编码器生成服务端 stub（自加密 stub 含 openssl 解密逻辑；当前连接协议仅 PHP 可用）
- 分块上传下载（4MB 块 + fseek），上传带进度条
- **数据库管理**（PDO，MySQL / PostgreSQL / SQLite）：连接探测、数据库/表浏览、SQL 执行、结果网格
- **请求调试**（协议帧检查器）：进程内环缓冲记录每条协议载荷与响应，密码自动脱敏
- 本地 Mock 协议（默认）：不产生任何网络流量
- 命令终端（xterm.js，多 Tab、cwd 追踪、历史持久化）、文件管理器、设置页、审计页
- 命令层异步化（阻塞线程池），网络操作不冻结 UI、多会话互不阻塞

安全姿态（三层防线）：

1. 真实网络协议**默认关闭**，需在「设置」中二次确认后开启
2. 创建 HTTP Shell 时必须勾选「我已确认目标位于授权范围内」
3. 后端校验 endpoint 落在 Workspace 授权范围内（精确主机 / `*.suffix` / CIDR / 通配），每次操作复查授权到期

## 使用真实 PHP 协议

### 1. 生成服务端 stub（到授权目标）

总览 → 生成 Webshell：选择语言（PHP/ASP/ASPX/JSP）、编码方式（XOR_BASE64 / BASE64）与连接密码，
生成脚本内容并可保存。上传到目标站点（如 `shell.php`）。stub 不保存明文密码——
密钥由密码的 md5 派生并内嵌，客户端与 stub 自动一致。

### 2. 开启真实网络

设置 → 真实网络协议 → 开启（二次确认）→ 保存。

### 3. 登记 Shell

总览 → 登记 Shell：选择「标准 PHP WebShell（类蚁剑）」，填写 Endpoint 与连接密码，
**编码方式选择与 stub 一致**（XOR_BASE64 或 BASE64），勾选授权确认。

### 4. 连接与操作

连接后可在详情页进行文件管理与命令执行。所有操作都会写入审计日志。

> ASP / ASPX / JSP 的客户端连接协议规划中，当前仅生成 stub。

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
- V2.0：动态加载插件
- V3.0：大型 Shell 库 / 团队共享 / 远程同步
