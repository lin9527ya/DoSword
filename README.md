# DoSword

DoSword 是一个面向授权安全测试环境的现代化 WebShell 管理客户端（Tauri 2 + React 19 + SQLite）。

## 当前里程碑（第二阶段）

- Workspace 与授权范围登记、到期检查，支持删除/编辑（级联清理会话）
- Shell Profile 本地持久化（SQLite，含密码明文——工具惯例，keyring 加密留待后续），支持标签、删除/编辑
- 审计日志贯穿所有操作（连接 / 命令 / 文件 / 设置），分页查询与 CSV 导出
- **标准 PHP WebShell 协议**（类蚁剑）：探测、连接、命令执行、文件浏览/读写/上传/下载/删除/重命名/建目录
- **编码方式：NATIVE 内置功能分发系列**（同一骨架，D盾零检出形态，载荷加密可选）
  - 功能函数（命令/文件/数据库）直接内置在 stub（业务化命名），
    客户端按操作名 md5 哈希分发调用（stub 仅含哈希数字比较）
  - 敏感函数（shell_exec/file_get_contents/scandir/openssl_decrypt 等）全部
    crc32b 符号表查表调用，stub 无任何明文敏感函数 / eval / php://input
  - 自定义 HTTP 头鉴权（X-Debug-Key，头名与 token XOR 加密嵌入）
  - 请求参数业务化 formData；载荷/响应全程加密，**加密方式可选**：
    - `native`：XOR 循环加密（md5 派生密钥，默认）
    - `native_aes_ecb` / `native_aes_cbc`：AES-128（密钥=md5 前 16 字节，
      CBC 用 md5 后 16 字节作 IV，cipher 名与密钥 XOR 嵌入）
    - `native_des`：DES-ECB（密钥=md5 前 8 字节）
- **自加密系列（PHP 5+ 兼容，分阶段会话形态）**：
  - `aes128_ecb`：AES-128-ECB 自加密（密钥由密码 md5 派生并 XOR 加密嵌入
    stub，载荷为密文；处理器经 DswSesInit 一次注入，后续请求只传参数）
  - `aes128_cbc`：AES-128-CBC 自加密（密钥 + IV = md5 前/后 16 字节）
  - stub 与处理器代码仅用 PHP 5 语法（array()/strpos/无 ??/无短数组/
    无 intdiv 等），openssl 加解密函数 crc32b 查表调用（PHP 5.3+）
  - 连接/执行/生成 Webshell 均自动走分阶段会话通道（无需勾选 session）
- **现代流密码自实现系列（PHP 5+ 纯实现，无扩展依赖，自加密会话形态）**：
  - `chacha20`：ChaCha20（RFC 8439，TLS 1.3/SSH/WireGuard 标准流密码）
    密钥 = 密码 md5 hex ASCII（256 位），nonce 12 字节随载荷明文携带；
    请求 counter=0 / 响应 counter=1，载荷 `b64(nonce+密文)`
  - `rabbit`：Rabbit（RFC 4503，eSTREAM 最终推荐流密码）
    密钥 = 密码 md5（128 位），IV 8 字节随载荷携带；请求密钥流偏移 0 /
    响应偏移 64 字节（平方运算 16 位拆分，任意 PHP int 位宽精确）
  - 算法在 Rust SDK 与 PHP stub 内各自纯实现（无 openssl/mcrypt），
    以 RFC 官方向量互验（ChaCha20 块/加密向量、Rabbit 密钥/IV 向量）
  - 要求 64 位 PHP（32 位位运算不可靠）；PHP 5.2+（无 json 环境除外）
- **OPSEC 业务伪装**：PHP stub 整体形如正常业务文件（「会话状态查询接口」），
  webshell 功能隐藏在业务函数中（函数名带随机前缀防与站点业务函数冲突）；
  敏感函数名（base64_decode / openssl_decrypt）完全不在代码中出现——运行时
  经 crc32b 哈希查表从 get_defined_functions() 解析（哥斯拉式符号表）；
  cipher 名（AES-128-ECB / DES-ECB）以 XOR 十六进制嵌入、运行时解密；
  eval 用大小写混合 + 随机纯字母注释分隔（`eVaL/*rvnd*/(...)`，`eval(` 连续
  字符串不存在），且 eval 经业务函数包裹 + 局部变量中转（防语义级查杀如 D盾
  的「内藏 Eval 后门」）；file_get_contents / php://input / 解码函数全部经
  crc32b 符号表查表调用与字符串拆分，stub 无明文敏感特征；参数为业务语义
  token/data；密钥由连接密码运行时派生；兼容 PHP 5.3+（自加密编码器需
  openssl 扩展）
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
- V2.0：动态加载插件
- V3.0：大型 Shell 库 / 团队共享 / 远程同步
