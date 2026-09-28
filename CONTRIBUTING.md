# 贡献指南

感谢你考虑为 DoSword 贡献代码。本文件说明开发环境、质量门禁与提交约定。

> **前置声明**：DoSword 是面向**授权安全测试环境**的工具。提交代码即表示你确认其用途
> 限于授权渗透测试、自有资产、CTF 与安全研究。详见 [SECURITY.md](SECURITY.md)。

## 环境准备

| 依赖 | 版本 |
|---|---|
| Rust | stable（`rust-toolchain.toml` 已固定，`edition 2024` 需 ≥ 1.85） |
| Node.js | ≥ 22.13（CI 用 24；pnpm 11 依赖 `node:sqlite` 内置模块，Node 20 不可用） |
| pnpm | 11.x —— 由 `package.json` 的 `packageManager` 固定，CI 自动读取该字段 |
| PHP | 可选，跑真实协议往返测试时需要（`php-cli`） |

Linux 打包与 CI 还需要系统库：

```bash
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev \
                        libayatana-appindicator3-dev patchelf
```

首次准备：

```bash
source "$HOME/.cargo/env"
pnpm install            # 不要用 npm，仓库以 pnpm 为准（只有 pnpm-lock.yaml）
pnpm tauri dev
```

## 质量门禁

提交前请在本地跑通全部四项，CI（`.github/workflows/ci.yml`）会逐项复核：

```bash
cargo fmt --all --check                                  # 格式
cargo clippy --workspace --all-targets -- -D warnings    # 零警告门禁
cargo test --workspace                                   # 单元测试（含真实 PHP 往返）
pnpm check && pnpm build                                 # 前端类型检查与构建
```

`cargo clippy` 配置为 **`-D warnings`**：任何警告都会让 CI 失败。若某处确实需要豁免，
请用带理由的 `#[allow(...)]`，并写清为什么，例如：

```rust
#[allow(clippy::too_many_arguments)] // 协议帧字段固定，拆结构体反而增加调用方噪声
```

## 代码约定

- **注释与提交信息用中文**，与现有代码库一致
- `cargo fmt` 是唯一格式权威，不要手工调整缩进对齐
- 公开 API 加文档注释（`///`），模块顶部加 `//!` 说明职责
- 错误处理：库层用 `Result` + 明确的错误类型；**不要在生产路径用 `unwrap()` / `expect()`**
  ——release 构建开启了 `panic = "abort"`，一次 panic 会终止整个应用并丢失全部活动会话
- 前端类型由 Rust DTO 经 ts-rs 生成，改 `crates/dosword-sdk/src/domain.rs` 后运行
  `pnpm gen:types`；`cargo test` 会校验生成文件是否漂移

## 提交信息

采用 `<类型>(<范围>): <中文简述>` 的形式，类型用 Conventional Commits 的集合：

```
feat(plugin): 插件工作室支持可视化编辑清单
fix(protocol): 修复 JSP 分块传输在超长路径下截断
refactor(sdk): 抽出协议注册表初始化
docs: 补充 SECURITY.md 的已知取舍说明
chore: 更新 CI 的依赖扫描步骤
```

## 接入新协议

协议体系已插件化。三步接入流程（含完整代码示例）见
[README 的「协议 SDK / 插件」章节](README.md#协议-sdk--插件)；
可运行的最小示例见 `crates/dosword-plugin-echo`（ECHO 帧协议，含测试）。

## 本地联调

没有 PHP 环境时用内置 mock 服务器（按 PHP 协议应答，文件操作落在本地临时目录）：

```bash
python3 scripts/mock_shell.py --port 18080 --password secret
```

在应用中登记 `http://127.0.0.1:18080/shell.php`（协议 PHP、密码 `secret`）即可联调全部功能。
**开发与测试请优先用 mock，避免对真实目标产生流量。**

## 提交前自查

- [ ] 四项门禁全部本地通过
- [ ] 没有提交密钥、凭据、真实目标地址或内网信息
- [ ] 新增功能有对应测试（协议层测试请放在源码的 `#[cfg(test)] mod tests` 内）
- [ ] 未提交 `target/`、`node_modules/`、`dist/` 或本地数据库文件
