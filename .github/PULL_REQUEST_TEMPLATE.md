<!-- 标题请用：<类型>(<范围>): <中文简述>，例如 feat(plugin): 插件工作室支持可视化编辑清单 -->

## 这个 PR 做了什么

<!-- 一到三句话说明改动内容与动机 -->

## 关联 Issue

<!-- 例如 Closes #12；没有就写「无」 -->

## 改动类型

- [ ] 缺陷修复
- [ ] 新功能
- [ ] 重构（不改变行为）
- [ ] 文档
- [ ] 构建 / CI

## 影响范围

- [ ] 协议 / 编码器（涉及 `crates/dosword-sdk/` 或 `src-tauri/src/protocol/`）
- [ ] 服务端 stub 生成（改动会影响已投放目标的兼容性，**请重点说明**）
- [ ] 前端界面
- [ ] 数据库 schema / 迁移
- [ ] 插件体系 / ABI
- [ ] 仅文档或 CI

## 自查清单

- [ ] `cargo fmt --all --check` 通过
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` 零警告
- [ ] `cargo test --workspace` 通过（新增功能已补测试）
- [ ] `pnpm check && pnpm build` 通过
- [ ] 未提交密钥、凭据、真实目标地址或内网信息
- [ ] 未提交 `target/`、`node_modules/`、`dist/` 或本地数据库文件（`*.sqlite3`）
- [ ] 若改了 `crates/dosword-sdk/src/domain.rs`，已运行 `pnpm gen:types` 且生成文件无漂移

## 授权用途确认

- [ ] 我确认本改动仅服务于授权安全测试场景，未加入针对未授权目标的自动化能力

## 补充说明

<!-- 破坏性变更、迁移注意事项、测试方式、截图等 -->
