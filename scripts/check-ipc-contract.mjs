#!/usr/bin/env node
/**
 * IPC 契约检查：前端 `invoke("cmd")` 名必须全部在后端 `generate_handler!` 中注册。
 *
 * 为什么需要它：`test_proxy_upstream` 曾在 `src/api.ts` 中被调用、后端却从未实现，
 * 结果设置页「测试代理连通性」100% 失败，而 `tsc` / `vite build` / Rust 单测
 * 都发现不了——两侧各自都是"合法"的。
 *
 * 用法：node scripts/check-ipc-contract.mjs
 * 退出码：0 通过；1 存在前端调用但后端未注册的命令（阻塞）。
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const apiPath = join(root, "src", "api.ts");
const libPath = join(root, "src-tauri", "src", "lib.rs");

const api = readFileSync(apiPath, "utf8");
const lib = readFileSync(libPath, "utf8");

/** 前端调用点：invoke<T>("name" ...) / invoke("name", { ... })（泛型允许一层嵌套） */
function frontendCommands(source) {
  const found = new Set();
  const generics = "(?:<[^<>]*(?:<[^<>]*>[^<>]*)*>)?";
  const pattern = new RegExp(`invoke\\s*${generics}\\s*\\(\\s*["'\`]([a-z0-9_]+)["'\`]`, "g");
  for (const match of source.matchAll(pattern)) found.add(match[1]);
  return found;
}

/** 后端注册点：generate_handler! 列表里的 commands::name */
function backendCommands(source) {
  const found = new Set();
  const pattern = /commands::([a-z0-9_]+)/g;
  for (const match of source.matchAll(pattern)) found.add(match[1]);
  return found;
}

const frontend = frontendCommands(api);
const backend = backendCommands(lib);

const missing = [...frontend].filter((name) => !backend.has(name)).sort();
const unused = [...backend].filter((name) => !frontend.has(name)).sort();

console.log(`IPC 契约：前端调用 ${frontend.size} 个命令，后端注册 ${backend.size} 个`);

if (unused.length > 0) {
  // 仅提示：后端可能为插件/未来前端保留入口
  console.log(`提示：后端已注册但前端未调用（${unused.length}）：${unused.join(", ")}`);
}

if (missing.length > 0) {
  console.error(
    `\n✗ 以下命令被前端调用但后端未注册（调用必然失败）：\n  ${missing.join("\n  ")}\n` +
      `请在 src-tauri/src/lib.rs 的 generate_handler! 中注册对应命令，或从 src/api.ts 移除调用。`,
  );
  process.exit(1);
}

console.log("✓ 所有前端 invoke 调用都有对应的后端命令");
