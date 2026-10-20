#!/usr/bin/env node
/**
 * 版本一致性守卫。
 *
 * 为什么需要：版本号分散在四处（package.json / 根 Cargo.toml / tauri.conf.json / 发布 tag），
 * 只改一处就会产出「装完显示 0.1.0、Cargo 里是 0.2.0」的包，或 tag 与二进制版本不符。
 * 这个脚本把它们对齐，并校验 tag（CI 上提供 GITHUB_REF_NAME 时）。
 *
 * 用法：node scripts/check-version.mjs
 * 退出码：0 一致；1 不一致（阻塞）。
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (relative) => readFileSync(join(root, relative), "utf8");

const pkg = JSON.parse(read("package.json"));

const cargoToml = read("Cargo.toml");
const cargoMatch = cargoToml.match(/^version\s*=\s*"([^"]+)"/m);

const tauriConf = JSON.parse(read("src-tauri/tauri.conf.json"));

const entries = [
  ["package.json", pkg.version],
  ["Cargo.toml", cargoMatch?.[1]],
  ["src-tauri/tauri.conf.json", tauriConf.version],
];

const missing = entries.filter(([, value]) => !value).map(([file]) => file);
if (missing.length > 0) {
  console.error(`✗ 以下文件缺少 version 字段：${missing.join(", ")}`);
  process.exit(1);
}

const versions = [...new Set(entries.map(([, value]) => value))];
console.log(
  `版本来源：${entries.map(([file, value]) => `${file}=${value}`).join("  ")}`,
);

if (versions.length > 1) {
  console.error(`\n✗ 版本号不一致：${versions.join(" vs ")}\n请同步修改 package.json、Cargo.toml、src-tauri/tauri.conf.json。`);
  process.exit(1);
}

const version = versions[0];

// 发布时（tag 触发）额外校验 tag 与版本一致：v0.2.0 ↔ 0.2.0
const refName = process.env.GITHUB_REF_NAME;
if (refName && refName.startsWith("v")) {
  const tagVersion = refName.slice(1);
  if (tagVersion !== version) {
    console.error(`\n✗ 发布 tag（${refName}）与代码版本（${version}）不一致。`);
    process.exit(1);
  }
  console.log(`✓ tag ${refName} 与版本 ${version} 一致`);
}

console.log(`✓ 版本一致：${version}`);
