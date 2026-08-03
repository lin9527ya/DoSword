#!/usr/bin/env bash
# DoSword 跨平台构建脚本（在 Linux 上构建 Linux / Windows 安装包）
#
# 用法：
#   ./scripts/build.sh linux        # 构建 Linux 安装包（deb / appimage / rpm）
#   ./scripts/build.sh windows      # 交叉编译 Windows 安装包（nsis，含免安装 exe）
#   ./scripts/build.sh all          # 依次构建两个平台
#   ./scripts/build.sh check        # 仅运行质量检查（cargo test + pnpm check）
#   ./scripts/build.sh help
#
# 前置依赖：
#   Linux 构建:  cargo / pnpm；系统包 librsvg2-dev、libayatana-appindicator3-dev、patchelf
#               （否则 appimage 打包会失败，可仅用 deb 包）
#   Windows 构建: mingw-w64（x86_64-w64-mingw32-gcc）——脚本会自动补装 rust target；
#                NSIS 打包需要 makensis（sudo apt install nsis）或 wine
#
# 产物位置：
#   Linux:   src-tauri/target/release/bundle/
#   Windows: src-tauri/target/x86_64-pc-windows-gnu/release/bundle/
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WINDOWS_TARGET="x86_64-pc-windows-gnu"

# cargo 路径（rustup 安装时不在默认 PATH）
if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

log()  { printf '\033[1;32m[build]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[build]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[build]\033[0m %s\n' "$*" >&2; }

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "缺少依赖：$1"
    err "  $2"
    exit 1
  fi
}

ensure_windows_target() {
  if ! rustup target list --installed 2>/dev/null | grep -qx "$WINDOWS_TARGET"; then
    log "安装 rust 目标：$WINDOWS_TARGET"
    rustup target add "$WINDOWS_TARGET"
  fi
}

run_check() {
  log "==> 运行后端测试（workspace：含 SDK / 示例插件 / 真实 PHP 往返）"
  cargo test --workspace --manifest-path Cargo.toml

  log "==> 运行前端类型检查"
  pnpm check

  log "==> 前端构建"
  pnpm build
}

build_linux() {
  require_cmd cargo "请先安装 Rust（https://rustup.rs）"
  require_cmd pnpm  "请先安装 pnpm（npm i -g pnpm）"

  log "==> 构建 Linux 安装包（deb / appimage / rpm）"
  pnpm tauri build

  log "==> Linux 产物："
  find src-tauri/target/release/bundle -type f \( -name "*.deb" -o -name "*.AppImage" -o -name "*.rpm" \) -printf "  %p  (%s 字节)\n" 2>/dev/null || true
}

build_windows() {
  require_cmd cargo "请先安装 Rust（https://rustup.rs）"
  require_cmd pnpm  "请先安装 pnpm（npm i -g pnpm）"
  require_cmd x86_64-w64-mingw32-gcc \
    "Windows 交叉编译需要 mingw-w64。Ubuntu/Debian: sudo apt install gcc-mingw-w64-x86-64"

  # NSIS 安装包需要 makensis。Linux 上优先用原生 nsis 包，缺 wine 时无法跑 Windows 版 makensis
  if ! command -v makensis >/dev/null 2>&1 && ! command -v wine >/dev/null 2>&1; then
    err "缺少 NSIS 打包工具"
    err "  安装 Linux 原生版：sudo apt install nsis"
    err "  或安装 wine（用 Windows 版 makensis）：sudo apt install wine"
    exit 1
  fi

  ensure_windows_target

  # WebView2 安装包体积较大（tauri 下载的 nsis），首次构建需要联网
  # 只打包 nsis：msi（WiX）在 Linux 上无法交叉生成
  log "==> 交叉编译 Windows 安装包（target: $WINDOWS_TARGET, bundle: nsis）"
  pnpm tauri build --target "$WINDOWS_TARGET" --bundles nsis

  log "==> Windows 产物："
  find "src-tauri/target/$WINDOWS_TARGET/release/bundle" -type f \( -name "*.exe" -o -name "*.msi" \) -printf "  %p  (%s 字节)\n" 2>/dev/null || true
}

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
}

case "${1:-help}" in
  linux)
    run_check
    build_linux
    ;;
  windows)
    run_check
    build_windows
    ;;
  all)
    run_check
    build_linux
    build_windows
    ;;
  check)
    run_check
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    err "未知命令：$1"
    usage
    exit 1
    ;;
esac

log "构建完成。"
