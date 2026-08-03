#!/usr/bin/env bash
# DoSword 跨平台构建脚本（在 Linux 上构建 Linux / Windows 安装包）
#
# 用法：
#   ./scripts/build.sh check                              # 质量检查（cargo test --workspace + pnpm check + pnpm build）
#   ./scripts/build.sh linux [--bundles deb,appimage,rpm] [--skip-check]
#   ./scripts/build.sh windows [--bundles nsis] [--skip-check]
#   ./scripts/build.sh all [--skip-check]                 # 依次构建两个平台
#   ./scripts/build.sh binary [linux|windows|all] [--skip-check]   # 仅构建独立可执行程序（不打包）
#   ./scripts/build.sh help
#
# 前置依赖：
#   Linux 构建:  cargo / pnpm；系统包 librsvg2-dev、libayatana-appindicator3-dev、patchelf
#               （否则 appimage 打包会失败，可仅用 deb 包）
#   Windows 构建: mingw-w64（x86_64-w64-mingw32-gcc）——脚本会自动补装 rust target；
#                NSIS 打包需要 makensis（sudo apt install nsis）或 wine
#
# 产物位置（workspace 化后 target 位于仓库根）：
#   Linux:    target/release/bundle/          （deb / appimage / rpm）
#   Windows:  target/x86_64-pc-windows-gnu/release/bundle/   （nsis）
#   可执行程序: target/dosword-bin/            （独立二进制，免安装直接运行）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WINDOWS_TARGET="x86_64-pc-windows-gnu"
BIN_DIR="target/dosword-bin"

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

# 列出某个 bundle 目录下的安装包产物
list_artifacts() {
  local dir="$1"
  local patterns=("$@")
  unset 'patterns[0]'
  if [ ! -d "$dir" ]; then
    warn "产物目录不存在：$dir"
    return 0
  fi
  local args=()
  local pat
  local first=true
  for pat in "${patterns[@]}"; do
    if $first; then
      args+=(-name "$pat")
      first=false
    else
      args+=(-o -name "$pat")
    fi
  done
  find "$dir" -type f \( "${args[@]}" \) -printf "  %p  (%s 字节)\n" 2>/dev/null || true
}

run_check() {
  log "==> 运行后端测试（workspace：主 crate / SDK / 示例插件 / 真实 PHP 往返）"
  cargo test --workspace --manifest-path Cargo.toml

  log "==> 运行前端类型检查（含 ts-rs 生成漂移校验）"
  pnpm check

  log "==> 前端构建"
  pnpm build
}

build_linux() {
  require_cmd cargo "请先安装 Rust（https://rustup.rs）"
  require_cmd pnpm  "请先安装 pnpm（npm i -g pnpm）"

  local bundles="${1:-deb,appimage,rpm}"
  log "==> 构建 Linux 安装包（bundle: $bundles）"
  if [ "$bundles" = "all" ]; then
    pnpm tauri build
  else
    pnpm tauri build --bundles "$bundles"
  fi

  log "==> Linux 产物："
  list_artifacts "target/release/bundle" "*.deb" "*.AppImage" "*.rpm"
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

  local bundles="${1:-nsis}"
  # WebView2 安装包体积较大（tauri 下载的 nsis），首次构建需要联网
  # msi（WiX）在 Linux 上无法交叉生成
  log "==> 交叉编译 Windows 安装包（target: $WINDOWS_TARGET, bundle: $bundles）"
  pnpm tauri build --target "$WINDOWS_TARGET" --bundles "$bundles"

  log "==> Windows 产物："
  list_artifacts "target/$WINDOWS_TARGET/release/bundle" "*.exe" "*.msi"
}

# 构建单个平台的独立可执行程序（假定前端资源已构建）
build_binary_one() {
  local platform="$1"
  case "$platform" in
    linux)
      log "==> 编译 Linux 可执行程序（release）"
      cargo build --release -p dosword
      cp target/release/dosword "$BIN_DIR/dosword-linux-x86_64"
      log "==> Linux 可执行程序："
      ls -lh "$BIN_DIR/dosword-linux-x86_64" | awk '{print "  " $5 "  " $9}'
      ;;
    windows)
      require_cmd x86_64-w64-mingw32-gcc \
        "Windows 交叉编译需要 mingw-w64。Ubuntu/Debian: sudo apt install gcc-mingw-w64-x86-64"
      ensure_windows_target
      log "==> 交叉编译 Windows 可执行程序（release, target: $WINDOWS_TARGET）"
      cargo build --release -p dosword --target "$WINDOWS_TARGET"
      cp "target/$WINDOWS_TARGET/release/dosword.exe" "$BIN_DIR/dosword-windows-x86_64.exe"
      log "==> Windows 可执行程序："
      ls -lh "$BIN_DIR/dosword-windows-x86_64.exe" | awk '{print "  " $5 "  " $9}'
      ;;
  esac
}

# 构建独立可执行程序（免安装直接运行）。tauri 二进制内嵌前端资源，
# 必须先 pnpm build 保证 dist 最新，再 cargo build。
build_binary() {
  local platform="$1"
  require_cmd cargo "请先安装 Rust（https://rustup.rs）"
  require_cmd pnpm  "请先安装 pnpm（npm i -g pnpm）"

  log "==> 构建前端资源（内嵌进二进制，必须最新）"
  pnpm build
  mkdir -p "$BIN_DIR"

  case "$platform" in
    all)
      build_binary_one linux
      build_binary_one windows
      ;;
    linux|windows)
      build_binary_one "$platform"
      ;;
  esac
}

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
}

# --- 参数解析 ---
COMMAND="${1:-help}"
shift 2>/dev/null || true
BIN_PLATFORM="all"
SKIP_CHECK=false
BUNDLES=""
while [ $# -gt 0 ]; do
  case "$1" in
    linux|windows|all)
      if [ "$COMMAND" = "binary" ]; then
        BIN_PLATFORM="$1"
      else
        err "未知参数：$1"
        usage
        exit 1
      fi
      ;;
    --skip-check) SKIP_CHECK=true ;;
    --bundles)
      [ $# -ge 2 ] || { err "--bundles 需要参数（如 deb,appimage 或 nsis）"; exit 1; }
      BUNDLES="$2"
      shift
      ;;
    *)
      err "未知参数：$1"
      usage
      exit 1
      ;;
  esac
  shift
done

if [ "$COMMAND" != "check" ] \
  && [ "$COMMAND" != "help" ] && [ "$COMMAND" != "-h" ] && [ "$COMMAND" != "--help" ] \
  && [ "$SKIP_CHECK" != "true" ]; then
  run_check
fi

case "$COMMAND" in
  linux)
    build_linux "${BUNDLES:-deb,appimage,rpm}"
    ;;
  windows)
    build_windows "${BUNDLES:-nsis}"
    ;;
  all)
    build_linux "${BUNDLES:-deb,appimage,rpm}"
    build_windows "${BUNDLES:-nsis}"
    ;;
  binary)
    build_binary "$BIN_PLATFORM"
    ;;
  check)
    run_check
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    err "未知命令：$COMMAND"
    usage
    exit 1
    ;;
esac

log "构建完成。"
