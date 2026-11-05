#!/usr/bin/env bash
# Plug-and-play installer for signbridge-rpc (any OS with bash + curl).
#   curl -fsSL https://raw.githubusercontent.com/Hunchbite/signbridge/main/scripts/install.sh | bash
set -euo pipefail

REPO="${SIGNBRIDGE_REPO:-Hunchbite/signbridge}"
PREFIX="${SIGNBRIDGE_PREFIX:-$HOME/.signbridge}"
BIN_DIR="$PREFIX/bin"
mkdir -p "$BIN_DIR"

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x86_64" ;;
  arm64|aarch64) arch="aarch64" ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac
case "$os" in
  darwin) target="${arch}-apple-darwin" ;;
  linux)  target="${arch}-unknown-linux-gnu" ;;
  mingw*|msys*|cygwin*|windows*) target="${arch}-pc-windows-msvc"; os=windows ;;
  *) echo "unsupported OS: $os" >&2; exit 1 ;;
esac

asset="signbridge-rpc-${target}"
if [[ "$os" == "windows" ]]; then asset="${asset}.exe"; fi

download_release() {
  local api="https://api.github.com/repos/${REPO}/releases/latest"
  local url
  url="$(curl -fsSL "$api" | python3 -c "
import json,sys
data=json.load(sys.stdin)
name=sys.argv[1]
for a in data.get('assets',[]):
  if a['name']==name or a['name'].startswith(name):
    print(a['browser_download_url']); break
" "$asset" 2>/dev/null || true)"
  if [[ -z "${url:-}" ]]; then
    return 1
  fi
  echo "→ downloading $asset"
  curl -fsSL "$url" -o "$BIN_DIR/signbridge-rpc"
  chmod +x "$BIN_DIR/signbridge-rpc"
  return 0
}

install_from_cargo() {
  if ! command -v cargo >/dev/null 2>&1; then
    echo "Rust/cargo not found and no release binary for $target." >&2
    echo "Install Rust: https://rustup.rs  then re-run this script." >&2
    exit 1
  fi
  echo "→ cargo install --git https://github.com/${REPO} signbridge-rpc"
  cargo install --git "https://github.com/${REPO}" signbridge-rpc --root "$PREFIX" --force
}

if download_release; then
  :
else
  echo "No prebuilt release for $target yet — building from source…"
  install_from_cargo
fi

# Prefer cargo install layout (bin/) or our download path
if [[ ! -x "$BIN_DIR/signbridge-rpc" && -x "$PREFIX/bin/signbridge-rpc" ]]; then
  :
fi

echo
echo "Installed: $BIN_DIR/signbridge-rpc"
"$BIN_DIR/signbridge-rpc" --version 2>/dev/null || true
echo
echo "Add to your shell profile:"
echo "  export PATH=\"$BIN_DIR:\$PATH\""
if ! echo ":$PATH:" | grep -q ":$BIN_DIR:"; then
  export PATH="$BIN_DIR:$PATH"
  echo "(PATH updated for this session)"
fi
echo
echo "Smoke test:"
echo "  echo '{\"id\":\"1\",\"method\":\"ping\"}' | signbridge-rpc --skip-origin"
