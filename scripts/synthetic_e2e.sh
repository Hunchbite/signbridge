#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MODULE="${SOFTHSM_MODULE:-/opt/homebrew/lib/softhsm/libsofthsm2.so}"
if [[ ! -f "$MODULE" ]]; then
  echo "SoftHSM module not found at $MODULE (brew install softhsm)" >&2
  exit 1
fi

echo "==> SoftHSM framework tests"
cargo test -p signbridge --features testing -- --nocapture

echo "==> all synthetic checks passed"
