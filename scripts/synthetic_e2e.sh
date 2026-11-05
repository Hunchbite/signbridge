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

echo "==> build RPC + FFI"
cargo build -q -p signbridge-rpc
cargo build -q -p signbridge --features ffi

echo "==> NDJSON ping via signbridge-rpc"
echo '{"id":"1","method":"ping"}' | SIGNBRIDGE_SKIP_ORIGIN=1 ./target/debug/signbridge-rpc | grep -q '"ok":true'

echo "==> Python create() ping"
PYTHONPATH=bindings/python python3 - <<'PY'
from signbridge import create
with create(binary="target/debug/signbridge-rpc") as c:
    assert c.ping()["name"] == "signbridge"
    print("python create() ok", c.ping())
PY

echo "==> shell demo"
PATH="$ROOT/target/debug:$PATH" bash examples/shell/demo.sh >/dev/null

echo "==> all synthetic checks passed"
