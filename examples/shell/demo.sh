#!/usr/bin/env bash
# Zero-dependency demo — only needs signbridge-rpc on PATH.
set -euo pipefail

if ! command -v signbridge-rpc >/dev/null; then
  echo "Installing signbridge-rpc…"
  curl -fsSL https://raw.githubusercontent.com/Hunchbite/signbridge/main/scripts/install.sh | bash
  export PATH="$HOME/.signbridge/bin:$PATH"
fi

echo "==> ping"
echo '{"id":"1","method":"ping"}' | signbridge-rpc --skip-origin

echo "==> list certificates"
echo '{"id":"2","method":"listCertificates","origin":"cli://shell"}' | signbridge-rpc --skip-origin

echo
echo "To sign: hash your doc, then send signHash (see docs/QUICKSTART.md)"
