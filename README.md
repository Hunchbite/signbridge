# SignBridge

**Language-agnostic signing framework.** Sign document fingerprints with USB DSC tokens (PKCS#11) — never the full PDF. No Java. No open TCP port.

Product apps (Chrome extension, installers) live in [`signbridge-apps`](https://github.com/Hunchbite/signbridge-apps).

## How any language uses core

```
TS / Python / Go / Swift / Java / shell
        │
        ├─ spawn signbridge-rpc   ← NDJSON stdio  (recommended)
        ├─ load libsignbridge     ← C ABI, JSON in/out
        ├─ cargo / Rust API       ← in-process
        └─ CLI (signbridge-apps)  ← one-shot commands
```

Full contract: **[docs/PROTOCOL.md](docs/PROTOCOL.md)**

| Surface | Path |
|---|---|
| JSON protocol | `docs/PROTOCOL.md` |
| RPC binary | `cargo run -p signbridge-rpc` |
| C header | `bindings/c/signbridge.h` |
| Python client | `bindings/python` |
| TypeScript client | `bindings/typescript` |

### Quick: any language via RPC

```bash
cargo build -p signbridge-rpc
echo '{"id":"1","method":"ping"}' | ./target/debug/signbridge-rpc --skip-origin
```

### Python

```bash
pip install -e bindings/python
python -c 'from signbridge import Client; print(Client().__enter__().ping())'
```

### TypeScript

```bash
cd bindings/typescript && npm i && npx tsx src/smoke.ts
```

### C / FFI

```bash
cargo build -p signbridge --features ffi --release
# link target/release/libsignbridge.{dylib,so,dll} with bindings/c/signbridge.h
```

### Rust

```toml
signbridge = { git = "https://github.com/Hunchbite/signbridge" }
```

## Security

1. Stdio or in-process only — no signing HTTP port.
2. Origin allowlist for browser hosts; SDKs use `--skip-origin` / `SIGNBRIDGE_SKIP_ORIGIN=1`.
3. Digests only (SHA-256 / 384 / 512).
4. Private keys never leave the token.

## Test

```bash
brew install softhsm opensc
cargo test -p signbridge --features testing
./scripts/synthetic_e2e.sh
```

## Licence

MIT OR Apache-2.0 · [Hunchbite](https://hunchbite.com)
