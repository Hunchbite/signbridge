# SignBridge

**Open-source signing framework** (Rust). Sign document fingerprints with USB DSC tokens via PKCS#11 — never the full PDF. No Java.

This repo is the **library**. Desktop apps, the Chrome extension, and Hunchbite packaging live in [`signbridge-apps`](https://github.com/Hunchbite/signbridge-apps).

## Install / embed

```toml
[dependencies]
signbridge = { git = "https://github.com/Hunchbite/signbridge" }
# or, side-by-side: path = "../signbridge/crates/signbridge"
```

```rust
use signbridge::{AppConfig, AutoConfirm, SignService};
use signbridge::protocol::Request;

let svc = SignService::new(AppConfig::for_cli(), AutoConfirm { pin: None });
let res = svc.handle(Request::Ping { id: "1".into() });
```

Implement `ConfirmPrompt` for your UI. Implement `CertificateBackend` for Keychain / Windows / cloud later — or use the bundled PKCS#11 backend.

Token **drivers** (OpenSC, SoftHSM, vendor modules) are not bundled; point `AppConfig.pkcs11_modules` at them.

## Build & test

```bash
brew install softhsm opensc   # synthetic tests
cargo test -p signbridge --features testing
./scripts/synthetic_e2e.sh
```

## Layout

```
crates/signbridge/   # publishable framework crate
docs/FRAMEWORK.md    # how to embed
```

## Licence

MIT OR Apache-2.0 · [Hunchbite Technologies Private Limited](https://hunchbite.com)
