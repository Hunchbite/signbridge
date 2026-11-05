# SignBridge as a framework

SignBridge is split so **the library is the product**, and apps are examples of how to use it.

```
┌─────────────────────────────────────────────────────────────┐
│  Your interface                                             │
│  (GUI, TUI, browser extension, Documenso plugin, CI job…)   │
└────────────────────────────┬────────────────────────────────┘
                             │  ConfirmPrompt + Request/Response
                             │  or direct CertificateBackend calls
┌────────────────────────────▼────────────────────────────────┐
│  signbridge  (this crate — publishable package)             │
│  · OriginAllowlist · validate_digest · SignService          │
│  · CertificateBackend trait                                 │
│  · PKCS#11 backend (tokens / SoftHSM)                       │
│  · (later) Keychain · Windows store · CSC cloud             │
└────────────────────────────┬────────────────────────────────┘
                             │
              USB token / SoftHSM / OS store / HSM
```

## What you depend on

```toml
[dependencies]
signbridge = "0.1"
```

```rust
use signbridge::{AppConfig, AutoConfirm, SignService};
use signbridge::protocol::Request;

let service = SignService::new(AppConfig::for_cli(), AutoConfirm { pin: None });
let response = service.handle(Request::Ping { id: "1".into() });
```

## What you implement

| Hook | Purpose |
|---|---|
| `ConfirmPrompt` | Your confirm dialog / policy (`AutoConfirm` for tests) |
| `CertificateBackend` | Optional — add Keychain, mocks, cloud CSC |
| Protocol JSON | Optional — only if your UI is out-of-process |

## Reference apps (not required to use the package)

| App | Role |
|---|---|
| `signbridge` CLI | Scripts, humans, CI |
| `signbridge-host` | Chrome/Firefox native messaging |
| `extension/` | Page ↔ host bridge |

Drivers (OpenSC, vendor PKCS#11 `.so` / `.dll`, SoftHSM) stay **outside** the package. The framework loads whatever modules you pass in `AppConfig.pkcs11_modules`.
