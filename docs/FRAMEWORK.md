# SignBridge as a framework

See also [PROTOCOL.md](./PROTOCOL.md) for the **language-agnostic** contract.

| Layer | Repo | Role |
|---|---|---|
| Core library + RPC + C ABI + py/ts clients | `signbridge` | Anyone embeds |
| CLI, browser host, Chrome extension | `signbridge-apps` | Hunchbite product UX |
| Token drivers | system packages | OpenSC / SoftHSM / vendor |

```
Your language  →  signbridge-rpc | libsignbridge | Rust API
                         ↓
                   SignService + CertificateBackend
                         ↓
                   PKCS#11 module (not bundled)
```
