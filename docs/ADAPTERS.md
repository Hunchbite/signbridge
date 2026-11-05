# Country / portal adapters

SignBridge core speaks one JSON protocol. **Adapters** translate other ecosystems onto that core so Indian DSC, Spanish AutoFirma-style flows, and EU Web eID can share the same engine.

```
 Spanish portal / AutoScript     Estonian/EU site (web-eid.js)     Documenso / any SDK
            │                              │                              │
            ▼                              ▼                              ▼
     afirma adapter                  webeid adapter                 native protocol
            │                              │                              │
            └──────────────────────────────┴──────────────────────────────┘
                                           ▼
                                    SignService + PKCS#11
                                           ▼
                         ePass2003 / ProxKey / DNIe / SoftHSM / …
```

## Research summary (what portals actually expect)

### India (DSC)
- Keys live on USB tokens (ePass2003 / Feitian, ProxKey / Watchdata, mToken, …).
- Apps talk **PKCS#11** (OpenSC for ePass2003; vendor DLL/dylib for some ProxKey).
- Sites historically used **emBridge** (closed). We replace that *app* layer, not the token driver.
- `profiles::india()` ships known module paths; `doctor` checks which are present.

### Spain (AutoFirma / @firma)
- Official stack: [ctt-gob-es/clienteafirma](https://github.com/ctt-gob-es/clienteafirma) (GPL/EUPL) + **AutoScript.js**.
- Browser launches **AutoFirma** via `afirma://` / local helper; large docs use **triphase** signing (server builds ToBeSigned, client signs hash, server assembles).
- Full AutoFirma replacement = multi-year Java parity. SignBridge implements the **hash-sign client phase** compatible with triphase-style integrators first (`--protocol afirma`).
- FNMT soft certs: later via macOS Keychain / Windows store backends (same `signHash`).

### EU Web eID
- Spec: [web-eid-system-architecture-doc](https://github.com/web-eid/web-eid-system-architecture-doc) (MIT ecosystem).
- Native messaging commands: `authenticate`, `get-signing-certificate`, `sign`.
- Sign request already is **hash-only** (same security model as SignBridge).
- SignBridge `--protocol webeid` speaks this API over stdio so a custom extension/host can use our engine (or coexist with official Web eID app).

## Honest status

| Goal | Status |
|---|---|
| Indian PKCS#11 profiles + `doctor` | Implemented (OpenSC, ePass2003, ProxKey, mToken, …) |
| SoftHSM synthetic India-like path | Works (CI / local e2e) |
| Real ePass2003 / ProxKey on device | Needs your token plugged in + vendor/OpenSC driver |
| Web eID native commands | Implemented — `authenticate` uses official `hash(hash(origin)‖hash(nonce))` |
| AutoFirma full desktop / `afirma://` | **Not** a full clone; hash-sign adapter first |
| Keychain / Windows store | Next backends |
| Documenso PAdES hook | Next product work in `signbridge-apps` |

### Web eID wire examples

```bash
# get-signing-certificate
echo '{"command":"get-signing-certificate","arguments":{"origin":"https://example.com"}}' \
  | signbridge-rpc --protocol webeid --skip-origin

# sign (hash + previously returned certificate, both base64)
echo '{"command":"sign","arguments":{"origin":"https://example.com","certificate":"…","hash":"…","hashFunction":"SHA-256"}}' \
  | signbridge-rpc --protocol webeid --skip-origin --framed   # use --framed with a real extension
```

### AutoFirma hash-sign examples

```bash
echo '{"id":"1","op":"listCertificates","origin":"https://sede.example"}' \
  | signbridge-rpc --protocol afirma --skip-origin

echo '{"id":"2","op":"signHash","origin":"https://sede.example","certificateId":"pkcs11:…","hashAlg":"SHA-256","digestHex":"…"}' \
  | signbridge-rpc --protocol afirma --skip-origin
```

## Usage

```bash
# Default SignBridge JSON (SDKs, Documenso)
signbridge-rpc --skip-origin

# Web eID native messaging JSON
signbridge-rpc --protocol webeid --skip-origin

# AutoFirma-style hash sign JSON
signbridge-rpc --protocol afirma --skip-origin

# Diagnose Indian / Spain / EU modules on this machine
echo '{"id":"1","method":"doctor"}' | signbridge-rpc --skip-origin
```
