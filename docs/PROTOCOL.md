# SignBridge language-agnostic protocol

Any language can drive SignBridge without linking Rust. There are three official surfaces; they all use the **same JSON request/response shapes**.

```
Your app (TS / Python / Go / Swift / …)
        │
        ├─ A. spawn `signbridge-rpc`  ── NDJSON or length-framed stdio
        ├─ B. spawn `signbridge` CLI  ── one-shot JSON flags
        └─ C. load `libsignbridge`    ── C ABI: JSON in → JSON out
                │
                ▼
         signbridge core (Rust)
                │
                ▼
         PKCS#11 token / SoftHSM
```

No TCP port. Private keys never leave the token. Only digests are signed.

## Requests

| `method` | Purpose |
|---|---|
| `ping` | Version / liveness |
| `doctor` | Probe PKCS#11 middleware (India / Spain / EU / SoftHSM) |
| `listCertificates` | List signable identities |
| `signHash` | Sign a hex digest |

### `ping`

```json
{ "id": "1", "method": "ping" }
```

### `doctor`

```json
{ "id": "d1", "method": "doctor" }
```

Returns which regional PKCS#11 modules exist on disk, which are configured in this process, certificate count, and setup hints. No origin required.

### `listCertificates`

```json
{
  "id": "2",
  "method": "listCertificates",
  "origin": "https://sign.hunchbite.com"
}
```

For CLI / local tools, set `SIGNBRIDGE_SKIP_ORIGIN=1` or use config `"skipOriginCheck": true`, and pass any origin (e.g. `"cli://app"`).

### `signHash`

```json
{
  "id": "3",
  "method": "signHash",
  "origin": "cli://app",
  "params": {
    "certificateId": "pkcs11:module=…;slot=0;label=SyntheticSigner",
    "hashAlg": "SHA-256",
    "digestHex": "<64 hex chars for SHA-256>",
    "documentTitle": "Optional title",
    "documentId": "optional-id"
  }
}
```

`digestHex` length must match the hash: 64 / 96 / 128 hex chars for SHA-256 / 384 / 512. Full documents are rejected.

## Responses

```json
{ "id": "1", "ok": true, "result": { … } }
{ "id": "1", "ok": false, "error": { "code": "bad_digest", "message": "…" } }
```

Stable error codes: `origin_denied`, `bad_digest`, `unknown_certificate`, `cancelled`, `pkcs11`, `backend`, `config`, `protocol`, `internal`.

## Transport A — `signbridge-rpc` (recommended for SDKs)

```bash
signbridge-rpc                           # NDJSON: one JSON object per line on stdin
signbridge-rpc --framed                  # Chrome native-messaging framing (4-byte LE length)
signbridge-rpc --protocol webeid         # Web eID native commands
signbridge-rpc --protocol afirma         # AutoFirma-style hash-sign subset
```

Env:

| Var | Meaning |
|---|---|
| `SIGNBRIDGE_CONFIG` | Path to JSON config |
| `SIGNBRIDGE_PIN` | Token PIN (tests / automation only) |
| `SIGNBRIDGE_SKIP_ORIGIN` | `1` to skip allowlist (local tools) |
| `SIGNBRIDGE_PROTOCOL` | `signbridge` (default) / `webeid` / `afirma` |

### NDJSON example

```bash
echo '{"id":"1","method":"ping"}' | signbridge-rpc
```

### Python

```python
from signbridge import Client
with Client() as c:
    print(c.ping())
    certs = c.list_certificates(origin="cli://demo")
    sig = c.sign_hash(certs[0]["id"], digest_hex=..., origin="cli://demo")
```

### TypeScript

```ts
import { SignBridge } from "@hunchbite/signbridge";
const sb = new SignBridge();
await sb.ping();
const certs = await sb.listCertificates("cli://demo");
const sig = await sb.signHash({ certificateId: certs[0].id, digestHex: "…" });
await sb.close();
```

## Transport B — one-shot CLI (`signbridge-apps`)

```bash
signbridge ping
signbridge list
signbridge sign --certificate-id '…' --digest-hex '…' --json
```

## Transport C — C ABI (`libsignbridge`)

```c
#include "signbridge.h"

SignBridge *sb = signbridge_new(NULL);           /* or config JSON */
char *out = signbridge_request(sb,
    "{\"id\":\"1\",\"method\":\"ping\"}");
/* out is malloc'd JSON — free with signbridge_string_free */
signbridge_string_free(out);
signbridge_free(sb);
```

Build: `cargo build -p signbridge --features ffi --release` → `target/release/libsignbridge.{dylib,so,dll}` + `bindings/c/signbridge.h`.

## Security

1. Prefer spawning `signbridge-rpc` as a child of your app (stdio only).
2. Do not open a localhost HTTP port for signing.
3. Never send a full PDF — only digests.
4. Collect PINs in your UI or via `SIGNBRIDGE_PIN` for tests; never from a web page.
