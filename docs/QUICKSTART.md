# Plug and play — 3 minutes

SignBridge is meant to drop into any stack. You do **not** write Rust.

## 1. Install the engine (once per machine)

```bash
curl -fsSL https://raw.githubusercontent.com/Hunchbite/signbridge/main/scripts/install.sh | bash
```

That puts `signbridge-rpc` on your PATH (`~/.signbridge/bin`).  
Same binary for Python, Node, Go, shell, etc.

Or with Rust already installed:

```bash
cargo install --git https://github.com/Hunchbite/signbridge signbridge-rpc
```

## 2. Pick your language (copy-paste)

### Node / TypeScript

```bash
npm i @hunchbite/signbridge
# or from the repo: cd bindings/typescript && npm i
```

```ts
import { create } from "@hunchbite/signbridge";

const sb = await create();          // finds or installs the engine
console.log(await sb.ping());
const certs = await sb.listCertificates();
// const sig = await sb.signHash({ certificateId: certs[0].id, digestHex: "…" });
await sb.close();
```

### Python

```bash
pip install signbridge
# or: pip install -e bindings/python
```

```python
from signbridge import create

with create() as sb:                # finds or installs the engine
    print(sb.ping())
    for c in sb.list_certificates():
        print(c["id"])
```

### Shell / any language

```bash
echo '{"id":"1","method":"ping"}' | signbridge-rpc --skip-origin
```

### C / Go / Java / Swift

Link `libsignbridge` + `bindings/c/signbridge.h` — JSON in, JSON out.  
See [PROTOCOL.md](./PROTOCOL.md).

## 3. Sign a digest (not a PDF)

```ts
import { createHash } from "node:crypto";
const digestHex = createHash("sha256").update("my-document-bytes").digest("hex");
const result = await sb.signHash({
  certificateId: certs[0].id,
  digestHex,
  documentTitle: "Contract.pdf",
});
console.log(result.signatureB64);
```

Your app (or Documenso) embeds that signature into the PDF. The token never sees the file.

## Drop-in examples

| Stack | Folder |
|---|---|
| Express API | `examples/node-express` |
| FastAPI | `examples/python-fastapi` |
| One-file Node script | `examples/node-script` |
| Plain shell | `examples/shell` |

```bash
cd examples/node-express && npm i && npm start
# POST /sign  { "text": "hello" }
```

## What you get / don’t get

| Included | Not included (install separately) |
|---|---|
| Protocol + RPC engine | USB token **drivers** (OpenSC / SoftHSM / vendor) |
| TS / Python SDKs | Real DSC hardware (SoftHSM works for synthetic) |
| C ABI | Browser extension (in `signbridge-apps`) |

## Next

- Protocol details: [PROTOCOL.md](./PROTOCOL.md)
- Browser product: [signbridge-apps](https://github.com/Hunchbite/signbridge-apps)
- SoftHSM for local demo: `brew install softhsm opensc`
