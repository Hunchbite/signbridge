# SignBridge

**Plug-and-play signing for any developer stack.**  
Sign document fingerprints with USB DSC tokens (PKCS#11) — never the full PDF. No Java. No open TCP port.

Product UI (Chrome extension, installers): [`signbridge-apps`](https://github.com/Hunchbite/signbridge-apps)

## 60-second start

```bash
# 1. Install the engine (once)
curl -fsSL https://raw.githubusercontent.com/Hunchbite/signbridge/main/scripts/install.sh | bash
export PATH="$HOME/.signbridge/bin:$PATH"

# 2. Talk to it from anything
echo '{"id":"1","method":"ping"}' | signbridge-rpc --skip-origin
```

### Node

```ts
import { create } from "@hunchbite/signbridge";
const sb = await create();          // auto-finds / installs the engine
console.log(await sb.ping());
await sb.close();
```

### Python

```python
from signbridge import create
with create() as sb:                # auto-finds / installs the engine
    print(sb.ping())
```

### Drop into your API

```bash
cd examples/node-express && npm i && npm start
# POST /sign  { "text": "hello" }
```

More: **[docs/QUICKSTART.md](docs/QUICKSTART.md)** · **[docs/PROTOCOL.md](docs/PROTOCOL.md)** · **[examples/](examples/)**

## How it plugs in

```
Your app (TS / Python / Go / C / shell / Express / FastAPI / …)
        │  same JSON protocol
        ▼
   signbridge-rpc   ← one binary, all languages
        │
        ▼
   PKCS#11 token / SoftHSM   ← drivers stay outside
```

| You want… | Use |
|---|---|
| Fastest integration | `install.sh` + JSON over stdio |
| Official SDK | `bindings/typescript` or `bindings/python` (`create()`) |
| Native embed | C ABI `bindings/c/signbridge.h` |
| Browser product | `signbridge-apps` extension + host |

## Develop this repo

```bash
cargo test -p signbridge --features testing
cargo build -p signbridge-rpc
./scripts/synthetic_e2e.sh
```

## Licence

MIT OR Apache-2.0 · [Hunchbite](https://hunchbite.com)
