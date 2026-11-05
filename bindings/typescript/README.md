# @hunchbite/signbridge

Node / TypeScript client: spawns `signbridge-rpc` and speaks NDJSON.

```bash
cargo build -p signbridge-rpc
cd bindings/typescript && npm i && npx tsx src/smoke.ts
```

```ts
import { SignBridge } from "@hunchbite/signbridge";

const sb = new SignBridge();
console.log(await sb.ping());
const certs = await sb.listCertificates();
await sb.close();
```

See [docs/PROTOCOL.md](../../docs/PROTOCOL.md).
