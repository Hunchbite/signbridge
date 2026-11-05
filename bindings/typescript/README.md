# @hunchbite/signbridge — plug and play

```bash
curl -fsSL https://raw.githubusercontent.com/Hunchbite/signbridge/main/scripts/install.sh | bash
export PATH="$HOME/.signbridge/bin:$PATH"

npm i   # in this folder, or publish to npm later
npm run build && npm run smoke
```

```ts
import { create } from "@hunchbite/signbridge";

const sb = await create();   // finds / installs signbridge-rpc
console.log(await sb.ping());
await sb.close();
```

See [docs/QUICKSTART.md](../../docs/QUICKSTART.md).
