import { create } from "./index.js";

const sb = await create();
console.log("ping", await sb.ping());
console.log("certs", (await sb.listCertificates()).length);
await sb.close();
console.log("plug-and-play ok");
