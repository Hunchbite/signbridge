import { SignBridge } from "./index.js";

const sb = new SignBridge();
const ping = await sb.ping();
console.log("ping", ping);
const certs = await sb.listCertificates();
console.log("certs", certs.length);
await sb.close();
