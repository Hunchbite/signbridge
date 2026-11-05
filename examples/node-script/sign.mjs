#!/usr/bin/env node
/**
 * One-file plug-and-play script.
 *   cargo build -p signbridge-rpc
 *   node --experimental-strip-types ../../bindings/typescript/src/smoke.ts
 * Or after npm link of the client:
 *   node sign.mjs "hello world"
 */
import { createHash } from "node:crypto";
import { create } from "../../bindings/typescript/dist/index.js";

const text = process.argv[2] ?? "hello from signbridge";
const sb = await create();
console.log(await sb.ping());

const certs = await sb.listCertificates();
if (!certs.length) {
  console.error("No certificates found. Plug in a token or set up SoftHSM.");
  await sb.close();
  process.exit(1);
}

const digestHex = createHash("sha256").update(text).digest("hex");
const result = await sb.signHash({
  certificateId: certs[0].id,
  digestHex,
  documentTitle: "node-script",
});
console.log({ text, digestHex, signatureB64: result.signatureB64 });
await sb.close();
