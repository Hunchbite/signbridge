/**
 * Plug-and-play Express API — only needs `signbridge-rpc` on PATH.
 *
 *   curl -fsSL …/install.sh | bash          # once
 *   cd examples/node-express && npm i && npm start
 *
 *   curl -s localhost:3847/health
 *   curl -s -X POST localhost:3847/sign -H 'content-type: application/json' \
 *     -d '{"text":"hello contract"}'
 */
import express from "express";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { homedir } from "node:os";
import path from "node:path";
import { existsSync } from "node:fs";

function resolveRpc() {
  if (process.env.SIGNBRIDGE_RPC) return process.env.SIGNBRIDGE_RPC;
  const home = path.join(homedir(), ".signbridge/bin/signbridge-rpc");
  if (existsSync(home)) return home;
  return "signbridge-rpc";
}

/** Tiny NDJSON client — same protocol as the official SDKs. */
class Rpc {
  constructor(bin = resolveRpc()) {
    this.n = 0;
    this.queue = [];
    this.proc = spawn(bin, [], {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, SIGNBRIDGE_SKIP_ORIGIN: "1" },
    });
    createInterface({ input: this.proc.stdout }).on("line", (line) => {
      const pending = this.queue.shift();
      if (!pending) return;
      const data = JSON.parse(line);
      if (!data.ok) pending.reject(new Error(data.error?.message || "rpc error"));
      else pending.resolve(data.result);
    });
  }
  call(method, payload = {}) {
    this.n += 1;
    const msg = { id: String(this.n), method, ...payload };
    return new Promise((resolve, reject) => {
      this.queue.push({ resolve, reject });
      this.proc.stdin.write(JSON.stringify(msg) + "\n");
    });
  }
  close() {
    this.proc.stdin.end();
  }
}

const app = express();
app.use(express.json({ limit: "256kb" }));
const rpc = new Rpc();

app.get("/health", async (_req, res) => {
  try {
    res.json({ ok: true, engine: await rpc.call("ping") });
  } catch (e) {
    res.status(503).json({ ok: false, error: String(e.message || e) });
  }
});

app.get("/certs", async (_req, res) => {
  try {
    const r = await rpc.call("listCertificates", { origin: "cli://express" });
    res.json(r);
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

app.post("/sign", async (req, res) => {
  try {
    const text = req.body?.text ?? req.body?.message;
    const digestHex =
      req.body?.digestHex ??
      (text != null ? createHash("sha256").update(String(text)).digest("hex") : null);
    if (!digestHex) {
      res.status(400).json({ error: "provide text or digestHex" });
      return;
    }
    const { certificates } = await rpc.call("listCertificates", {
      origin: "cli://express",
    });
    if (!certificates?.length) {
      res.status(503).json({
        error: "no certificates — plug in a DSC token or set up SoftHSM",
      });
      return;
    }
    const certificateId = req.body?.certificateId ?? certificates[0].id;
    const result = await rpc.call("signHash", {
      origin: "cli://express",
      params: {
        certificateId,
        hashAlg: "SHA-256",
        digestHex,
        documentTitle: req.body?.title ?? "express-demo",
      },
    });
    res.json({ ok: true, digestHex, ...result });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

const port = Number(process.env.PORT || 3847);
app.listen(port, () => {
  console.log(`SignBridge Express on http://localhost:${port}`);
});

process.on("SIGINT", () => {
  rpc.close();
  process.exit(0);
});
