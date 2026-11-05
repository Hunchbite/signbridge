/**
 * SignBridge Node/TypeScript client — plug-and-play NDJSON over `signbridge-rpc`.
 */
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import { ensureRpc, findRpc } from "./ensure.js";

export { ensureRpc, findRpc } from "./ensure.js";

export type HashAlg = "SHA-256" | "SHA-384" | "SHA-512";

export class SignBridgeError extends Error {
  constructor(
    public code: string,
    message: string,
  ) {
    super(`${code}: ${message}`);
    this.name = "SignBridgeError";
  }
}

export type CertificateInfo = {
  id: string;
  subject: string;
  issuer: string;
  serialHex: string;
  backend: string;
  tokenLabel?: string;
  keyAlgo?: string;
};

export type SignBridgeOptions = {
  binary?: string;
  config?: string;
  pin?: string;
  skipOrigin?: boolean;
};

export class SignBridge {
  private proc: ChildProcessWithoutNullStreams;
  private rl: ReturnType<typeof createInterface>;
  private queue: Array<{
    resolve: (v: unknown) => void;
    reject: (e: Error) => void;
  }> = [];
  private n = 0;

  constructor(opts: SignBridgeOptions & { binary: string }) {
    const bin = opts.binary;
    const env = { ...process.env };
    if (opts.config) env.SIGNBRIDGE_CONFIG = opts.config;
    if (opts.pin) env.SIGNBRIDGE_PIN = opts.pin;
    if (opts.skipOrigin !== false) env.SIGNBRIDGE_SKIP_ORIGIN = "1";

    this.proc = spawn(bin, [], {
      stdio: ["pipe", "pipe", "pipe"],
      env,
    });
    this.rl = createInterface({ input: this.proc.stdout });
    this.rl.on("line", (line) => {
      const pending = this.queue.shift();
      if (!pending) return;
      try {
        const data = JSON.parse(line) as {
          ok: boolean;
          result?: unknown;
          error?: { code: string; message: string };
        };
        if (!data.ok) {
          pending.reject(
            new SignBridgeError(
              data.error?.code ?? "internal",
              data.error?.message ?? "unknown",
            ),
          );
          return;
        }
        pending.resolve(data.result);
      } catch (e) {
        pending.reject(e as Error);
      }
    });
    this.proc.on("exit", (code) => {
      while (this.queue.length) {
        this.queue
          .shift()!
          .reject(new SignBridgeError("internal", `rpc exited (${code})`));
      }
    });
  }

  async close(): Promise<void> {
    this.proc.stdin.end();
    this.rl.close();
    await new Promise<void>((resolve) => this.proc.once("close", () => resolve()));
  }

  private request(method: string, payload: Record<string, unknown> = {}): Promise<unknown> {
    this.n += 1;
    const msg = { id: String(this.n), method, ...payload };
    return new Promise((resolve, reject) => {
      this.queue.push({ resolve, reject });
      this.proc.stdin.write(`${JSON.stringify(msg)}\n`);
    });
  }

  ping(): Promise<{ name: string; version: string }> {
    return this.request("ping") as Promise<{ name: string; version: string }>;
  }

  async listCertificates(origin = "cli://typescript"): Promise<CertificateInfo[]> {
    const result = (await this.request("listCertificates", { origin })) as {
      certificates: CertificateInfo[];
    };
    return result.certificates ?? [];
  }

  signHash(args: {
    certificateId: string;
    digestHex: string;
    origin?: string;
    hashAlg?: HashAlg;
    documentTitle?: string;
    documentId?: string;
  }): Promise<{
    signatureB64: string;
    certificateId: string;
    hashAlg: HashAlg;
    certificateDerB64?: string;
  }> {
    return this.request("signHash", {
      origin: args.origin ?? "cli://typescript",
      params: {
        certificateId: args.certificateId,
        hashAlg: args.hashAlg ?? "SHA-256",
        digestHex: args.digestHex,
        documentTitle: args.documentTitle,
        documentId: args.documentId,
      },
    }) as Promise<{
      signatureB64: string;
      certificateId: string;
      hashAlg: HashAlg;
      certificateDerB64?: string;
    }>;
  }
}

/** Plug-and-play: ensure engine is present, then open a client. */
export async function create(opts: SignBridgeOptions = {}): Promise<SignBridge> {
  const binary = opts.binary ?? (await ensureRpc());
  return new SignBridge({ ...opts, binary });
}
