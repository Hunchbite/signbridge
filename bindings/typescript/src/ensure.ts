/**
 * Locate or install `signbridge-rpc` for plug-and-play use.
 */
import { existsSync, mkdirSync, chmodSync, createWriteStream } from "node:fs";
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";

const REPO = process.env.SIGNBRIDGE_REPO ?? "Hunchbite/signbridge";

export function homeBinDir(): string {
  const prefix = process.env.SIGNBRIDGE_PREFIX ?? path.join(homedir(), ".signbridge");
  return path.join(prefix, "bin");
}

function platformAsset(): string {
  const platform = process.platform;
  const arch =
    process.arch === "x64" ? "x86_64" : process.arch === "arm64" ? "aarch64" : process.arch;
  if (platform === "darwin") return `signbridge-rpc-${arch}-apple-darwin`;
  if (platform === "linux") return `signbridge-rpc-${arch}-unknown-linux-gnu`;
  if (platform === "win32") return `signbridge-rpc-${arch}-pc-windows-msvc.exe`;
  throw new Error(`unsupported platform: ${platform}/${process.arch}`);
}

function candidates(): string[] {
  const out: string[] = [];
  if (process.env.SIGNBRIDGE_RPC) out.push(process.env.SIGNBRIDGE_RPC);
  out.push(path.join(homeBinDir(), process.platform === "win32" ? "signbridge-rpc.exe" : "signbridge-rpc"));
  // which
  const which = spawnSync(process.platform === "win32" ? "where" : "which", ["signbridge-rpc"], {
    encoding: "utf8",
  });
  if (which.status === 0 && which.stdout.trim()) {
    out.unshift(which.stdout.trim().split(/\r?\n/)[0]!);
  }
  const here = path.dirname(fileURLToPath(import.meta.url));
  const root = path.resolve(here, "../../..");
  out.push(path.join(root, "target/debug/signbridge-rpc"));
  out.push(path.join(root, "target/release/signbridge-rpc"));
  return out;
}

export function findRpc(): string | undefined {
  for (const p of candidates()) {
    if (p && existsSync(p)) return p;
  }
  return undefined;
}

async function downloadRelease(dest: string): Promise<boolean> {
  const asset = platformAsset();
  const api = `https://api.github.com/repos/${REPO}/releases/latest`;
  try {
    const res = await fetch(api, {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "signbridge" },
    });
    if (!res.ok) return false;
    const data = (await res.json()) as {
      assets?: Array<{ name: string; browser_download_url: string }>;
    };
    const hit = data.assets?.find(
      (a) => a.name === asset || a.name.startsWith(asset.replace(/\.exe$/, "")),
    );
    if (!hit) return false;
    const bin = await fetch(hit.browser_download_url);
    if (!bin.ok || !bin.body) return false;
    mkdirSync(path.dirname(dest), { recursive: true });
    await pipeline(Readable.fromWeb(bin.body as never), createWriteStream(dest));
    chmodSync(dest, 0o755);
    return true;
  } catch {
    return false;
  }
}

function cargoInstall(): string {
  const prefix = path.dirname(homeBinDir());
  const r = spawnSync(
    "cargo",
    ["install", "--git", `https://github.com/${REPO}`, "signbridge-rpc", "--root", prefix, "--force"],
    { stdio: "inherit" },
  );
  if (r.status !== 0) {
    throw new Error(
      "Could not install signbridge-rpc. Run:\n" +
        "  curl -fsSL https://raw.githubusercontent.com/Hunchbite/signbridge/main/scripts/install.sh | bash",
    );
  }
  const bin = path.join(homeBinDir(), "signbridge-rpc");
  if (!existsSync(bin)) throw new Error("cargo install ok but binary missing");
  return bin;
}

/** Return path to signbridge-rpc, downloading or building if needed. */
export async function ensureRpc(opts: { install?: boolean } = {}): Promise<string> {
  const found = findRpc();
  if (found) return found;
  if (opts.install === false) {
    throw new Error("signbridge-rpc not found");
  }
  const dest = path.join(homeBinDir(), "signbridge-rpc");
  if (await downloadRelease(dest)) return dest;
  return cargoInstall();
}
