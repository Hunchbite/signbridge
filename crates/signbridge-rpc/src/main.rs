//! `signbridge-rpc` — language-agnostic JSON protocol on stdin/stdout.
//!
//! Default: NDJSON (one request JSON per line). Use `--framed` for Chrome
//! native-messaging length prefixes. Use `--protocol webeid|afirma` for
//! ecosystem adapters.

use anyhow::{Context, Result};
use clap::Parser;
use signbridge::ipc::{serve_stdio_protocol, Framing};
use signbridge::{AppConfig, AutoConfirm, SignService, WireProtocol};
use std::io::{stdin, stdout};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "signbridge-rpc",
    version,
    about = "SignBridge JSON-RPC over stdio for any language"
)]
struct Args {
    /// JSON config path (allowlist + PKCS#11 modules).
    #[arg(long, env = "SIGNBRIDGE_CONFIG")]
    config: Option<PathBuf>,

    /// Token PIN for automation (never for untrusted input).
    #[arg(long, env = "SIGNBRIDGE_PIN")]
    pin: Option<String>,

    /// Skip origin allowlist (local / SDK tools). Also set SIGNBRIDGE_SKIP_ORIGIN=1.
    #[arg(long, default_value_t = false)]
    skip_origin: bool,

    /// Use Chrome native-messaging framing instead of NDJSON.
    #[arg(long)]
    framed: bool,

    /// Wire protocol: `signbridge` (default), `webeid`, or `afirma`.
    #[arg(long, env = "SIGNBRIDGE_PROTOCOL", default_value = "signbridge")]
    protocol: String,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("signbridge-rpc fatal: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("signbridge=info".parse()?))
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let mut config =
        AppConfig::load_or_default(args.config.as_deref()).context("load config")?;
    config = config.with_profile_modules();
    if args.skip_origin || std::env::var_os("SIGNBRIDGE_SKIP_ORIGIN").is_some() {
        config.skip_origin_check = true;
    }
    if let Some(pin) = args.pin.clone() {
        config.test_pin = Some(pin);
    }

    let pin = args
        .pin
        .or_else(|| std::env::var("SIGNBRIDGE_PIN").ok())
        .or_else(|| config.test_pin.clone());

    let framing = if args.framed {
        Framing::NativeMessage
    } else {
        Framing::Ndjson
    };

    let protocol = WireProtocol::parse(&args.protocol).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown --protocol {:?} (expected signbridge|webeid|afirma)",
            args.protocol
        )
    })?;

    info!(
        version = signbridge::VERSION,
        ?framing,
        ?protocol,
        modules = config.pkcs11_modules.len(),
        "signbridge-rpc ready"
    );

    let service = SignService::new(config, AutoConfirm { pin });
    serve_stdio_protocol(
        &service,
        framing,
        protocol,
        stdin().lock(),
        stdout().lock(),
    )?;
    Ok(())
}
