//! # SignBridge
//!
//! Embeddable **signing framework** for document fingerprints (digests).
//! Language-agnostic by design: Rust API, JSON stdio RPC, and optional C ABI.
//!
//! ## How other languages talk to core
//!
//! | Surface | Use when |
//! |---|---|
//! | **`signbridge-rpc`** (NDJSON / framed stdio) | TypeScript, Python, Go, … — spawn a child |
//! | **C ABI** (`libsignbridge`, feature `ffi`) | Native apps, JNI, CGO, ctypes, N-API |
//! | **Rust API** ([`SignService`]) | In-process Rust |
//! | **CLI** (in `signbridge-apps`) | Shell scripts / one-shot |
//!
//! See [`docs/PROTOCOL.md`](../../docs/PROTOCOL.md) in the repo.
//!
//! ```ignore
//! use signbridge::{AppConfig, AutoConfirm, SignService};
//! use signbridge::protocol::Request;
//!
//! let service = SignService::new(AppConfig::for_cli(), AutoConfirm { pin: None });
//! let response = service.handle(Request::Ping { id: "1".into() });
//! ```

#![deny(missing_docs)]

pub mod adapters;
pub mod allowlist;
pub mod backend;
pub mod config;
pub mod error;
pub mod ipc;
pub mod profiles;
pub mod protocol;
pub mod security;
pub mod service;

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

#[cfg(feature = "testing")]
pub mod testing;

#[cfg(feature = "ffi")]
pub mod ffi;

pub use adapters::{handle_wire, WireProtocol};
pub use allowlist::OriginAllowlist;
pub use backend::{CertificateBackend, SignOutput, SignParams};
pub use config::AppConfig;
pub use error::{Error, Result};
pub use ipc::{handle_bytes, serve_stdio, serve_stdio_protocol, Framing};
pub use profiles::{doctor, DoctorReport, ModuleCandidate};
pub use protocol::{HashAlg, Request, Response};
pub use service::{AutoConfirm, ConfirmPrompt, SignService};

/// Framework / product name.
pub const NAME: &str = "signbridge";
/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
