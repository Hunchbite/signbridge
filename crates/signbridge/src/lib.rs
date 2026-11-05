//! # SignBridge
//!
//! Embeddable **signing framework** for document fingerprints (digests).
//! Build your own UI, CLI, browser host, or server plugin on top — this crate
//! never opens a network port and never accepts a full PDF.
//!
//! ## Layers
//!
//! | Layer | What it is | Who uses it |
//! |---|---|---|
//! | **`signbridge` (this crate)** | Framework: backends, allowlist, digest gate, `SignService` | Your app |
//! | **`signbridge-cli`** | Reference CLI | Humans / scripts |
//! | **`signbridge-host`** | Browser native-messaging app | Chrome / Firefox extension |
//! | **`extension/`** | Browser UI glue | Web pages (Documenso, …) |
//!
//! ## Embed
//!
//! ```ignore
//! use signbridge::{AppConfig, AutoConfirm, SignService};
//! use signbridge::protocol::Request;
//!
//! let service = SignService::new(AppConfig::default(), AutoConfirm { pin: None });
//! let response = service.handle(Request::Ping { id: "1".into() });
//! ```
//!
//! Swap `AutoConfirm` for your own [`ConfirmPrompt`] (GUI, TUI, headless policy).
//! Swap or compose [`CertificateBackend`] implementations (PKCS#11 today;
//! Keychain / Windows store / CSC later).

#![deny(missing_docs)]

pub mod allowlist;
pub mod backend;
pub mod config;
pub mod error;
pub mod protocol;
pub mod security;
pub mod service;

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

#[cfg(feature = "testing")]
pub mod testing;

pub use allowlist::OriginAllowlist;
pub use backend::{CertificateBackend, SignOutput, SignParams};
pub use config::AppConfig;
pub use error::{Error, Result};
pub use protocol::{HashAlg, Request, Response};
pub use service::{AutoConfirm, ConfirmPrompt, SignService};

/// Framework / product name.
pub const NAME: &str = "signbridge";
/// Crate version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
