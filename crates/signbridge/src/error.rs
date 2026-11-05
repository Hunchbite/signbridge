//! Error types for the SignBridge framework.

use thiserror::Error;

/// Convenient result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Framework-level errors. Stable `code()` strings are safe to show to clients.
#[derive(Debug, Error)]
pub enum Error {
    /// Request origin is not on the allowlist.
    #[error("origin not allowed: {0}")]
    OriginDenied(String),

    /// Digest failed length / encoding checks.
    #[error("digest rejected: {0}")]
    BadDigest(String),

    /// No matching certificate or key id.
    #[error("unknown certificate: {0}")]
    UnknownCertificate(String),

    /// User (or automated policy) cancelled the operation.
    #[error("user cancelled")]
    Cancelled,

    /// PKCS#11 / token error.
    #[error("PKCS#11: {0}")]
    Pkcs11(String),

    /// Backend-specific error (Keychain, Windows store, …).
    #[error("backend: {0}")]
    Backend(String),

    /// Bad configuration file or value.
    #[error("config: {0}")]
    Config(String),

    /// Malformed protocol payload.
    #[error("protocol: {0}")]
    Protocol(String),

    /// Catch-all for unexpected failures.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// Stable machine-readable code for JSON responses.
    pub fn code(&self) -> &'static str {
        match self {
            Self::OriginDenied(_) => "origin_denied",
            Self::BadDigest(_) => "bad_digest",
            Self::UnknownCertificate(_) => "unknown_certificate",
            Self::Cancelled => "cancelled",
            Self::Pkcs11(_) => "pkcs11",
            Self::Backend(_) => "backend",
            Self::Config(_) => "config",
            Self::Protocol(_) => "protocol",
            Self::Other(_) => "internal",
        }
    }
}
