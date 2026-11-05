//! Pluggable certificate / key backends.
//!
//! Implement [`CertificateBackend`] to add Keychain, Windows CAPI, cloud CSC,
//! mock stores for tests, etc. The framework talks only to this trait.

use crate::error::Result;
use crate::protocol::{CertificateInfo, HashAlg};

/// Parameters for a digest signature. The backend must refuse non-digest input
/// at its own layer if it accepts raw bytes from elsewhere — the framework
/// already gates length via [`crate::security::validate_digest`].
#[derive(Debug, Clone)]
pub struct SignParams<'a> {
    /// Backend-specific certificate / key id (e.g. `pkcs11:module=…;slot=0;label=…`).
    pub certificate_id: &'a str,
    /// Hash algorithm that produced `digest`.
    pub hash_alg: HashAlg,
    /// Raw digest bytes (32 / 48 / 64).
    pub digest: &'a [u8],
    /// Optional user PIN / passphrase. `None` lets middleware prompt.
    pub pin: Option<&'a str>,
}

/// Result of a successful signature.
#[derive(Debug, Clone)]
pub struct SignOutput {
    /// Raw signature bytes (RSA PKCS#1 v1.5 or ECDSA raw r‖s, depending on key).
    pub signature: Vec<u8>,
    /// DER-encoded leaf certificate when the backend has one.
    pub certificate_der: Option<Vec<u8>>,
}

/// Something that can list signable identities and sign digests.
///
/// Thread-safe so a long-lived host can share one backend across requests.
pub trait CertificateBackend: Send + Sync {
    /// Short name for logs / `CertificateInfo.backend` (`"pkcs11"`, `"keychain"`, …).
    fn name(&self) -> &'static str;

    /// Enumerate certificates / keys currently available.
    fn list_certificates(&self) -> Result<Vec<CertificateInfo>>;

    /// Sign a digest with the identified key. Private key material must not leave
    /// the backend's store / token.
    fn sign_digest(&self, params: SignParams<'_>) -> Result<SignOutput>;
}

/// Fan-out across several backends (PKCS#11 + Keychain + …).
pub struct CompositeBackend {
    backends: Vec<Box<dyn CertificateBackend>>,
}

impl CompositeBackend {
    /// Create an empty composite; add backends with [`Self::push`].
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
        }
    }

    /// Append a backend (order = list order).
    pub fn push(&mut self, backend: impl CertificateBackend + 'static) {
        self.backends.push(Box::new(backend));
    }

    /// Number of registered backends.
    pub fn len(&self) -> usize {
        self.backends.len()
    }

    /// Whether any backend is registered.
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }
}

impl Default for CompositeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateBackend for CompositeBackend {
    fn name(&self) -> &'static str {
        "composite"
    }

    fn list_certificates(&self) -> Result<Vec<CertificateInfo>> {
        let mut out = Vec::new();
        for b in &self.backends {
            match b.list_certificates() {
                Ok(mut certs) => out.append(&mut certs),
                Err(e) => tracing::warn!(backend = b.name(), error = %e, "backend list failed"),
            }
        }
        Ok(out)
    }

    fn sign_digest(&self, params: SignParams<'_>) -> Result<SignOutput> {
        // Route by id prefix when possible; otherwise try each backend.
        let mut last_err = None;
        for b in &self.backends {
            match b.sign_digest(SignParams {
                certificate_id: params.certificate_id,
                hash_alg: params.hash_alg,
                digest: params.digest,
                pin: params.pin,
            }) {
                Ok(out) => return Ok(out),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            crate::Error::UnknownCertificate(params.certificate_id.to_string())
        }))
    }
}
