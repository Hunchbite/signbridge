//! High-level request handler — the main entry point for embedding apps.

use crate::backend::{CertificateBackend, SignParams};
use crate::config::AppConfig;
use crate::error::{Error, Result};
use crate::protocol::{
    ListCertificatesResult, PingResult, Request, Response, ResponseBody, SignResult,
};
use crate::security::validate_digest;
use crate::{NAME, VERSION};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::sync::Arc;
use tracing::info;

/// UI / policy hook: confirm the signature and optionally collect a PIN.
///
/// Implement this in your app (native dialog, TUI, auto-approve for CI, …).
pub trait ConfirmPrompt: Send + Sync {
    /// Return `true` if the user approves signing for this origin / document / cert.
    fn confirm_sign(
        &self,
        origin: &str,
        document_title: Option<&str>,
        certificate_subject: &str,
    ) -> Result<bool>;

    /// Optional PIN. Return `None` to let token middleware prompt.
    fn ask_pin(&self, token_label: Option<&str>) -> Result<Option<String>>;
}

/// Always-approve prompt for unit / SoftHSM tests.
#[derive(Debug, Clone, Default)]
pub struct AutoConfirm {
    /// PIN to supply (e.g. SoftHSM user PIN).
    pub pin: Option<String>,
}

impl ConfirmPrompt for AutoConfirm {
    fn confirm_sign(
        &self,
        _origin: &str,
        _document_title: Option<&str>,
        _certificate_subject: &str,
    ) -> Result<bool> {
        Ok(true)
    }

    fn ask_pin(&self, _token_label: Option<&str>) -> Result<Option<String>> {
        Ok(self.pin.clone())
    }
}

/// Framework façade: allowlist → confirm → backend sign.
pub struct SignService<C: ConfirmPrompt> {
    config: AppConfig,
    backend: Arc<dyn CertificateBackend>,
    confirm: C,
}

impl<C: ConfirmPrompt> SignService<C> {
    /// Build a service with the default PKCS#11 backend from `config.pkcs11_modules`.
    #[cfg(feature = "pkcs11")]
    pub fn new(config: AppConfig, confirm: C) -> Self {
        let backend = crate::pkcs11::Pkcs11Backend::new(config.pkcs11_modules.clone());
        Self::with_backend(config, Arc::new(backend), confirm)
    }

    /// Build a service with an arbitrary backend (mocks, composites, Keychain, …).
    pub fn with_backend(config: AppConfig, backend: Arc<dyn CertificateBackend>, confirm: C) -> Self {
        Self {
            config,
            backend,
            confirm,
        }
    }

    /// Shared backend handle (for advanced callers).
    pub fn backend(&self) -> &Arc<dyn CertificateBackend> {
        &self.backend
    }

    /// Handle one protocol request and return a protocol response.
    pub fn handle(&self, request: Request) -> Response {
        let id = request.id().to_string();
        match self.handle_inner(request) {
            Ok(body) => Response::ok(id, body),
            Err(e) => Response::err(id, e.code(), e.to_string()),
        }
    }

    fn handle_inner(&self, request: Request) -> Result<ResponseBody> {
        if !self.config.skip_origin_check {
            if let Some(origin) = request.origin() {
                self.config.allowlist.check(origin)?;
            }
        }

        match request {
            Request::Ping { .. } => Ok(ResponseBody::Ping(PingResult {
                name: NAME.into(),
                version: VERSION.into(),
            })),
            Request::ListCertificates { .. } => {
                let certificates = self.backend.list_certificates()?;
                info!(count = certificates.len(), "listed certificates");
                Ok(ResponseBody::Certificates(ListCertificatesResult {
                    certificates,
                }))
            }
            Request::SignHash {
                origin, params, ..
            } => {
                let digest = validate_digest(params.hash_alg, &params.digest_hex)?;

                let certs = self.backend.list_certificates()?;
                let cert = certs
                    .iter()
                    .find(|c| c.id == params.certificate_id)
                    .ok_or_else(|| Error::UnknownCertificate(params.certificate_id.clone()))?;

                let approved = self.confirm.confirm_sign(
                    &origin,
                    params.document_title.as_deref(),
                    &cert.subject,
                )?;
                if !approved {
                    return Err(Error::Cancelled);
                }

                let pin = if let Some(test_pin) = &self.config.test_pin {
                    Some(test_pin.clone())
                } else {
                    self.confirm.ask_pin(cert.token_label.as_deref())?
                };

                let out = self.backend.sign_digest(SignParams {
                    certificate_id: &params.certificate_id,
                    hash_alg: params.hash_alg,
                    digest: &digest,
                    pin: pin.as_deref(),
                })?;

                info!(
                    origin = %origin,
                    certificate_id = %params.certificate_id,
                    "signed digest"
                );

                Ok(ResponseBody::Sign(SignResult {
                    signature_b64: B64.encode(out.signature),
                    certificate_id: params.certificate_id,
                    hash_alg: params.hash_alg,
                    certificate_der_b64: out.certificate_der.map(|d| B64.encode(d)),
                }))
            }
        }
    }
}
