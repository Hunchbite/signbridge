//! Protocol adapters for Web eID, AutoFirma-style hash sign, etc.

pub mod afirma;
pub mod webeid;

use crate::error::Result;
use crate::service::{ConfirmPrompt, SignService};
use serde_json::Value;

/// Which external protocol the RPC binary should speak on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WireProtocol {
    /// Native SignBridge JSON (`ping` / `listCertificates` / `signHash` / `doctor`).
    #[default]
    SignBridge,
    /// Web eID native-app messaging (`authenticate` / `get-signing-certificate` / `sign`).
    WebEid,
    /// AutoFirma-style hash-sign subset (`signHash` / `listCertificates` / `echo`).
    Afirma,
}

impl WireProtocol {
    /// Parse CLI / env value.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "signbridge" | "native" | "default" => Some(Self::SignBridge),
            "webeid" | "web-eid" | "web_eid" => Some(Self::WebEid),
            "afirma" | "autofirma" | "clienteafirma" => Some(Self::Afirma),
            _ => None,
        }
    }
}

/// Dispatch one raw JSON request according to [`WireProtocol`].
pub fn handle_wire<C: ConfirmPrompt>(
    protocol: WireProtocol,
    service: &SignService<C>,
    raw: &[u8],
) -> Result<Value> {
    match protocol {
        WireProtocol::SignBridge => {
            let out = crate::ipc::handle_bytes(service, raw);
            Ok(serde_json::from_slice(&out).unwrap_or_else(|_| {
                serde_json::json!({"ok":false,"error":{"code":"internal","message":"bad json"}})
            }))
        }
        WireProtocol::WebEid => webeid::handle(service, raw),
        WireProtocol::Afirma => afirma::handle(service, raw),
    }
}
