//! AutoFirma / @firma **hash-sign** subset → SignBridge.
//!
//! Full AutoFirma (afirma://, AutoScript, trifásica services) is the Spanish
//! government Java stack. Here we implement the client-side operation that
//! triphase integrators need: sign a precomputed digest with a local cert.
//!
//! Wire JSON (SignBridge afirma mode):
//! ```json
//! {"id":"1","op":"listCertificates"}
//! {"id":"2","op":"signHash","certificateId":"…","hashAlg":"SHA-256","digestHex":"…","origin":"https://sede.example"}
//! ```

use crate::error::{Error, Result};
use crate::protocol::{HashAlg, Request, ResponseBody, SignHashParams};
use crate::service::{ConfirmPrompt, SignService};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
struct AfirmaRequest {
    id: Option<String>,
    op: String,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default, rename = "certificateId")]
    certificate_id: Option<String>,
    #[serde(default, rename = "hashAlg")]
    hash_alg: Option<String>,
    #[serde(default, rename = "digestHex")]
    digest_hex: Option<String>,
    /// Some AutoFirma-style clients send raw base64 digest instead of hex.
    #[serde(default, rename = "digestB64")]
    digest_b64: Option<String>,
}

/// Handle one AutoFirma-compat JSON object.
pub fn handle<C: ConfirmPrompt>(service: &SignService<C>, raw: &[u8]) -> Result<Value> {
    let req: AfirmaRequest =
        serde_json::from_slice(raw).map_err(|e| Error::Protocol(e.to_string()))?;
    let id = req.id.clone().unwrap_or_else(|| "afirma".into());
    let origin = req
        .origin
        .clone()
        .unwrap_or_else(|| "https://afirma.local".into());

    match req.op.as_str() {
        "echo" | "ping" => Ok(json!({
            "id": id,
            "ok": true,
            "protocol": "afirma-hash-sign",
            "note": "Subset of AutoFirma client capabilities — not a full afirma:// desktop replacement"
        })),
        "listCertificates" => {
            let resp = service.handle(Request::ListCertificates {
                id: id.clone(),
                origin,
            });
            Ok(serde_json::to_value(resp).unwrap_or_else(|_| json!({"ok":false})))
        }
        "signHash" | "sign" => {
            let digest_hex = if let Some(h) = req.digest_hex.clone() {
                h
            } else if let Some(b64) = req.digest_b64.as_deref() {
                use base64::{engine::general_purpose::STANDARD as B64, Engine};
                let bytes = B64
                    .decode(b64)
                    .map_err(|e| Error::Protocol(format!("digestB64: {e}")))?;
                hex::encode(bytes)
            } else {
                return Ok(json!({
                    "id": id,
                    "ok": false,
                    "error": {"code": "protocol", "message": "digestHex or digestB64 required"}
                }));
            };
            let certificate_id = req.certificate_id.clone().ok_or_else(|| {
                Error::Protocol("certificateId required for signHash".into())
            })?;
            let hash_alg = match req.hash_alg.as_deref().unwrap_or("SHA-256") {
                "SHA-256" | "SHA256" => HashAlg::Sha256,
                "SHA-384" | "SHA384" => HashAlg::Sha384,
                "SHA-512" | "SHA512" => HashAlg::Sha512,
                other => {
                    return Ok(json!({
                        "id": id,
                        "ok": false,
                        "error": {"code": "protocol", "message": format!("bad hashAlg: {other}")}
                    }));
                }
            };
            let resp = service.handle(Request::SignHash {
                id: id.clone(),
                origin,
                params: SignHashParams {
                    certificate_id,
                    hash_alg,
                    digest_hex,
                    document_title: Some("AutoFirma-compat sign".into()),
                    document_id: None,
                },
            });
            // Map to a shape triphase-ish clients expect.
            if let Some(ResponseBody::Sign(s)) = &resp.result {
                Ok(json!({
                    "id": id,
                    "ok": true,
                    "signatureB64": s.signature_b64,
                    "certificateId": s.certificate_id,
                    "hashAlg": s.hash_alg.as_str(),
                    "format": "PKCS1",
                }))
            } else {
                Ok(serde_json::to_value(resp).unwrap_or_else(|_| json!({"ok":false})))
            }
        }
        other => Ok(json!({
            "id": id,
            "ok": false,
            "error": {
                "code": "unsupported",
                "message": format!("afirma adapter op '{other}' not implemented — use listCertificates|signHash")
            }
        })),
    }
}
