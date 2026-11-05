//! Web eID native application messaging API → SignBridge.
//!
//! Spec (web-eid-system-architecture-doc + web-eid-app):
//! - `authenticate` — sign `hash(hash(origin)||hash(challengeNonce))`
//! - `get-signing-certificate` — return base64 X.509 DER
//! - `sign` — sign a precomputed document hash with the matching cert
//!
//! Origin + challengeNonce must be present on authenticate/sign; messages ≤ 8 KiB.

use crate::error::{Error, Result};
use crate::protocol::{CertificateInfo, HashAlg, Request, ResponseBody, SignHashParams};
use crate::service::{ConfirmPrompt, SignService};
use crate::{NAME, VERSION};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};

#[derive(Debug, Deserialize)]
struct NativeRequest {
    command: String,
    #[serde(default)]
    arguments: Value,
}

/// Handle one Web eID native-messaging JSON object.
pub fn handle<C: ConfirmPrompt>(service: &SignService<C>, raw: &[u8]) -> Result<Value> {
    if raw.len() > 8192 {
        return Ok(json!({
            "error": {"code": "invalid-argument", "message": "message exceeds 8 KiB"}
        }));
    }
    let req: NativeRequest =
        serde_json::from_slice(raw).map_err(|e| Error::Protocol(e.to_string()))?;

    match req.command.as_str() {
        "version" | "status" => Ok(json!({
            "version": VERSION,
            "name": NAME,
            "protocol": "webeid-compat"
        })),
        "get-signing-certificate" => get_signing_certificate(service, &req.arguments),
        "sign" => sign(service, &req.arguments),
        "authenticate" => authenticate(service, &req.arguments),
        other => Ok(json!({
            "error": {
                "code": "unknown-command",
                "message": format!("unsupported Web eID command: {other}")
            }
        })),
    }
}

fn origin_of(args: &Value) -> Result<String> {
    args.get("origin")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Protocol("origin required".into()))
}

fn list_certs<C: ConfirmPrompt>(
    service: &SignService<C>,
    origin: &str,
) -> Result<Vec<CertificateInfo>> {
    let resp = service.handle(Request::ListCertificates {
        id: "webeid".into(),
        origin: origin.into(),
    });
    if !resp.ok {
        return Err(Error::Backend(
            resp.error
                .map(|e| e.message)
                .unwrap_or_else(|| "listCertificates failed".into()),
        ));
    }
    match resp.result {
        Some(ResponseBody::Certificates(c)) => Ok(c.certificates),
        _ => Ok(Vec::new()),
    }
}

fn get_signing_certificate<C: ConfirmPrompt>(
    service: &SignService<C>,
    args: &Value,
) -> Result<Value> {
    // Origin is optional for get-signing-certificate in some builds; default for allowlist.
    let origin = args
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("https://webeid.local");
    let certs = list_certs(service, origin)?;
    // Prefer a real X.509 DER; fall back to first key (SoftHSM without cert object).
    let cert = certs
        .iter()
        .find(|c| c.certificate_der_b64.is_some())
        .or_else(|| certs.first());
    let Some(cert) = cert else {
        return Ok(json!({
            "error": {"code": "no-certificates", "message": "no signing certificate available"}
        }));
    };
    let certificate = cert
        .certificate_der_b64
        .clone()
        .unwrap_or_else(|| B64.encode(cert.id.as_bytes()));
    let crypto = normalize_crypto(cert.key_algo.as_deref());
    Ok(json!({
        "certificate": certificate,
        "supportedSignatureAlgorithms": [{
            "cryptoAlgorithm": crypto,
            "hashFunction": "SHA-256",
            "paddingScheme": if crypto == "ECC" { "NONE" } else { "PKCS1.5" }
        },{
            "cryptoAlgorithm": crypto,
            "hashFunction": "SHA-384",
            "paddingScheme": if crypto == "ECC" { "NONE" } else { "PKCS1.5" }
        },{
            "cryptoAlgorithm": crypto,
            "hashFunction": "SHA-512",
            "paddingScheme": if crypto == "ECC" { "NONE" } else { "PKCS1.5" }
        }]
    }))
}

fn sign<C: ConfirmPrompt>(service: &SignService<C>, args: &Value) -> Result<Value> {
    let origin = origin_of(args)?;
    let hash_b64 = args
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Protocol("sign requires arguments.hash".into()))?;
    let hash_fn = args
        .get("hashFunction")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Protocol("sign requires arguments.hashFunction".into()))?;
    let cert_b64 = args
        .get("certificate")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Protocol("sign requires arguments.certificate".into()))?;

    let digest = B64
        .decode(hash_b64)
        .map_err(|e| Error::Protocol(format!("hash base64: {e}")))?;
    let hash_alg = parse_hash_fn(hash_fn)?;
    if digest.len() != hash_alg.digest_len() {
        return Ok(json!({
            "error": {
                "code": "invalid-argument",
                "message": format!(
                    "{} hash must be {} bytes, got {}",
                    hash_fn,
                    hash_alg.digest_len(),
                    digest.len()
                )
            }
        }));
    }

    let certs = list_certs(service, &origin)?;
    let certificate_id = match_certificate(&certs, cert_b64).ok_or_else(|| {
        Error::UnknownCertificate("signing certificate mismatch with available tokens".into())
    })?;

    let crypto = certs
        .iter()
        .find(|c| c.id == certificate_id)
        .and_then(|c| c.key_algo.clone())
        .map(|a| normalize_crypto(Some(&a)))
        .unwrap_or_else(|| "RSA".into());

    let resp = service.handle(Request::SignHash {
        id: "webeid-sign".into(),
        origin,
        params: SignHashParams {
            certificate_id,
            hash_alg,
            digest_hex: hex::encode(&digest),
            document_title: Some("Web eID sign".into()),
            document_id: None,
        },
    });
    if !resp.ok {
        return Ok(error_from_response(&resp));
    }
    let Some(ResponseBody::Sign(s)) = resp.result else {
        return Ok(json!({"error":{"code":"internal","message":"no signature"}}));
    };
    Ok(json!({
        "signature": s.signature_b64,
        "signatureAlgorithm": {
            "cryptoAlgorithm": crypto,
            "hashFunction": hash_fn,
            "paddingScheme": if crypto == "ECC" { "NONE" } else { "PKCS1.5" }
        }
    }))
}

fn authenticate<C: ConfirmPrompt>(service: &SignService<C>, args: &Value) -> Result<Value> {
    let origin = origin_of(args)?;
    let nonce = args
        .get("challengeNonce")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Protocol("authenticate requires challengeNonce".into()))?;
    if nonce.len() < 44 {
        return Ok(json!({
            "error": {"code": "invalid-argument", "message": "challengeNonce too short (min 44)"}
        }));
    }
    if nonce.len() > 128 {
        return Ok(json!({
            "error": {"code": "invalid-argument", "message": "challengeNonce too long (max 128)"}
        }));
    }

    // Official Web eID: hashToBeSigned = hash(hash(origin) || hash(challengeNonce)).
    // Origin must be ASCII serialization (https://host[:port]). We take the string as given.
    let hash_alg = HashAlg::Sha256;
    let digest = webeid_auth_digest(hash_alg, origin.as_bytes(), nonce.as_bytes());

    let certs = list_certs(service, &origin)?;
    let cert = certs
        .iter()
        .find(|c| c.certificate_der_b64.is_some())
        .or_else(|| certs.first());
    let Some(cert) = cert else {
        return Ok(json!({
            "error": {"code": "no-certificates", "message": "no certificate for authenticate"}
        }));
    };
    let unverified = cert
        .certificate_der_b64
        .clone()
        .unwrap_or_else(|| B64.encode(cert.id.as_bytes()));
    let algo = match normalize_crypto(cert.key_algo.as_deref()).as_str() {
        "ECC" => "ES256",
        _ => "RS256",
    };

    let resp = service.handle(Request::SignHash {
        id: "webeid-auth".into(),
        origin: origin.clone(),
        params: SignHashParams {
            certificate_id: cert.id.clone(),
            hash_alg,
            digest_hex: hex::encode(digest),
            document_title: Some("Web eID authenticate".into()),
            document_id: None,
        },
    });
    if !resp.ok {
        return Ok(error_from_response(&resp));
    }
    let Some(ResponseBody::Sign(s)) = resp.result else {
        return Ok(json!({"error":{"code":"internal","message":"no signature"}}));
    };

    Ok(json!({
        "unverifiedCertificate": unverified,
        "algorithm": algo,
        "signature": s.signature_b64,
        "format": "web-eid:1.0",
        "appVersion": format!("https://github.com/Hunchbite/signbridge/releases/v{VERSION}")
    }))
}

/// `hash(hash(origin) || hash(challenge))` as implemented by web-eid-app authenticate.cpp.
pub fn webeid_auth_digest(alg: HashAlg, origin: &[u8], challenge: &[u8]) -> Vec<u8> {
    let origin_hash = digest_bytes(alg, origin);
    let challenge_hash = digest_bytes(alg, challenge);
    let mut concat = origin_hash;
    concat.extend_from_slice(&challenge_hash);
    digest_bytes(alg, &concat)
}

fn digest_bytes(alg: HashAlg, data: &[u8]) -> Vec<u8> {
    match alg {
        HashAlg::Sha256 => Sha256::digest(data).to_vec(),
        HashAlg::Sha384 => Sha384::digest(data).to_vec(),
        HashAlg::Sha512 => Sha512::digest(data).to_vec(),
    }
}

fn match_certificate(certs: &[CertificateInfo], cert_b64: &str) -> Option<String> {
    let der = B64.decode(cert_b64).ok();
    for c in certs {
        if let Some(ref stored) = c.certificate_der_b64 {
            if stored == cert_b64 {
                return Some(c.id.clone());
            }
            if let (Some(ref der), Ok(stored_der)) = (&der, B64.decode(stored)) {
                if *der == stored_der {
                    return Some(c.id.clone());
                }
            }
        }
        // SoftHSM / no X.509: allow opaque id encoded as base64, or raw id string.
        if let Ok(bytes) = B64.decode(cert_b64) {
            if let Ok(id) = String::from_utf8(bytes) {
                if id == c.id {
                    return Some(c.id.clone());
                }
            }
        }
        if cert_b64 == c.id {
            return Some(c.id.clone());
        }
    }
    None
}

fn normalize_crypto(algo: Option<&str>) -> String {
    match algo.map(|s| s.to_ascii_uppercase()) {
        Some(s) if s.contains("EC") => "ECC".into(),
        _ => "RSA".into(),
    }
}

fn parse_hash_fn(s: &str) -> Result<HashAlg> {
    match s.to_ascii_uppercase().as_str() {
        "SHA-256" | "SHA256" | "SHA2-256" => Ok(HashAlg::Sha256),
        "SHA-384" | "SHA384" => Ok(HashAlg::Sha384),
        "SHA-512" | "SHA512" => Ok(HashAlg::Sha512),
        other => Err(Error::Protocol(format!("unsupported hashFunction: {other}"))),
    }
}

fn error_from_response(resp: &crate::protocol::Response) -> Value {
    let (code, message) = resp
        .error
        .as_ref()
        .map(|e| (e.code.clone(), e.message.clone()))
        .unwrap_or_else(|| ("internal".into(), "unknown".into()));
    json!({"error": {"code": code, "message": message}})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_digest_is_32_bytes_sha256() {
        let d = webeid_auth_digest(HashAlg::Sha256, b"https://ria.ee", b"a".repeat(44).as_slice());
        assert_eq!(d.len(), 32);
    }

    #[test]
    fn auth_digest_field_separation() {
        // hash(a)+hash(b) ≠ hash(a||b) style — changing split changes digest.
        let a = webeid_auth_digest(HashAlg::Sha256, b"https://a.example", b"nonce-AAAAAAAAAAAAAAAAAAAAAAAAAA");
        let b = webeid_auth_digest(HashAlg::Sha256, b"https://b.example", b"nonce-AAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert_ne!(a, b);
    }
}
