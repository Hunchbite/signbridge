//! JSON protocol shared by the CLI, native-messaging host, and future HTTP adapters.
//!
//! Apps may use [`SignService`](crate::SignService) directly in Rust and skip JSON;
//! this module is the stable wire format for out-of-process UIs.

use serde::{Deserialize, Serialize};

/// Supported digest algorithms for `signHash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HashAlg {
    /// SHA-256 (32-byte digest).
    #[serde(rename = "SHA-256", alias = "SHA256")]
    Sha256,
    /// SHA-384 (48-byte digest).
    #[serde(rename = "SHA-384", alias = "SHA384")]
    Sha384,
    /// SHA-512 (64-byte digest).
    #[serde(rename = "SHA-512", alias = "SHA512")]
    Sha512,
}

impl HashAlg {
    /// Expected digest length in bytes.
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Canonical name (`SHA-256`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }
}

/// Inbound request from a UI / extension / CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "camelCase")]
pub enum Request {
    /// Liveness / version probe.
    #[serde(rename = "ping")]
    Ping {
        /// Correlation id.
        id: String,
    },

    /// List certificates / keys visible to the backend.
    #[serde(rename = "listCertificates")]
    ListCertificates {
        /// Correlation id.
        id: String,
        /// Page origin (checked against the allowlist unless skipped).
        origin: String,
    },

    /// Sign a document fingerprint.
    #[serde(rename = "signHash")]
    SignHash {
        /// Correlation id.
        id: String,
        /// Page origin.
        origin: String,
        /// Sign parameters.
        params: SignHashParams,
    },
}

impl Request {
    /// Correlation id.
    pub fn id(&self) -> &str {
        match self {
            Self::Ping { id }
            | Self::ListCertificates { id, .. }
            | Self::SignHash { id, .. } => id,
        }
    }

    /// Origin when present.
    pub fn origin(&self) -> Option<&str> {
        match self {
            Self::Ping { .. } => None,
            Self::ListCertificates { origin, .. } | Self::SignHash { origin, .. } => {
                Some(origin.as_str())
            }
        }
    }
}

/// Body of `signHash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignHashParams {
    /// Backend certificate / key id.
    pub certificate_id: String,
    /// Hash algorithm.
    pub hash_alg: HashAlg,
    /// Hex-encoded digest only — never a full document.
    pub digest_hex: String,
    /// Human-readable document title for the confirm dialog.
    pub document_title: Option<String>,
    /// Optional document id for audit logs.
    pub document_id: Option<String>,
}

/// One signable identity returned by `listCertificates`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    /// Stable id for `signHash`.
    pub id: String,
    /// Subject / display name.
    pub subject: String,
    /// Issuer display name.
    pub issuer: String,
    /// Serial or fingerprint fragment.
    pub serial_hex: String,
    /// Not-before instant when known.
    pub not_before: Option<String>,
    /// Not-after instant when known.
    pub not_after: Option<String>,
    /// Backend name (`pkcs11`, …).
    pub backend: String,
    /// Token / store label.
    pub token_label: Option<String>,
    /// Key algorithm hint (`RSA`, `EC`, …).
    pub key_algo: Option<String>,
}

/// Successful `signHash` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResult {
    /// Base64 signature.
    pub signature_b64: String,
    /// Certificate / key id used.
    pub certificate_id: String,
    /// Hash algorithm.
    pub hash_alg: HashAlg,
    /// Base64 DER leaf certificate when available.
    pub certificate_der_b64: Option<String>,
}

/// Successful response bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseBody {
    /// `ping` result.
    Ping(PingResult),
    /// `listCertificates` result.
    Certificates(ListCertificatesResult),
    /// `signHash` result.
    Sign(SignResult),
}

/// `ping` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PingResult {
    /// Product name.
    pub name: String,
    /// Semver.
    pub version: String,
}

/// `listCertificates` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListCertificatesResult {
    /// Identities.
    pub certificates: Vec<CertificateInfo>,
}

/// Error payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorBody {
    /// Stable code.
    pub code: String,
    /// Human message.
    pub message: String,
}

/// Outbound response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    /// Correlation id.
    pub id: String,
    /// Success flag.
    pub ok: bool,
    /// Result when `ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ResponseBody>,
    /// Error when not `ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    /// Build a success response.
    pub fn ok(id: impl Into<String>, result: ResponseBody) -> Self {
        Self {
            id: id.into(),
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response.
    pub fn err(id: impl Into<String>, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ok: false,
            result: None,
            error: Some(ErrorBody {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sign_hash() {
        let raw = r#"{
            "id": "3",
            "method": "signHash",
            "origin": "https://sign.hunchbite.com",
            "params": {
                "certificateId": "pkcs11:slot=0;label=key",
                "hashAlg": "SHA-256",
                "digestHex": "aabb"
            }
        }"#;
        let req: Request = serde_json::from_str(raw).unwrap();
        match req {
            Request::SignHash { params, .. } => {
                assert_eq!(params.hash_alg, HashAlg::Sha256);
            }
            _ => panic!("wrong variant"),
        }
    }
}
