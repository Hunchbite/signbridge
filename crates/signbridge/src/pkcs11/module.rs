//! PKCS#11 module loader, certificate/key enumeration, and digest signing.

use crate::backend::{CertificateBackend, SignOutput, SignParams};
use crate::error::{Error, Result};
use crate::pkcs11::digest_info::wrap_digest_info;
use crate::protocol::{CertificateInfo, HashAlg};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, CertificateType, KeyType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{debug, warn};

/// Parsed `pkcs11:…` certificate / key id.
#[derive(Debug, Clone)]
pub struct CertificateId {
    /// Module path.
    pub module: PathBuf,
    /// Slot id.
    pub slot_id: u64,
    /// Object label.
    pub label: String,
    /// Optional CKA_ID hint.
    pub cert_handle_hint: Option<String>,
}

impl CertificateId {
    /// Parse `pkcs11:module=…;slot=…;label=…`.
    pub fn parse(id: &str) -> Result<Self> {
        if !id.starts_with("pkcs11:") {
            return Err(Error::UnknownCertificate(id.into()));
        }
        let body = &id["pkcs11:".len()..];
        let mut map = HashMap::new();
        for part in body.split(';') {
            if let Some((k, v)) = part.split_once('=') {
                map.insert(k.to_string(), urlencoding_decode(v));
            }
        }
        let module = map
            .get("module")
            .cloned()
            .ok_or_else(|| Error::UnknownCertificate("missing module".into()))?;
        let slot_id = map
            .get("slot")
            .ok_or_else(|| Error::UnknownCertificate("missing slot".into()))?
            .parse::<u64>()
            .map_err(|_| Error::UnknownCertificate("bad slot".into()))?;
        let label = map
            .get("label")
            .cloned()
            .ok_or_else(|| Error::UnknownCertificate("missing label".into()))?;
        Ok(Self {
            module: PathBuf::from(module),
            slot_id,
            label,
            cert_handle_hint: map.get("id").cloned(),
        })
    }

    /// Format a stable id.
    pub fn format(module: &Path, slot_id: u64, label: &str) -> String {
        format!(
            "pkcs11:module={};slot={};label={}",
            urlencoding_encode(&module.display().to_string()),
            slot_id,
            urlencoding_encode(label)
        )
    }
}

/// PKCS#11 [`CertificateBackend`] over one or more modules.
pub struct Pkcs11Backend {
    modules: Vec<PathBuf>,
    contexts: Mutex<HashMap<PathBuf, Pkcs11>>,
}

impl Pkcs11Backend {
    /// Probe the given module paths (missing files are skipped at list time).
    pub fn new(modules: Vec<PathBuf>) -> Self {
        Self {
            modules,
            contexts: Mutex::new(HashMap::new()),
        }
    }

    /// Module paths this backend was constructed with.
    pub fn modules(&self) -> &[PathBuf] {
        &self.modules
    }

    fn context_for(&self, module: &Path) -> Result<Pkcs11> {
        let mut guard = self
            .contexts
            .lock()
            .map_err(|_| Error::Pkcs11("context lock poisoned".into()))?;
        if let Some(ctx) = guard.get(module) {
            return Ok(ctx.clone());
        }
        let pkcs11 = Pkcs11::new(module)
            .map_err(|e| Error::Pkcs11(format!("load {}: {e}", module.display())))?;
        match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) => {}
            // Same process / SoftHSM re-entry from fixtures and the host.
            Err(e) if format!("{e}").to_lowercase().contains("already") => {}
            Err(e) => {
                return Err(Error::Pkcs11(format!("init {}: {e}", module.display())));
            }
        }
        guard.insert(module.to_path_buf(), pkcs11.clone());
        Ok(pkcs11)
    }

    fn list_module(&self, module: &Path) -> Result<Vec<CertificateInfo>> {
        let pkcs11 = self.context_for(module)?;
        let slots = pkcs11
            .get_slots_with_token()
            .map_err(|e| Error::Pkcs11(e.to_string()))?;
        let mut out = Vec::new();

        for slot in slots {
            let slot_id = slot.id();
            let token_info = pkcs11.get_token_info(slot).ok();
            let token_label = token_info
                .as_ref()
                .map(|t| t.label().trim_end().to_string());

            // SoftHSM uninitialized tokens still appear; skip ones we can't open usefully.
            let session = match pkcs11.open_ro_session(slot) {
                Ok(s) => s,
                Err(e) => {
                    warn!(slot = slot_id, error = %e, "skip slot");
                    continue;
                }
            };

            let mut seen_labels = HashSet::new();

            // 1) Real X.509 certificates.
            if let Ok(cert_handles) = session.find_objects(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
            ]) {
                for handle in cert_handles {
                    let label = object_label(&session, handle)
                        .unwrap_or_else(|| format!("cert-{slot_id}"));
                    let value = object_value(&session, handle).unwrap_or_default();
                    let (subject, issuer, serial_hex) = parse_cert_summary(&value);
                    seen_labels.insert(label.clone());
                    out.push(CertificateInfo {
                        id: CertificateId::format(module, slot_id, &label),
                        subject,
                        issuer,
                        serial_hex,
                        not_before: None,
                        not_after: None,
                        backend: "pkcs11".into(),
                        token_label: token_label.clone(),
                        key_algo: key_type_for_id(&session, handle),
                    });
                }
            }

            // 2) Public keys (visible without login on SoftHSM) — stand in when no X.509.
            if let Ok(keys) = session.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY)]) {
                for handle in keys {
                    let label = match object_label(&session, handle) {
                        Some(l) if !l.is_empty() => l,
                        _ => continue,
                    };
                    if !seen_labels.insert(label.clone()) {
                        continue;
                    }
                    let algo = session
                        .get_attributes(handle, &[AttributeType::KeyType])
                        .ok()
                        .and_then(|attrs| {
                            attrs.into_iter().find_map(|a| match a {
                                Attribute::KeyType(t) => Some(format!("{t:?}")),
                                _ => None,
                            })
                        });
                    out.push(CertificateInfo {
                        id: CertificateId::format(module, slot_id, &label),
                        subject: format!("CN={label}"),
                        issuer: token_label
                            .clone()
                            .unwrap_or_else(|| "PKCS#11 token".into()),
                        serial_hex: hex::encode(label.as_bytes()),
                        not_before: None,
                        not_after: None,
                        backend: "pkcs11".into(),
                        token_label: token_label.clone(),
                        key_algo: algo,
                    });
                }
            }

            // 3) Private keys (needs login on many tokens; still useful after PIN).
            if let Ok(keys) = session.find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)]) {
                for handle in keys {
                    let label = match object_label(&session, handle) {
                        Some(l) if !l.is_empty() => l,
                        _ => continue,
                    };
                    if !seen_labels.insert(label.clone()) {
                        continue;
                    }
                    let algo = session
                        .get_attributes(handle, &[AttributeType::KeyType])
                        .ok()
                        .and_then(|attrs| {
                            attrs.into_iter().find_map(|a| match a {
                                Attribute::KeyType(t) => Some(format!("{t:?}")),
                                _ => None,
                            })
                        });
                    out.push(CertificateInfo {
                        id: CertificateId::format(module, slot_id, &label),
                        subject: format!("CN={label} (private)"),
                        issuer: token_label
                            .clone()
                            .unwrap_or_else(|| "PKCS#11 token".into()),
                        serial_hex: hex::encode(label.as_bytes()),
                        not_before: None,
                        not_after: None,
                        backend: "pkcs11".into(),
                        token_label: token_label.clone(),
                        key_algo: algo,
                    });
                }
            }
        }
        Ok(out)
    }

    fn sign_inner(&self, params: SignParams<'_>) -> Result<SignOutput> {
        let id = CertificateId::parse(params.certificate_id)?;
        let pkcs11 = self.context_for(&id.module)?;
        let slots = pkcs11
            .get_slots_with_token()
            .map_err(|e| Error::Pkcs11(e.to_string()))?;
        let slot = slots
            .into_iter()
            .find(|s| s.id() == id.slot_id)
            .ok_or_else(|| Error::UnknownCertificate(format!("slot {} gone", id.slot_id)))?;

        let session = pkcs11
            .open_rw_session(slot)
            .map_err(|e| Error::Pkcs11(e.to_string()))?;

        if let Some(pin) = params.pin {
            match session.login(UserType::User, Some(&AuthPin::new(pin.into()))) {
                Ok(()) => {}
                // SoftHSM / leaked contexts across tests: session already logged in.
                Err(e) if format!("{e}").to_lowercase().contains("already") => {}
                Err(e) => return Err(Error::Pkcs11(format!("login failed: {e}"))),
            }
        }

        let cert_der = session
            .find_objects(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::Label(id.label.as_bytes().to_vec()),
            ])
            .ok()
            .and_then(|certs| certs.first().copied())
            .and_then(|h| object_value(&session, h));

        let key = find_private_key(&session, &id.label)?;

        let key_type = session
            .get_attributes(key, &[AttributeType::KeyType])
            .ok()
            .and_then(|attrs| {
                attrs.into_iter().find_map(|a| match a {
                    Attribute::KeyType(t) => Some(t),
                    _ => None,
                })
            })
            .unwrap_or(KeyType::RSA);

        let (mechanism, payload) = match key_type {
            KeyType::RSA => (
                Mechanism::RsaPkcs,
                wrap_digest_info(params.hash_alg, params.digest),
            ),
            KeyType::EC => (Mechanism::Ecdsa, params.digest.to_vec()),
            other => {
                return Err(Error::Pkcs11(format!("unsupported key type: {other:?}")));
            }
        };

        debug!(
            label = %id.label,
            mechanism = ?mechanism,
            payload_len = payload.len(),
            hash = %params.hash_alg.as_str(),
            "signing digest on token"
        );

        let signature = session
            .sign(&mechanism, key, &payload)
            .map_err(|e| Error::Pkcs11(format!("sign failed: {e}")))?;

        let _ = session.logout();
        Ok(SignOutput {
            signature,
            certificate_der: cert_der,
        })
    }
}

impl Drop for Pkcs11Backend {
    fn drop(&mut self) {
        // SoftHSM 2 on macOS can SIGSEGV inside C_Finalize. A long-lived host
        // never needs finalize; the OS reclaims the module on process exit.
        if let Ok(mut guard) = self.contexts.lock() {
            for (_path, ctx) in guard.drain() {
                std::mem::forget(ctx);
            }
        }
    }
}

impl CertificateBackend for Pkcs11Backend {
    fn name(&self) -> &'static str {
        "pkcs11"
    }

    fn list_certificates(&self) -> Result<Vec<CertificateInfo>> {
        let mut out = Vec::new();
        for module in &self.modules {
            if !module.exists() {
                continue;
            }
            match self.list_module(module) {
                Ok(mut certs) => out.append(&mut certs),
                Err(e) => warn!(module = %module.display(), error = %e, "skipping PKCS#11 module"),
            }
        }
        Ok(out)
    }

    fn sign_digest(&self, params: SignParams<'_>) -> Result<SignOutput> {
        if !params.certificate_id.starts_with("pkcs11:") {
            return Err(Error::UnknownCertificate(params.certificate_id.into()));
        }
        self.sign_inner(params)
    }
}

fn find_private_key(
    session: &Session,
    label: &str,
) -> Result<cryptoki::object::ObjectHandle> {
    let keys = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .map_err(|e| Error::Pkcs11(e.to_string()))?;
    if let Some(k) = keys.first().copied() {
        return Ok(k);
    }

    // Fall back via certificate CKA_ID.
    let certs = session
        .find_objects(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .map_err(|e| Error::Pkcs11(e.to_string()))?;
    let cert_handle = *certs
        .first()
        .ok_or_else(|| Error::UnknownCertificate(label.into()))?;
    let cka_id = session
        .get_attributes(cert_handle, &[AttributeType::Id])
        .map_err(|e| Error::Pkcs11(e.to_string()))?
        .into_iter()
        .find_map(|a| match a {
            Attribute::Id(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| Error::Pkcs11("no private key for certificate".into()))?;
    let by_id = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(cka_id),
        ])
        .map_err(|e| Error::Pkcs11(e.to_string()))?;
    by_id
        .first()
        .copied()
        .ok_or_else(|| Error::Pkcs11("no private key for certificate".into()))
}

fn object_label(session: &Session, handle: cryptoki::object::ObjectHandle) -> Option<String> {
    session
        .get_attributes(handle, &[AttributeType::Label])
        .ok()?
        .into_iter()
        .find_map(|a| match a {
            Attribute::Label(bytes) => Some(String::from_utf8_lossy(&bytes).trim_end().to_string()),
            _ => None,
        })
}

fn object_value(session: &Session, handle: cryptoki::object::ObjectHandle) -> Option<Vec<u8>> {
    session
        .get_attributes(handle, &[AttributeType::Value])
        .ok()?
        .into_iter()
        .find_map(|a| match a {
            Attribute::Value(v) => Some(v),
            _ => None,
        })
}

fn key_type_for_id(session: &Session, cert_handle: cryptoki::object::ObjectHandle) -> Option<String> {
    let cka_id = session
        .get_attributes(cert_handle, &[AttributeType::Id])
        .ok()?
        .into_iter()
        .find_map(|a| match a {
            Attribute::Id(v) => Some(v),
            _ => None,
        })?;
    let keys = session
        .find_objects(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Id(cka_id),
        ])
        .ok()?;
    let key = *keys.first()?;
    session
        .get_attributes(key, &[AttributeType::KeyType])
        .ok()?
        .into_iter()
        .find_map(|a| match a {
            Attribute::KeyType(t) => Some(format!("{t:?}")),
            _ => None,
        })
}

fn parse_cert_summary(der: &[u8]) -> (String, String, String) {
    if der.is_empty() {
        return ("(unknown)".into(), "(unknown)".into(), String::new());
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(der);
    let fingerprint = hex::encode(h.finalize());
    (
        format!("X.509 cert sha256:{fingerprint}"),
        "(see certificate)".into(),
        fingerprint[..16.min(fingerprint.len())].to_string(),
    )
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn urlencoding_decode(s: &str) -> String {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// silence unused import in non-test builds if HashAlg only used via params
#[allow(dead_code)]
fn _hash_alg_link(h: HashAlg) -> &'static str {
    h.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_cert_id() {
        let id = CertificateId::format(
            Path::new("/opt/homebrew/lib/opensc-pkcs11.so"),
            0,
            "Signing key",
        );
        let parsed = CertificateId::parse(&id).unwrap();
        assert_eq!(parsed.slot_id, 0);
        assert_eq!(parsed.label, "Signing key");
        assert!(parsed.module.ends_with("opensc-pkcs11.so"));
    }
}
