//! Synthetic end-to-end against SoftHSM (one test = one C_Initialize lifetime).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha2::{Digest, Sha256};
use signbridge::backend::{CertificateBackend, SignParams};
use signbridge::protocol::{HashAlg, Request, ResponseBody, SignHashParams};
use signbridge::testing::{lock_softhsm, SoftHsmFixture};
use signbridge::{AppConfig, AutoConfirm, OriginAllowlist, SignService};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;

#[test]
fn softhsm_framework_e2e() {
    let Some(_) = signbridge::testing::find_softhsm_module() else {
        eprintln!("skipping: SoftHSM not installed");
        return;
    };
    let _lock = lock_softhsm();

    let fixture = SoftHsmFixture::create().expect("create SoftHSM fixture");
    fixture.activate();

    // --- direct backend API (what embedders call) ---
    let backend = Arc::new(fixture.backend());
    let certs = backend.list_certificates().expect("list");
    assert!(!certs.is_empty(), "expected synthetic key");
    let cert_id = certs
        .iter()
        .find(|c| c.id.contains("SyntheticSigner"))
        .map(|c| c.id.clone())
        .unwrap_or_else(|| fixture.certificate_id());
    eprintln!("identity: {cert_id}");

    let document = b"VELOCITY-NOV-1 synthetic novation agreement body";
    let digest = Sha256::digest(document);
    let out = backend
        .sign_digest(SignParams {
            certificate_id: &cert_id,
            hash_alg: HashAlg::Sha256,
            digest: &digest,
            pin: Some(&fixture.pin),
        })
        .expect("backend sign");
    assert_eq!(out.signature.len(), 256);
    eprintln!("backend sign OK");

    // --- SignService protocol API (what CLI / host call) ---
    let config = AppConfig {
        allowlist: OriginAllowlist::hunchbite_defaults(),
        pkcs11_modules: vec![fixture.module.clone()],
        test_pin: Some(fixture.pin.clone()),
        skip_origin_check: false,
    };
    let service = SignService::with_backend(
        config,
        backend,
        AutoConfirm {
            pin: Some(fixture.pin.clone()),
        },
    );

    let ping = service.handle(Request::Ping { id: "0".into() });
    assert!(ping.ok);

    let list = service.handle(Request::ListCertificates {
        id: "1".into(),
        origin: "https://sign.hunchbite.com".into(),
    });
    assert!(list.ok, "{:?}", list.error);

    let sign = service.handle(Request::SignHash {
        id: "2".into(),
        origin: "https://sign.hunchbite.com".into(),
        params: SignHashParams {
            certificate_id: cert_id.clone(),
            hash_alg: HashAlg::Sha256,
            digest_hex: hex::encode(digest),
            document_title: Some("Synthetic Novation".into()),
            document_id: Some("doc_synth_1".into()),
        },
    });
    assert!(sign.ok, "sign failed: {:?}", sign.error);
    let result = match sign.result {
        Some(ResponseBody::Sign(s)) => s,
        other => panic!("unexpected: {other:?}"),
    };
    let signature = B64.decode(&result.signature_b64).expect("b64");
    assert_eq!(signature.len(), 256);
    eprintln!("service signHash OK");

    let denied = service.handle(Request::ListCertificates {
        id: "3".into(),
        origin: "https://evil.example".into(),
    });
    assert!(!denied.ok);
    assert_eq!(denied.error.as_ref().unwrap().code, "origin_denied");

    let bad = service.handle(Request::SignHash {
        id: "4".into(),
        origin: "https://sign.hunchbite.com".into(),
        params: SignHashParams {
            certificate_id: cert_id,
            hash_alg: HashAlg::Sha256,
            digest_hex: "ab".repeat(1000),
            document_title: None,
            document_id: None,
        },
    });
    assert!(!bad.ok);
    assert_eq!(bad.error.as_ref().unwrap().code, "bad_digest");

    // --- openssl verifies the service signature against the pre-exported pubkey ---
    let sig_path = fixture.conf().parent().unwrap().join("sig.bin");
    std::fs::write(&sig_path, &signature).unwrap();
    let mut child = Command::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-verify",
            fixture.public_pem.to_str().unwrap(),
            "-signature",
            sig_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openssl");
    child.stdin.as_mut().unwrap().write_all(document).unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("Verified OK"),
        "openssl verify failed: status={} stdout={stdout} stderr={stderr}",
        out.status
    );
    eprintln!("openssl Verified OK — synthetic e2e passed");
}
