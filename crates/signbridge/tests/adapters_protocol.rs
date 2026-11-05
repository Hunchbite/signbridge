//! Protocol-level tests for Web eID + AutoFirma adapters (SoftHSM when available).

use signbridge::adapters::{afirma, webeid, WireProtocol};
use signbridge::adapters::handle_wire;
use signbridge::protocol::{HashAlg, Request};
use signbridge::{AppConfig, AutoConfirm, SignService};
use serde_json::json;

fn mock_service() -> SignService<AutoConfirm> {
    // Empty module list — never touch SoftHSM here so the SoftHSM e2e can
    // C_Initialize with its own SOFTHSM2_CONF later in the same process.
    let mut cfg = AppConfig::for_cli();
    cfg.pkcs11_modules.clear();
    SignService::new(cfg, AutoConfirm { pin: None })
}

#[test]
fn webeid_unknown_command() {
    let svc = mock_service();
    let raw = br#"{"command":"nope","arguments":{}}"#;
    let v = webeid::handle(&svc, raw).unwrap();
    assert!(v.get("error").is_some());
}

#[test]
fn webeid_authenticate_rejects_short_nonce() {
    let svc = mock_service();
    let raw = serde_json::to_vec(&json!({
        "command": "authenticate",
        "arguments": {
            "challengeNonce": "tooshort",
            "origin": "https://example.com"
        }
    }))
    .unwrap();
    let v = webeid::handle(&svc, raw.as_slice()).unwrap();
    assert_eq!(
        v["error"]["code"],
        "invalid-argument"
    );
}

#[test]
fn afirma_echo() {
    let svc = mock_service();
    let raw = br#"{"id":"1","op":"echo"}"#;
    let v = afirma::handle(&svc, raw).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["protocol"], "afirma-hash-sign");
}

#[test]
fn wire_protocol_parse() {
    assert_eq!(WireProtocol::parse("webeid"), Some(WireProtocol::WebEid));
    assert_eq!(WireProtocol::parse("autofirma"), Some(WireProtocol::Afirma));
    assert_eq!(WireProtocol::parse("signbridge"), Some(WireProtocol::SignBridge));
    assert!(WireProtocol::parse("nope").is_none());
}

#[test]
fn doctor_via_native_protocol() {
    let svc = mock_service();
    let raw = br#"{"id":"d1","method":"doctor"}"#;
    let out = handle_wire(WireProtocol::SignBridge, &svc, raw).unwrap();
    assert_eq!(out["ok"], true);
    assert!(out["result"]["os"].is_string());
    assert!(out["result"]["hints"].is_array());
}

#[test]
fn webeid_auth_digest_matches_spec_shape() {
    let d = webeid::webeid_auth_digest(
        HashAlg::Sha256,
        b"https://ria.ee",
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 44 chars
    );
    assert_eq!(d.len(), 32);
}

/// SoftHSM end-to-end: afirma signHash + webeid sign when SoftHSM is installed.
#[test]
fn softhsm_adapters_sign_when_available() {
    use signbridge::OriginAllowlist;
    use std::sync::Arc;

    let Some(_) = signbridge::testing::find_softhsm_module() else {
        eprintln!("skip: SoftHSM not installed");
        return;
    };
    let _lock = signbridge::testing::lock_softhsm();
    let fixture = signbridge::testing::SoftHsmFixture::create().expect("create SoftHSM fixture");
    fixture.activate();

    let backend = Arc::new(fixture.backend());
    let cfg = AppConfig {
        allowlist: OriginAllowlist::hunchbite_defaults(),
        pkcs11_modules: vec![fixture.module.clone()],
        test_pin: Some(fixture.pin.clone()),
        skip_origin_check: true,
    };
    let svc = SignService::with_backend(
        cfg,
        backend,
        AutoConfirm {
            pin: Some(fixture.pin.clone()),
        },
    );

    let list = svc.handle(Request::ListCertificates {
        id: "1".into(),
        origin: "https://example.com".into(),
    });
    assert!(list.ok, "{list:?}");
    let certs = match list.result {
        Some(signbridge::protocol::ResponseBody::Certificates(c)) => c.certificates,
        _ => panic!("no certs"),
    };
    assert!(!certs.is_empty(), "expected SoftHSM key");
    let cert_id = &certs[0].id;

    // AutoFirma-compat signHash
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(b"adapter-e2e");
    let afirma_req = serde_json::to_vec(&json!({
        "id": "a1",
        "op": "signHash",
        "origin": "https://sede.example",
        "certificateId": cert_id,
        "hashAlg": "SHA-256",
        "digestHex": hex::encode(digest)
    }))
    .unwrap();
    let a = afirma::handle(&svc, &afirma_req).unwrap();
    assert_eq!(a["ok"], true, "{a}");
    assert!(a["signatureB64"].as_str().unwrap().len() > 20);

    // Web eID get-signing-certificate + sign
    let gc = webeid::handle(
        &svc,
        serde_json::to_vec(&json!({
            "command": "get-signing-certificate",
            "arguments": {"origin": "https://example.com"}
        }))
        .unwrap()
        .as_slice(),
    )
    .unwrap();
    let certificate = gc["certificate"].as_str().expect("certificate field");

    let sign = webeid::handle(
        &svc,
        serde_json::to_vec(&json!({
            "command": "sign",
            "arguments": {
                "origin": "https://example.com",
                "certificate": certificate,
                "hash": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    digest.as_slice()
                ),
                "hashFunction": "SHA-256"
            }
        }))
        .unwrap()
        .as_slice(),
    )
    .unwrap();
    assert!(sign.get("signature").is_some(), "{sign}");
    assert!(sign.get("error").is_none(), "{sign}");

    // Web eID authenticate
    let nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // 44
    let auth = webeid::handle(
        &svc,
        serde_json::to_vec(&json!({
            "command": "authenticate",
            "arguments": {
                "origin": "https://example.com",
                "challengeNonce": nonce
            }
        }))
        .unwrap()
        .as_slice(),
    )
    .unwrap();
    assert_eq!(auth["format"], "web-eid:1.0", "{auth}");
    assert!(auth["signature"].is_string(), "{auth}");
}
