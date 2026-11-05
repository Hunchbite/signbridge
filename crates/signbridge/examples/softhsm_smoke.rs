//! Manual SoftHSM smoke: `cargo run -p signbridge --example softhsm_smoke --features testing`

use signbridge::backend::{CertificateBackend, SignParams};
use signbridge::protocol::HashAlg;
use signbridge::testing::SoftHsmFixture;
use sha2::{Digest, Sha256};

fn main() {
    let fixture = SoftHsmFixture::create().expect("fixture");
    fixture.activate();
    let backend = fixture.backend();
    let certs = backend.list_certificates().expect("list");
    let id = certs[0].id.clone();
    eprintln!("signing with {id}");
    let digest = Sha256::digest(b"smoke-document");
    let out = backend
        .sign_digest(SignParams {
            certificate_id: &id,
            hash_alg: HashAlg::Sha256,
            digest: &digest,
            pin: Some(&fixture.pin),
        })
        .expect("sign");
    eprintln!("signature {} bytes OK", out.signature.len());
}
