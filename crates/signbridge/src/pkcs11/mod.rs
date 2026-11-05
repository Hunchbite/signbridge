//! PKCS#11 backend — USB tokens, SoftHSM, OpenSC, vendor modules.
//!
//! This is one [`CertificateBackend`](crate::CertificateBackend). Apps depend on
//! the trait; they should not need to import this module unless configuring modules.

mod digest_info;
mod module;

pub use digest_info::wrap_digest_info;
pub use module::{CertificateId, Pkcs11Backend};
