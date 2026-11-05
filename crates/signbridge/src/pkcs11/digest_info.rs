//! PKCS#1 DigestInfo wrappers for pre-hashed RSA signatures.

use crate::protocol::HashAlg;

/// Build a PKCS#1 DigestInfo structure for `CKM_RSA_PKCS` when the caller
/// already hashed the document. The token must never see the full PDF.
pub fn wrap_digest_info(hash_alg: HashAlg, digest: &[u8]) -> Vec<u8> {
    // DER prefixes from RFC 8017 Appendix A.2.4 / PKCS#1 v2.2.
    let prefix: &[u8] = match hash_alg {
        HashAlg::Sha256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        HashAlg::Sha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        HashAlg::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
    };
    let mut out = Vec::with_capacity(prefix.len() + digest.len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_digest_info_length() {
        let d = vec![0u8; 32];
        let info = wrap_digest_info(HashAlg::Sha256, &d);
        assert_eq!(info.len(), 19 + 32);
        assert_eq!(&info[19..], d.as_slice());
    }
}
