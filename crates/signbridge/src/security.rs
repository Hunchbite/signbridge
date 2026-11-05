//! Digest-only gates — the hard line between a fingerprint and a document.

use crate::error::{Error, Result};
use crate::protocol::HashAlg;

/// Reject anything that is not a fixed-length digest for the declared hash algorithm.
/// This stops a page (or buggy client) from shipping a full PDF to the token.
pub fn validate_digest(hash_alg: HashAlg, digest_hex: &str) -> Result<Vec<u8>> {
    let hex = digest_hex.trim();
    if hex.is_empty() {
        return Err(Error::BadDigest("empty digest".into()));
    }
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::BadDigest("digest must be hex".into()));
    }
    if hex.len() % 2 != 0 {
        return Err(Error::BadDigest("digest hex length must be even".into()));
    }

    let bytes = hex::decode(hex).map_err(|e| Error::BadDigest(e.to_string()))?;
    let expected = hash_alg.digest_len();
    if bytes.len() != expected {
        return Err(Error::BadDigest(format!(
            "{} digest must be {} bytes, got {}",
            hash_alg.as_str(),
            expected,
            bytes.len()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_sha256() {
        let hex = "a".repeat(64);
        assert_eq!(validate_digest(HashAlg::Sha256, &hex).unwrap().len(), 32);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(matches!(
            validate_digest(HashAlg::Sha256, "abcd"),
            Err(Error::BadDigest(_))
        ));
    }

    #[test]
    fn rejects_non_hex() {
        assert!(matches!(
            validate_digest(HashAlg::Sha256, &("zz".repeat(32))),
            Err(Error::BadDigest(_))
        ));
    }
}
