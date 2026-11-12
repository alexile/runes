//! Optional signatures over record hashes.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::Digest;

/// Signs record hashes and checks those signatures.
///
/// A hash chain alone shows that records were not changed *after*
/// another record was appended to them; anyone who can rewrite the
/// whole file can recompute every hash. A signature with a key the
/// writer of the file does not hold closes that gap. [`HmacSha256`] is
/// built in; implement this trait for asymmetric schemes (Ed25519, an
/// HSM, a KMS) so verifiers need no secret.
pub trait Signer {
    /// The signature over `hash`.
    fn sign(&self, hash: &Digest) -> Vec<u8>;

    /// Whether `signature` is valid for `hash`. Compare in constant time.
    fn verify(&self, hash: &Digest, signature: &[u8]) -> bool;
}

/// HMAC-SHA256 ([RFC 2104]) over the record hash with a shared key.
///
/// [RFC 2104]: https://www.rfc-editor.org/rfc/rfc2104
///
/// ```
/// use rune_audit_log::{Digest, HmacSha256, Signer};
///
/// let signer = HmacSha256::new(b"a key from your secret store");
/// let sig = signer.sign(&Digest::GENESIS);
/// assert_eq!(sig.len(), 32);
/// assert!(signer.verify(&Digest::GENESIS, &sig));
/// assert!(!HmacSha256::new(b"another key").verify(&Digest::GENESIS, &sig));
/// ```
#[derive(Clone)]
pub struct HmacSha256 {
    key: Vec<u8>,
}

impl HmacSha256 {
    /// A signer with `key`. Use at least 32 random bytes.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    fn mac(&self, hash: &Digest) -> Vec<u8> {
        // HMAC accepts keys of any length, so this cannot fail.
        <Hmac<Sha256> as Mac>::new_from_slice(&self.key).map_or_else(
            |_| Vec::new(),
            |mut mac| {
                mac.update(hash.as_bytes());
                mac.finalize().into_bytes().to_vec()
            },
        )
    }
}

impl std::fmt::Debug for HmacSha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HmacSha256 { key: <redacted> }")
    }
}

impl Signer for HmacSha256 {
    fn sign(&self, hash: &Digest) -> Vec<u8> {
        self.mac(hash)
    }

    fn verify(&self, hash: &Digest, signature: &[u8]) -> bool {
        let expected = self.mac(hash);
        !expected.is_empty() && bool::from(expected.as_slice().ct_eq(signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signature is plain HMAC-SHA256 over the 32 hash bytes.
    #[test]
    fn matches_hmac_sha256() {
        let signer = HmacSha256::new(b"Jefe");
        let digest = Digest([7; 32]);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"Jefe").unwrap();
        mac.update(&[7; 32]);
        assert_eq!(signer.sign(&digest), mac.finalize().into_bytes().to_vec());
        assert!(!signer.verify(&digest, &[]));
        assert!(!format!("{signer:?}").contains("Jefe"));
    }
}
