//! Ed25519 keys, key ids, keyrings and detached manifest signatures.

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::{Error, hex};

/// Domain-separation prefix: the signed message is this prefix followed by
/// the raw manifest bytes, so a pack signature can never be replayed as a
/// signature over anything else made with the same key.
pub const SIGNING_CONTEXT: &[u8] = b"rune-wordlist/v1 manifest\n";

/// Prefix of the one-line signature file (`pack.toml.sig`).
const SIGNATURE_PREFIX: &str = "ed25519:";

/// The id of a [`PublicKey`]: the first 8 bytes of SHA-256 over the key,
/// written as 16 hex digits. Manifests name their signing key by id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub [u8; 8]);

impl KeyId {
    /// Parses 16 lowercase hex digits.
    pub fn from_hex(text: &str) -> Result<Self, Error> {
        hex::decode(text, "key id").map(Self)
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

/// An Ed25519 public key that verifies pack signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// A key from its 32 bytes. Fails on bytes that are not a curve point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKey)
    }

    /// A key from 64 lowercase hex digits.
    pub fn from_hex(text: &str) -> Result<Self, Error> {
        Self::from_bytes(&hex::decode(text.trim(), "public key")?)
    }

    /// The key's 32 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The key as 64 lowercase hex digits.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    /// The key's [`KeyId`].
    #[must_use]
    pub fn id(&self) -> KeyId {
        let digest = Sha256::digest(self.0.as_bytes());
        let mut id = [0u8; 8];
        id.copy_from_slice(&digest[..8]);
        KeyId(id)
    }

    /// Checks `signature` over `manifest` (strict Ed25519 verification:
    /// non-canonical and small-order encodings are rejected).
    pub fn verify(&self, manifest: &[u8], signature: &Signature) -> Result<(), Error> {
        let sig = ed25519_dalek::Signature::from_bytes(&signature.0);
        self.0
            .verify_strict(&signed_message(manifest), &sig)
            .map_err(|_| Error::BadSignature)
    }
}

/// An Ed25519 secret key that signs pack manifests. Its bytes are wiped when
/// it is dropped.
pub struct SecretKey(SigningKey);

impl SecretKey {
    /// A key from its 32-byte seed. Draw the seed from a cryptographically
    /// secure random source.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// A key from a seed written as 64 lowercase hex digits.
    pub fn from_hex(text: &str) -> Result<Self, Error> {
        hex::decode(text.trim(), "secret key").map(|seed| Self::from_seed(&seed))
    }

    /// The seed as 64 lowercase hex digits, for storing the key.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    /// The matching public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Signs raw manifest bytes.
    #[must_use]
    pub fn sign(&self, manifest: &[u8]) -> Signature {
        Signature(self.0.sign(&signed_message(manifest)).to_bytes())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("public", &self.public_key().id())
            .finish_non_exhaustive()
    }
}

/// A detached Ed25519 signature over a manifest.
///
/// Its file form is one line: `ed25519:` followed by 128 lowercase hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    /// Parses the signature file's contents (surrounding whitespace allowed).
    pub fn parse(text: &str) -> Result<Self, Error> {
        let text = text.trim();
        let hex = text.strip_prefix(SIGNATURE_PREFIX).ok_or_else(|| {
            Error::SignatureFormat(format!(
                "expected a line starting with {SIGNATURE_PREFIX:?}"
            ))
        })?;
        hex::decode(hex, "signature").map(Self)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SIGNATURE_PREFIX}{}", hex::encode(&self.0))
    }
}

/// The public keys a loader trusts, looked up by [`KeyId`].
///
/// Keep the keyring in the application (compiled in or in its own
/// configuration), never inside the pack it verifies.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    keys: Vec<PublicKey>,
}

impl Keyring {
    /// An empty keyring, which trusts nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a trusted key (builder style).
    #[must_use]
    pub fn with_key(mut self, key: PublicKey) -> Self {
        self.add(key);
        self
    }

    /// Adds a trusted key. Adding the same key twice has no effect.
    pub fn add(&mut self, key: PublicKey) {
        if !self.keys.contains(&key) {
            self.keys.push(key);
        }
    }

    /// The trusted key with this id.
    #[must_use]
    pub fn get(&self, id: KeyId) -> Option<&PublicKey> {
        self.keys.iter().find(|k| k.id() == id)
    }

    /// Whether the keyring is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// The id of the trusted key that made `signature` over `manifest`, or
    /// [`Error::BadSignature`] if none of them did.
    pub fn signer_of(&self, manifest: &[u8], signature: &Signature) -> Result<KeyId, Error> {
        self.keys
            .iter()
            .find(|k| k.verify(manifest, signature).is_ok())
            .map(PublicKey::id)
            .ok_or(Error::BadSignature)
    }

    /// Checks that `signature` over `manifest` was made by the trusted key `id`.
    pub fn verify(&self, id: KeyId, manifest: &[u8], signature: &Signature) -> Result<(), Error> {
        self.get(id)
            .ok_or_else(|| Error::UnknownKey(id.to_string()))?
            .verify(manifest, signature)
    }
}

fn signed_message(manifest: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGNING_CONTEXT.len() + manifest.len());
    msg.extend_from_slice(SIGNING_CONTEXT);
    msg.extend_from_slice(manifest);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 section 7.1, TEST 1: the seed and its public key.
    const RFC8032_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC8032_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    #[test]
    fn rfc8032_key_derivation() {
        let secret = SecretKey::from_hex(RFC8032_SEED).unwrap();
        assert_eq!(secret.public_key().to_hex(), RFC8032_PUBLIC);
        assert_eq!(secret.to_hex(), RFC8032_SEED);
    }

    #[test]
    fn sign_verify_and_reject() {
        let secret = SecretKey::from_seed(&[7; 32]);
        let public = secret.public_key();
        let sig = secret.sign(b"name = \"x\"\n");
        public.verify(b"name = \"x\"\n", &sig).unwrap();
        assert!(matches!(
            public.verify(b"name = \"y\"\n", &sig),
            Err(Error::BadSignature)
        ));

        // The context prefix matters: a plain signature over the bytes fails.
        let raw = Signature(secret.0.sign(b"name = \"x\"\n").to_bytes());
        assert!(public.verify(b"name = \"x\"\n", &raw).is_err());
    }

    #[test]
    fn signature_file_round_trip() {
        let sig = SecretKey::from_seed(&[1; 32]).sign(b"m");
        let text = format!("{sig}\n");
        assert_eq!(Signature::parse(&text).unwrap(), sig);
        assert!(Signature::parse("deadbeef").is_err());
        assert!(Signature::parse("ed25519:00").is_err());
    }

    #[test]
    fn keyring_lookup() {
        let a = SecretKey::from_seed(&[1; 32]).public_key();
        let b = SecretKey::from_seed(&[2; 32]).public_key();
        let ring = Keyring::new().with_key(a).with_key(a);
        assert_eq!(ring.get(a.id()), Some(&a));
        assert_eq!(ring.get(b.id()), None);
        assert_eq!(KeyId::from_hex(&a.id().to_string()).unwrap(), a.id());
    }
}
