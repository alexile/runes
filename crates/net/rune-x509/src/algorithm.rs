//! Typed public-key and signature algorithms.

use std::fmt;

/// A hash function named by a signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// MD2: broken.
    Md2,
    /// MD4: broken.
    Md4,
    /// MD5: broken (chosen-prefix collisions, RFC 6151).
    Md5,
    /// SHA-1: broken for certificate signatures (`SHAttered`; CA/B Forum
    /// ballot 118 retired it in 2016).
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Whether the hash is too weak for certificate signatures: MD2, MD4,
    /// MD5 and SHA-1.
    #[must_use]
    pub const fn is_weak(self) -> bool {
        matches!(self, Self::Md2 | Self::Md4 | Self::Md5 | Self::Sha1)
    }

    /// The conventional name (`SHA-256`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Md2 => "MD2",
            Self::Md4 => "MD4",
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    pub(crate) fn from_digest_oid(oid: &str) -> Option<Self> {
        Some(match oid {
            "1.2.840.113549.2.2" => Self::Md2,
            "1.2.840.113549.2.4" => Self::Md4,
            "1.2.840.113549.2.5" => Self::Md5,
            "1.3.14.3.2.26" => Self::Sha1,
            "2.16.840.1.101.3.4.2.4" => Self::Sha224,
            "2.16.840.1.101.3.4.2.1" => Self::Sha256,
            "2.16.840.1.101.3.4.2.2" => Self::Sha384,
            "2.16.840.1.101.3.4.2.3" => Self::Sha512,
            _ => return None,
        })
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The algorithm a certificate is signed with (its outer
/// `signatureAlgorithm`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// RSA PKCS #1 v1.5 (`sha256WithRSAEncryption` and friends).
    RsaPkcs1(HashAlgorithm),
    /// RSASSA-PSS. The hash comes from the parameters; `None` when they
    /// are absent or unreadable (the RFC 4055 default is SHA-1).
    RsaPss(Option<HashAlgorithm>),
    /// ECDSA.
    Ecdsa(HashAlgorithm),
    /// DSA.
    Dsa(HashAlgorithm),
    /// Ed25519 (RFC 8410).
    Ed25519,
    /// Ed448 (RFC 8410).
    Ed448,
    /// Anything else, by dotted OID.
    Other(String),
}

impl SignatureAlgorithm {
    /// The hash the signature is computed over, when the algorithm names
    /// one. `EdDSA` hashes internally and returns `None`.
    #[must_use]
    pub const fn hash(&self) -> Option<HashAlgorithm> {
        match self {
            Self::RsaPkcs1(hash) | Self::Ecdsa(hash) | Self::Dsa(hash) => Some(*hash),
            Self::RsaPss(hash) => *hash,
            Self::Ed25519 | Self::Ed448 | Self::Other(_) => None,
        }
    }

    /// Whether the signature relies on a weak hash (MD5, SHA-1, ...).
    /// RSASSA-PSS with unreadable parameters counts as weak, since the
    /// RFC 4055 default hash is SHA-1.
    #[must_use]
    pub fn is_weak(&self) -> bool {
        match self {
            Self::RsaPss(None) => true,
            other => other.hash().is_some_and(HashAlgorithm::is_weak),
        }
    }

    /// Classifies a `signatureAlgorithm` OID and, for RSASSA-PSS, the hash
    /// named in its parameters.
    pub(crate) fn from_oid(oid: &str, pss_hash: Option<&str>) -> Self {
        use HashAlgorithm::{Md2, Md4, Md5, Sha1, Sha224, Sha256, Sha384, Sha512};
        match oid {
            "1.2.840.113549.1.1.2" => Self::RsaPkcs1(Md2),
            "1.2.840.113549.1.1.3" => Self::RsaPkcs1(Md4),
            "1.2.840.113549.1.1.4" => Self::RsaPkcs1(Md5),
            "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => Self::RsaPkcs1(Sha1),
            "1.2.840.113549.1.1.14" => Self::RsaPkcs1(Sha224),
            "1.2.840.113549.1.1.11" => Self::RsaPkcs1(Sha256),
            "1.2.840.113549.1.1.12" => Self::RsaPkcs1(Sha384),
            "1.2.840.113549.1.1.13" => Self::RsaPkcs1(Sha512),
            "1.2.840.113549.1.1.10" => {
                Self::RsaPss(pss_hash.and_then(HashAlgorithm::from_digest_oid))
            }
            "1.2.840.10045.4.1" => Self::Ecdsa(Sha1),
            "1.2.840.10045.4.3.1" => Self::Ecdsa(Sha224),
            "1.2.840.10045.4.3.2" => Self::Ecdsa(Sha256),
            "1.2.840.10045.4.3.3" => Self::Ecdsa(Sha384),
            "1.2.840.10045.4.3.4" => Self::Ecdsa(Sha512),
            "1.2.840.10040.4.3" => Self::Dsa(Sha1),
            "2.16.840.1.101.3.4.3.1" => Self::Dsa(Sha224),
            "2.16.840.1.101.3.4.3.2" => Self::Dsa(Sha256),
            "1.3.101.112" => Self::Ed25519,
            "1.3.101.113" => Self::Ed448,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RsaPkcs1(hash) => write!(f, "RSA PKCS#1 v1.5 with {hash}"),
            Self::RsaPss(Some(hash)) => write!(f, "RSA-PSS with {hash}"),
            Self::RsaPss(None) => f.write_str("RSA-PSS"),
            Self::Ecdsa(hash) => write!(f, "ECDSA with {hash}"),
            Self::Dsa(hash) => write!(f, "DSA with {hash}"),
            Self::Ed25519 => f.write_str("Ed25519"),
            Self::Ed448 => f.write_str("Ed448"),
            Self::Other(oid) => write!(f, "unknown ({oid})"),
        }
    }
}

/// A named elliptic curve.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Curve {
    /// NIST P-256 (`prime256v1`, `secp256r1`).
    P256,
    /// NIST P-384 (`secp384r1`).
    P384,
    /// NIST P-521 (`secp521r1`).
    P521,
    /// `secp256k1`.
    Secp256k1,
    /// Another curve, by dotted OID (or empty when the parameters are not
    /// a named curve).
    Other(String),
}

impl Curve {
    fn from_oid(oid: &str) -> Self {
        match oid {
            "1.2.840.10045.3.1.7" => Self::P256,
            "1.3.132.0.34" => Self::P384,
            "1.3.132.0.35" => Self::P521,
            "1.3.132.0.10" => Self::Secp256k1,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The curve's field size in bits, for known curves.
    #[must_use]
    pub const fn bits(&self) -> Option<u32> {
        match self {
            Self::P256 | Self::Secp256k1 => Some(256),
            Self::P384 => Some(384),
            Self::P521 => Some(521),
            Self::Other(_) => None,
        }
    }
}

impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::P256 => f.write_str("P-256"),
            Self::P384 => f.write_str("P-384"),
            Self::P521 => f.write_str("P-521"),
            Self::Secp256k1 => f.write_str("secp256k1"),
            Self::Other(oid) => write!(f, "curve {oid}"),
        }
    }
}

/// The subject public key: its type and strength.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PublicKeyInfo {
    /// RSA (`rsaEncryption` or `id-RSASSA-PSS`), with the modulus size.
    Rsa {
        /// Modulus length in bits.
        bits: u32,
    },
    /// An elliptic-curve key (`id-ecPublicKey`).
    Ec {
        /// The named curve.
        curve: Curve,
        /// Field size in bits: from the curve when it is known, else from
        /// the encoded point (0 when that is unreadable too).
        bits: u32,
    },
    /// Ed25519.
    Ed25519,
    /// Ed448.
    Ed448,
    /// DSA, with the size of the public value `y`.
    Dsa {
        /// Size of `y` in bits.
        bits: u32,
    },
    /// Anything else, by dotted algorithm OID.
    Other(String),
}

impl PublicKeyInfo {
    /// The key's size in bits, where it is meaningful: the RSA modulus,
    /// the EC field, 256 for Ed25519 and 456 for Ed448.
    #[must_use]
    pub const fn bits(&self) -> Option<u32> {
        match self {
            Self::Rsa { bits } | Self::Ec { bits, .. } | Self::Dsa { bits } => Some(*bits),
            Self::Ed25519 => Some(256),
            Self::Ed448 => Some(456),
            Self::Other(_) => None,
        }
    }

    pub(crate) fn from_spki(spki: &x509_parser::x509::SubjectPublicKeyInfo<'_>) -> Self {
        use x509_parser::public_key::PublicKey;
        let oid = spki.algorithm.algorithm.to_id_string();
        match oid.as_str() {
            "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => {
                let bits = match spki.parsed() {
                    Ok(PublicKey::RSA(rsa)) => integer_bits(rsa.modulus),
                    _ => 0,
                };
                Self::Rsa { bits }
            }
            "1.2.840.10045.2.1" => {
                let curve = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|any| any.as_oid().ok())
                    .map_or_else(
                        || Curve::Other(String::new()),
                        |oid| Curve::from_oid(&oid.to_id_string()),
                    );
                let bits = curve.bits().unwrap_or_else(|| match spki.parsed() {
                    Ok(PublicKey::EC(point)) => u32::try_from(point.key_size()).unwrap_or(0),
                    _ => 0,
                });
                Self::Ec { curve, bits }
            }
            "1.3.101.112" => Self::Ed25519,
            "1.3.101.113" => Self::Ed448,
            "1.2.840.10040.4.1" => {
                let bits = match spki.parsed() {
                    Ok(PublicKey::DSA(y)) => integer_bits(y),
                    _ => 0,
                };
                Self::Dsa { bits }
            }
            _ => Self::Other(oid),
        }
    }
}

impl fmt::Display for PublicKeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa { bits } => write!(f, "RSA {bits}"),
            Self::Ec { curve, .. } => write!(f, "EC {curve}"),
            Self::Ed25519 => f.write_str("Ed25519"),
            Self::Ed448 => f.write_str("Ed448"),
            Self::Dsa { bits } => write!(f, "DSA {bits}"),
            Self::Other(oid) => write!(f, "unknown ({oid})"),
        }
    }
}

/// Bit length of a big-endian unsigned integer, ignoring leading zeros.
fn integer_bits(bytes: &[u8]) -> u32 {
    let Some(start) = bytes.iter().position(|&b| b != 0) else {
        return 0;
    };
    let significant = &bytes[start..];
    let Ok(len) = u32::try_from(significant.len()) else {
        return 0;
    };
    let top = significant.first().copied().unwrap_or(0);
    len.saturating_mul(8).saturating_sub(top.leading_zeros())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_bits_ignores_sign_byte() {
        assert_eq!(integer_bits(&[]), 0);
        assert_eq!(integer_bits(&[0, 0]), 0);
        assert_eq!(integer_bits(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(integer_bits(&[0x01, 0x00]), 9);
        assert_eq!(integer_bits(&[0x7f]), 7);
    }

    #[test]
    fn signature_oids() {
        assert_eq!(
            SignatureAlgorithm::from_oid("1.2.840.113549.1.1.5", None),
            SignatureAlgorithm::RsaPkcs1(HashAlgorithm::Sha1)
        );
        assert!(SignatureAlgorithm::from_oid("1.2.840.113549.1.1.4", None).is_weak());
        assert!(!SignatureAlgorithm::from_oid("1.2.840.10045.4.3.2", None).is_weak());
        assert!(SignatureAlgorithm::from_oid("1.2.840.113549.1.1.10", None).is_weak());
        assert_eq!(
            SignatureAlgorithm::from_oid("1.2.840.113549.1.1.10", Some("2.16.840.1.101.3.4.2.1")),
            SignatureAlgorithm::RsaPss(Some(HashAlgorithm::Sha256))
        );
        assert_eq!(
            SignatureAlgorithm::from_oid("1.3.101.112", None).hash(),
            None
        );
        assert_eq!(
            SignatureAlgorithm::from_oid("1.2.3", None),
            SignatureAlgorithm::Other("1.2.3".into())
        );
    }
}
