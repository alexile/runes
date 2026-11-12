//! Weak-crypto and hygiene checks on a single certificate.

use std::fmt;

use crate::algorithm::{PublicKeyInfo, SignatureAlgorithm};
use crate::{CertSummary, Certificate};

/// How bad a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// Worth reporting; does not make a chain untrusted.
    Warning,
    /// Makes a chain untrusted.
    Error,
}

/// Thresholds for [`Certificate::weaknesses`].
///
/// The defaults follow the CA/Browser Forum Baseline Requirements: RSA
/// of at least 2048 bits, EC of at least 256, no DSA, and TLS leaf
/// certificates valid for at most 398 days.
///
/// ```
/// use rune_x509::Policy;
///
/// let policy = Policy::default().with_min_rsa_bits(3072).with_max_leaf_validity_days(None);
/// assert_eq!(policy.min_rsa_bits, 3072);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Policy {
    /// Smallest acceptable RSA modulus, in bits. Default 2048.
    pub min_rsa_bits: u32,
    /// Smallest acceptable EC field size, in bits. Default 256.
    pub min_ec_bits: u32,
    /// Accept DSA keys. Default `false`.
    pub allow_dsa: bool,
    /// Longest acceptable validity for a non-CA certificate, in days;
    /// `None` disables the check. Default `Some(398)`.
    pub max_leaf_validity_days: Option<i64>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_rsa_bits: 2048,
            min_ec_bits: 256,
            allow_dsa: false,
            max_leaf_validity_days: Some(398),
        }
    }
}

impl Policy {
    /// Sets [`Policy::min_rsa_bits`].
    #[must_use]
    pub const fn with_min_rsa_bits(mut self, bits: u32) -> Self {
        self.min_rsa_bits = bits;
        self
    }

    /// Sets [`Policy::min_ec_bits`].
    #[must_use]
    pub const fn with_min_ec_bits(mut self, bits: u32) -> Self {
        self.min_ec_bits = bits;
        self
    }

    /// Sets [`Policy::allow_dsa`].
    #[must_use]
    pub const fn with_allow_dsa(mut self, allow: bool) -> Self {
        self.allow_dsa = allow;
        self
    }

    /// Sets [`Policy::max_leaf_validity_days`].
    #[must_use]
    pub const fn with_max_leaf_validity_days(mut self, days: Option<i64>) -> Self {
        self.max_leaf_validity_days = days;
        self
    }
}

/// A weakness found in one certificate, independent of time and chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Weakness {
    /// Signed with a broken hash (MD5, SHA-1, ...).
    WeakSignature(SignatureAlgorithm),
    /// RSA modulus below [`Policy::min_rsa_bits`].
    SmallRsaKey {
        /// Modulus size in bits.
        bits: u32,
        /// The policy minimum.
        min: u32,
    },
    /// EC key below [`Policy::min_ec_bits`].
    SmallEcKey {
        /// Field size in bits.
        bits: u32,
        /// The policy minimum.
        min: u32,
    },
    /// A DSA key while [`Policy::allow_dsa`] is off.
    DsaKey,
    /// A non-CA certificate valid for longer than
    /// [`Policy::max_leaf_validity_days`].
    LongValidity {
        /// Validity period in days.
        days: i64,
        /// The policy maximum.
        max: i64,
    },
    /// A critical extension this crate does not understand, by dotted OID.
    UnhandledCriticalExtension(String),
}

impl Weakness {
    /// [`Severity::Warning`] for [`Weakness::LongValidity`];
    /// [`Severity::Error`] otherwise.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::LongValidity { .. } => Severity::Warning,
            _ => Severity::Error,
        }
    }
}

impl fmt::Display for Weakness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WeakSignature(alg) => write!(f, "weak signature algorithm: {alg}"),
            Self::SmallRsaKey { bits, min } => write!(f, "RSA key of {bits} bits, below {min}"),
            Self::SmallEcKey { bits, min } => write!(f, "EC key of {bits} bits, below {min}"),
            Self::DsaKey => f.write_str("DSA key"),
            Self::LongValidity { days, max } => write!(f, "valid for {days} days, more than {max}"),
            Self::UnhandledCriticalExtension(oid) => {
                write!(f, "unhandled critical extension {oid}")
            }
        }
    }
}

impl Certificate {
    /// The certificate's [`Weakness`]es under `policy`.
    ///
    /// ```
    /// use rune_x509::{Certificate, Policy, Weakness};
    ///
    /// # let pem = include_bytes!("../tests/fixtures/weak-rsa.pem");
    /// let cert = Certificate::from_pem(pem)?;
    /// assert_eq!(
    ///     cert.weaknesses(&Policy::default()),
    ///     [Weakness::SmallRsaKey { bits: 1024, min: 2048 }]
    /// );
    /// # Ok::<(), rune_x509::Error>(())
    /// ```
    #[must_use]
    pub fn weaknesses(&self, policy: &Policy) -> Vec<Weakness> {
        weaknesses(self.summary(), policy)
    }
}

pub fn weaknesses(summary: &CertSummary, policy: &Policy) -> Vec<Weakness> {
    let mut found = Vec::new();
    if summary.signature_algorithm.is_weak() {
        found.push(Weakness::WeakSignature(summary.signature_algorithm.clone()));
    }
    match summary.public_key {
        PublicKeyInfo::Rsa { bits } if bits < policy.min_rsa_bits => {
            found.push(Weakness::SmallRsaKey {
                bits,
                min: policy.min_rsa_bits,
            });
        }
        PublicKeyInfo::Ec { bits, .. } if bits < policy.min_ec_bits => {
            found.push(Weakness::SmallEcKey {
                bits,
                min: policy.min_ec_bits,
            });
        }
        PublicKeyInfo::Dsa { .. } if !policy.allow_dsa => found.push(Weakness::DsaKey),
        _ => {}
    }
    if let Some(max) = policy.max_leaf_validity_days {
        let days = summary.validity_days();
        if !summary.is_ca() && days > max {
            found.push(Weakness::LongValidity { days, max });
        }
    }
    found.extend(
        summary
            .unhandled_critical_extensions
            .iter()
            .cloned()
            .map(Weakness::UnhandledCriticalExtension),
    );
    found
}
