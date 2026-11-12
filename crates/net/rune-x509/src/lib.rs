//! X.509 certificate analysis: typed summaries, weak-crypto flags, chain
//! building and path validation, and host name checks.
//!
//! DER parsing and signature verification come from
//! [`x509-parser`](https://docs.rs/x509-parser) (with `ring`); this crate
//! is the analysis layer on top, for TLS auditors, PKI tooling and mTLS
//! middleware:
//!
//! - [`Certificate`] parses DER or PEM into an owned [`CertSummary`]:
//!   subject and issuer, validity, key type and size, signature
//!   algorithm, SANs, basic constraints, key usages, embedded CT SCTs,
//!   self-signed detection and the SHA-256 fingerprint.
//! - [`Certificate::weaknesses`] flags MD5/SHA-1 signatures, small RSA and
//!   EC keys, DSA, over-long leaf validity and unhandled critical
//!   extensions under a [`Policy`].
//! - [`verify_chain`] builds a path to a [`TrustStore`] anchor and validates
//!   it ([RFC 5280 §6](https://www.rfc-editor.org/rfc/rfc5280#section-6)),
//!   reporting every [`ChainIssue`]: expired, self-signed, untrusted root,
//!   incomplete chain, bad signature, name mismatch, wrong purpose...
//! - Host names are matched with [`rune_host_match`]'s RFC 9525 certificate
//!   semantics, after UTS #46 conversion (`rune-idna`), with public-suffix
//!   wildcards (`*.co.uk`) rejected through `rune-psl`.
//!
//! Everything is sans-I/O: callers read the files or sockets and pass the
//! validation time in [`VerifyOptions`] (or let it read the system clock).
//!
//! # Example
//!
//! ```
//! use rune_x509::{Certificate, ChainIssue, HashAlgorithm, SignatureAlgorithm, TrustStore,
//!                 VerifyOptions, verify_chain};
//!
//! # let leaf_pem = include_bytes!("../tests/fixtures/leaf.pem");
//! # let inter_pem = include_bytes!("../tests/fixtures/inter.pem");
//! # let root_pem = include_bytes!("../tests/fixtures/root.pem");
//! let leaf = Certificate::from_pem(leaf_pem)?;
//! let summary = leaf.summary();
//! assert_eq!(summary.subject, "CN=example.com");
//! assert_eq!(summary.signature_algorithm, SignatureAlgorithm::Ecdsa(HashAlgorithm::Sha256));
//! assert_eq!(summary.sct_count, 1);
//!
//! let store = TrustStore::from_pem(root_pem)?;
//! let chain = rune_x509::parse_pem(inter_pem)?;
//! let options = VerifyOptions::default()
//!     .with_time(1_780_272_000) // 2026-06-01T00:00:00Z
//!     .with_hostname("www.example.com");
//! assert!(verify_chain(&leaf, &chain, &store, &options).is_trusted());
//!
//! let report = verify_chain(&leaf, &chain, &store, &options.with_hostname("example.org"));
//! assert_eq!(
//!     report.issues,
//!     [ChainIssue::NameMismatch { hostname: "example.org".into() }]
//! );
//! # Ok::<(), rune_x509::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod algorithm;
mod cert;
mod chain;
mod error;
mod host;
mod policy;

pub use algorithm::{Curve, HashAlgorithm, PublicKeyInfo, SignatureAlgorithm};
pub use cert::{
    BasicConstraints, CertSummary, Certificate, ExtendedKeyUsage, KeyUsage, SignatureError,
    SubjectAltName, parse_pem,
};
pub use chain::{ChainIssue, ChainReport, Purpose, TrustStore, VerifyOptions, verify_chain};
pub use error::Error;
pub use host::HostOptions;
pub use policy::{Policy, Severity, Weakness};
pub use rune_host_match;
