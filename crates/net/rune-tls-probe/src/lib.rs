//! Read-only TLS server probing over raw handshakes: which protocol
//! versions (SSL 3.0 to TLS 1.3) and which cipher suites a server accepts,
//! with weak-suite flags, `TLS_FALLBACK_SCSV` downgrade protection, TLS
//! compression (CRIME), RFC 5746 secure renegotiation and the DHE/ECDHE
//! parameters; a policy grader after Mozilla's server-side TLS profiles;
//! and JARM fingerprinting.
//!
//! TLS libraries such as rustls cannot speak SSL 3.0, TLS 1.0 or 1.1, nor
//! offer export, NULL, anonymous or RC4 suites, so an auditor built on them
//! cannot see what matters most. This crate builds the `ClientHello` itself
//! with [`rune_tls_hello`] and reads the server's `ServerHello` or alert;
//! it never completes a handshake, derives a key or sends application
//! data.
//!
//! - [`Offer`] builds one hello; [`ResponseReader`] turns the server's bytes
//!   into an [`Outcome`] (accepted version and suite, alert, no answer).
//! - [`Scanner`] is the sans-I/O planner: per version it offers the IANA
//!   suite registry in chunks, removing each accepted suite until the
//!   server refuses, then tests fallback SCSV and compression, and builds a
//!   [`Report`].
//! - [`Report::findings`] gives [`rune_finding::Finding`]s (`tls.sslv3`,
//!   `tls.cipher.export`, `tls.compression`...); [`Report::service_info`]
//!   gives a `rune-service-probe` [`ServiceInfo`](rune_service_probe::ServiceInfo).
//! - [`policy`] grades a [`Report`] under a `modern`, `intermediate` or
//!   `old` [`Profile`](policy::Profile) (after Mozilla's server-side TLS
//!   guidelines, with verdicts from RFC 9325), plus your own allow/deny
//!   rules: every version, suite and key exchange is good, ok, warn or
//!   fail with a reason and a source, rolled into an `A`-`F`
//!   [`Grade`](policy::Grade) and `tls.weak_*` / `tls.discouraged_*`
//!   findings.
//! - [`jarm`] builds JARM's ten probe hellos, reads the answers and
//!   computes the 62-character fingerprint, sans-I/O, with an async
//!   [`jarm::fingerprint`] runner under the `tokio` feature.
//! - [`TlsHelloProbe`] is one hello as a `rune-service-probe`
//!   [`ServiceProbe`](rune_service_probe::ServiceProbe), and with the
//!   `tokio` feature [`scan`] runs a whole scan over its `Runner`
//!   (timeouts, budgets, concurrency bound).
//!
//! Use it only against systems you are authorised to assess; scope checks
//! are the caller's.
//!
//! Specifications: SSL 3.0 [RFC 6101](https://www.rfc-editor.org/rfc/rfc6101),
//! TLS 1.0-1.3 [RFC 2246](https://www.rfc-editor.org/rfc/rfc2246),
//! [RFC 4346](https://www.rfc-editor.org/rfc/rfc4346),
//! [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246),
//! [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446); fallback SCSV
//! [RFC 7507](https://www.rfc-editor.org/rfc/rfc7507); secure renegotiation
//! [RFC 5746](https://www.rfc-editor.org/rfc/rfc5746); RC4 prohibition
//! [RFC 7465](https://www.rfc-editor.org/rfc/rfc7465); TLS 1.0/1.1
//! deprecation [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996); secure
//! use of TLS [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325); JARM
//! (Salesforce, BSD 3-Clause), implemented from its published design.
//!
//! # Example
//!
//! A scan against an in-memory server that only speaks TLS 1.0 with RC4
//! and 3DES, the server rustls-based auditors report as "not probeable":
//!
//! ```
//! use rune_service_probe::Target;
//! use rune_tls_hello::{CipherSuite, ProtocolVersion, ServerHello};
//! use rune_tls_probe::{Observed, Offer, Outcome, ResponseReader, ScanOptions, Scanner};
//!
//! const RC4: CipherSuite = CipherSuite(0x0005); // TLS_RSA_WITH_RC4_128_SHA
//! const DES3: CipherSuite = CipherSuite(0x000a); // TLS_RSA_WITH_3DES_EDE_CBC_SHA
//!
//! fn legacy_server(offer: &Offer) -> Vec<u8> {
//!     let pick = [DES3, RC4].into_iter().find(|s| offer.cipher_suites.contains(s));
//!     match pick {
//!         Some(suite) if offer.version >= ProtocolVersion::TLS_1_0 && !offer.is_tls13() => ServerHello::new()
//!             .with_legacy_version(ProtocolVersion::TLS_1_0)
//!             .with_cipher_suite(suite)
//!             .to_records(ProtocolVersion::TLS_1_0, 16_384)
//!             .unwrap(),
//!         _ => vec![21, 3, 1, 0, 2, 2, 40], // handshake_failure
//!     }
//! }
//!
//! let mut scanner = Scanner::new(ScanOptions::default());
//! while let Some(offer) = scanner.next_offer() {
//!     let mut reader = ResponseReader::new();
//!     let outcome = reader.feed(&legacy_server(&offer)).unwrap_or_else(|| reader.finish());
//!     scanner.record(&outcome);
//! }
//! let report = scanner.finish();
//!
//! assert_eq!(report.supported_versions(), [ProtocolVersion::TLS_1_0]);
//! assert_eq!(report.version(ProtocolVersion::TLS_1_0).unwrap().cipher_suites, [DES3, RC4]);
//! assert_eq!(report.fallback_scsv, Observed::NotApplicable);
//!
//! let target = Target::new("legacy.test", 443);
//! let ids: Vec<_> = report.findings(&target).into_iter().map(|f| f.check_id).collect();
//! assert_eq!(
//!     ids,
//!     [
//!         "tls.tls1_0",
//!         "tls.no_modern_version",
//!         "tls.cipher.rc4",
//!         "tls.cipher.sweet32",
//!         "tls.cipher.no_forward_secrecy",
//!         "tls.insecure_renegotiation",
//!     ]
//! );
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
pub mod jarm;
mod kex;
mod offer;
pub mod policy;
mod probe;
mod registry;
mod report;
#[cfg(feature = "tokio")]
mod runner;
mod scan;
mod suites;

pub use error::Error;
pub use kex::{KeyExchange, KeyExchangeKind, kind_of as key_exchange_kind};
pub use offer::{Accepted, MAX_RESPONSE_BYTES, Offer, Outcome, ResponseReader};
pub use probe::TlsHelloProbe;
pub use report::{Observed, Report, ServerKeyExchange, VersionResult};
#[cfg(feature = "tokio")]
pub use runner::scan;
pub use scan::{ALL_VERSIONS, ScanOptions, Scanner};
pub use suites::{Weakness, suite_label, suite_name, weaknesses};
