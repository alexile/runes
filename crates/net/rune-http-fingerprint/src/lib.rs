//! Passive HTTP server and stack fingerprinting from header order, header
//! casing, status-line quirks, default error pages and method handling.
//!
//! Servers betray their implementation in how they answer, not only in
//! what their `Server` header claims: the order and capitalisation of the
//! headers they emit, how they write the status line, what their default
//! `404` page looks like, which methods they allow and how they refuse an
//! unknown one. This crate turns a handful of responses into
//!
//! - a stable [`StackFingerprint`] (`a_b_c`, in the spirit of JA4H, but for
//!   the server side) that clusters hosts running the same stack even when
//!   the `Server` header is removed or forged, and
//! - a ranked list of [`Candidate`] products from a [`Database`] of
//!   [`Signature`]s, with versions and the evidence for each.
//!
//! The crate is sans-I/O. [`probe_plan`] lists the requests to send
//! ([`ProbeKind`]); the caller sends them with any client, records the
//! responses in [`Observations`] (as [`rune_http_model`] values, with
//! `raw` bytes when available for wire-level [`Quirk`]s) and calls
//! [`analyze`]. Any subset of the probes works, including a single
//! passively captured response.
//!
//! Signature clues are [`rune_matchers`] rules, so `Server` tokens, error
//! pages and vendor headers use the same nuclei-style matching as the rest
//! of the toolkit, plus header-order and casing clues.
//!
//! # Example
//!
//! ```
//! use rune_http_fingerprint::{Database, Observations, ProbeKind, analyze};
//! use rune_http_model::HttpResponse;
//!
//! // Responses as a client recorded them (here: written by hand).
//! let observations = Observations::new()
//!     .with_response(
//!         ProbeKind::Baseline,
//!         HttpResponse::new(200)
//!             .with_reason("OK")
//!             .with_raw(b"HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: Thu, 12 Nov 2026 10:00:00 GMT\r\nContent-Type: text/html\r\nContent-Length: 615\r\n\r\n".to_vec())
//!             .with_header("Server", "nginx")
//!             .with_header("Date", "Thu, 12 Nov 2026 10:00:00 GMT")
//!             .with_header("Content-Type", "text/html")
//!             .with_header("Content-Length", "615"),
//!     )
//!     .with_response(
//!         ProbeKind::NotFound,
//!         HttpResponse::new(404)
//!             .with_reason("Not Found")
//!             .with_header("Server", "nginx")
//!             .with_body("<html><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>"),
//!     );
//!
//! let report = analyze(&observations, &Database::builtin());
//! assert!(report.fingerprint.hash.starts_with("11t04s_"));
//! assert_eq!(report.candidates[0].name, "nginx");
//! assert_eq!(report.candidates[0].confidence, 100);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod db;
mod error;
mod probe;
mod raw;
mod shape;

pub use db::{Candidate, Clue, ClueKind, Database, Evidence, Signature, builtin_signatures};
pub use error::Error;
pub use probe::{Observations, ProbeKind, UNKNOWN_METHOD, probe_plan};
pub use raw::{MAX_HEAD_LEN, Quirk, RawHead, analyze_raw_head};
pub use shape::{
    Casing, ReasonForm, ResponseShape, StackFeatures, StackFingerprint, allowed_methods,
    fingerprint, fingerprint_features, standard_reason,
};

/// The result of [`analyze`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Report {
    /// The stack fingerprint.
    pub fingerprint: StackFingerprint,
    /// The features it was computed from.
    pub features: StackFeatures,
    /// Matching signatures, most confident first.
    pub candidates: Vec<Candidate>,
}

/// Fingerprints `observations` and ranks the signatures of `database`.
#[must_use]
pub fn analyze(observations: &Observations, database: &Database) -> Report {
    let features = StackFeatures::of(observations);
    Report {
        fingerprint: fingerprint_features(&features),
        features,
        candidates: database.identify(observations),
    }
}

#[cfg(test)]
mod tests;
