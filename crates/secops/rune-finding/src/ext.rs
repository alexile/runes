//! Capability traits for the extension slot of [`Finding<X>`](crate::Finding).
//!
//! An extension that implements one of these traits gives `Finding<X>` the
//! matching builder methods as *inherent* methods, so call sites chain them
//! like the core builders without importing anything:
//!
//! | Trait | `Finding<X>` methods |
//! | --- | --- |
//! | [`HasLegacyCwe`] | [`with_cwe`](crate::Finding::with_cwe) |
//! | [`HasExchanges`] | [`with_exchanges`](crate::Finding::with_exchanges), [`push_exchange`](crate::Finding::push_exchange) |
//! | [`HasProof`] | [`with_proof`](crate::Finding::with_proof) |
//! | [`HasSeenTimes`] | [`with_first_seen_unix_ms`](crate::Finding::with_first_seen_unix_ms), [`with_last_seen_unix_ms`](crate::Finding::with_last_seen_unix_ms) |
//!
//! They exist so a product that moves its own finding type onto
//! `Finding<X>` (for example, with its HTTP exchanges and proofs) keeps its
//! builder call sites unchanged.
//!
//! # Examples
//!
//! ```
//! use rune_finding::ext::{HasExchanges, HasLegacyCwe};
//! use rune_finding::{Confidence, Finding, Location, Severity, Taxonomy};
//!
//! #[derive(Debug, Default)]
//! struct DastExt {
//!     cwe: Option<String>,
//!     exchanges: Vec<u64>,
//! }
//!
//! impl HasLegacyCwe for DastExt {
//!     fn legacy_cwe_mut(&mut self) -> &mut Option<String> {
//!         &mut self.cwe
//!     }
//! }
//!
//! impl HasExchanges for DastExt {
//!     type Exchange = u64;
//!     fn exchanges_mut(&mut self) -> &mut Vec<u64> {
//!         &mut self.exchanges
//!     }
//! }
//!
//! let finding = Finding::<DastExt>::new(
//!     "xss.reflected",
//!     "Reflected XSS",
//!     Severity::High,
//!     Confidence::Firm,
//!     Location::url("https://shop.test/s?q=x"),
//! )
//! .with_cwe("CWE-79")
//! .push_exchange(7);
//!
//! assert_eq!(finding.cwe.as_deref(), Some("CWE-79"));
//! assert_eq!(finding.taxonomy_in(&Taxonomy::Cwe).count(), 1);
//! assert_eq!(finding.exchanges, [7]);
//! ```

/// An extension that keeps a free-text CWE id next to
/// [`Finding::taxonomy`](crate::Finding::taxonomy), for compatibility with
/// a finding shape that had a `cwe` string.
///
/// Gives `Finding<X>` the [`with_cwe`](crate::Finding::with_cwe) builder.
pub trait HasLegacyCwe {
    /// The legacy CWE id, e.g. `CWE-319`.
    fn legacy_cwe_mut(&mut self) -> &mut Option<String>;
}

/// An extension that carries supporting exchanges (HTTP request/response
/// pairs, or references to them).
///
/// Gives `Finding<X>` the [`with_exchanges`](crate::Finding::with_exchanges)
/// and [`push_exchange`](crate::Finding::push_exchange) builders.
pub trait HasExchanges {
    /// One exchange.
    type Exchange;

    /// The exchange list.
    fn exchanges_mut(&mut self) -> &mut Vec<Self::Exchange>;
}

/// An extension that carries a reproducible proof of the issue.
///
/// Gives `Finding<X>` the [`with_proof`](crate::Finding::with_proof) builder.
pub trait HasProof {
    /// The proof.
    type Proof;

    /// The proof slot.
    fn proof_mut(&mut self) -> &mut Option<Self::Proof>;
}

/// An extension that records when the issue was first and last observed,
/// in Unix epoch milliseconds.
///
/// Gives `Finding<X>` the
/// [`with_first_seen_unix_ms`](crate::Finding::with_first_seen_unix_ms) and
/// [`with_last_seen_unix_ms`](crate::Finding::with_last_seen_unix_ms)
/// builders.
pub trait HasSeenTimes {
    /// When the issue was first observed.
    fn first_seen_unix_ms_mut(&mut self) -> &mut Option<u64>;

    /// When the issue was last observed.
    fn last_seen_unix_ms_mut(&mut self) -> &mut Option<u64>;
}
