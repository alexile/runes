//! Internationalized domain names: Punycode, UTS #46 / IDNA2008 processing
//! and IDN homograph detection.
//!
//! - [`punycode`]: the Bootstring encoding of
//!   [RFC 3492](https://www.rfc-editor.org/rfc/rfc3492), label by label.
//! - [`to_ascii`] and [`to_unicode`]: [UTS #46](https://www.unicode.org/reports/tr46/)
//!   `ToASCII` and `ToUnicode` (nontransitional), with the STD3 rules, hyphen
//!   checks, DNS length checks and an optional IDNA2008
//!   ([RFC 5890](https://www.rfc-editor.org/rfc/rfc5890)–5893) repertoire
//!   restriction, all set in [`Options`]. [`same_domain`] compares names.
//! - Confusables from [UTS #39](https://www.unicode.org/reports/tr39/):
//!   [`skeleton`], [`is_confusable_with`] and [`confusable_kind`];
//!   [`resolved_script_set`], [`is_mixed_script`] and
//!   [`restriction_level`] for mixed-script detection.
//! - Whole domains: [`DomainReport`] analyses every label, flags look-alikes
//!   under a [`SpoofPolicy`] and gives a safe display form;
//!   [`LookalikeIndex`] finds look-alikes of a list of known names.
//!
//! Everything is sans-I/O: strings in, values out. UTS #46 mapping,
//! normalization and the script properties come from the `idna` and ICU4X
//! crates; the UTS #39 data (`confusables.txt`, `IdentifierStatus.txt`) and
//! the IDNA2008 exclusions of `IdnaMappingTable.txt` are embedded, Unicode
//! version [`UNICODE_VERSION`].
//!
//! # Example
//!
//! ```
//! use rune_idna::{DomainReport, Options, SpoofPolicy, punycode, to_ascii, to_unicode};
//!
//! // Punycode, one label at a time.
//! assert_eq!(punycode::encode("münchen")?, "mnchen-3ya");
//!
//! // Whole domain names, with UTS #46 mapping.
//! let options = Options::default();
//! assert_eq!(to_ascii("MÜNCHEN.de", &options)?, "xn--mnchen-3ya.de");
//! assert_eq!(to_unicode("xn--mnchen-3ya.de", &options)?, "münchen.de");
//!
//! // Homograph detection: the first `а` is Cyrillic.
//! let report = DomainReport::analyze("pаypal.com", &options)?;
//! assert_eq!(report.skeleton, rune_idna::skeleton("paypal.com"));
//! assert!(report.is_suspicious(&SpoofPolicy::default()));
//! assert!(rune_idna::is_confusable_with("pаypal", "paypal"));
//! # Ok::<(), rune_idna::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod confusable;
mod data;
mod error;
mod homograph;
pub mod punycode;
mod script;
mod uts46;

pub use confusable::{ConfusableKind, confusable_kind, is_confusable_with, skeleton};
pub use data::UNICODE_VERSION;
pub use error::Error;
pub use homograph::{DomainReport, LabelReport, LookalikeIndex, SpoofPolicy};
pub use script::{
    RestrictionLevel, ScriptSet, is_identifier_allowed, is_mixed_script, resolved_script_set,
    restriction_level,
};
pub use uts46::{AsciiRules, Options, same_domain, to_ascii, to_unicode};

/// Whether `c` lies in one of `ranges`: sorted, disjoint, inclusive.
fn in_ranges(ranges: &[(char, char)], c: char) -> bool {
    ranges
        .binary_search_by(|&(lo, hi)| {
            if hi < c {
                core::cmp::Ordering::Less
            } else if lo > c {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        })
        .is_ok()
}
