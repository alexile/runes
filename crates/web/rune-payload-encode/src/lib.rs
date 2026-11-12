//! WAF-evasion variants of a payload, for testing how a web application
//! firewall or input filter handles encoded and obfuscated input.
//!
//! Given a payload and the [`Context`] it is injected into, the crate
//! produces variants in the style of sqlmap tamper scripts: case toggling,
//! URL, double-URL, `\uXXXX`, HTML-entity and hex encodings, SQL inline
//! comments and alternate whitespace, `CHAR(…)` rewriting, null bytes,
//! `....//` traversal, `${IFS}` command separators and string
//! concatenation (see [`Technique`]).
//!
//! Every technique is a [`rune_transform::Transform`] ([`EvasionTransform`]).
//! [`register`] adds them to a [`TransformRegistry`](rune_transform::TransformRegistry)
//! as `evade_*` ids, so they chain with every other codec there; the
//! encodings reuse the registry's built-ins. [`Encoder`] generates the
//! variants with bounded output ([`Options`]) in a deterministic order, and
//! reverses the reversible ones.
//!
//! [`Technique::UnicodeEscape`] escapes characters outside the
//! Basic Multilingual Plane as UTF-16 surrogate pairs (`😀`), as
//! JavaScript and JSON expect, rather than `ὠ0`.
//!
//! Everything is sans-I/O and offline. It is meant for authorized security
//! testing: scanners, fuzzers and filter regression tests.
//!
//! # Example
//!
//! ```
//! use rune_payload_encode::{Context, Options, run};
//!
//! let report = run("' OR 1=1-- -", &Options::default().with_context(Context::Sql))?;
//! let variants: Vec<(&str, &str)> = report
//!     .variants
//!     .iter()
//!     .map(|v| (v.technique.as_str(), v.payload.as_str()))
//!     .collect();
//! assert_eq!(variants[0], ("original", "' OR 1=1-- -"));
//! assert_eq!(variants[2], ("sql_inline_comment", "'/**/OR/**/1=1--/**/-"));
//! assert_eq!(variants[5], ("hex_encode", "0x27204f5220313d312d2d202d"));
//! assert_eq!(variants[7], ("concatenation", "'' OR 1'+'=1-- -'"));
//! # Ok::<(), rune_payload_encode::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod encoder;
mod error;
mod technique;
mod transforms;

pub use encoder::{Encoder, ORIGINAL, Options, Report, Variant};
pub use error::Error;
pub use technique::{Context, Technique};
pub use transforms::{EvasionTransform, register};

/// Generate the variants of `payload` with a fresh [`Encoder`].
///
/// Building an encoder builds the transform registry; to generate variants
/// for many payloads, build one [`Encoder`] and call [`Encoder::run`].
///
/// # Errors
/// As for [`Encoder::run`].
pub fn run(payload: &str, options: &Options) -> Result<Report, Error> {
    Encoder::new()?.run(payload, options)
}
