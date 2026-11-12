//! Pattern-based subdomain permutation, in the style of alterx.
//!
//! Take names you already know (`api.example.com`, `db2.eu.example.com`),
//! apply patterns and wordlists, and get candidate names worth resolving:
//! `dev-api.example.com`, `api.staging.example.com`, `db3.eu.example.com`.
//! Generation is pure and deterministic; resolving the candidates and
//! dropping wildcard answers is the job of a resolver and
//! `rune-wildcard-dns`.
//!
//! - [`Seed`] splits a known name into the parts patterns refer to
//!   (`{{sub}}`, `{{sub1}}`, `{{suffix}}`, `{{root}}`, `{{sld}}`,
//!   `{{etld}}`, `{{tld}}`), using the Public Suffix List (`rune-psl`) and
//!   IDNA (`rune-idna`).
//! - [`Pattern`] is a template such as `{{word}}-{{sub}}.{{suffix}}`; any
//!   non-built-in variable draws from a named list in [`Payloads`].
//! - [`Permutator`] expands seeds × patterns × payloads, adds number
//!   mutation (`api2` → `api1`, `api3`) and optional enrichment with
//!   tokens seen in the seeds, and streams deduplicated, valid host names,
//!   bounded by [`Options::limit`].
//!
//! Strategies covered by [`DEFAULT_PATTERNS`] and the built-in payloads:
//! prefix/suffix words with dash, dot or no separator, environment tokens
//! (`dev`, `staging`, …), region tokens (`us-east-1`, `eu`, …) and numeric
//! suffixes.
//!
//! # Example
//!
//! ```
//! use rune_subdomain_permute::{Options, Payloads, Permutator, Seed};
//!
//! let mut payloads = Payloads::new();
//! payloads.insert("word", ["dev", "internal"])?;
//! let permutator = Permutator::new(
//!     ["{{word}}-{{sub}}.{{suffix}}", "{{sub}}.{{word}}.{{suffix}}"],
//!     payloads,
//!     Options::default().with_limit(100),
//! )?;
//!
//! let seeds = [Seed::parse("api.example.com")?, Seed::parse("api.example.com")?];
//! let candidates: Vec<String> = permutator.permute(&seeds).collect();
//! assert_eq!(candidates, [
//!     "dev-api.example.com",
//!     "internal-api.example.com",
//!     "api.dev.example.com",
//!     "api.internal.example.com",
//! ]);
//!
//! // The defaults: alterx-style patterns over built-in wordlists.
//! let all = Permutator::default();
//! assert!(all.estimate(&seeds[..1]) > 100);
//! # Ok::<(), rune_subdomain_permute::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod pattern;
mod payloads;
mod permute;
mod seed;

pub use error::Error;
pub use pattern::{DEFAULT_PATTERNS, Pattern};
pub use payloads::{DEFAULT_ENVS, DEFAULT_REGIONS, DEFAULT_WORDS, Payloads};
pub use permute::{Options, Permutations, Permutator};
pub use seed::Seed;
