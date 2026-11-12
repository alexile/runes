//! Technology fingerprinting: detect the web servers, languages,
//! frameworks, CMSs and libraries behind an HTTP response, with versions
//! and confidence.
//!
//! The engine applies a Wappalyzer-style ruleset to a response:
//!
//! - **Rules** ([`Technology`]) match response headers, cookies, `<meta>`
//!   tags, the HTML body, `<script src>` URLs, the URL and the Shodan-style
//!   favicon hash ([`rune_favicon_hash`]). Each [`Pattern`] is a regex with
//!   optional `\;version:\1` and `\;confidence:50` tags; technologies can
//!   `implies`, `requires` and `excludes` each other.
//! - **Rule files** in the Wappalyzer JSON format load with
//!   [`Ruleset::from_wappalyzer_json`] (one or many files, plus
//!   `categories.json`). Browser-only fields (`js`, `dom`, `css`, `xhr`)
//!   need a rendered page and are ignored.
//! - **Detection** ([`Detector`]) returns each [`Detection`] with the
//!   highest version found, a confidence (sum of matching patterns, capped
//!   at 100) and the [`Evidence`].
//!
//! The crate is sans-I/O: it reads [`rune_http_model`] exchanges or a
//! hand-built [`Page`]. Regexes are compiled case-insensitively under the
//! same size limits as [`rune_matchers`] (Rust `regex` syntax: no
//! lookaround or backreferences; [`Detector::new`] skips such patterns and
//! lists them in [`Detector::skipped`]).
//!
//! # Rule data and licences
//!
//! The crate ships only a small ruleset written for it
//! ([`BUILTIN_TECHNOLOGIES`]). It bundles no third-party fingerprint data.
//! Community Wappalyzer-format rule sets carry their own licences (some
//! are GPL); load them at run time and check their terms first.
//!
//! # Example
//!
//! ```
//! use rune_tech_detect::{Detector, Page, Ruleset};
//!
//! let mut rules = Ruleset::from_wappalyzer_json(r#"{
//!   "Acme Shop": {
//!     "cats": [1],
//!     "headers": { "X-Acme": "^shop/([\\d.]+)\\;version:\\1" },
//!     "scriptSrc": "/acme-shop\\.js\\;confidence:50",
//!     "implies": "PHP"
//!   },
//!   "PHP": { "cookies": { "PHPSESSID": "" } }
//! }"#)?;
//! rules.extend_categories_from_json(r#"{ "1": { "name": "Ecommerce" } }"#)?;
//!
//! let page = Page::new("https://store.example.test/")
//!     .with_header("X-Acme", "shop/4.2.0")
//!     .with_html(r#"<script src="/static/acme-shop.js"></script>"#);
//! let found = Detector::strict(&rules)?.detect(&page);
//!
//! assert_eq!(found[0].name, "Acme Shop");
//! assert_eq!(found[0].version.as_deref(), Some("4.2.0"));
//! assert_eq!(found[0].confidence, 100);
//! assert_eq!(found[0].categories, ["Ecommerce"]);
//! assert_eq!(found[1].name, "PHP"); // implied
//! # Ok::<(), rune_tech_detect::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod builtin;
mod detect;
mod error;
mod page;
mod pattern;
mod rules;

pub use builtin::{BUILTIN_CATEGORIES, BUILTIN_TECHNOLOGIES, builtin_ruleset};
pub use detect::{Detection, Detector, Evidence, SkippedPattern, Source};
pub use error::Error;
pub use page::{MAX_HTML_LEN, MAX_TAGS, Page};
pub use pattern::{Pattern, compare_versions, resolve_version};
pub use rules::{Implied, Ruleset, Technology};

#[cfg(test)]
mod tests;
