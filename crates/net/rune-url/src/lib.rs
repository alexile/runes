//! URL canonicalization for crawlers and scanners: one canonical form per
//! URL, a configurable dedup key, same-origin and same-site tests, query
//! parameter handling and scan-scope matching.
//!
//! A thin layer over the [`url`] crate, which parses by the
//! [WHATWG URL Standard](https://url.spec.whatwg.org/), adding the
//! [RFC 3986 §6](https://www.rfc-editor.org/rfc/rfc3986#section-6)
//! normalizations it leaves out and the policy a crawler needs on top.
//! Everything is sans-I/O: no DNS, no requests.
//!
//! | Need | API |
//! | --- | --- |
//! | Canonical URL | [`canonicalize`], [`canonicalize_url`], [`resolve`], [`Options`] |
//! | "Have I seen this already?" | [`dedup_key`], [`KeyOptions`], [`DedupKey`] |
//! | Query parameters | [`split_query`], [`join_query`], [`QueryParams`], [`ParamFilter`] |
//! | Origin and site | [`same_origin`], [`same_site`], [`site`], [`registrable_domain`] (Public Suffix List via `rune-psl`) |
//! | Scope | [`Scope`], [`ScopeRule`], [`is_internal_host`] (via `rune-ip`, `rune-cidr`, `rune-host-match`) |
//! | Display | [`display_host`], [`to_display_string`] (Unicode hosts via `rune-idna`) |
//!
//! [`Options::default`] only applies steps that never change which resource
//! a URL names. [`Options::crawler`] also drops fragments, tracking
//! parameters and the like, and is what [`KeyOptions::default`] uses.
//!
//! # Example
//!
//! ```
//! use rune_url::{KeyOptions, Options, Scope, Url, canonicalize, dedup_key, resolve, same_site};
//!
//! // Canonical form.
//! let url = canonicalize("HTTP://Example.COM:80/a/./b/../%7Euser?q=%41#top", &Options::default())?;
//! assert_eq!(url.as_str(), "http://example.com/a/~user?q=A#top");
//!
//! // A crawler resolves links found on a page...
//! let page = Url::parse("https://shop.example.com/catalog/")?;
//! let link = resolve(&page, "../item?id=7&utm_source=mail#reviews", &Options::crawler())?;
//! assert_eq!(link.as_str(), "https://shop.example.com/item?id=7");
//!
//! // ...and agrees with the site map on what is a duplicate.
//! let keys = KeyOptions::default();
//! assert_eq!(
//!     dedup_key(link.as_str(), &keys)?,
//!     dedup_key("https://SHOP.example.com:443/item?id=7", &keys)?,
//! );
//!
//! assert!(same_site(&link, &Url::parse("https://example.com/")?));
//!
//! let scope = Scope::parse([".example.com"], ["https://shop.example.com/logout"])?;
//! assert!(scope.contains(&link));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod canon;
mod error;
mod key;
mod percent;
mod query;
mod scope;
mod site;

pub use canon::{Options, canonicalize, canonicalize_url, resolve};
pub use error::Error;
pub use key::{DedupKey, KeyOptions, QueryKey, dedup_key, dedup_key_url};
pub use percent::normalize_percent_encoding;
pub use query::{ParamFilter, QueryParam, QueryParams, join_query, split_query};
pub use scope::{Scope, ScopeRule};
pub use site::{
    display_host, host_ip, is_internal_host, registrable_domain, registrable_domain_with,
    same_origin, same_site, same_site_with, schemelessly_same_site, schemelessly_same_site_with,
    site, site_with, to_display_string,
};
/// The `url` crate, whose [`Url`] type this crate's API takes and returns.
pub use url;
pub use url::Url;
