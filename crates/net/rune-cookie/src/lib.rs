//! HTTP cookies per [RFC 6265]: `Set-Cookie` and `Cookie` parsing and
//! serialization, cookie dates, and a sans-I/O cookie jar with correct
//! domain, path, `Secure`, `HttpOnly` and `SameSite` semantics.
//!
//! - [`SetCookie`] parses a `Set-Cookie` header with the user-agent
//!   algorithm of RFC 6265 §5.2 and writes one back. It keeps every raw
//!   attribute next to the interpretation, for analysers.
//! - [`parse_cookie_header`] / [`serialize_cookie_header`] handle the
//!   `Cookie` request header; [`is_valid_name`] and [`is_valid_value`]
//!   check the strict server grammar of §4.1.1.
//! - [`parse_cookie_date`] / [`format_cookie_date`]: the lenient
//!   §5.1.1 date parser and IMF-fixdate.
//! - [`CookieJar`] implements the storage model (§5.3) and retrieval
//!   (§5.4). `Domain` attributes that are public suffixes are refused with
//!   the Public Suffix List of `rune-psl`, and the
//!   [RFC 6265bis] rules browsers enforce (strict secure cookies, name
//!   prefixes, `SameSite`) are on by default; see [`JarOptions`].
//! - [`domain_match`], [`path_match`], [`default_path`] and
//!   [`is_same_site`] expose the matching rules.
//! - [`CookieJar::store_response`], [`CookieJar::apply_to_request`] and
//!   [`response_set_cookies`] work on the `rune-http-model` types.
//!
//! The jar never reads the clock: every call takes `now`.
//!
//! # Example
//!
//! ```
//! use std::time::{Duration, SystemTime};
//! use rune_cookie::{CookieJar, RequestContext, SameSite, SetCookie, SiteContext};
//! use url::Url;
//!
//! let cookie = SetCookie::parse("id=a3fWa; Max-Age=2592000; Secure; SameSite=Strict")?;
//! assert_eq!(cookie.same_site, Some(SameSite::Strict));
//!
//! let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
//! let site = Url::parse("https://example.com/").unwrap();
//! let mut jar = CookieJar::new();
//! jar.store_parsed(&site, &cookie, &RequestContext::http(), now)?;
//!
//! let same_site = RequestContext::http();
//! assert_eq!(jar.cookie_header(&site, &same_site, now)?.as_deref(), Some("id=a3fWa"));
//!
//! let cross_site = RequestContext::http().with_site(SiteContext::CrossSite);
//! assert_eq!(jar.cookie_header(&site, &cross_site, now)?, None);
//! # Ok::<(), rune_cookie::Error>(())
//! ```
//!
//! # Features
//!
//! - `serde`: `Serialize`/`Deserialize` for [`SetCookie`], [`Cookie`],
//!   [`CookiePair`] and [`SameSite`], so a jar can be saved with
//!   [`CookieJar::iter`] and restored with [`CookieJar::from_cookies`].
//!
//! [RFC 6265]: https://www.rfc-editor.org/rfc/rfc6265
//! [RFC 6265bis]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cookie_header;
mod date;
mod error;
mod http;
mod jar;
mod matching;
mod set_cookie;

pub use cookie_header::{
    CookiePair, is_valid_name, is_valid_value, parse_cookie_header, serialize_cookie_header,
};
pub use date::{format_cookie_date, parse_cookie_date};
pub use error::{Error, Rejection};
pub use http::response_set_cookies;
pub use jar::{Api, Cookie, CookieJar, JarOptions, RequestContext, SiteContext, StoreOutcome};
pub use matching::{
    canonical_host, default_path, domain_match, is_same_site, is_secure_scheme, path_match,
};
pub use set_cookie::{
    MAX_ATTRIBUTE_VALUE_LEN, MAX_NAME_VALUE_LEN, RawAttribute, SameSite, SetCookie,
};
