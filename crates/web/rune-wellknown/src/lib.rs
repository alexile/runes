//! Discover and parse `/.well-known` resources
//! ([RFC 8615](https://www.rfc-editor.org/rfc/rfc8615)) into typed models.
//!
//! | Resource | Model | Specification |
//! | --- | --- | --- |
//! | `security.txt` | [`rune_securitytxt::SecurityTxt`] | [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) |
//! | `change-password` | [`ChangePassword`] | [W3C Change Password URL](https://w3c.github.io/webappsec-change-password-url/) |
//! | `mta-sts.txt` | [`MtaStsPolicy`] | [RFC 8461 §3.2](https://www.rfc-editor.org/rfc/rfc8461#section-3.2) |
//! | `openid-configuration` | [`OpenIdConfiguration`] | [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) |
//! | `assetlinks.json` | [`AssetLinks`] | [Digital Asset Links](https://developers.google.com/digital-asset-links/v1/statements) |
//! | `apple-app-site-association` | [`AppleAppSiteAssociation`] | [Apple associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains) |
//!
//! [`parse`] takes the request path and a [`Response`] the caller obtained
//! and returns a [`Resource`]; paths it does not know come back raw as
//! [`Resource::Unknown`]. The core is sans-I/O. The `fetch` feature adds
//! [`fetch::discover`] over a caller-supplied [`fetch::Fetcher`], and the
//! `reqwest` feature a ready-made fetcher.
//!
//! # Example
//!
//! ```
//! use rune_wellknown::{ChangePassword, Resource, Response, WellKnown, parse};
//!
//! let body = "version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 86400\n";
//! let Resource::MtaSts(policy) = parse("/.well-known/mta-sts.txt", &Response::new(200, body))? else {
//!     unreachable!()
//! };
//! assert!(policy.matches_mx("mx.example.com"));
//!
//! let redirect = Response::new(302, "").with_header("Location", "/settings/password");
//! assert!(matches!(
//!     parse(&WellKnown::ChangePassword.path(), &redirect)?,
//!     Resource::ChangePassword(ChangePassword::Redirect { .. })
//! ));
//!
//! let Resource::Unknown(raw) = parse("/.well-known/nodeinfo", &Response::new(200, "{}"))? else {
//!     unreachable!()
//! };
//! assert_eq!(raw.body, b"{}");
//! # Ok::<(), rune_wellknown::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "fetch")]
pub mod fetch;
mod json;
mod mta_sts;
mod resource;

pub use json::{
    AppLinkComponent, AppLinkDetail, AppLinks, AppList, AppleAppSiteAssociation, AssetLinks,
    AssetStatement, AssetTarget, GET_LOGIN_CREDS, HANDLE_ALL_URLS, OpenIdConfiguration,
};
pub use mta_sts::{MTA_STS_MAX_AGE_LIMIT, MTA_STS_MAX_LEN, Mode, MtaStsPolicy};
pub use resource::{
    ChangePassword, MAX_BODY_LEN, RawResource, Resource, Response, STATUS_PROBE_PATH, WellKnown,
    parse, parse_body, status_codes_reliable,
};
pub use rune_securitytxt;
pub use serde_json;

/// Errors from parsing a well-known resource.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The response status is not 2xx.
    #[error("unexpected HTTP status {status}")]
    Status {
        /// The status code.
        status: u16,
    },
    /// The body is larger than the limit.
    #[error("body is larger than {limit} bytes")]
    TooLarge {
        /// The limit, in bytes.
        limit: usize,
    },
    /// The body is not UTF-8.
    #[error("body is not UTF-8 (invalid at byte {offset})")]
    NotUtf8 {
        /// Length of the valid prefix.
        offset: usize,
    },
    /// A JSON resource is malformed or has the wrong shape.
    #[error("invalid JSON resource: {message}")]
    Json {
        /// What is wrong.
        message: String,
    },
    /// An MTA-STS policy is malformed.
    #[error("invalid MTA-STS policy at line {line}: {message}")]
    InvalidMtaSts {
        /// 1-based line number.
        line: usize,
        /// What is wrong.
        message: String,
    },
    /// The apple-app-site-association file is a legacy PKCS #7-signed
    /// file; extract the JSON content and use [`parse_body`].
    #[error("apple-app-site-association is PKCS #7-signed")]
    SignedAasa,
    /// A signed security.txt has a broken signature framing.
    #[error(transparent)]
    SecurityTxt(#[from] rune_securitytxt::Error),
}
