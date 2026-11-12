//! The crate's error type.

use std::fmt;

/// Why a cookie jar refused to store a cookie that parsed correctly
/// ([RFC 6265 §5.3], with the RFC 6265bis rules where enabled).
///
/// [RFC 6265 §5.3]: https://www.rfc-editor.org/rfc/rfc6265#section-5.3
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rejection {
    /// The request host does not domain-match the `Domain` attribute.
    DomainMismatch {
        /// The canonical request host.
        host: String,
        /// The canonical `Domain` attribute.
        domain: String,
    },
    /// The `Domain` attribute is a public suffix (and not the request host
    /// itself), so the cookie would be shared across unrelated sites.
    PublicSuffix {
        /// The canonical `Domain` attribute.
        domain: String,
    },
    /// The `Domain` attribute is not a valid host name.
    InvalidDomain {
        /// The attribute as parsed.
        domain: String,
    },
    /// An `HttpOnly` cookie came from a non-HTTP API (such as script).
    HttpOnlyFromNonHttp,
    /// A non-HTTP API tried to overwrite an `HttpOnly` cookie.
    OverwritesHttpOnly,
    /// A `Secure` cookie came from an insecure origin (RFC 6265bis §5.7
    /// step 15).
    SecureFromInsecureOrigin,
    /// An insecure origin tried to overwrite or shadow a `Secure` cookie
    /// (RFC 6265bis §5.7 step 16, "leave secure cookies alone").
    OverwritesSecure,
    /// A `__Secure-` cookie without `Secure`, or from an insecure origin.
    SecurePrefix,
    /// A `__Host-` cookie without `Secure`, with a `Domain` attribute or
    /// with a path other than `/`.
    HostPrefix,
    /// `SameSite=None` without `Secure` (RFC 6265bis §5.7 step 18).
    SameSiteNoneWithoutSecure,
    /// A `SameSite=Strict` or `Lax` cookie was set by a cross-site request
    /// that was not a top-level navigation (RFC 6265bis §5.7 step 17).
    CrossSiteSameSite,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DomainMismatch { host, domain } => {
                write!(f, "host `{host}` does not domain-match `Domain={domain}`")
            }
            Self::PublicSuffix { domain } => write!(f, "`Domain={domain}` is a public suffix"),
            Self::InvalidDomain { domain } => write!(f, "`Domain={domain}` is not a valid host"),
            Self::HttpOnlyFromNonHttp => f.write_str("`HttpOnly` cookie set by a non-HTTP API"),
            Self::OverwritesHttpOnly => {
                f.write_str("a non-HTTP API may not overwrite an `HttpOnly` cookie")
            }
            Self::SecureFromInsecureOrigin => {
                f.write_str("`Secure` cookie set by an insecure origin")
            }
            Self::OverwritesSecure => {
                f.write_str("an insecure origin may not overwrite a `Secure` cookie")
            }
            Self::SecurePrefix => {
                f.write_str("`__Secure-` cookie must be `Secure` and set by a secure origin")
            }
            Self::HostPrefix => {
                f.write_str("`__Host-` cookie must be `Secure`, host-only and have `Path=/`")
            }
            Self::SameSiteNoneWithoutSecure => f.write_str("`SameSite=None` requires `Secure`"),
            Self::CrossSiteSameSite => {
                f.write_str("`SameSite=Strict`/`Lax` cookie set by a cross-site request")
            }
        }
    }
}

/// Everything that can go wrong in this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The `Set-Cookie` name-value pair has no `=` (RFC 6265 §5.2 step 2).
    #[error("cookie has no `=` between its name and value")]
    MissingSeparator,
    /// The cookie name is empty (RFC 6265 §5.2 step 5).
    #[error("cookie name is empty")]
    EmptyName,
    /// The header contains a control character other than horizontal tab.
    #[error("cookie contains a control character")]
    ControlCharacter,
    /// Name plus value exceed [`MAX_NAME_VALUE_LEN`](crate::MAX_NAME_VALUE_LEN).
    #[error("cookie name and value are {len} bytes, more than 4096")]
    TooLong {
        /// The combined length in bytes.
        len: usize,
    },
    /// The request URL could not be parsed.
    #[error("invalid request URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    /// The request URL has no host, so it cannot send or receive cookies.
    #[error("request URL has no host")]
    NoHost,
    /// The cookie parsed but the jar refused it.
    #[error("cookie rejected: {0}")]
    Rejected(Rejection),
}

impl From<Rejection> for Error {
    fn from(rejection: Rejection) -> Self {
        Self::Rejected(rejection)
    }
}
