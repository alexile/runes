//! HTTP protocol versions.

use std::fmt;
use std::str::FromStr;

use crate::HttpModelError;

/// HTTP protocol version.
///
/// Serialized as `http09`, `http10`, `http11`, `http2` or `http3`. Use
/// [`HttpVersion::as_str`] for the status-line form.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum HttpVersion {
    /// HTTP/0.9.
    Http09,
    /// HTTP/1.0.
    Http10,
    /// HTTP/1.1.
    #[default]
    Http11,
    /// HTTP/2.
    Http2,
    /// HTTP/3.
    Http3,
}

impl HttpVersion {
    /// Every version, oldest first.
    pub const ALL: [Self; 5] = [
        Self::Http09,
        Self::Http10,
        Self::Http11,
        Self::Http2,
        Self::Http3,
    ];

    /// The version as written on a status line, e.g. `HTTP/1.1`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http09 => "HTTP/0.9",
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
            Self::Http2 => "HTTP/2",
            Self::Http3 => "HTTP/3",
        }
    }

    /// The ALPN protocol id ([RFC 7301]), when the version has one:
    /// `http/1.0`, `http/1.1`, `h2` or `h3`.
    ///
    /// [RFC 7301]: https://www.rfc-editor.org/rfc/rfc7301
    #[must_use]
    pub const fn alpn(self) -> Option<&'static str> {
        match self {
            Self::Http09 => None,
            Self::Http10 => Some("http/1.0"),
            Self::Http11 => Some("http/1.1"),
            Self::Http2 => Some("h2"),
            Self::Http3 => Some("h3"),
        }
    }

    /// Parses `HTTP/1.1`, `HTTP/2`, `HTTP/2.0`, `h2`, `h3` and similar,
    /// ignoring case and surrounding whitespace.
    ///
    /// ```
    /// use rune_http_model::HttpVersion;
    ///
    /// assert_eq!(HttpVersion::parse("HTTP/1.1"), Some(HttpVersion::Http11));
    /// assert_eq!(HttpVersion::parse("h2"), Some(HttpVersion::Http2));
    /// assert_eq!(HttpVersion::parse("SPDY/3"), None);
    /// ```
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let lower = text.trim().to_ascii_lowercase();
        match lower.as_str() {
            "http/0.9" | "http09" => Some(Self::Http09),
            "http/1.0" | "http10" | "http/1" => Some(Self::Http10),
            "http/1.1" | "http11" | "http/1.x" => Some(Self::Http11),
            "http/2" | "http/2.0" | "http2" | "h2" | "h2c" => Some(Self::Http2),
            "http/3" | "http/3.0" | "http3" | "h3" => Some(Self::Http3),
            _ => None,
        }
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for HttpVersion {
    type Err = HttpModelError;

    /// Same as [`HttpVersion::parse`], with an error for unknown text.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text).ok_or_else(|| HttpModelError::UnknownVersion(text.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        assert_eq!(HttpVersion::parse("HTTP/1.1"), Some(HttpVersion::Http11));
        assert_eq!(HttpVersion::parse("http/1.0"), Some(HttpVersion::Http10));
        assert_eq!(HttpVersion::parse("HTTP/0.9"), Some(HttpVersion::Http09));
        assert_eq!(HttpVersion::parse("HTTP/2"), Some(HttpVersion::Http2));
        assert_eq!(HttpVersion::parse("HTTP/2.0"), Some(HttpVersion::Http2));
        assert_eq!(HttpVersion::parse(" h2 "), Some(HttpVersion::Http2));
        assert_eq!(HttpVersion::parse("h3"), Some(HttpVersion::Http3));
        assert_eq!(HttpVersion::parse("SPDY"), None);
        for version in HttpVersion::ALL {
            assert_eq!(HttpVersion::parse(version.as_str()), Some(version));
            assert_eq!(version.to_string(), version.as_str());
            if let Some(alpn) = version.alpn() {
                assert_eq!(HttpVersion::parse(alpn), Some(version));
            }
        }
        assert_eq!(HttpVersion::default(), HttpVersion::Http11);
        assert!(HttpVersion::Http10 < HttpVersion::Http2);
    }

    #[test]
    fn from_str_reports_unknown() {
        assert_eq!("HTTP/3".parse::<HttpVersion>(), Ok(HttpVersion::Http3));
        let error = "gopher".parse::<HttpVersion>().unwrap_err();
        assert_eq!(error, HttpModelError::UnknownVersion("gopher".to_owned()));
        assert_eq!(error.code(), "unknown_http_version");
    }
}
