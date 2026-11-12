//! The CORS response headers of one HTTP response.

use std::fmt;

use crate::origin::Origin;

/// The value of `Access-Control-Allow-Origin`, as the
/// [Fetch CORS check](https://fetch.spec.whatwg.org/#cors-check) reads it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AllowOrigin {
    /// The header is absent: no cross-origin read is allowed.
    Missing,
    /// `*`: any origin may read, but only without credentials.
    Any,
    /// `null`: documents with an opaque origin (sandboxed frames, `data:`
    /// and `file:` URLs) may read.
    Null,
    /// One serialized origin, written exactly as browsers send it.
    Origin(Origin),
    /// A value no browser request can match: several values, a list,
    /// non-canonical case or port, a path, or garbage. The raw text is kept.
    Invalid(String),
}

impl AllowOrigin {
    /// Interprets a combined header value.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value {
            "*" => Self::Any,
            "null" => Self::Null,
            v => match Origin::parse(v) {
                // The Fetch check compares bytes, so only the canonical
                // serialization can ever match a request's `Origin`.
                Ok(o) if o.to_string() == v => Self::Origin(o),
                _ => Self::Invalid(v.to_owned()),
            },
        }
    }

    /// The origin this value grants access to, when it names one: the
    /// serialized origin or `null`.
    #[must_use]
    pub fn granted(&self) -> Option<String> {
        match self {
            Self::Null => Some("null".to_owned()),
            Self::Origin(o) => Some(o.to_string()),
            _ => None,
        }
    }
}

impl fmt::Display for AllowOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => Ok(()),
            Self::Any => f.write_str("*"),
            Self::Null => f.write_str("null"),
            Self::Origin(o) => o.fmt(f),
            Self::Invalid(v) => f.write_str(v),
        }
    }
}

/// The CORS-relevant response headers, collected from name/value pairs.
///
/// Header names are matched case-insensitively and values are trimmed of
/// HTTP whitespace. A header that occurs more than once is combined with
/// `", "`, as Fetch's "get" does, so a duplicated
/// `Access-Control-Allow-Origin` becomes [`AllowOrigin::Invalid`].
///
/// ```
/// use rune_cors::{AllowOrigin, CorsHeaders};
///
/// let h = CorsHeaders::from_pairs([
///     ("access-control-allow-origin", "https://app.example"),
///     ("Access-Control-Allow-Credentials", "true"),
///     ("Vary", "Accept-Encoding, Origin"),
/// ]);
/// assert!(matches!(h.allow_origin(), AllowOrigin::Origin(_)));
/// assert!(h.allows_credentials());
/// assert!(h.varies_on_origin());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CorsHeaders {
    /// Combined `Access-Control-Allow-Origin`, if present.
    pub allow_origin: Option<String>,
    /// Combined `Access-Control-Allow-Credentials`, if present.
    pub allow_credentials: Option<String>,
    /// `Access-Control-Allow-Methods` list members.
    pub allow_methods: Vec<String>,
    /// `Access-Control-Allow-Headers` list members.
    pub allow_headers: Vec<String>,
    /// `Access-Control-Expose-Headers` list members.
    pub expose_headers: Vec<String>,
    /// Combined `Access-Control-Max-Age`, if present.
    pub max_age: Option<String>,
    /// Combined `Access-Control-Allow-Private-Network`, if present.
    pub allow_private_network: Option<String>,
    /// `Vary` list members, lowercased.
    pub vary: Vec<String>,
}

impl CorsHeaders {
    /// Collects the CORS headers from `(name, value)` pairs; other headers
    /// are ignored.
    pub fn from_pairs<I, N, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<str>,
        V: AsRef<str>,
    {
        let mut h = Self::default();
        for (name, value) in pairs {
            h.push(name.as_ref(), value.as_ref());
        }
        h
    }

    /// Parses a raw response header block, such as `curl -sI` output: one
    /// `Name: value` per line. Status lines, blank lines and lines that are
    /// not headers are skipped.
    ///
    /// ```
    /// use rune_cors::CorsHeaders;
    ///
    /// let h = CorsHeaders::parse_block(
    ///     "HTTP/2 200\r\naccess-control-allow-origin: *\r\ncontent-type: text/html\r\n",
    /// );
    /// assert_eq!(h.allow_origin.as_deref(), Some("*"));
    /// ```
    #[must_use]
    pub fn parse_block(block: &str) -> Self {
        let mut h = Self::default();
        for line in block.lines() {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if is_token(name) {
                h.push(name, value);
            }
        }
        h
    }

    /// Adds one header; non-CORS headers are ignored.
    pub fn push(&mut self, name: &str, value: &str) {
        let value = value.trim_matches([' ', '\t', '\r', '\n']);
        let name = name.trim_matches([' ', '\t']).to_ascii_lowercase();
        match name.as_str() {
            "access-control-allow-origin" => combine(&mut self.allow_origin, value),
            "access-control-allow-credentials" => combine(&mut self.allow_credentials, value),
            "access-control-allow-methods" => extend_list(&mut self.allow_methods, value, false),
            "access-control-allow-headers" => extend_list(&mut self.allow_headers, value, false),
            "access-control-expose-headers" => extend_list(&mut self.expose_headers, value, false),
            "access-control-max-age" => combine(&mut self.max_age, value),
            "access-control-allow-private-network" => {
                combine(&mut self.allow_private_network, value);
            }
            "vary" => extend_list(&mut self.vary, value, true),
            _ => {}
        }
    }

    /// `Access-Control-Allow-Origin`, interpreted.
    #[must_use]
    pub fn allow_origin(&self) -> AllowOrigin {
        self.allow_origin
            .as_deref()
            .map_or(AllowOrigin::Missing, AllowOrigin::parse)
    }

    /// Whether `Access-Control-Allow-Credentials` is exactly `true`, the
    /// only value browsers accept.
    #[must_use]
    pub fn allows_credentials(&self) -> bool {
        self.allow_credentials.as_deref() == Some("true")
    }

    /// Whether `Access-Control-Allow-Private-Network` is exactly `true`.
    #[must_use]
    pub fn allows_private_network(&self) -> bool {
        self.allow_private_network.as_deref() == Some("true")
    }

    /// Whether `Vary` lists `Origin` or `*`, so caches keep per-origin
    /// copies.
    #[must_use]
    pub fn varies_on_origin(&self) -> bool {
        self.vary.iter().any(|v| v == "origin" || v == "*")
    }

    /// Whether no CORS header at all was seen.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.allow_origin.is_none()
            && self.allow_credentials.is_none()
            && self.allow_methods.is_empty()
            && self.allow_headers.is_empty()
            && self.expose_headers.is_empty()
            && self.max_age.is_none()
            && self.allow_private_network.is_none()
    }
}

/// Combines repeated header values with `", "`.
fn combine(slot: &mut Option<String>, value: &str) {
    match slot {
        Some(existing) => {
            existing.push_str(", ");
            existing.push_str(value);
        }
        None => *slot = Some(value.to_owned()),
    }
}

/// Appends the non-empty members of a comma-separated list.
fn extend_list(list: &mut Vec<String>, value: &str, lowercase: bool) {
    for item in value.split(',') {
        let item = item.trim_matches([' ', '\t']);
        if !item.is_empty() {
            list.push(if lowercase {
                item.to_ascii_lowercase()
            } else {
                item.to_owned()
            });
        }
    }
}

/// Whether `s` is an HTTP token (RFC 9110 §5.6.2).
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_origin_values() {
        assert_eq!(AllowOrigin::parse("*"), AllowOrigin::Any);
        assert_eq!(AllowOrigin::parse("null"), AllowOrigin::Null);
        assert!(matches!(
            AllowOrigin::parse("https://a.example"),
            AllowOrigin::Origin(_)
        ));
        for bad in [
            "",
            "NULL",
            "https://A.example",
            "https://a.example:443",
            "https://a.example/",
            "https://a.example, https://b.example",
            "https://a.example https://b.example",
            "*, *",
        ] {
            assert_eq!(
                AllowOrigin::parse(bad),
                AllowOrigin::Invalid(bad.to_owned())
            );
        }
    }

    #[test]
    fn duplicates_combine() {
        let h = CorsHeaders::from_pairs([
            ("Access-Control-Allow-Origin", "*"),
            ("access-control-allow-origin", " * "),
        ]);
        assert_eq!(h.allow_origin.as_deref(), Some("*, *"));
        assert!(matches!(h.allow_origin(), AllowOrigin::Invalid(_)));
    }

    #[test]
    fn credentials_exactly_true() {
        for (v, ok) in [
            ("true", true),
            ("True", false),
            ("false", false),
            ("1", false),
        ] {
            let h = CorsHeaders::from_pairs([("access-control-allow-credentials", v)]);
            assert_eq!(h.allows_credentials(), ok, "{v}");
        }
    }

    #[test]
    fn block_skips_non_headers() {
        let h = CorsHeaders::parse_block(
            "HTTP/1.1 200 OK\nbad header: x\n\nVary: Accept, ORIGIN\nAccess-Control-Allow-Methods: GET,  POST,\n",
        );
        assert!(h.varies_on_origin());
        assert_eq!(h.allow_methods, ["GET", "POST"]);
        assert!(h.allow_origin.is_none());
        assert!(!h.is_empty());
        assert!(CorsHeaders::parse_block("HTTP/2 204\r\n").is_empty());
    }
}
