//! `Set-Cookie` parsing ([RFC 6265 §5.2]) and serialization ([§4.1]).
//!
//! [RFC 6265 §5.2]: https://www.rfc-editor.org/rfc/rfc6265#section-5.2
//! [§4.1]: https://www.rfc-editor.org/rfc/rfc6265#section-4.1

use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;

use crate::Error;
use crate::date::{format_cookie_date, parse_cookie_date};

/// The longest name plus value a cookie may have, in bytes
/// ([RFC 6265bis §5.6] step 4).
///
/// [RFC 6265bis §5.6]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-5.6
pub const MAX_NAME_VALUE_LEN: usize = 4096;

/// The longest attribute value that is honoured, in bytes; longer
/// attributes are ignored ([RFC 6265bis §5.6] step 6).
///
/// [RFC 6265bis §5.6]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-5.6
pub const MAX_ATTRIBUTE_VALUE_LEN: usize = 1024;

/// The `SameSite` attribute ([RFC 6265bis §4.1.2.7]).
///
/// [RFC 6265bis §4.1.2.7]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-4.1.2.7
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum SameSite {
    /// Sent only with same-site requests.
    Strict,
    /// Sent with same-site requests and cross-site top-level navigations
    /// that use a safe method.
    Lax,
    /// Sent with every request (the cookie must be `Secure` to be stored).
    None,
}

impl SameSite {
    /// The attribute value: `Strict`, `Lax` or `None`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }

    /// Parses an attribute value, ignoring ASCII case. `None` for anything
    /// else (which a user agent treats as if the attribute were absent).
    #[must_use]
    pub fn from_attribute(value: &str) -> Option<Self> {
        [Self::Strict, Self::Lax, Self::None]
            .into_iter()
            .find(|candidate| value.eq_ignore_ascii_case(candidate.as_str()))
    }
}

impl fmt::Display for SameSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One `cookie-av` exactly as received (whitespace-trimmed), in wire order.
///
/// [`SetCookie`] keeps these next to the interpreted fields, so analyzers
/// can see duplicated, unknown, oversized or unparseable attributes that
/// the interpretation dropped.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RawAttribute {
    /// The attribute name, case preserved.
    pub name: String,
    /// The text after the first `=`, or `None` if there was no `=`.
    pub value: Option<String>,
}

/// A parsed `Set-Cookie` header value.
///
/// The fields hold the interpretation of [RFC 6265 §5.2]: when an attribute
/// appears more than once the last valid one wins, invalid `Expires`,
/// `Max-Age` and empty `Domain` attributes are ignored, and a `Path` that
/// does not start with `/` means the default path. `SameSite` and
/// `Partitioned` come from RFC 6265bis and CHIPS. [`attributes`] keeps every
/// attribute as received.
///
/// Build one with [`SetCookie::new`] and the `with_*` methods, or parse it
/// with [`SetCookie::parse`] (also [`FromStr`]). [`Display`](fmt::Display)
/// writes a header value back.
///
/// ```
/// use rune_cookie::{SameSite, SetCookie};
///
/// let cookie = SetCookie::parse("sid=abc; Path=/; Secure; HttpOnly; SameSite=lax; Max-Age=60")?;
/// assert_eq!((cookie.name.as_str(), cookie.value.as_str()), ("sid", "abc"));
/// assert_eq!(cookie.path.as_deref(), Some("/"));
/// assert!(cookie.secure && cookie.http_only);
/// assert_eq!(cookie.same_site, Some(SameSite::Lax));
/// assert_eq!(cookie.max_age, Some(60));
/// assert_eq!(cookie.to_string(), "sid=abc; Max-Age=60; Path=/; Secure; HttpOnly; SameSite=Lax");
/// # Ok::<(), rune_cookie::Error>(())
/// ```
///
/// [RFC 6265 §5.2]: https://www.rfc-editor.org/rfc/rfc6265#section-5.2
/// [`attributes`]: SetCookie::attributes
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct SetCookie {
    /// The cookie name (never empty after parsing).
    pub name: String,
    /// The cookie value, including any surrounding double quotes.
    pub value: String,
    /// `Expires`, if a valid one was given.
    pub expires: Option<SystemTime>,
    /// `Max-Age` in seconds, if a valid one was given. Values beyond the
    /// range of `i64` saturate. Zero or negative means "expire now".
    pub max_age: Option<i64>,
    /// `Domain`, without its leading dot and lowercased; `None` if absent
    /// or empty.
    pub domain: Option<String>,
    /// `Path`, if it starts with `/`; `None` means the default path.
    pub path: Option<String>,
    /// `Secure` was present.
    pub secure: bool,
    /// `HttpOnly` was present.
    pub http_only: bool,
    /// `SameSite`, if a recognised value was given.
    pub same_site: Option<SameSite>,
    /// `Partitioned` (CHIPS) was present.
    pub partitioned: bool,
    /// Every attribute as received, in order. Empty for a cookie built
    /// with [`SetCookie::new`].
    pub attributes: Vec<RawAttribute>,
}

impl SetCookie {
    /// A cookie with only a name and a value, as `name=value` would parse.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            expires: None,
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: None,
            partitioned: false,
            attributes: Vec::new(),
        }
    }

    /// Sets `Expires`.
    #[must_use]
    pub const fn with_expires(mut self, expires: SystemTime) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Sets `Max-Age`, in seconds.
    #[must_use]
    pub const fn with_max_age(mut self, seconds: i64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Sets `Domain`. A leading dot is dropped and the name lowercased, as
    /// the parser would.
    #[must_use]
    pub fn with_domain(mut self, domain: impl AsRef<str>) -> Self {
        let domain = domain.as_ref();
        let domain = domain.strip_prefix('.').unwrap_or(domain);
        self.domain = (!domain.is_empty()).then(|| domain.to_lowercase());
        self
    }

    /// Sets `Path`.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Sets or clears `Secure`.
    #[must_use]
    pub const fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Sets or clears `HttpOnly`.
    #[must_use]
    pub const fn with_http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// Sets `SameSite`.
    #[must_use]
    pub const fn with_same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = Some(same_site);
        self
    }

    /// Sets or clears `Partitioned`.
    #[must_use]
    pub const fn with_partitioned(mut self, partitioned: bool) -> Self {
        self.partitioned = partitioned;
        self
    }

    /// Parses a `Set-Cookie` header value with the algorithm of
    /// [RFC 6265 §5.2], plus the RFC 6265bis limits and attributes.
    ///
    /// # Errors
    ///
    /// - [`Error::MissingSeparator`]: the name-value pair has no `=`.
    /// - [`Error::EmptyName`]: the name is empty after trimming.
    /// - [`Error::ControlCharacter`]: the header contains a control
    ///   character other than horizontal tab (RFC 6265bis §5.6 step 2).
    /// - [`Error::TooLong`]: name plus value exceed
    ///   [`MAX_NAME_VALUE_LEN`] bytes.
    ///
    /// [RFC 6265 §5.2]: https://www.rfc-editor.org/rfc/rfc6265#section-5.2
    pub fn parse(header: &str) -> Result<Self, Error> {
        if header
            .bytes()
            .any(|b| (b < 0x20 && b != b'\t') || b == 0x7F)
        {
            return Err(Error::ControlCharacter);
        }
        let (pair, attributes) = header.split_once(';').unwrap_or((header, ""));
        let (name, value) = pair.split_once('=').ok_or(Error::MissingSeparator)?;
        let (name, value) = (trim_wsp(name), trim_wsp(value));
        if name.is_empty() {
            return Err(Error::EmptyName);
        }
        if name.len() + value.len() > MAX_NAME_VALUE_LEN {
            return Err(Error::TooLong {
                len: name.len() + value.len(),
            });
        }
        let mut cookie = Self::new(name, value);
        for av in attributes.split(';') {
            let (attr_name, attr_value) = match av.split_once('=') {
                Some((n, v)) => (trim_wsp(n), Some(trim_wsp(v))),
                None => (trim_wsp(av), None),
            };
            if attr_name.is_empty() && attr_value.is_none() {
                continue;
            }
            cookie.attributes.push(RawAttribute {
                name: attr_name.to_owned(),
                value: attr_value.map(str::to_owned),
            });
            let value = attr_value.unwrap_or("");
            if value.len() > MAX_ATTRIBUTE_VALUE_LEN {
                continue;
            }
            cookie.apply_attribute(attr_name, value);
        }
        Ok(cookie)
    }

    /// Interprets one attribute (RFC 6265 §5.2.1–§5.2.6, RFC 6265bis
    /// §5.6.7, CHIPS).
    fn apply_attribute(&mut self, name: &str, value: &str) {
        if name.eq_ignore_ascii_case("expires") {
            if let Some(expires) = parse_cookie_date(value) {
                self.expires = Some(expires);
            }
        } else if name.eq_ignore_ascii_case("max-age") {
            if let Some(max_age) = parse_max_age(value) {
                self.max_age = Some(max_age);
            }
        } else if name.eq_ignore_ascii_case("domain") {
            // An empty value is ignored (§5.2.3); `Domain=.` means "no
            // domain", so the cookie is host-only (§5.3 step 6).
            if !value.is_empty() {
                let domain = value.strip_prefix('.').unwrap_or(value);
                self.domain = (!domain.is_empty()).then(|| domain.to_lowercase());
            }
        } else if name.eq_ignore_ascii_case("path") {
            self.path = value.starts_with('/').then(|| value.to_owned());
        } else if name.eq_ignore_ascii_case("secure") {
            self.secure = true;
        } else if name.eq_ignore_ascii_case("httponly") {
            self.http_only = true;
        } else if name.eq_ignore_ascii_case("samesite") {
            self.same_site = SameSite::from_attribute(value);
        } else if name.eq_ignore_ascii_case("partitioned") {
            self.partitioned = true;
        }
    }

    /// Whether the name has the `__Secure-` prefix (ASCII case-insensitive,
    /// RFC 6265bis §4.1.3.1).
    #[must_use]
    pub fn has_secure_prefix(&self) -> bool {
        has_prefix_ci(&self.name, "__Secure-")
    }

    /// Whether the name has the `__Host-` prefix (ASCII case-insensitive,
    /// RFC 6265bis §4.1.3.2).
    #[must_use]
    pub fn has_host_prefix(&self) -> bool {
        has_prefix_ci(&self.name, "__Host-")
    }

    /// Whether the cookie would persist past the session: it has a valid
    /// `Max-Age` or `Expires`.
    #[must_use]
    pub const fn is_persistent(&self) -> bool {
        self.max_age.is_some() || self.expires.is_some()
    }
}

impl FromStr for SetCookie {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Writes the header value from the interpreted fields (not from
/// [`SetCookie::attributes`]), in the order `Expires`, `Max-Age`, `Domain`,
/// `Path`, `Secure`, `HttpOnly`, `SameSite`, `Partitioned`.
impl fmt::Display for SetCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.value)?;
        if let Some(expires) = self.expires {
            write!(f, "; Expires={}", format_cookie_date(expires))?;
        }
        if let Some(max_age) = self.max_age {
            write!(f, "; Max-Age={max_age}")?;
        }
        if let Some(domain) = &self.domain {
            // The parser trims whitespace and then drops one leading dot,
            // so a domain that still starts with either needs a dot to
            // survive a round trip.
            let dot = if domain.starts_with(['.', ' ', '\t']) {
                "."
            } else {
                ""
            };
            write!(f, "; Domain={dot}{domain}")?;
        }
        if let Some(path) = &self.path {
            write!(f, "; Path={path}")?;
        }
        if self.secure {
            f.write_str("; Secure")?;
        }
        if self.http_only {
            f.write_str("; HttpOnly")?;
        }
        if let Some(same_site) = self.same_site {
            write!(f, "; SameSite={same_site}")?;
        }
        if self.partitioned {
            f.write_str("; Partitioned")?;
        }
        Ok(())
    }
}

/// `Max-Age`: an optional `-` then one or more digits (RFC 6265 §5.2.2).
fn parse_max_age(value: &str) -> Option<i64> {
    let (negative, digits) = value
        .strip_prefix('-')
        .map_or((false, value), |rest| (true, rest));
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let magnitude = digits.bytes().fold(0_i64, |acc, d| {
        acc.saturating_mul(10).saturating_add(i64::from(d - b'0'))
    });
    Some(if negative { -magnitude } else { magnitude })
}

/// Trims spaces and horizontal tabs (`WSP`), and nothing else.
pub fn trim_wsp(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

fn has_prefix_ci(name: &str, prefix: &str) -> bool {
    name.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_value_only() {
        let cookie = SetCookie::parse("  foo = bar baz ").unwrap();
        assert_eq!(cookie, SetCookie::new("foo", "bar baz"));
        assert_eq!(cookie.to_string(), "foo=bar baz");
    }

    #[test]
    fn value_may_contain_equals_and_quotes() {
        let cookie = SetCookie::parse("a=b=c").unwrap();
        assert_eq!(cookie.value, "b=c");
        let cookie = SetCookie::parse("a=\"x y\"").unwrap();
        assert_eq!(cookie.value, "\"x y\"");
        let cookie = SetCookie::parse("a=").unwrap();
        assert_eq!(cookie.value, "");
    }

    #[test]
    fn errors() {
        assert_eq!(SetCookie::parse("foo"), Err(Error::MissingSeparator));
        assert_eq!(SetCookie::parse("; a=b"), Err(Error::MissingSeparator));
        assert_eq!(SetCookie::parse(" =bar"), Err(Error::EmptyName));
        assert_eq!(
            SetCookie::parse("a=b\r\nX: y"),
            Err(Error::ControlCharacter)
        );
        assert_eq!(SetCookie::parse("a=b\0"), Err(Error::ControlCharacter));
        assert!(SetCookie::parse("a=b\t; Path=/").is_ok());
        let long = format!("a={}", "x".repeat(MAX_NAME_VALUE_LEN));
        assert_eq!(SetCookie::parse(&long), Err(Error::TooLong { len: 4097 }));
    }

    #[test]
    fn attributes_last_valid_wins() {
        let cookie = SetCookie::parse(
            "a=b; domain=Example.COM; DOMAIN=; path=/x; Path=relative; max-age=5; max-age=x; \
             samesite=strict; SameSite=bogus; Expires=nope",
        )
        .unwrap();
        assert_eq!(cookie.domain.as_deref(), Some("example.com"));
        assert_eq!(cookie.path, None);
        assert_eq!(cookie.max_age, Some(5));
        assert_eq!(cookie.same_site, None);
        assert_eq!(cookie.expires, None);
        assert_eq!(cookie.attributes.len(), 9);
        assert_eq!(
            cookie.attributes[1],
            RawAttribute {
                name: "DOMAIN".into(),
                value: Some(String::new())
            }
        );
    }

    #[test]
    fn domain_leading_dot_stripped_once() {
        let cookie = SetCookie::parse("a=b; Domain=..example.com").unwrap();
        assert_eq!(cookie.domain.as_deref(), Some(".example.com"));
        // Regression (fuzz): the extra dot must survive serialization.
        assert_eq!(cookie.to_string(), "a=b; Domain=..example.com");
        let cookie = SetCookie::parse("a=b; Domain=. x").unwrap();
        assert_eq!(cookie.to_string(), "a=b; Domain=. x");
        assert_eq!(
            SetCookie::parse(&cookie.to_string())
                .unwrap()
                .domain
                .as_deref(),
            Some(" x")
        );
        let cookie = SetCookie::parse("a=b; Domain=example.com; Domain=.").unwrap();
        assert_eq!(cookie.domain, None);
    }

    #[test]
    fn max_age_forms() {
        assert_eq!(parse_max_age("0"), Some(0));
        assert_eq!(parse_max_age("-1"), Some(-1));
        assert_eq!(parse_max_age("+1"), None);
        assert_eq!(parse_max_age("-"), None);
        assert_eq!(parse_max_age("1e3"), None);
        assert_eq!(parse_max_age("99999999999999999999999"), Some(i64::MAX));
        assert_eq!(parse_max_age("-99999999999999999999999"), Some(-i64::MAX));
    }

    #[test]
    fn oversized_attribute_ignored() {
        let header = format!("a=b; Path=/{}", "p".repeat(MAX_ATTRIBUTE_VALUE_LEN));
        let cookie = SetCookie::parse(&header).unwrap();
        assert_eq!(cookie.path, None);
        assert_eq!(cookie.attributes.len(), 1);
    }

    #[test]
    fn flags_and_prefixes() {
        let cookie = SetCookie::parse("__host-id=1; secure; HTTPONLY; Partitioned").unwrap();
        assert!(cookie.secure && cookie.http_only && cookie.partitioned);
        assert!(cookie.has_host_prefix());
        assert!(!cookie.has_secure_prefix());
        assert!(!cookie.is_persistent());
    }

    #[test]
    fn display_round_trip() {
        let expires = parse_cookie_date("Wed, 21 Oct 2015 07:28:00 GMT").unwrap();
        let cookie = SetCookie::new("id", "a3fWa")
            .with_expires(expires)
            .with_max_age(-1)
            .with_domain(".Example.org")
            .with_path("/docs")
            .with_secure(true)
            .with_http_only(true)
            .with_same_site(SameSite::None)
            .with_partitioned(true);
        let text = cookie.to_string();
        assert_eq!(
            text,
            "id=a3fWa; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=-1; Domain=example.org; \
             Path=/docs; Secure; HttpOnly; SameSite=None; Partitioned"
        );
        let mut reparsed: SetCookie = text.parse().unwrap();
        reparsed.attributes.clear();
        assert_eq!(reparsed, cookie);
    }
}
