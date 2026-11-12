//! Serialized web origins (`scheme://host[:port]`), as sent in the `Origin`
//! request header and echoed in `Access-Control-Allow-Origin`.

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// A tuple origin: scheme, host and optional non-default port
/// ([RFC 6454](https://www.rfc-editor.org/rfc/rfc6454),
/// [HTML origin serialization](https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin)).
///
/// Parsing lowercases the scheme and host and drops a default port, so
/// [`Display`](fmt::Display) yields the serialization browsers send. An
/// `Access-Control-Allow-Origin` value only matches when it is byte-equal to
/// that serialization.
///
/// ```
/// use rune_cors::Origin;
///
/// let o: Origin = "HTTPS://API.Example.com:443".parse()?;
/// assert_eq!(o.to_string(), "https://api.example.com");
/// assert_eq!(o.effective_port(), Some(443));
/// assert!(o.is_secure());
/// # Ok::<(), rune_cors::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Origin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl Origin {
    /// Parses a serialized origin. Paths, queries, fragments, user info and
    /// non-ASCII hosts are rejected; `null` is not a tuple origin and is
    /// rejected too.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let err = |reason: &'static str| Error::InvalidOrigin {
            input: input.to_owned(),
            reason,
        };
        let (scheme, rest) = input
            .split_once("://")
            .ok_or_else(|| err("missing \"://\""))?;
        let mut chars = scheme.chars();
        if !chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            || !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        {
            return Err(err("invalid scheme"));
        }
        if rest.contains(['/', '?', '#', '@']) {
            return Err(err("an origin has no path, query, fragment or user info"));
        }
        let (host, port) = if let Some(after) = rest.strip_prefix('[') {
            let (inner, tail) = after
                .split_once(']')
                .ok_or_else(|| err("unterminated IPv6 literal"))?;
            if inner.is_empty()
                || !inner
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
            {
                return Err(err("invalid IPv6 literal"));
            }
            let port = match tail {
                "" => None,
                t => Some(t.strip_prefix(':').ok_or_else(|| err("junk after host"))?),
            };
            (format!("[{inner}]"), port)
        } else {
            let (host, port) = rest
                .split_once(':')
                .map_or((rest, None), |(h, p)| (h, Some(p)));
            if host.is_empty()
                || !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
            {
                return Err(err("invalid host"));
            }
            (host.to_owned(), port)
        };
        let port = match port {
            None => None,
            Some(p) => {
                if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(err("invalid port"));
                }
                Some(p.parse::<u16>().map_err(|_| err("port out of range"))?)
            }
        };
        let scheme = scheme.to_ascii_lowercase();
        let port = port.filter(|p| default_port(&scheme) != Some(*p));
        Ok(Self {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    /// Builds an origin from parts; the result is normalized like
    /// [`Origin::parse`].
    pub fn new(scheme: &str, host: &str, port: Option<u16>) -> Result<Self, Error> {
        let text = port.map_or_else(
            || format!("{scheme}://{host}"),
            |p| format!("{scheme}://{host}:{p}"),
        );
        Self::parse(&text)
    }

    /// The lowercase scheme, e.g. `https`.
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The lowercase host; IPv6 literals keep their brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The explicit port, `None` when it is the scheme's default.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// The port in use: the explicit one, or the scheme default for
    /// `http`, `https`, `ws` and `wss`.
    #[must_use]
    pub fn effective_port(&self) -> Option<u16> {
        self.port.or_else(|| default_port(&self.scheme))
    }

    /// Whether the scheme is `https` or `wss`, so the origin cannot be
    /// spoofed by a network attacker.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        matches!(self.scheme.as_str(), "https" | "wss")
    }

    /// Whether `self`'s host is a strict subdomain of `other`'s host
    /// (`a.example.com` of `example.com`). Schemes and ports are ignored.
    #[must_use]
    pub fn is_subdomain_of(&self, other: &Self) -> bool {
        self.host
            .strip_suffix(other.host.as_str())
            .is_some_and(|label| label.len() > 1 && label.ends_with('.'))
    }
}

/// The default port of a special scheme.
fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}", self.scheme, self.host)?;
        if let Some(p) = self.port {
            write!(f, ":{p}")?;
        }
        Ok(())
    }
}

impl FromStr for Origin {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes() {
        let o = Origin::parse("HTTPS://Example.COM").unwrap();
        assert_eq!(o.to_string(), "https://example.com");
        assert_eq!(o.port(), None);
        assert_eq!(
            Origin::parse("http://example.com:80").unwrap().to_string(),
            "http://example.com"
        );
        assert_eq!(
            Origin::parse("https://example.com:8443")
                .unwrap()
                .to_string(),
            "https://example.com:8443"
        );
        assert_eq!(
            Origin::parse("http://[::1]:3000").unwrap().to_string(),
            "http://[::1]:3000"
        );
        assert_eq!(
            Origin::parse("chrome-extension://abcdef")
                .unwrap()
                .effective_port(),
            None
        );
    }

    #[test]
    fn rejects_non_origins() {
        for bad in [
            "",
            "null",
            "*",
            "example.com",
            "https://",
            "https://example.com/",
            "https://example.com/path",
            "https://user@example.com",
            "https://example.com:",
            "https://example.com:65536",
            "https://example.com:8a",
            "https://exa mple.com",
            "https://exämple.com",
            "1https://example.com",
            "https://[::1",
            "https://[]",
            "https://[::1]x",
        ] {
            assert!(Origin::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn subdomains() {
        let base = Origin::parse("https://example.com").unwrap();
        let sub = Origin::parse("http://a.b.example.com").unwrap();
        let fake = Origin::parse("https://evilexample.com").unwrap();
        assert!(sub.is_subdomain_of(&base));
        assert!(!fake.is_subdomain_of(&base));
        assert!(!base.is_subdomain_of(&base));
        assert!(
            !Origin::parse("https://.example.com")
                .unwrap()
                .is_subdomain_of(&base)
        );
    }

    #[test]
    fn new_matches_parse() {
        assert_eq!(
            Origin::new("HTTPS", "Example.com", Some(443)).unwrap(),
            Origin::parse("https://example.com").unwrap()
        );
    }
}
