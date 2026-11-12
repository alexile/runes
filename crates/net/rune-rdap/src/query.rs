//! RDAP lookup queries and their URL paths
//! ([RFC 9082 §3.1](https://www.rfc-editor.org/rfc/rfc9082#section-3.1)).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::Error;

/// Longest handle accepted by [`Query::entity`].
const MAX_HANDLE_LEN: usize = 255;

/// One RDAP lookup.
///
/// Build it with [`Query::parse`] (which guesses the kind from the text)
/// or with the typed constructors. Domain and nameserver names are
/// normalised to lower-case A-labels (IDNA/UTS 46), without a trailing dot.
///
/// ```
/// use rune_rdap::Query;
///
/// assert_eq!(Query::parse("Example.COM.")?.path(), "domain/example.com");
/// assert_eq!(Query::parse("bücher.de")?.path(), "domain/xn--bcher-kva.de");
/// assert_eq!(Query::parse("AS15169")?.path(), "autnum/15169");
/// assert_eq!(Query::parse("2001:db8::/32")?.path(), "ip/2001:db8::/32");
/// assert_eq!(Query::parse("8.8.8.8")?.path(), "ip/8.8.8.8");
/// assert_eq!(Query::parse("ZG39-ARIN")?.path(), "entity/ZG39-ARIN");
/// # Ok::<(), rune_rdap::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Query {
    /// A domain name (`domain/<name>`).
    Domain(String),
    /// The network that contains one address (`ip/<addr>`).
    Ip(IpAddr),
    /// A CIDR block (`ip/<addr>/<len>`). The address has its host bits
    /// cleared.
    Network {
        /// The network address.
        addr: IpAddr,
        /// The prefix length.
        prefix: u8,
    },
    /// An autonomous system number (`autnum/<n>`).
    Autnum(u32),
    /// A nameserver host name (`nameserver/<name>`).
    Nameserver(String),
    /// An entity handle (`entity/<handle>`), routed by its object tag
    /// ([RFC 8521](https://www.rfc-editor.org/rfc/rfc8521)).
    Entity(String),
}

impl Query {
    /// Guesses the kind of `input`: `AS<n>` is an ASN, an address or
    /// `addr/len` is an IP query, text containing a dot is a domain, and
    /// anything else is an entity handle.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let text = input.trim();
        if text.is_empty() {
            return Err(invalid(input, "empty query"));
        }
        if let Some(digits) = text
            .strip_prefix("AS")
            .or_else(|| text.strip_prefix("as"))
            .or_else(|| text.strip_prefix("As"))
            .or_else(|| text.strip_prefix("aS"))
            && !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Self::autnum_str(input, digits);
        }
        if let Ok(ip) = text.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        if let Some((addr, len)) = text.split_once('/')
            && let Ok(addr) = addr.parse::<IpAddr>()
        {
            let prefix = len
                .parse::<u8>()
                .map_err(|_| invalid(input, "prefix length is not a number"))?;
            return Self::network(addr, prefix);
        }
        if text.contains('.') {
            return Self::domain(text);
        }
        Self::entity(text)
    }

    /// A domain query; `name` may be a U-label or an A-label.
    pub fn domain(name: &str) -> Result<Self, Error> {
        normalize_name(name).map(Self::Domain)
    }

    /// A nameserver query; `name` may be a U-label or an A-label.
    pub fn nameserver(name: &str) -> Result<Self, Error> {
        normalize_name(name).map(Self::Nameserver)
    }

    /// A CIDR query. Fails when `prefix` is longer than the address.
    pub fn network(addr: IpAddr, prefix: u8) -> Result<Self, Error> {
        let addr = mask(addr, prefix).ok_or_else(|| {
            invalid(
                &format!("{addr}/{prefix}"),
                "prefix length exceeds the address size",
            )
        })?;
        Ok(Self::Network { addr, prefix })
    }

    /// An entity query. Handles are sent verbatim (percent-encoded in the
    /// URL); they must be non-empty, at most 255 bytes and free of control
    /// characters and whitespace.
    pub fn entity(handle: &str) -> Result<Self, Error> {
        if handle.is_empty() || handle.len() > MAX_HANDLE_LEN {
            return Err(invalid(handle, "handle must be 1 to 255 bytes"));
        }
        if handle.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(invalid(handle, "handle contains whitespace or controls"));
        }
        Ok(Self::Entity(handle.to_owned()))
    }

    fn autnum_str(input: &str, digits: &str) -> Result<Self, Error> {
        digits
            .parse::<u32>()
            .map(Self::Autnum)
            .map_err(|_| invalid(input, "ASN is out of range"))
    }

    /// The RDAP path segments, without a leading slash, e.g.
    /// `["ip", "192.0.2.0", "24"]`.
    #[must_use]
    pub fn segments(&self) -> Vec<String> {
        match self {
            Self::Domain(name) => vec!["domain".into(), name.clone()],
            Self::Nameserver(name) => vec!["nameserver".into(), name.clone()],
            Self::Ip(ip) => vec!["ip".into(), ip.to_string()],
            Self::Network { addr, prefix } => {
                vec!["ip".into(), addr.to_string(), prefix.to_string()]
            }
            Self::Autnum(asn) => vec!["autnum".into(), asn.to_string()],
            Self::Entity(handle) => vec!["entity".into(), handle.clone()],
        }
    }

    /// The RDAP path, without a leading slash and without percent-encoding,
    /// e.g. `domain/example.com`.
    #[must_use]
    pub fn path(&self) -> String {
        self.segments().join("/")
    }
}

/// Renders the query the way [`Query::parse`] reads it back: a
/// single-label domain (a TLD) keeps a trailing dot so that it is not read
/// as an entity handle. A nameserver renders as its name, which
/// [`Query::parse`] reads as a domain.
impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(name) if !name.contains('.') => write!(f, "{name}."),
            Self::Domain(name) | Self::Nameserver(name) | Self::Entity(name) => f.write_str(name),
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Network { addr, prefix } => write!(f, "{addr}/{prefix}"),
            Self::Autnum(asn) => write!(f, "AS{asn}"),
        }
    }
}

impl FromStr for Query {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn invalid(input: &str, reason: &'static str) -> Error {
    Error::InvalidQuery {
        input: input.to_owned(),
        reason,
    }
}

/// Lower-case A-label form of a domain or host name, without the root dot.
pub fn normalize_name(name: &str) -> Result<String, Error> {
    let trimmed = name.trim();
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return Err(invalid(name, "empty domain name"));
    }
    if trimmed.contains(['/', '?', '#', '@', ':', '%', '\\']) {
        return Err(invalid(name, "domain name contains URL delimiters"));
    }
    match url::Host::parse(trimmed) {
        Ok(url::Host::Domain(ascii)) => {
            if ascii.len() > 253 || ascii.split('.').any(|l| l.is_empty() || l.len() > 63) {
                return Err(invalid(name, "domain name or label too long or empty"));
            }
            Ok(ascii)
        }
        Ok(_) => Err(invalid(name, "an IP address is not a domain name")),
        Err(_) => Err(invalid(name, "not a valid domain name")),
    }
}

/// `addr` with the bits beyond `prefix` cleared, or `None` when `prefix` is
/// too long.
pub fn mask(addr: IpAddr, prefix: u8) -> Option<IpAddr> {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = prefix_mask_u32(prefix)?;
            Some(IpAddr::V4((bits & m).into()))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = prefix_mask_u128(prefix)?;
            Some(IpAddr::V6((bits & m).into()))
        }
    }
}

pub fn prefix_mask_u32(prefix: u8) -> Option<u32> {
    match prefix {
        0 => Some(0),
        1..=32 => Some(u32::MAX << (32 - u32::from(prefix))),
        _ => None,
    }
}

pub fn prefix_mask_u128(prefix: u8) -> Option<u128> {
    match prefix {
        0 => Some(0),
        1..=128 => Some(u128::MAX << (128 - u32::from(prefix))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guesses_kinds() {
        assert_eq!(Query::parse("as64496").unwrap(), Query::Autnum(64_496));
        assert_eq!(
            Query::parse(" 192.0.2.1 ").unwrap(),
            Query::Ip("192.0.2.1".parse().unwrap())
        );
        assert_eq!(
            Query::parse("192.0.2.77/24").unwrap(),
            Query::Network {
                addr: "192.0.2.0".parse().unwrap(),
                prefix: 24
            }
        );
        assert_eq!(
            Query::parse("WWW.Example.Org.").unwrap(),
            Query::Domain("www.example.org".into())
        );
        assert_eq!(Query::parse("IANA").unwrap(), Query::Entity("IANA".into()));
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            "   ",
            "AS4294967296",
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/x",
            "exa mple.com",
            "a..b",
            "example.com/path",
            "user@example.com",
            "bad handle",
        ] {
            assert!(Query::parse(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(Query::entity(&"X".repeat(256)).is_err());
        assert!(Query::domain(&format!("{}.com", "a".repeat(64))).is_err());
    }

    #[test]
    fn display_round_trips() {
        for text in [
            "example.com",
            "AS15169",
            "8.8.8.8",
            "2001:db8::/32",
            "ZG39-ARIN",
        ] {
            let q = Query::parse(text).unwrap();
            assert_eq!(q.to_string(), text);
            assert_eq!(Query::parse(&q.to_string()).unwrap(), q);
        }
    }

    // Regression: a TLD query rendered without its dot
    // re-parsed as an entity handle.
    #[test]
    fn tld_round_trips() {
        let q = Query::parse("example.").unwrap();
        assert_eq!(q, Query::Domain("example".into()));
        assert_eq!(q.to_string(), "example.");
        assert_eq!(Query::parse(&q.to_string()).unwrap(), q);
        assert_eq!(q.path(), "domain/example");
    }

    #[test]
    fn nameserver_path() {
        let q = Query::nameserver("NS1.Example.NET.").unwrap();
        assert_eq!(q.path(), "nameserver/ns1.example.net");
    }

    #[test]
    fn masks() {
        assert_eq!(prefix_mask_u32(0), Some(0));
        assert_eq!(prefix_mask_u32(32), Some(u32::MAX));
        assert_eq!(prefix_mask_u32(33), None);
        assert_eq!(prefix_mask_u128(128), Some(u128::MAX));
        assert_eq!(
            mask("2001:db8:ffff::1".parse().unwrap(), 32),
            Some("2001:db8::".parse().unwrap())
        );
    }
}
