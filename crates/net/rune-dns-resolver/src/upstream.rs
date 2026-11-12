//! Upstream servers and how to reach them.

use core::fmt;
use core::str::FromStr;
use std::net::{IpAddr, SocketAddr};

use crate::Error;

/// A recursive resolver to send queries to, and the transport to use.
///
/// The text form ([`FromStr`], [`Display`](fmt::Display)) is:
///
/// | Text                                  | Upstream                           |
/// | ------------------------------------- | ---------------------------------- |
/// | `192.0.2.53`, `[2001:db8::53]:5353`   | UDP (TCP on truncation), port 53   |
/// | `udp://192.0.2.53:53`                 | the same                           |
/// | `tcp://192.0.2.53`                    | TCP only, port 53                  |
/// | `tls://1.1.1.1#cloudflare-dns.com`    | DNS over TLS, port 853; the name after `#` is checked against the certificate (default: the IP) |
/// | `https://dns.google/dns-query`        | DNS over HTTPS (see [`DohEndpoint`]) |
///
/// ```
/// use std::net::SocketAddr;
/// use rune_dns_resolver::Upstream;
///
/// let udp: Upstream = "9.9.9.9".parse()?;
/// assert_eq!(udp, Upstream::udp(SocketAddr::from(([9, 9, 9, 9], 53))));
///
/// let dot: Upstream = "tls://1.1.1.1#cloudflare-dns.com".parse()?;
/// assert_eq!(dot.to_string(), "tls://1.1.1.1:853#cloudflare-dns.com");
///
/// let doh: Upstream = "https://dns.google/dns-query".parse()?;
/// assert_eq!(doh.to_string(), "https://dns.google/dns-query");
/// # Ok::<(), rune_dns_resolver::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Upstream {
    /// Plain DNS over UDP; a truncated answer is retried over TCP.
    Udp(SocketAddr),
    /// Plain DNS over TCP.
    Tcp(SocketAddr),
    /// DNS over TLS (RFC 7858).
    Tls {
        /// Address of the server.
        addr: SocketAddr,
        /// Name (or IP address) its certificate must be valid for.
        server_name: String,
    },
    /// DNS over HTTPS (RFC 8484).
    Https(DohEndpoint),
}

impl Upstream {
    /// UDP, falling back to TCP on truncation.
    #[must_use]
    pub const fn udp(addr: SocketAddr) -> Self {
        Self::Udp(addr)
    }

    /// TCP only.
    #[must_use]
    pub const fn tcp(addr: SocketAddr) -> Self {
        Self::Tcp(addr)
    }

    /// DNS over TLS to `addr`, whose certificate must be valid for
    /// `server_name`.
    #[must_use]
    pub fn tls(addr: SocketAddr, server_name: impl Into<String>) -> Self {
        Self::Tls {
            addr,
            server_name: server_name.into(),
        }
    }

    /// DNS over HTTPS to `url` (see [`DohEndpoint::parse`]).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUpstream`] for a malformed URL.
    pub fn https(url: &str) -> Result<Self, Error> {
        DohEndpoint::parse(url).map(Self::Https)
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp(addr) => write!(f, "udp://{addr}"),
            Self::Tcp(addr) => write!(f, "tcp://{addr}"),
            Self::Tls { addr, server_name } => write!(f, "tls://{addr}#{server_name}"),
            Self::Https(endpoint) => write!(f, "{}", endpoint.url()),
        }
    }
}

impl FromStr for Upstream {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        if text.starts_with("https://") || text.starts_with("http://") {
            return Self::https(text);
        }
        if let Some(rest) = text.strip_prefix("tls://") {
            let (addr, name) = rest
                .split_once('#')
                .map_or((rest, None), |(a, n)| (a, Some(n)));
            let addr = socket_addr(addr, 853)?;
            let server_name = match name {
                Some("") => {
                    return Err(Error::InvalidUpstream {
                        reason: "empty TLS server name",
                    });
                }
                Some(name) => name.to_owned(),
                None => addr.ip().to_string(),
            };
            return Ok(Self::Tls { addr, server_name });
        }
        if let Some(rest) = text.strip_prefix("tcp://") {
            return socket_addr(rest, 53).map(Self::Tcp);
        }
        let rest = text.strip_prefix("udp://").unwrap_or(text);
        socket_addr(rest, 53).map(Self::Udp)
    }
}

/// `ip`, `ip:port`, `[ipv6]` or `[ipv6]:port`.
fn socket_addr(text: &str, default_port: u16) -> Result<SocketAddr, Error> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let ip = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(text);
    ip.parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, default_port))
        .map_err(|_| Error::InvalidUpstream {
            reason: "expected an IP address with an optional port",
        })
}

/// A DNS-over-HTTPS endpoint: an `https://` URL (or `http://`, for local
/// testing and trusted networks), and optionally the address to connect
/// to.
///
/// Without [`DohEndpoint::with_addr`] the host name is resolved with the
/// system resolver when a query is sent; set the address to avoid that
/// bootstrap lookup.
///
/// ```
/// use std::net::SocketAddr;
/// use rune_dns_resolver::DohEndpoint;
///
/// let endpoint = DohEndpoint::parse("https://dns.google/dns-query")?
///     .with_addr(SocketAddr::from(([8, 8, 8, 8], 443)));
/// assert_eq!(endpoint.host(), "dns.google");
/// assert_eq!(endpoint.port(), 443);
/// assert_eq!(endpoint.path(), "/dns-query");
/// assert!(endpoint.is_tls());
/// # Ok::<(), rune_dns_resolver::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DohEndpoint {
    tls: bool,
    host: String,
    port: u16,
    path: String,
    addr: Option<SocketAddr>,
}

impl DohEndpoint {
    /// Parses `https://host[:port][/path]`. The path defaults to
    /// `/dns-query`; an IPv6 host goes in brackets.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUpstream`] for another scheme, an empty or invalid
    /// host, a bad port, user information or a fragment.
    pub fn parse(url: &str) -> Result<Self, Error> {
        let invalid = |reason| Error::InvalidUpstream { reason };
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(invalid("DoH URL must start with https:// or http://"));
        };
        if url.contains('#') {
            return Err(invalid("DoH URL must not have a fragment"));
        }
        let (authority, path) = rest
            .find(['/', '?'])
            .map_or((rest, ""), |at| rest.split_at(at));
        if authority.contains('@') {
            return Err(invalid("DoH URL must not have user information"));
        }
        let default_port = if tls { 443 } else { 80 };
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (ip, after) = bracketed
                .split_once(']')
                .ok_or_else(|| invalid("unclosed '[' in DoH host"))?;
            ip.parse::<std::net::Ipv6Addr>()
                .map_err(|_| invalid("invalid IPv6 address in DoH host"))?;
            let port = match after.strip_prefix(':') {
                Some(port) => port.parse().map_err(|_| invalid("invalid DoH port"))?,
                None if after.is_empty() => default_port,
                None => return Err(invalid("invalid DoH authority")),
            };
            (ip.to_owned(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (
                    host.to_owned(),
                    port.parse().map_err(|_| invalid("invalid DoH port"))?,
                ),
                None => (authority.to_owned(), default_port),
            }
        };
        let host_ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'));
        if !host_ok {
            return Err(invalid("invalid DoH host"));
        }
        let path = match path {
            "" => "/dns-query".to_owned(),
            p if p.starts_with('?') => format!("/{p}"),
            p => p.to_owned(),
        };
        if path.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return Err(invalid("invalid DoH path"));
        }
        Ok(Self {
            tls,
            host: host.to_ascii_lowercase(),
            port,
            path,
            addr: None,
        })
    }

    /// Connects to `addr` instead of resolving the host name.
    #[must_use]
    pub const fn with_addr(mut self, addr: SocketAddr) -> Self {
        self.addr = Some(addr);
        self
    }

    /// Whether the URL is `https://`.
    #[must_use]
    pub const fn is_tls(&self) -> bool {
        self.tls
    }

    /// The host, without brackets for IPv6.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The path, query string included.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The address to connect to, if set.
    #[must_use]
    pub const fn addr(&self) -> Option<SocketAddr> {
        self.addr
    }

    /// `host[:port]` as it goes in a URL or `Host` header; the port is left
    /// out when it is the scheme's default.
    #[must_use]
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default_port = if self.tls { 443 } else { 80 };
        if self.port == default_port {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// The URL.
    #[must_use]
    pub fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{}{}", self.authority(), self.path)
    }
}

/// Reads the `nameserver` lines of a `resolv.conf(5)` file as UDP
/// upstreams, in order. Other options are ignored, as are IPv6 zone ids
/// (`fe80::1%eth0`), which a socket address cannot carry portably.
///
/// ```
/// use rune_dns_resolver::{Upstream, parse_resolv_conf};
///
/// let conf = "# generated\nsearch example.com\nnameserver 192.0.2.53\nnameserver 2001:db8::53\n";
/// let upstreams = parse_resolv_conf(conf);
/// assert_eq!(upstreams.len(), 2);
/// assert_eq!(upstreams[1], "[2001:db8::53]:53".parse::<Upstream>()?);
/// # Ok::<(), rune_dns_resolver::Error>(())
/// ```
#[must_use]
pub fn parse_resolv_conf(text: &str) -> Vec<Upstream> {
    text.lines()
        .filter_map(|line| {
            let line = line.split(['#', ';']).next().unwrap_or_default();
            let mut words = line.split_whitespace();
            if words.next() != Some("nameserver") {
                return None;
            }
            let ip = words.next()?;
            let ip = ip.split('%').next().unwrap_or(ip);
            ip.parse::<IpAddr>()
                .ok()
                .map(|ip| Upstream::Udp(SocketAddr::new(ip, 53)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_text_round_trips() {
        for text in [
            "udp://192.0.2.1:53",
            "tcp://[2001:db8::1]:5353",
            "tls://192.0.2.1:853#dns.example",
            "https://dns.example/dns-query",
            "https://dns.example:8443/q?x=1",
            "http://127.0.0.1:8053/dns-query",
            "https://[2001:db8::1]/dns-query",
        ] {
            let upstream: Upstream = text.parse().unwrap();
            assert_eq!(upstream.to_string(), text);
        }
        let dot: Upstream = "tls://[2001:db8::1]".parse().unwrap();
        assert_eq!(dot.to_string(), "tls://[2001:db8::1]:853#2001:db8::1");
    }

    #[test]
    fn rejects_bad_upstreams() {
        for bad in [
            "",
            "dns.google",
            "udp://dns.google",
            "tls://1.1.1.1#",
            "ftp://x/",
            "https:///dns-query",
            "https://user@host/",
            "https://host:99999/",
            "https://host/#frag",
            "https://[::1/",
            "https://[nope]/",
            "https://ho st/",
            "https://host/a b",
        ] {
            assert!(bad.parse::<Upstream>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn doh_defaults() {
        let endpoint = DohEndpoint::parse("https://DNS.Example").unwrap();
        assert_eq!(endpoint.host(), "dns.example");
        assert_eq!(endpoint.path(), "/dns-query");
        assert_eq!(endpoint.port(), 443);
        assert_eq!(endpoint.addr(), None);
        let endpoint = DohEndpoint::parse("http://h?dns").unwrap();
        assert_eq!((endpoint.port(), endpoint.path()), (80, "/?dns"));
        assert!(!endpoint.is_tls());
    }

    #[test]
    fn resolv_conf() {
        let conf = "nameserver 192.0.2.1 ; trailing\n  nameserver fe80::1%eth0\nnameserver bogus\noptions ndots:2\n#nameserver 192.0.2.9\n";
        let upstreams = parse_resolv_conf(conf);
        assert_eq!(
            upstreams,
            [
                Upstream::Udp("192.0.2.1:53".parse().unwrap()),
                Upstream::Udp("[fe80::1]:53".parse().unwrap()),
            ]
        );
    }
}
