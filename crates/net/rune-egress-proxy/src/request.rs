//! Sans-I/O parsing of a `CONNECT` request head.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use rune_host_match::Hostname;

use crate::Error;

/// Default limit on the size of a request head: 8 KiB, the common
/// default of HTTP servers and proxies.
pub const DEFAULT_MAX_HEAD_LEN: usize = 8 * 1024;

/// The host half of a CONNECT target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Host {
    /// A validated, normalized hostname (lowercase, no trailing dot).
    Name(Hostname),
    /// An IPv4 literal, or an IPv6 literal that was written in brackets.
    Ip(IpAddr),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => f.write_str(name.as_str()),
            Self::Ip(IpAddr::V4(v4)) => write!(f, "{v4}"),
            Self::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]"),
        }
    }
}

/// A CONNECT target in authority form: `host:port`
/// ([RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6)).
///
/// The port is mandatory and non-zero. IPv6 literals must be bracketed
/// (`[2001:db8::1]:443`) and must not carry a zone ID. A hostname must pass
/// [`Hostname::parse`], which also rejects the numeric shorthands
/// (`127.1`, `0x7f.1`) that some resolvers would otherwise turn into
/// loopback.
///
/// ```
/// use rune_egress_proxy::{Host, Target};
///
/// let t: Target = "API.Example.com:443".parse()?;
/// assert_eq!(t.to_string(), "api.example.com:443");
/// assert!(matches!(t.host, Host::Name(_)));
///
/// let v6: Target = "[::1]:8080".parse()?;
/// assert_eq!(v6.port, 8080);
/// assert!("example.com".parse::<Target>().is_err(), "port is required");
/// # Ok::<(), rune_egress_proxy::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Target {
    /// Host to connect to.
    pub host: Host,
    /// TCP port, never 0.
    pub port: u16,
}

impl Target {
    /// A target for `host` on `port`.
    #[must_use]
    pub const fn new(host: Host, port: u16) -> Self {
        Self { host, port }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl FromStr for Target {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = |reason| Error::InvalidTarget {
            target: truncate(s, 256),
            reason,
        };
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (literal, after) = rest
                .split_once(']')
                .ok_or_else(|| invalid("unterminated IPv6 literal"))?;
            let port = after
                .strip_prefix(':')
                .ok_or_else(|| invalid("missing port"))?;
            let ip = literal
                .parse::<Ipv6Addr>()
                .map_err(|_| invalid("invalid IPv6 literal"))?;
            (Host::Ip(IpAddr::V6(ip)), port)
        } else {
            let (host, port) = s.rsplit_once(':').ok_or_else(|| invalid("missing port"))?;
            if host.contains(':') {
                return Err(invalid("IPv6 literal must be bracketed"));
            }
            let host = if let Ok(v4) = host.parse::<Ipv4Addr>() {
                Host::Ip(IpAddr::V4(v4))
            } else {
                Host::Name(Hostname::parse(host).map_err(|_| invalid("invalid hostname"))?)
            };
            (host, port)
        };
        Ok(Self::new(
            host,
            parse_port(port).ok_or_else(|| invalid("invalid port"))?,
        ))
    }
}

/// Decimal port 1..=65535, digits only (no sign, no whitespace).
fn parse_port(s: &str) -> Option<u16> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok().filter(|&port| port != 0)
}

fn truncate(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

/// A complete, valid `CONNECT` request head.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConnectRequest {
    /// Where the client wants a tunnel to.
    pub target: Target,
    /// Length of the head in bytes, terminating blank line included. Bytes
    /// after it are tunnel payload the client sent early (often a TLS
    /// `ClientHello`) and belong upstream.
    pub head_len: usize,
}

/// Parses a `CONNECT` request head from the start of `buf`.
///
/// Returns `Ok(None)` while the head is incomplete and still within
/// `max_head_len` bytes: read more and call again with the longer buffer.
/// Lines may end in CRLF or a bare LF. Header fields are checked for
/// syntax and otherwise ignored; obsolete line folding is rejected.
///
/// ```
/// use rune_egress_proxy::{parse_request, DEFAULT_MAX_HEAD_LEN};
///
/// let buf = b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n\x16\x03";
/// let req = parse_request(buf, DEFAULT_MAX_HEAD_LEN)?.unwrap();
/// assert_eq!(req.target.to_string(), "api.example.com:443");
/// assert_eq!(&buf[req.head_len..], b"\x16\x03");
///
/// assert_eq!(parse_request(b"CONNECT a.example:443 HTTP/1.1\r\n", 8192)?, None);
/// assert!(parse_request(b"GET / HTTP/1.1\r\n\r\n", 8192).is_err());
/// # Ok::<(), rune_egress_proxy::Error>(())
/// ```
pub fn parse_request(buf: &[u8], max_head_len: usize) -> Result<Option<ConnectRequest>, Error> {
    let Some(head_len) = find_head_end(buf) else {
        return if buf.len() >= max_head_len {
            Err(Error::HeadTooLarge { max: max_head_len })
        } else {
            Ok(None)
        };
    };
    if head_len > max_head_len {
        return Err(Error::HeadTooLarge { max: max_head_len });
    }
    let head = std::str::from_utf8(&buf[..head_len])
        .map_err(|_| Error::Malformed("request head is not UTF-8"))?;
    let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let request_line = lines.next().unwrap_or_default();
    let target = parse_request_line(request_line)?;
    for line in lines.take_while(|l| !l.is_empty()) {
        check_field_line(line)?;
    }
    Ok(Some(ConnectRequest { target, head_len }))
}

/// Offset just past the blank line ending the head, if there is one.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    let mut start = 0;
    while let Some(offset) = buf[start..].iter().position(|&b| b == b'\n') {
        let end = start + offset;
        let line = &buf[start..end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() && start > 0 {
            return Some(end + 1);
        }
        start = end + 1;
    }
    None
}

fn parse_request_line(line: &str) -> Result<Target, Error> {
    if line.bytes().any(|b| b.is_ascii_control()) {
        return Err(Error::Malformed("control character in request line"));
    }
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Malformed(
            "request line is not `METHOD target HTTP/1.x`",
        ));
    };
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err(Error::Malformed("invalid method"));
    }
    if method != "CONNECT" {
        return Err(Error::UnsupportedMethod(truncate(method, 32)));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(Error::Malformed("unsupported HTTP version"));
    }
    target.parse()
}

fn check_field_line(line: &str) -> Result<(), Error> {
    if line.starts_with([' ', '\t']) {
        return Err(Error::Malformed("obsolete header line folding"));
    }
    let (name, value) = line
        .split_once(':')
        .ok_or(Error::Malformed("header line without a colon"))?;
    if name.is_empty() || !name.bytes().all(is_tchar) {
        return Err(Error::Malformed("invalid header name"));
    }
    if value.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
        return Err(Error::Malformed("control character in header value"));
    }
    Ok(())
}

/// RFC 9110 §5.6.2 `tchar`.
const fn is_tchar(b: u8) -> bool {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(buf: &[u8]) -> Result<Option<ConnectRequest>, Error> {
        parse_request(buf, DEFAULT_MAX_HEAD_LEN)
    }

    #[test]
    fn parses_hostname_ipv4_and_ipv6_targets() {
        let req = parse(b"CONNECT Example.COM.:443 HTTP/1.1\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(req.target.to_string(), "example.com:443");
        let req = parse(b"CONNECT 10.0.0.1:80 HTTP/1.0\n\n").unwrap().unwrap();
        assert_eq!(req.target.host, Host::Ip("10.0.0.1".parse().unwrap()));
        assert_eq!(req.head_len, 30);
        let req = parse(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n")
            .unwrap()
            .unwrap();
        assert_eq!(req.target.to_string(), "[2001:db8::1]:8443");
    }

    #[test]
    fn incomplete_head_asks_for_more() {
        assert_eq!(parse(b""), Ok(None));
        assert_eq!(
            parse(b"CONNECT a.example:443 HTTP/1.1\r\nHost: a"),
            Ok(None)
        );
        assert_eq!(parse(b"CONNECT a.example:443 HTTP/1.1\r\n\r"), Ok(None));
    }

    #[test]
    fn head_len_excludes_early_payload() {
        let buf = b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example\r\n\r\nPAYLOAD";
        let req = parse(buf).unwrap().unwrap();
        assert_eq!(&buf[req.head_len..], b"PAYLOAD");
    }

    #[test]
    fn enforces_the_head_limit() {
        let mut buf = b"CONNECT a.example:443 HTTP/1.1\r\nX: ".to_vec();
        buf.resize(64, b'a');
        assert_eq!(
            parse_request(&buf, 64),
            Err(Error::HeadTooLarge { max: 64 })
        );
        buf.extend_from_slice(b"\r\n\r\n");
        assert_eq!(
            parse_request(&buf, 64),
            Err(Error::HeadTooLarge { max: 64 })
        );
        assert!(parse_request(&buf, 128).unwrap().is_some());
    }

    #[test]
    fn rejects_other_methods_with_501() {
        let err = parse(b"GET http://example.com/ HTTP/1.1\r\n\r\n").unwrap_err();
        assert_eq!(err, Error::UnsupportedMethod("GET".into()));
        assert_eq!(err.status(), Some(501));
        // Methods are case-sensitive (RFC 9110 §9.1).
        assert!(matches!(
            parse(b"connect a.example:443 HTTP/1.1\r\n\r\n"),
            Err(Error::UnsupportedMethod(_))
        ));
    }

    #[test]
    fn rejects_malformed_heads() {
        for bad in [
            &b"\r\n\r\n"[..],
            b"CONNECT a.example:443\r\n\r\n",
            b"CONNECT  a.example:443 HTTP/1.1\r\n\r\n",
            b"CONNECT a.example:443 HTTP/2\r\n\r\n",
            b"CONNECT a.example:443 HTTP/1.1 x\r\n\r\n",
            b"CONNECT a.example:443 HTTP/1.1\r\nNoColon\r\n\r\n",
            b"CONNECT a.example:443 HTTP/1.1\r\nBad Name: x\r\n\r\n",
            b"CONNECT a.example:443 HTTP/1.1\r\nA: b\r\n folded\r\n\r\n",
            b"CONNECT a.example:443 HTTP/1.1\r\nA: \x00\r\n\r\n",
            b"CONNECT a.example:443 HTTP/1.1\r\nA: \xff\r\n\r\n",
        ] {
            let err = parse(bad).unwrap_err();
            assert_eq!(err.status(), Some(400), "{bad:?}: {err}");
        }
    }

    #[test]
    fn rejects_invalid_targets() {
        for bad in [
            "a.example",
            "a.example:",
            "a.example:0",
            "a.example:65536",
            "a.example:+443",
            "a.example: 443",
            "::1:443",
            "[::1]",
            "[::1]443",
            "[::1:443",
            "[fe80::1%eth0]:443",
            "[10.0.0.1]:443",
            "127.1:443",
            "0x7f.1:443",
            "*.example.com:443",
            "user@a.example:443",
            ":443",
        ] {
            assert!(
                matches!(bad.parse::<Target>(), Err(Error::InvalidTarget { .. })),
                "{bad}"
            );
        }
    }

    #[test]
    fn target_display_round_trips() {
        for ok in ["a.example:1", "10.0.0.1:65535", "[::ffff:127.0.0.1]:80"] {
            let t: Target = ok.parse().unwrap();
            assert_eq!(t.to_string().parse::<Target>().unwrap(), t);
        }
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate("héllo", 2), "h");
        assert_eq!(truncate("abc", 10), "abc");
    }
}
