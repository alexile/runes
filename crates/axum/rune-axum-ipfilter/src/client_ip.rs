//! Spoof-resistant client IP resolution.
//!
//! [`ClientIpConfig`] decides which address a request comes from. By default it uses only
//! the TCP peer address that Axum records as [`ConnectInfo<SocketAddr>`] and ignores every
//! forwarding header, because any client can write `X-Forwarded-For` itself.
//!
//! Behind a reverse proxy, list the proxy's addresses with
//! [`ClientIpConfig::trust_proxy`]. Forwarding headers are then read only when the peer is
//! one of those proxies, and the chain is walked from the right (the end the proxies append
//! to): trusted hops are skipped and the first untrusted address is the client.
//!
//! All parsing is bounded: at most [`MAX_HOPS`] hops are examined, a hop longer than
//! [`MAX_HOP_LEN`] bytes is malformed, and malformed input never panics. IPv4-mapped IPv6
//! addresses (`::ffff:192.0.2.1`) are normalised to plain IPv4 everywhere.

use axum::extract::ConnectInfo;
use http::{Extensions, HeaderMap, HeaderName, Request};
use rune_cidr::{Cidr, CidrParseError};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// The maximum number of forwarding hops examined, counted from the right.
///
/// A longer chain is cut off there and the last trusted hop seen is used as the client.
pub const MAX_HOPS: usize = 32;

/// The maximum length in bytes of one hop (one comma-separated entry). Longer entries are
/// treated as malformed.
pub const MAX_HOP_LEN: usize = 128;

/// The header a trusted proxy uses to pass on the client address.
///
/// It is read only when the socket peer matches a trusted proxy CIDR.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ProxyHeader {
    /// `X-Forwarded-For`, walked from the right (default).
    #[default]
    XForwardedFor,
    /// RFC 7239 `Forwarded`, using the `for=` parameter of each element, walked from the right.
    Forwarded,
    /// A single-value header written by the proxy, such as `CF-Connecting-IP` or `X-Real-IP`.
    ///
    /// If the header occurs more than once, the last occurrence is used. Make sure the proxy
    /// overwrites the header rather than passing on a client-supplied value.
    Header(HeaderName),
}

/// How to determine the client IP of a request.
///
/// The default trusts no proxies: the client IP is the socket peer address taken from the
/// [`ConnectInfo<SocketAddr>`] request extension, and forwarding headers are ignored. Serve
/// the router with `into_make_service_with_connect_info::<SocketAddr>()` so that the
/// extension is present. Without it [`ClientIpConfig::resolve`] returns `None`, and each
/// middleware documents how it fails closed.
///
/// # Examples
///
/// ```rust
/// use rune_axum_ipfilter::{ClientIpConfig, ProxyHeader};
///
/// // Directly exposed server: socket peer only.
/// let direct = ClientIpConfig::new();
///
/// // Behind a load balancer in 10.0.0.0/8 that appends to X-Forwarded-For.
/// let behind_lb = ClientIpConfig::new().trust_proxy("10.0.0.0/8")?;
///
/// // Behind Cloudflare (abbreviated range list), using its dedicated header.
/// let cloudflare = ClientIpConfig::new()
///     .trust_proxy("173.245.48.0/20")?
///     .trust_proxy("2400:cb00::/32")?
///     .header(ProxyHeader::Header(http::HeaderName::from_static("cf-connecting-ip")));
/// # Ok::<(), rune_axum_ipfilter::CidrParseError>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct ClientIpConfig {
    trusted: Vec<Cidr>,
    header: ProxyHeader,
}

impl ClientIpConfig {
    /// Creates a config that uses the socket peer address and trusts no proxy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a trusted proxy range in CIDR notation (`"10.0.0.0/8"`, `"::1/128"`).
    ///
    /// A bare address (`"10.0.0.1"`) is accepted as a single-host range.
    ///
    /// # Errors
    ///
    /// Returns [`CidrParseError`] if `cidr` is neither CIDR notation nor an IP address.
    pub fn trust_proxy(mut self, cidr: &str) -> Result<Self, CidrParseError> {
        // A bare address becomes a single-host range; mapped IPv6 is folded to IPv4 so it
        // matches the (normalised) peer.
        let parsed = match cidr.trim().parse::<IpAddr>() {
            Ok(ip) => Cidr::parse(&canonical(ip).to_string())?,
            Err(_) => Cidr::parse(cidr)?,
        };
        self.trusted.push(parsed);
        Ok(self)
    }

    /// Adds an already-parsed trusted proxy range.
    #[must_use]
    pub fn trust_cidr(mut self, cidr: Cidr) -> Self {
        self.trusted.push(cidr);
        self
    }

    /// Sets the header read from trusted proxies. Defaults to [`ProxyHeader::XForwardedFor`].
    #[must_use]
    pub fn header(mut self, header: ProxyHeader) -> Self {
        self.header = header;
        self
    }

    /// Returns the configured trusted proxy ranges.
    #[must_use]
    pub fn trusted_proxies(&self) -> &[Cidr] {
        &self.trusted
    }

    /// Returns `true` when `ip` lies in one of the trusted proxy ranges.
    #[must_use]
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|cidr| cidr_contains(cidr, ip))
    }

    /// Resolves the client IP of `req`. See [`ClientIpConfig::resolve_parts`].
    #[must_use]
    pub fn resolve<B>(&self, req: &Request<B>) -> Option<IpAddr> {
        self.resolve_parts(req.headers(), req.extensions())
    }

    /// Resolves the client IP from request headers and extensions.
    ///
    /// Returns `None` only when the [`ConnectInfo<SocketAddr>`] extension is missing.
    /// Forwarding headers are never consulted unless the peer is a trusted proxy; if such a
    /// header is absent or unusable the nearest trusted hop (at worst the peer itself) is
    /// returned instead.
    #[must_use]
    pub fn resolve_parts(&self, headers: &HeaderMap, extensions: &Extensions) -> Option<IpAddr> {
        let peer = canonical(extensions.get::<ConnectInfo<SocketAddr>>()?.0.ip());
        Some(self.resolve_from_peer(peer, headers))
    }

    /// Resolves the client IP given an already-known socket peer address.
    ///
    /// Useful for servers that record the peer some other way than [`ConnectInfo`].
    #[must_use]
    pub fn resolve_from_peer(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = canonical(peer);
        if !self.is_trusted(peer) {
            return peer;
        }
        match &self.header {
            ProxyHeader::XForwardedFor => self.walk(
                peer,
                headers,
                &http::header::HeaderName::from_static("x-forwarded-for"),
                parse_node,
            ),
            ProxyHeader::Forwarded => {
                self.walk(peer, headers, &http::header::FORWARDED, forwarded_for)
            }
            ProxyHeader::Header(name) => headers
                .get_all(name)
                .iter()
                .next_back()
                .and_then(|value| parse_node(value.as_bytes()))
                .unwrap_or(peer),
        }
    }

    /// Walks a comma-separated chain from the right, starting at the trusted `peer`.
    fn walk(
        &self,
        peer: IpAddr,
        headers: &HeaderMap,
        name: &HeaderName,
        hop_ip: impl Fn(&[u8]) -> Option<IpAddr>,
    ) -> IpAddr {
        let mut last_trusted = peer;
        let mut seen = 0usize;
        // Header lines in reverse order, entries within each line in reverse order.
        for value in headers.get_all(name).iter().rev() {
            for hop in value.as_bytes().rsplit(|&b| b == b',') {
                if hop.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                seen += 1;
                if seen > MAX_HOPS {
                    return last_trusted;
                }
                let Some(ip) = hop_ip(hop) else {
                    // Malformed or obfuscated hop: nothing to its left can be trusted.
                    return last_trusted;
                };
                if !self.is_trusted(ip) {
                    return ip;
                }
                last_trusted = ip;
            }
        }
        last_trusted
    }
}

/// Whether `cidr` contains `ip`, treating an IPv4 address and its
/// `::ffff:a.b.c.d` form as the same address, whichever way the range is
/// written.
pub(crate) fn cidr_contains(cidr: &Cidr, ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => {
            cidr.contains(IpAddr::V4(v4)) || cidr.contains(IpAddr::V6(v4.to_ipv6_mapped()))
        }
        v6 @ IpAddr::V6(_) => cidr.contains(v6),
    }
}

/// Normalises IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to IPv4.
#[must_use]
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Masks an IPv6 address to its first `prefix_len` bits; IPv4 addresses pass unchanged.
///
/// `prefix_len` values above 128 are treated as 128. Useful to rate-limit per `/64`, the
/// smallest block normally assigned to one IPv6 subscriber.
#[must_use]
pub fn ipv6_prefix(ip: IpAddr, prefix_len: u8) -> IpAddr {
    match canonical(ip) {
        IpAddr::V6(v6) => {
            let bits = u32::from(prefix_len.min(128));
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Parses one node: `ip`, `"ip"`, `ipv4:port`, `[ipv6]` or `[ipv6]:port`, with surrounding
/// whitespace and optional double quotes.
fn parse_node(raw: &[u8]) -> Option<IpAddr> {
    if raw.len() > MAX_HOP_LEN {
        return None;
    }
    let s = std::str::from_utf8(raw).ok()?.trim();
    let s = s
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(s);
    let ip = if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if !(tail.is_empty() || is_port(tail.strip_prefix(':')?)) {
            return None;
        }
        IpAddr::V6(host.parse().ok()?)
    } else if let Ok(ip) = s.parse::<IpAddr>() {
        ip
    } else {
        let (host, port) = s.split_once(':')?;
        if !is_port(port) {
            return None;
        }
        IpAddr::V4(host.parse().ok()?)
    };
    Some(canonical(ip))
}

fn is_port(s: &str) -> bool {
    !s.is_empty() && s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit())
}

/// Extracts the `for=` node of one RFC 7239 `Forwarded` element.
fn forwarded_for(element: &[u8]) -> Option<IpAddr> {
    if element.len() > MAX_HOP_LEN * 2 {
        return None;
    }
    element.split(|&b| b == b';').find_map(|pair| {
        let eq = pair.iter().position(|&b| b == b'=')?;
        let (key, value) = pair.split_at(eq);
        key.trim_ascii()
            .eq_ignore_ascii_case(b"for")
            .then(|| parse_node(&value[1..]))
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn proxied() -> ClientIpConfig {
        ClientIpConfig::new()
            .trust_proxy("10.0.0.0/8")
            .unwrap()
            .trust_proxy("::1")
            .unwrap()
            .trust_proxy("::ffff:192.168.0.1")
            .unwrap()
    }

    #[test]
    fn default_ignores_headers() {
        let cfg = ClientIpConfig::new();
        let h = headers(&[("x-forwarded-for", "1.2.3.4"), ("x-real-ip", "5.6.7.8")]);
        assert_eq!(cfg.resolve_from_peer(ip("9.9.9.9"), &h), ip("9.9.9.9"));
    }

    #[test]
    fn untrusted_peer_ignores_headers() {
        let h = headers(&[("x-forwarded-for", "1.2.3.4")]);
        assert_eq!(
            proxied().resolve_from_peer(ip("8.8.8.8"), &h),
            ip("8.8.8.8")
        );
    }

    #[test]
    fn walks_from_right_skipping_trusted() {
        let h = headers(&[("x-forwarded-for", "6.6.6.6, 7.7.7.7, 10.0.0.2")]);
        assert_eq!(
            proxied().resolve_from_peer(ip("10.0.0.1"), &h),
            ip("7.7.7.7")
        );
    }

    #[test]
    fn spoofed_leftmost_is_ignored() {
        // Client sent "1.1.1.1"; the proxy appended the real address.
        let h = headers(&[("x-forwarded-for", "1.1.1.1, 203.0.113.9")]);
        assert_eq!(
            proxied().resolve_from_peer(ip("10.0.0.1"), &h),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn multiple_header_lines_are_one_chain() {
        let h = headers(&[
            ("x-forwarded-for", "203.0.113.9"),
            ("x-forwarded-for", "10.0.0.5"),
        ]);
        assert_eq!(
            proxied().resolve_from_peer(ip("10.0.0.1"), &h),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn all_trusted_returns_leftmost_trusted() {
        let h = headers(&[("x-forwarded-for", "10.0.0.3, 10.0.0.2")]);
        assert_eq!(
            proxied().resolve_from_peer(ip("10.0.0.1"), &h),
            ip("10.0.0.3")
        );
    }

    #[test]
    fn missing_header_returns_peer() {
        assert_eq!(
            proxied().resolve_from_peer(ip("10.0.0.1"), &HeaderMap::new()),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn malformed_hop_stops_at_last_trusted() {
        let h = headers(&[("x-forwarded-for", "1.2.3.4, garbage, 10.0.0.2")]);
        assert_eq!(
            proxied().resolve_from_peer(ip("10.0.0.1"), &h),
            ip("10.0.0.2")
        );
    }

    #[test]
    fn hop_limit_is_enforced() {
        let chain = std::iter::repeat_n("10.0.0.7", MAX_HOPS + 5)
            .collect::<Vec<_>>()
            .join(",");
        let h = headers(&[("x-forwarded-for", &format!("1.2.3.4,{chain}"))]);
        assert_eq!(
            proxied().resolve_from_peer(ip("10.0.0.1"), &h),
            ip("10.0.0.7")
        );
    }

    #[test]
    fn overlong_hop_is_malformed() {
        let long = "1".repeat(MAX_HOP_LEN + 1);
        let h = headers(&[("x-forwarded-for", &long)]);
        assert_eq!(
            proxied().resolve_from_peer(ip("10.0.0.1"), &h),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn ports_and_brackets() {
        let h = headers(&[("x-forwarded-for", "[2001:db8::1]:443, 192.0.2.7:8080")]);
        assert_eq!(
            proxied().resolve_from_peer(ip("10.0.0.1"), &h),
            ip("192.0.2.7")
        );
        let h = headers(&[("x-forwarded-for", "[2001:db8::1]:443")]);
        assert_eq!(
            proxied().resolve_from_peer(ip("10.0.0.1"), &h),
            ip("2001:db8::1")
        );
    }

    #[test]
    fn rfc7239_forwarded() {
        let cfg = proxied().header(ProxyHeader::Forwarded);
        let h = headers(&[(
            "forwarded",
            r#"for=1.1.1.1, For="[2001:db8:cafe::17]:4711";proto=https, for=10.0.0.9;by=10.0.0.1"#,
        )]);
        assert_eq!(
            cfg.resolve_from_peer(ip("10.0.0.1"), &h),
            ip("2001:db8:cafe::17")
        );
        let h = headers(&[("forwarded", "for=unknown, for=10.0.0.9")]);
        assert_eq!(cfg.resolve_from_peer(ip("10.0.0.1"), &h), ip("10.0.0.9"));
        let h = headers(&[("forwarded", "for=_hidden;proto=http")]);
        assert_eq!(cfg.resolve_from_peer(ip("10.0.0.1"), &h), ip("10.0.0.1"));
    }

    #[test]
    fn named_header_only_from_trusted_peer() {
        let cfg = proxied().header(ProxyHeader::Header(HeaderName::from_static(
            "cf-connecting-ip",
        )));
        let h = headers(&[("cf-connecting-ip", "198.51.100.4")]);
        assert_eq!(
            cfg.resolve_from_peer(ip("10.0.0.1"), &h),
            ip("198.51.100.4")
        );
        assert_eq!(cfg.resolve_from_peer(ip("8.8.8.8"), &h), ip("8.8.8.8"));
        let h = headers(&[("cf-connecting-ip", "not-an-ip")]);
        assert_eq!(cfg.resolve_from_peer(ip("10.0.0.1"), &h), ip("10.0.0.1"));
    }

    #[test]
    fn mapped_trusted_proxy_matches_ipv4_peer() {
        let h = headers(&[("x-forwarded-for", "198.51.100.1")]);
        assert_eq!(
            proxied().resolve_from_peer(ip("192.168.0.1"), &h),
            ip("198.51.100.1")
        );
    }

    #[test]
    fn mapped_trusted_range_matches_ipv4_peer() {
        let cfg = ClientIpConfig::new()
            .trust_proxy("::ffff:10.0.0.0/104")
            .unwrap();
        let h = headers(&[("x-forwarded-for", "198.51.100.1")]);
        assert_eq!(
            cfg.resolve_from_peer(ip("10.0.0.1"), &h),
            ip("198.51.100.1")
        );
    }

    #[test]
    fn ipv4_mapped_is_normalised() {
        let cfg = proxied();
        // Mapped peer matches an IPv4 trusted range.
        let h = headers(&[("x-forwarded-for", "::ffff:198.51.100.1")]);
        assert_eq!(
            cfg.resolve_from_peer(ip("::ffff:10.0.0.1"), &h),
            ip("198.51.100.1")
        );
        assert_eq!(
            ClientIpConfig::new().resolve_from_peer(ip("::ffff:1.2.3.4"), &HeaderMap::new()),
            ip("1.2.3.4")
        );
    }

    #[test]
    fn missing_connect_info_is_none() {
        let req = Request::builder().body(()).unwrap();
        assert_eq!(ClientIpConfig::new().resolve(&req), None);
        let mut req = Request::builder()
            .header("x-forwarded-for", "1.2.3.4")
            .body(())
            .unwrap();
        assert_eq!(ClientIpConfig::new().resolve(&req), None);
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([5, 6, 7, 8], 1234))));
        assert_eq!(ClientIpConfig::new().resolve(&req), Some(ip("5.6.7.8")));
    }

    #[test]
    fn prefix_masking() {
        assert_eq!(
            ipv6_prefix(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), 64),
            ip("2001:db8:1:2::")
        );
        assert_eq!(ipv6_prefix(ip("2001:db8::1"), 0), ip("::"));
        assert_eq!(ipv6_prefix(ip("2001:db8::1"), 200), ip("2001:db8::1"));
        assert_eq!(ipv6_prefix(ip("1.2.3.4"), 64), ip("1.2.3.4"));
    }

    #[test]
    fn garbage_never_panics() {
        let cfg = proxied().header(ProxyHeader::Forwarded);
        for raw in [
            "",
            ",",
            ",,,",
            "[",
            "]",
            "[::1",
            "[::1]x",
            "1.2.3.4:",
            "1.2.3.4:999999",
            "=",
            "for",
            "for=",
            "for=\"",
            ";;;",
            "for=[]:1",
            "\"\"",
        ] {
            let mut h = headers(&[("forwarded", raw), ("x-forwarded-for", raw)]);
            let _ = cfg.resolve_from_peer(ip("10.0.0.1"), &h);
            let _ = proxied().resolve_from_peer(ip("10.0.0.1"), &h);
            h.insert(
                "x-forwarded-for",
                HeaderValue::from_bytes(b"\xff\xfe").unwrap(),
            );
            let _ = proxied().resolve_from_peer(ip("10.0.0.1"), &h);
        }
    }
}
