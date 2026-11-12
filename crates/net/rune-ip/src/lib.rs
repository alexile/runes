//! IPv4/IPv6 address classification per the IANA special-purpose registries.
//!
//! SSRF guards, scope checks and egress filters all ask the same question:
//! *is this address safe to talk to?* This crate answers it from the IANA
//! [IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) and
//! [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/)
//! Special-Purpose Address Registries ([RFC 6890]), the IPv6 scoped
//! addressing architecture ([RFC 4291], [RFC 4007]) and the carrier-grade NAT
//! block ([RFC 6598]).
//!
//! Every helper takes anything that converts into [`IpAddr`] (an
//! [`Ipv4Addr`], an [`Ipv6Addr`] or an [`IpAddr`]) and first passes it
//! through [`canonical`], which unwraps IPv4-mapped (`::ffff:a.b.c.d`) and
//! IPv4-compatible (`::a.b.c.d`) IPv6 addresses. A guard built on these
//! helpers therefore cannot be bypassed with `::ffff:169.254.169.254`.
//! [`is_global`] additionally checks the IPv4 address embedded in NAT64
//! (`64:ff9b::/96`), 6to4 (`2002::/16`) and Teredo addresses.
//!
//! | Helper | True for |
//! | --- | --- |
//! | [`is_global`] | globally reachable unicast, per the registries |
//! | [`is_private`] | RFC 1918 and IPv6 unique-local (`fc00::/7`) |
//! | [`is_shared`] | carrier-grade NAT space `100.64.0.0/10` |
//! | [`is_loopback`] | `127.0.0.0/8`, `::1` |
//! | [`is_link_local`] | `169.254.0.0/16`, `fe80::/10` |
//! | [`is_documentation`] | TEST-NET-1/2/3, `2001:db8::/32`, `3fff::/20` |
//! | [`is_bogon`] | prefixes that never appear in the global routing table |
//! | [`scope`] | the address's [`Scope`] (host, link, site, …, global) |
//! | [`category`] / [`lookup`] | the registry block and its RFC 6890 attributes |
//!
//! The library has no dependencies, does no I/O and keeps no global state.
//!
//! # Example
//!
//! ```
//! use core::net::IpAddr;
//! use rune_ip::{Category, Scope, category, is_global, is_private, scope};
//!
//! let ip: IpAddr = "10.1.2.3".parse()?;
//! assert!(is_private(ip));
//! assert!(!is_global(ip));
//! assert_eq!(category(ip), Category::Private);
//!
//! // IPv4-mapped IPv6 is classified as the IPv4 address it carries.
//! let metadata: IpAddr = "::ffff:169.254.169.254".parse()?;
//! assert_eq!(scope(metadata), Scope::Link);
//! assert!(!is_global(metadata));
//!
//! // So is the IPv4 address inside a NAT64 address.
//! let nat64: IpAddr = "64:ff9b::7f00:1".parse()?;
//! assert!(!is_global(nat64));
//!
//! assert!(is_global("1.1.1.1".parse::<IpAddr>()?));
//! assert!(is_global("2606:4700::1111".parse::<IpAddr>()?));
//! # Ok::<(), core::net::AddrParseError>(())
//! ```
//!
//! [RFC 6890]: https://www.rfc-editor.org/rfc/rfc6890
//! [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291
//! [RFC 4007]: https://www.rfc-editor.org/rfc/rfc4007
//! [RFC 6598]: https://www.rfc-editor.org/rfc/rfc6598

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

mod registry;

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub use registry::{Category, Registry, SpecialRange};
use registry::{most_specific, most_specific_where, prefix_match_v4, prefix_match_v6};

/// The reach of an address: how far packets to it are meant to travel.
///
/// IPv6 multicast scopes come from the scope field ([RFC 7346]), IPv4
/// multicast scopes from [RFC 2365]. Unicast follows [RFC 4007], with two
/// additions useful for egress decisions: [`Scope::Private`] for private-use
/// space and [`Scope::Reserved`] for addresses that are not meant to be
/// reachable at all (documentation, benchmarking, reserved, discard).
///
/// [RFC 7346]: https://www.rfc-editor.org/rfc/rfc7346
/// [RFC 2365]: https://www.rfc-editor.org/rfc/rfc2365
/// [RFC 4007]: https://www.rfc-editor.org/rfc/rfc4007
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scope {
    /// This host only: loopback, the unspecified address (which connects to
    /// the local host on most systems), `0.0.0.0/8` and interface-local
    /// multicast (`ff01::/16`).
    Host,
    /// The attached link: link-local unicast, limited broadcast,
    /// `224.0.0.0/24` and link-local multicast (`ff02::/16`).
    Link,
    /// IPv6 realm-local multicast (`ff03::/16`, RFC 7346).
    Realm,
    /// Administratively scoped multicast: `ff04::/16`, the unassigned IPv6
    /// multicast scopes, and `239.0.0.0/8` outside the site and organization
    /// ranges.
    Admin,
    /// A site: deprecated `fec0::/10`, `ff05::/16` and `239.255.0.0/16`.
    Site,
    /// An organization: `ff08::/16` and `239.192.0.0/14`.
    Organization,
    /// Private-use unicast: RFC 1918, carrier-grade NAT (RFC 6598) and
    /// unique-local IPv6 (RFC 4193).
    Private,
    /// The public internet.
    Global,
    /// Not reachable at any scope: documentation, benchmarking, reserved and
    /// discard space, and non-global protocol assignments.
    Reserved,
}

impl Scope {
    /// A short lower-case name, e.g. `"link"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Link => "link",
            Self::Realm => "realm",
            Self::Admin => "admin",
            Self::Site => "site",
            Self::Organization => "organization",
            Self::Private => "private",
            Self::Global => "global",
            Self::Reserved => "reserved",
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Category {
    /// A short lower-case name, e.g. `"link-local"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::ThisNetwork => "this-network",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::Shared => "shared",
            Self::LinkLocal => "link-local",
            Self::SiteLocal => "site-local",
            Self::UniqueLocal => "unique-local",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Documentation => "documentation",
            Self::Benchmarking => "benchmarking",
            Self::Reserved => "reserved",
            Self::ProtocolAssignment => "protocol-assignment",
            Self::Anycast => "anycast",
            Self::Ipv4Mapped => "ipv4-mapped",
            Self::Ipv4Compatible => "ipv4-compatible",
            Self::Translation => "translation",
            Self::Discard => "discard",
            Self::Teredo => "teredo",
            Self::SixToFour => "6to4",
            Self::SegmentRouting => "segment-routing",
            Self::Global => "global",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How an IPv4 address is carried inside an IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Embedding {
    /// `::ffff:a.b.c.d` (RFC 4291 §2.5.5.2).
    Mapped,
    /// `::a.b.c.d`, deprecated (RFC 4291 §2.5.5.1). `::` and `::1` are not
    /// treated as compatible addresses.
    Compatible,
    /// `64:ff9b::a.b.c.d`, the NAT64 well-known prefix (RFC 6052).
    Nat64,
    /// `2002:aabb:ccdd::/48`, 6to4 (RFC 3056).
    SixToFour,
    /// The Teredo client's public address (RFC 4380 §4), stored inverted in
    /// the low 32 bits of a `2001::/32` address.
    Teredo,
}

/// An IPv4 address found inside an IPv6 address by [`embedded_ipv4`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct EmbeddedIpv4 {
    /// How the address is embedded.
    pub kind: Embedding,
    /// The embedded IPv4 address.
    pub addr: Ipv4Addr,
}

/// Extracts the IPv4 address embedded in an IPv6 address, if any.
///
/// Recognises IPv4-mapped, IPv4-compatible, NAT64 well-known-prefix, 6to4
/// and Teredo addresses. Network-specific NAT64 prefixes (RFC 6052 §2.2)
/// cannot be recognised without knowing the prefix, so they are not.
///
/// ```
/// use rune_ip::{Embedding, embedded_ipv4};
/// use core::net::Ipv4Addr;
///
/// let e = embedded_ipv4("2002:c000:204::1".parse()?).unwrap();
/// assert_eq!(e.kind, Embedding::SixToFour);
/// assert_eq!(e.addr, Ipv4Addr::new(192, 0, 2, 4));
/// assert!(embedded_ipv4("::1".parse()?).is_none());
/// # Ok::<(), core::net::AddrParseError>(())
/// ```
#[must_use]
pub fn embedded_ipv4(ip: Ipv6Addr) -> Option<EmbeddedIpv4> {
    let bits = u128::from(ip);
    let o = ip.octets();
    let low32 = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    let found = |kind, addr| Some(EmbeddedIpv4 { kind, addr });
    let s = ip.segments();
    if bits >> 32 == 0xffff {
        found(Embedding::Mapped, low32)
    } else if bits >> 32 == 0 && bits > 1 {
        found(Embedding::Compatible, low32)
    } else if bits >> 32 == 0x0064_ff9b_0000_0000_0000_0000 {
        found(Embedding::Nat64, low32)
    } else if s[0] == 0x2002 {
        found(Embedding::SixToFour, Ipv4Addr::new(o[2], o[3], o[4], o[5]))
    } else if s[0] == 0x2001 && s[1] == 0 {
        found(Embedding::Teredo, Ipv4Addr::from(!u32::from(low32)))
    } else {
        None
    }
}

/// Unwraps IPv4-mapped and IPv4-compatible IPv6 addresses to the IPv4
/// address they carry; every other address is returned unchanged.
///
/// These two forms address the same host as the IPv4 address (a dual-stack
/// socket connecting to `::ffff:127.0.0.1` reaches `127.0.0.1`), so every
/// classifier in this crate applies `canonical` first.
///
/// ```
/// use rune_ip::canonical;
/// use core::net::IpAddr;
///
/// let ip: IpAddr = "::ffff:10.0.0.1".parse()?;
/// assert_eq!(canonical(ip), "10.0.0.1".parse::<IpAddr>()?);
/// assert_eq!(canonical("::1".parse::<IpAddr>()?), "::1".parse::<IpAddr>()?);
/// # Ok::<(), core::net::AddrParseError>(())
/// ```
#[must_use]
pub fn canonical(ip: impl Into<IpAddr>) -> IpAddr {
    match ip.into() {
        IpAddr::V6(v6) => match embedded_ipv4(v6) {
            Some(EmbeddedIpv4 {
                kind: Embedding::Mapped | Embedding::Compatible,
                addr,
            }) => IpAddr::V4(addr),
            _ => IpAddr::V6(v6),
        },
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// The most specific registry block containing `ip`, without unwrapping.
///
/// `lookup("::ffff:10.0.0.1")` returns the IPv4-mapped block; call
/// `lookup(canonical(ip))` to look up the IPv4 address instead. Returns
/// `None` for ordinary global unicast and for IPv6 space outside `2000::/3`
/// that no block covers.
///
/// ```
/// use rune_ip::{lookup, Registry};
/// use core::net::Ipv4Addr;
///
/// let block = lookup(Ipv4Addr::new(100, 64, 1, 1)).unwrap();
/// assert_eq!(block.to_string(), "100.64.0.0/10");
/// assert_eq!(block.rfc(), "RFC 6598");
/// assert_eq!(block.registry(), Registry::SpecialPurpose);
/// assert_eq!(block.globally_reachable(), Some(false));
/// ```
#[must_use]
pub fn lookup(ip: impl Into<IpAddr>) -> Option<&'static SpecialRange> {
    most_specific(ip.into())
}

/// Every registry block containing `ip`, least specific first, without
/// unwrapping.
pub fn matching(ip: impl Into<IpAddr>) -> impl Iterator<Item = &'static SpecialRange> {
    let ip = ip.into();
    let mut found: Vec<_> = registry::table(ip)
        .iter()
        .filter(move |r| r.contains(ip))
        .collect();
    found.sort_by_key(|r| r.prefix_len());
    found.into_iter()
}

/// The full IPv4 table: the special-purpose registry plus `224.0.0.0/4`.
#[must_use]
pub fn registry_v4() -> &'static [SpecialRange] {
    registry::IPV4
}

/// The full IPv6 table: the special-purpose registry plus `::/96`,
/// `fec0::/10` and `ff00::/8`.
#[must_use]
pub fn registry_v6() -> &'static [SpecialRange] {
    registry::IPV6
}

/// The category of the most specific block containing the
/// [canonical] form of `ip`.
///
/// Returns [`Category::Reserved`] for IPv6 space outside `2000::/3` that no
/// block covers, and [`Category::Global`] when nothing applies.
#[must_use]
pub fn category(ip: impl Into<IpAddr>) -> Category {
    let ip = canonical(ip);
    most_specific(ip).map_or_else(
        || match ip {
            IpAddr::V6(v6) if !in_global_unicast_space(v6) => Category::Reserved,
            _ => Category::Global,
        },
        SpecialRange::category,
    )
}

/// Whether `ip` is globally reachable unicast.
///
/// Decided by the registry's "Globally Reachable" column: the most specific
/// block that has an answer wins (so `192.0.0.9`, PCP anycast, is global
/// although `192.0.0.0/24` is not). Without one, IPv4 is global and IPv6 is
/// global inside `2000::/3`. Multicast is never global here; use [`scope`]
/// for multicast reach.
///
/// The check runs on the [canonical] address, and for NAT64,
/// 6to4 and Teredo addresses the embedded IPv4 address must be global too,
/// so `64:ff9b::a9fe:a9fe` (169.254.169.254 through NAT64) is not.
///
/// ```
/// use rune_ip::is_global;
/// use core::net::IpAddr;
///
/// for ok in ["8.8.8.8", "192.0.0.9", "2001:4860:4860::8888", "64:ff9b::808:808"] {
///     assert!(is_global(ok.parse::<IpAddr>()?), "{ok}");
/// }
/// for bad in ["127.0.0.1", "100.64.0.1", "::ffff:192.168.0.1", "fd00::1", "2001:db8::1", "ff0e::1"] {
///     assert!(!is_global(bad.parse::<IpAddr>()?), "{bad}");
/// }
/// # Ok::<(), core::net::AddrParseError>(())
/// ```
#[must_use]
pub fn is_global(ip: impl Into<IpAddr>) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

fn reachable(ip: IpAddr, default: bool) -> bool {
    most_specific_where(ip, |r| r.globally_reachable().is_some())
        .and_then(SpecialRange::globally_reachable)
        .unwrap_or(default)
}

fn is_global_v4(ip: Ipv4Addr) -> bool {
    !ip.is_multicast() && reachable(IpAddr::V4(ip), true)
}

fn is_global_v6(ip: Ipv6Addr) -> bool {
    if ip.is_multicast() || !reachable(IpAddr::V6(ip), in_global_unicast_space(ip)) {
        return false;
    }
    match embedded_ipv4(ip) {
        Some(EmbeddedIpv4 {
            kind: Embedding::Nat64 | Embedding::SixToFour | Embedding::Teredo,
            addr,
        }) => is_global_v4(addr),
        _ => true,
    }
}

/// `2000::/3`, the only IPv6 space IANA allocates as global unicast.
const fn in_global_unicast_space(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xe000 == 0x2000
}

/// Whether `ip` is private-use: RFC 1918 or IPv6 unique-local (`fc00::/7`).
///
/// Carrier-grade NAT space is *not* included; see [`is_shared`].
#[must_use]
pub fn is_private(ip: impl Into<IpAddr>) -> bool {
    matches!(category(ip), Category::Private | Category::UniqueLocal)
}

/// Whether `ip` is in the carrier-grade NAT shared address space
/// `100.64.0.0/10` (RFC 6598).
#[must_use]
pub fn is_shared(ip: impl Into<IpAddr>) -> bool {
    category(ip) == Category::Shared
}

/// Whether `ip` is a loopback address: `127.0.0.0/8` or `::1`.
#[must_use]
pub fn is_loopback(ip: impl Into<IpAddr>) -> bool {
    category(ip) == Category::Loopback
}

/// Whether `ip` is the unspecified address `0.0.0.0` or `::`.
#[must_use]
pub fn is_unspecified(ip: impl Into<IpAddr>) -> bool {
    category(ip) == Category::Unspecified
}

/// Whether `ip` is link-local unicast: `169.254.0.0/16` or `fe80::/10`.
///
/// Link-scoped multicast is not included; use [`scope`] for that.
#[must_use]
pub fn is_link_local(ip: impl Into<IpAddr>) -> bool {
    category(ip) == Category::LinkLocal
}

/// Whether `ip` is in a documentation prefix: `192.0.2.0/24`,
/// `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` or `3fff::/20`.
#[must_use]
pub fn is_documentation(ip: impl Into<IpAddr>) -> bool {
    category(ip) == Category::Documentation
}

/// Whether `ip` is in a benchmarking prefix: `198.18.0.0/15` or
/// `2001:2::/48`.
#[must_use]
pub fn is_benchmarking(ip: impl Into<IpAddr>) -> bool {
    category(ip) == Category::Benchmarking
}

/// Whether `ip` is multicast: `224.0.0.0/4` or `ff00::/8`.
#[must_use]
pub fn is_multicast(ip: impl Into<IpAddr>) -> bool {
    category(ip) == Category::Multicast
}

/// Whether `ip` is reserved: `240.0.0.0/4` (except the broadcast address),
/// deprecated blocks, or IPv6 space outside `2000::/3` that no block covers.
#[must_use]
pub fn is_reserved(ip: impl Into<IpAddr>) -> bool {
    category(ip) == Category::Reserved
}

/// IPv4 bogon (martian) prefixes: the special-purpose space that must never
/// appear in the global routing table, as in the Team Cymru bogon list
/// (without unallocated space, which changes over time).
const BOGONS_V4: &[(u32, u8)] = &[
    (0x0000_0000, 8),  // 0.0.0.0/8
    (0x0a00_0000, 8),  // 10.0.0.0/8
    (0x6440_0000, 10), // 100.64.0.0/10
    (0x7f00_0000, 8),  // 127.0.0.0/8
    (0xa9fe_0000, 16), // 169.254.0.0/16
    (0xac10_0000, 12), // 172.16.0.0/12
    (0xc000_0000, 24), // 192.0.0.0/24
    (0xc000_0200, 24), // 192.0.2.0/24
    (0xc058_6300, 24), // 192.88.99.0/24
    (0xc0a8_0000, 16), // 192.168.0.0/16
    (0xc612_0000, 15), // 198.18.0.0/15
    (0xc633_6400, 24), // 198.51.100.0/24
    (0xcb00_7100, 24), // 203.0.113.0/24
    (0xe000_0000, 4),  // 224.0.0.0/4
    (0xf000_0000, 4),  // 240.0.0.0/4
];

/// IPv6 bogon prefixes inside `2000::/3`; everything outside it is a bogon.
const BOGONS_V6: &[(u128, u8)] = &[
    (0x2001_0002_0000_0000_0000_0000_0000_0000, 48), // 2001:2::/48
    (0x2001_0010_0000_0000_0000_0000_0000_0000, 28), // 2001:10::/28
    (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32), // 2001:db8::/32
    (0x2002_0000_0000_0000_0000_0000_0000_0000, 16), // 2002::/16
    (0x3ffe_0000_0000_0000_0000_0000_0000_0000, 16), // 3ffe::/16 (6bone)
    (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20), // 3fff::/20
    (0x5f00_0000_0000_0000_0000_0000_0000_0000, 16), // 5f00::/16
];

/// Whether `ip` is a bogon: in a prefix that should never be routed on the
/// public internet (a "martian").
///
/// This is a routing notion, not a reachability one, so it differs from
/// `!is_global` at the edges: `192.0.0.9` (PCP anycast) and
/// `64:ff9b::8.8.8.8` (NAT64) are bogons, being inside non-routed prefixes,
/// yet [globally reachable](is_global). IPv4 follows the Team Cymru bogon
/// list; IPv6 treats everything outside `2000::/3`, plus documentation,
/// benchmarking, 6to4, ORCHID, 6bone and `SRv6` SID space, as bogon.
/// Unallocated space is not included, as it changes over time.
#[must_use]
pub fn is_bogon(ip: impl Into<IpAddr>) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            BOGONS_V4
                .iter()
                .any(|&(net, len)| prefix_match_v4(net, bits, len))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            !in_global_unicast_space(v6)
                || BOGONS_V6
                    .iter()
                    .any(|&(net, len)| prefix_match_v6(net, bits, len))
        }
    }
}

/// The [`Scope`] of the [canonical] form of `ip`.
///
/// ```
/// use rune_ip::{Scope, scope};
/// use core::net::IpAddr;
///
/// assert_eq!(scope("0.0.0.0".parse::<IpAddr>()?), Scope::Host);
/// assert_eq!(scope("fe80::1".parse::<IpAddr>()?), Scope::Link);
/// assert_eq!(scope("ff05::2".parse::<IpAddr>()?), Scope::Site);
/// assert_eq!(scope("239.192.0.1".parse::<IpAddr>()?), Scope::Organization);
/// assert_eq!(scope("100.64.0.1".parse::<IpAddr>()?), Scope::Private);
/// assert_eq!(scope("198.51.100.7".parse::<IpAddr>()?), Scope::Reserved);
/// assert_eq!(scope("9.9.9.9".parse::<IpAddr>()?), Scope::Global);
/// # Ok::<(), core::net::AddrParseError>(())
/// ```
#[must_use]
pub fn scope(ip: impl Into<IpAddr>) -> Scope {
    let ip = canonical(ip);
    match ip {
        IpAddr::V4(v4) if v4.is_multicast() => multicast_scope_v4(v4),
        IpAddr::V6(v6) if v6.is_multicast() => multicast_scope_v6(v6),
        _ => match category(ip) {
            Category::Unspecified | Category::ThisNetwork | Category::Loopback => Scope::Host,
            Category::LinkLocal | Category::Broadcast => Scope::Link,
            Category::SiteLocal => Scope::Site,
            Category::Private | Category::Shared | Category::UniqueLocal => Scope::Private,
            _ if is_global(ip) => Scope::Global,
            _ => Scope::Reserved,
        },
    }
}

fn multicast_scope_v4(ip: Ipv4Addr) -> Scope {
    let bits = u32::from(ip);
    if prefix_match_v4(0xe000_0000, bits, 24) {
        Scope::Link
    } else if prefix_match_v4(0xefff_0000, bits, 16) {
        Scope::Site
    } else if prefix_match_v4(0xefc0_0000, bits, 14) {
        Scope::Organization
    } else if prefix_match_v4(0xef00_0000, bits, 8) {
        Scope::Admin
    } else {
        Scope::Global
    }
}

const fn multicast_scope_v6(ip: Ipv6Addr) -> Scope {
    match ip.segments()[0] & 0x000f {
        0x1 => Scope::Host,
        0x2 => Scope::Link,
        0x3 => Scope::Realm,
        0x5 => Scope::Site,
        0x8 => Scope::Organization,
        0xe => Scope::Global,
        0x0 | 0xf => Scope::Reserved,
        // 4 is admin-local; 6, 7 and 9–d are unassigned and available to
        // administrators (RFC 4291 §2.7).
        _ => Scope::Admin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn mapped_and_compatible_unwrap() {
        assert_eq!(canonical(ip("::ffff:1.2.3.4")), ip("1.2.3.4"));
        assert_eq!(canonical(ip("::1.2.3.4")), ip("1.2.3.4"));
        assert_eq!(canonical(ip("::ffff:0.0.0.0")), ip("0.0.0.0"));
        assert_eq!(canonical(ip("::")), ip("::"));
        assert_eq!(canonical(ip("::1")), ip("::1"));
        assert_eq!(canonical(ip("64:ff9b::1.2.3.4")), ip("64:ff9b::1.2.3.4"));
    }

    #[test]
    fn embedded_forms() {
        let e = |s: &str| embedded_ipv4(s.parse().unwrap());
        assert_eq!(
            e("::ffff:10.0.0.1").map(|e| e.kind),
            Some(Embedding::Mapped)
        );
        assert_eq!(e("::10.0.0.1").map(|e| e.kind), Some(Embedding::Compatible));
        let nat = e("64:ff9b::a9fe:a9fe").unwrap();
        assert_eq!(
            (nat.kind, nat.addr),
            (Embedding::Nat64, Ipv4Addr::new(169, 254, 169, 254))
        );
        // RFC 4380 §4 example: client 192.0.2.45 stored as 3fff:fdd2.
        let teredo = e("2001:0:4136:e378:8000:63bf:3fff:fdd2").unwrap();
        assert_eq!(
            (teredo.kind, teredo.addr),
            (Embedding::Teredo, Ipv4Addr::new(192, 0, 2, 45))
        );
        assert!(e("2001:db8::1").is_none());
        assert!(e("::").is_none());
    }

    #[test]
    fn global_respects_more_specific_blocks() {
        assert!(is_global(ip("192.0.0.9")));
        assert!(is_global(ip("192.0.0.10")));
        assert!(!is_global(ip("192.0.0.11")));
        assert!(is_global(ip("2001:1::1")));
        assert!(!is_global(ip("2001:1::4")));
        assert!(is_global(ip("2001:20::1")));
        assert!(!is_global(ip("2001:10::1")));
        assert!(!is_global(ip("2001::1")));
        assert!(is_global(ip("2620:4f:8000::1")));
    }

    #[test]
    fn embedded_v4_must_be_global() {
        assert!(is_global(ip("2002:0808:0808::1")));
        assert!(!is_global(ip("2002:0a00:0001::1")));
        assert!(!is_global(ip("64:ff9b::127.0.0.1")));
        assert!(is_global(ip("64:ff9b::1.1.1.1")));
    }

    #[test]
    fn categories_and_scopes() {
        assert_eq!(category(ip("0.0.0.0")), Category::Unspecified);
        assert_eq!(category(ip("0.1.2.3")), Category::ThisNetwork);
        assert_eq!(category(ip("255.255.255.255")), Category::Broadcast);
        assert_eq!(category(ip("250.0.0.1")), Category::Reserved);
        assert_eq!(category(ip("4000::1")), Category::Reserved);
        assert_eq!(category(ip("2a00::1")), Category::Global);
        assert_eq!(scope(ip("224.0.0.251")), Scope::Link);
        assert_eq!(scope(ip("239.1.1.1")), Scope::Admin);
        assert_eq!(scope(ip("233.1.1.1")), Scope::Global);
        assert_eq!(scope(ip("ff01::1")), Scope::Host);
        assert_eq!(scope(ip("ff03::1")), Scope::Realm);
        assert_eq!(scope(ip("ff0f::1")), Scope::Reserved);
        assert_eq!(scope(ip("ff06::1")), Scope::Admin);
        assert_eq!(scope(ip("fec0::1")), Scope::Site);
        assert_eq!(scope(ip("fd12::1")), Scope::Private);
        assert_eq!(scope(ip("::ffff:127.0.0.1")), Scope::Host);
    }

    #[test]
    fn matching_is_least_specific_first() {
        let names: Vec<_> = matching(ip("192.0.0.9"))
            .map(SpecialRange::prefix_len)
            .collect();
        assert_eq!(names, [24, 32]);
        let names: Vec<_> = matching(ip("192.0.0.1"))
            .map(SpecialRange::prefix_len)
            .collect();
        assert_eq!(names, [24, 29]);
        assert_eq!(
            lookup(ip("192.0.0.9")).map(SpecialRange::category),
            Some(Category::Anycast)
        );
        assert!(lookup(ip("8.8.8.8")).is_none());
    }

    #[test]
    fn display() {
        assert_eq!(Category::LinkLocal.to_string(), "link-local");
        assert_eq!(Scope::Organization.to_string(), "organization");
        assert_eq!(
            registry_v6().last().map(ToString::to_string).as_deref(),
            Some("ff00::/8")
        );
    }
}
