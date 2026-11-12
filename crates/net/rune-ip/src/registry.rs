//! The address-block tables: the IANA IPv4 and IPv6 Special-Purpose Address
//! Registries, plus the few blocks from the general address-space registries
//! (multicast, IPv4-compatible IPv6, site-local) that classification needs.
//!
//! Sources:
//! - <https://www.iana.org/assignments/iana-ipv4-special-registry/>
//! - <https://www.iana.org/assignments/iana-ipv6-special-registry/>
//! - <https://www.iana.org/assignments/ipv4-address-space/>
//! - <https://www.iana.org/assignments/ipv6-address-space/>

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What an address block is used for.
///
/// Every [`SpecialRange`] carries one category; [`category`](crate::category)
/// returns the category of the most specific block containing an address, or
/// [`Category::Global`] when no block matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Category {
    /// `0.0.0.0/32` and `::/128`: the unspecified address.
    Unspecified,
    /// `0.0.0.0/8`: "this network" (RFC 791, RFC 1122).
    ThisNetwork,
    /// `127.0.0.0/8` and `::1/128`.
    Loopback,
    /// Private-use space: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
    /// (RFC 1918).
    Private,
    /// `100.64.0.0/10`: shared address space for carrier-grade NAT (RFC 6598).
    Shared,
    /// Link-local unicast: `169.254.0.0/16` (RFC 3927) and `fe80::/10`
    /// (RFC 4291).
    LinkLocal,
    /// `fec0::/10`: deprecated IPv6 site-local unicast (RFC 3879).
    SiteLocal,
    /// `fc00::/7`: IPv6 unique local addresses (RFC 4193).
    UniqueLocal,
    /// `224.0.0.0/4` and `ff00::/8`.
    Multicast,
    /// `255.255.255.255/32`: limited broadcast (RFC 919, RFC 8190).
    Broadcast,
    /// Documentation prefixes: TEST-NET-1/2/3 (RFC 5737), `2001:db8::/32`
    /// (RFC 3849) and `3fff::/20` (RFC 9637).
    Documentation,
    /// Benchmarking: `198.18.0.0/15` (RFC 2544) and `2001:2::/48` (RFC 5180).
    Benchmarking,
    /// Reserved for future use or deprecated: `240.0.0.0/4`, the former
    /// 6to4 relay anycast block, the deprecated ORCHID block, and every IPv6
    /// address outside `2000::/3` that no other block covers.
    Reserved,
    /// IETF protocol assignments (`192.0.0.0/24`, `2001::/23`) and their
    /// non-anycast sub-assignments (dummy addresses, NAT64 discovery, …).
    ProtocolAssignment,
    /// Globally reachable special-purpose anycast or service blocks: PCP and
    /// TURN anycast, AS112, AMT, `ORCHIDv2`, DRIP.
    Anycast,
    /// `::ffff:0:0/96`: IPv4-mapped IPv6 addresses (RFC 4291).
    Ipv4Mapped,
    /// `::/96`: deprecated IPv4-compatible IPv6 addresses (RFC 4291).
    Ipv4Compatible,
    /// IPv4/IPv6 translation: `64:ff9b::/96` (RFC 6052) and
    /// `64:ff9b:1::/48` (RFC 8215).
    Translation,
    /// `100::/64`: discard-only prefix (RFC 6666) and the dummy prefix
    /// `100:0:0:1::/64` (RFC 9780).
    Discard,
    /// `2001::/32`: Teredo (RFC 4380).
    Teredo,
    /// `2002::/16`: 6to4 (RFC 3056).
    SixToFour,
    /// `5f00::/16`: `SRv6` segment identifiers (RFC 9602).
    SegmentRouting,
    /// No special-purpose block applies: ordinary global unicast.
    Global,
}

/// Which IANA registry a [`SpecialRange`] comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Registry {
    /// The IPv4 or IPv6 Special-Purpose Address Registry (RFC 6890). The
    /// four boolean attributes are filled in from it.
    SpecialPurpose,
    /// The general IPv4 or IPv6 address-space registry. These blocks have no
    /// special-purpose attributes, so all four are `None`.
    AddressSpace,
}

/// One address block from an IANA registry, with its RFC 6890 attributes.
///
/// The boolean attributes mirror the registry columns. `None` stands for the
/// registry's "N/A", which means the answer is decided by a more specific
/// (or, failing that, a less specific) block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpecialRange {
    network: IpAddr,
    prefix_len: u8,
    name: &'static str,
    rfc: &'static str,
    category: Category,
    registry: Registry,
    source: Option<bool>,
    destination: Option<bool>,
    forwardable: Option<bool>,
    globally_reachable: Option<bool>,
    reserved_by_protocol: Option<bool>,
}

impl SpecialRange {
    /// The first address of the block.
    #[must_use]
    pub const fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length in bits.
    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// The registry's name for the block, e.g. `"Private-Use"`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The defining document(s), e.g. `"RFC 1918"`.
    #[must_use]
    pub const fn rfc(&self) -> &'static str {
        self.rfc
    }

    /// What the block is used for.
    #[must_use]
    pub const fn category(&self) -> Category {
        self.category
    }

    /// Which registry the block comes from.
    #[must_use]
    pub const fn registry(&self) -> Registry {
        self.registry
    }

    /// Whether an address from the block may be used as a source address.
    #[must_use]
    pub const fn source(&self) -> Option<bool> {
        self.source
    }

    /// Whether an address from the block may be used as a destination.
    #[must_use]
    pub const fn destination(&self) -> Option<bool> {
        self.destination
    }

    /// Whether routers may forward packets with an address from the block.
    #[must_use]
    pub const fn forwardable(&self) -> Option<bool> {
        self.forwardable
    }

    /// Whether the block is globally reachable.
    #[must_use]
    pub const fn globally_reachable(&self) -> Option<bool> {
        self.globally_reachable
    }

    /// Whether the block is reserved by the IP protocol itself, rather than
    /// set aside by an allocation.
    #[must_use]
    pub const fn reserved_by_protocol(&self) -> Option<bool> {
        self.reserved_by_protocol
    }

    /// Whether `ip` lies inside the block. Addresses of the other family
    /// never match; IPv4-mapped IPv6 addresses are *not* unwrapped here (see
    /// [`canonical`](crate::canonical)).
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_match_v4(u32::from(net), u32::from(ip), self.prefix_len)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_match_v6(u128::from(net), u128::from(ip), self.prefix_len)
            }
            _ => false,
        }
    }
}

impl fmt::Display for SpecialRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

pub fn prefix_match_v4(net: u32, ip: u32, len: u8) -> bool {
    let mask = u32::MAX
        .checked_shl(32 - u32::from(len.min(32)))
        .unwrap_or(0);
    net & mask == ip & mask
}

pub fn prefix_match_v6(net: u128, ip: u128, len: u8) -> bool {
    let mask = u128::MAX
        .checked_shl(128 - u32::from(len.min(128)))
        .unwrap_or(0);
    net & mask == ip & mask
}

const T: Option<bool> = Some(true);
const F: Option<bool> = Some(false);
const NA: Option<bool> = None;

#[allow(clippy::too_many_arguments, reason = "mirrors the registry columns")]
const fn sp(
    network: IpAddr,
    prefix_len: u8,
    name: &'static str,
    rfc: &'static str,
    category: Category,
    [
        source,
        destination,
        forwardable,
        globally_reachable,
        reserved_by_protocol,
    ]: [Option<bool>; 5],
) -> SpecialRange {
    SpecialRange {
        network,
        prefix_len,
        name,
        rfc,
        category,
        registry: Registry::SpecialPurpose,
        source,
        destination,
        forwardable,
        globally_reachable,
        reserved_by_protocol,
    }
}

const fn space(
    network: IpAddr,
    prefix_len: u8,
    name: &'static str,
    rfc: &'static str,
    category: Category,
) -> SpecialRange {
    SpecialRange {
        network,
        prefix_len,
        name,
        rfc,
        category,
        registry: Registry::AddressSpace,
        source: NA,
        destination: NA,
        forwardable: NA,
        globally_reachable: NA,
        reserved_by_protocol: NA,
    }
}

const fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

const fn v6(s: [u16; 8]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ))
}

use Category as C;

/// The IPv4 blocks, in registry order. Columns of the attribute array:
/// source, destination, forwardable, globally reachable, reserved-by-protocol.
#[rustfmt::skip]
pub static IPV4: &[SpecialRange] = &[
    sp(v4(0, 0, 0, 0), 8, "\"This network\"", "RFC 791", C::ThisNetwork, [T, F, F, F, T]),
    sp(v4(0, 0, 0, 0), 32, "\"This host on this network\"", "RFC 1122", C::Unspecified, [T, F, F, F, T]),
    sp(v4(10, 0, 0, 0), 8, "Private-Use", "RFC 1918", C::Private, [T, T, T, F, F]),
    sp(v4(100, 64, 0, 0), 10, "Shared Address Space", "RFC 6598", C::Shared, [T, T, T, F, F]),
    sp(v4(127, 0, 0, 0), 8, "Loopback", "RFC 1122", C::Loopback, [F, F, F, F, T]),
    sp(v4(169, 254, 0, 0), 16, "Link Local", "RFC 3927", C::LinkLocal, [T, T, F, F, T]),
    sp(v4(172, 16, 0, 0), 12, "Private-Use", "RFC 1918", C::Private, [T, T, T, F, F]),
    sp(v4(192, 0, 0, 0), 24, "IETF Protocol Assignments", "RFC 6890", C::ProtocolAssignment, [F, F, F, F, F]),
    sp(v4(192, 0, 0, 0), 29, "IPv4 Service Continuity Prefix", "RFC 7335", C::ProtocolAssignment, [T, T, T, F, F]),
    sp(v4(192, 0, 0, 8), 32, "IPv4 dummy address", "RFC 7600", C::ProtocolAssignment, [T, F, F, F, F]),
    sp(v4(192, 0, 0, 9), 32, "Port Control Protocol Anycast", "RFC 7723", C::Anycast, [T, T, T, T, F]),
    sp(v4(192, 0, 0, 10), 32, "Traversal Using Relays around NAT Anycast", "RFC 8155", C::Anycast, [T, T, T, T, F]),
    sp(v4(192, 0, 0, 170), 32, "NAT64/DNS64 Discovery", "RFC 8880, RFC 7050", C::ProtocolAssignment, [F, F, F, F, T]),
    sp(v4(192, 0, 0, 171), 32, "NAT64/DNS64 Discovery", "RFC 8880, RFC 7050", C::ProtocolAssignment, [F, F, F, F, T]),
    sp(v4(192, 0, 2, 0), 24, "Documentation (TEST-NET-1)", "RFC 5737", C::Documentation, [F, F, F, F, F]),
    sp(v4(192, 31, 196, 0), 24, "AS112-v4", "RFC 7535", C::Anycast, [T, T, T, T, F]),
    sp(v4(192, 52, 193, 0), 24, "AMT", "RFC 7450", C::Anycast, [T, T, T, T, F]),
    // Deprecated by RFC 7526; no longer routed. Treated as not globally
    // reachable so that it never passes an egress check.
    sp(v4(192, 88, 99, 0), 24, "Deprecated (6to4 Relay Anycast)", "RFC 7526", C::Reserved, [NA, NA, NA, F, NA]),
    sp(v4(192, 88, 99, 2), 32, "6a44-relay anycast address", "RFC 6751", C::ProtocolAssignment, [T, T, T, F, F]),
    sp(v4(192, 168, 0, 0), 16, "Private-Use", "RFC 1918", C::Private, [T, T, T, F, F]),
    sp(v4(192, 175, 48, 0), 24, "Direct Delegation AS112 Service", "RFC 7534", C::Anycast, [T, T, T, T, F]),
    sp(v4(198, 18, 0, 0), 15, "Benchmarking", "RFC 2544", C::Benchmarking, [T, T, T, F, F]),
    sp(v4(198, 51, 100, 0), 24, "Documentation (TEST-NET-2)", "RFC 5737", C::Documentation, [F, F, F, F, F]),
    sp(v4(203, 0, 113, 0), 24, "Documentation (TEST-NET-3)", "RFC 5737", C::Documentation, [F, F, F, F, F]),
    space(v4(224, 0, 0, 0), 4, "Multicast", "RFC 5771", C::Multicast),
    sp(v4(240, 0, 0, 0), 4, "Reserved", "RFC 1112", C::Reserved, [F, F, F, F, T]),
    sp(v4(255, 255, 255, 255), 32, "Limited Broadcast", "RFC 8190, RFC 919", C::Broadcast, [F, T, F, F, T]),
];

/// The IPv6 blocks, in registry order. Columns as for [`IPV4`].
#[rustfmt::skip]
pub static IPV6: &[SpecialRange] = &[
    space(v6([0, 0, 0, 0, 0, 0, 0, 0]), 96, "IPv4-compatible (deprecated)", "RFC 4291", C::Ipv4Compatible),
    sp(v6([0, 0, 0, 0, 0, 0, 0, 1]), 128, "Loopback Address", "RFC 4291", C::Loopback, [F, F, F, F, T]),
    sp(v6([0, 0, 0, 0, 0, 0, 0, 0]), 128, "Unspecified Address", "RFC 4291", C::Unspecified, [T, F, F, F, T]),
    sp(v6([0, 0, 0, 0, 0, 0xffff, 0, 0]), 96, "IPv4-mapped Address", "RFC 4291", C::Ipv4Mapped, [F, F, F, F, T]),
    sp(v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0]), 96, "IPv4-IPv6 Translation", "RFC 6052", C::Translation, [T, T, T, T, F]),
    sp(v6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0]), 48, "IPv4-IPv6 Translation", "RFC 8215", C::Translation, [T, T, T, F, F]),
    sp(v6([0x100, 0, 0, 0, 0, 0, 0, 0]), 64, "Discard-Only Address Block", "RFC 6666", C::Discard, [T, T, T, F, F]),
    sp(v6([0x100, 0, 0, 1, 0, 0, 0, 0]), 64, "Dummy IPv6 Prefix", "RFC 9780", C::Discard, [F, F, F, F, F]),
    sp(v6([0x2001, 0, 0, 0, 0, 0, 0, 0]), 23, "IETF Protocol Assignments", "RFC 2928", C::ProtocolAssignment, [NA, NA, NA, F, F]),
    sp(v6([0x2001, 0, 0, 0, 0, 0, 0, 0]), 32, "TEREDO", "RFC 4380, RFC 8190", C::Teredo, [T, T, T, NA, F]),
    sp(v6([0x2001, 1, 0, 0, 0, 0, 0, 1]), 128, "Port Control Protocol Anycast", "RFC 7723", C::Anycast, [T, T, T, T, F]),
    sp(v6([0x2001, 1, 0, 0, 0, 0, 0, 2]), 128, "Traversal Using Relays around NAT Anycast", "RFC 8155", C::Anycast, [T, T, T, T, F]),
    sp(v6([0x2001, 1, 0, 0, 0, 0, 0, 3]), 128, "DNS-SD Service Registration Protocol Anycast", "RFC 9665", C::Anycast, [T, T, T, T, F]),
    sp(v6([0x2001, 2, 0, 0, 0, 0, 0, 0]), 48, "Benchmarking", "RFC 5180", C::Benchmarking, [T, T, T, F, F]),
    sp(v6([0x2001, 3, 0, 0, 0, 0, 0, 0]), 32, "AMT", "RFC 7450", C::Anycast, [T, T, T, T, F]),
    sp(v6([0x2001, 4, 0x112, 0, 0, 0, 0, 0]), 48, "AS112-v6", "RFC 7535", C::Anycast, [T, T, T, T, F]),
    sp(v6([0x2001, 0x10, 0, 0, 0, 0, 0, 0]), 28, "Deprecated (previously ORCHID)", "RFC 4843", C::Reserved, [NA, NA, NA, F, NA]),
    sp(v6([0x2001, 0x20, 0, 0, 0, 0, 0, 0]), 28, "ORCHIDv2", "RFC 7343", C::Anycast, [T, T, T, T, F]),
    sp(v6([0x2001, 0x30, 0, 0, 0, 0, 0, 0]), 28, "Drone Remote ID Protocol Entity Tags (DETs) Prefix", "RFC 9374", C::Anycast, [T, T, T, T, F]),
    sp(v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]), 32, "Documentation", "RFC 3849", C::Documentation, [F, F, F, F, F]),
    sp(v6([0x2002, 0, 0, 0, 0, 0, 0, 0]), 16, "6to4", "RFC 3056", C::SixToFour, [T, T, T, NA, F]),
    sp(v6([0x2620, 0x4f, 0x8000, 0, 0, 0, 0, 0]), 48, "Direct Delegation AS112 Service", "RFC 7534", C::Anycast, [T, T, T, T, F]),
    sp(v6([0x3fff, 0, 0, 0, 0, 0, 0, 0]), 20, "Documentation", "RFC 9637", C::Documentation, [F, F, F, F, F]),
    sp(v6([0x5f00, 0, 0, 0, 0, 0, 0, 0]), 16, "Segment Routing (SRv6) SIDs", "RFC 9602", C::SegmentRouting, [T, T, T, F, F]),
    sp(v6([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7, "Unique-Local", "RFC 4193, RFC 8190", C::UniqueLocal, [T, T, T, F, F]),
    sp(v6([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10, "Link-Local Unicast", "RFC 4291", C::LinkLocal, [T, T, F, F, T]),
    space(v6([0xfec0, 0, 0, 0, 0, 0, 0, 0]), 10, "Site-Local Unicast (deprecated)", "RFC 3879", C::SiteLocal),
    space(v6([0xff00, 0, 0, 0, 0, 0, 0, 0]), 8, "Multicast", "RFC 4291", C::Multicast),
];

/// Every block for `ip`'s family, in registry order.
pub fn table(ip: IpAddr) -> &'static [SpecialRange] {
    match ip {
        IpAddr::V4(_) => IPV4,
        IpAddr::V6(_) => IPV6,
    }
}

/// The most specific block containing `ip` (no unwrapping).
pub fn most_specific(ip: IpAddr) -> Option<&'static SpecialRange> {
    most_specific_where(ip, |_| true)
}

/// The most specific block containing `ip` that satisfies `pred`.
pub fn most_specific_where(
    ip: IpAddr,
    pred: impl Fn(&SpecialRange) -> bool,
) -> Option<&'static SpecialRange> {
    table(ip)
        .iter()
        .filter(|r| r.contains(ip) && pred(r))
        .max_by_key(|r| r.prefix_len)
}
