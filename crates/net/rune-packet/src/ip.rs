//! IP protocol numbers.

use std::fmt;

/// An IP protocol / IPv6 next-header number.
///
/// Registry: <https://www.iana.org/assignments/protocol-numbers>.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpProtocol(pub u8);

impl IpProtocol {
    /// IPv6 Hop-by-Hop Options.
    pub const HOPOPT: Self = Self(0);
    /// ICMP for IPv4.
    pub const ICMP: Self = Self(1);
    /// IGMP.
    pub const IGMP: Self = Self(2);
    /// IPv4 encapsulation (IP-in-IP).
    pub const IPV4: Self = Self(4);
    /// TCP.
    pub const TCP: Self = Self(6);
    /// UDP.
    pub const UDP: Self = Self(17);
    /// IPv6 encapsulation.
    pub const IPV6: Self = Self(41);
    /// IPv6 Routing header.
    pub const IPV6_ROUTE: Self = Self(43);
    /// IPv6 Fragment header.
    pub const IPV6_FRAG: Self = Self(44);
    /// GRE.
    pub const GRE: Self = Self(47);
    /// Encapsulating Security Payload.
    pub const ESP: Self = Self(50);
    /// Authentication Header.
    pub const AH: Self = Self(51);
    /// `ICMPv6`.
    pub const ICMPV6: Self = Self(58);
    /// IPv6 "no next header".
    pub const IPV6_NONXT: Self = Self(59);
    /// IPv6 Destination Options.
    pub const IPV6_OPTS: Self = Self(60);
    /// SCTP.
    pub const SCTP: Self = Self(132);
    /// Mobility header.
    pub const MOBILITY: Self = Self(135);
    /// Host Identity Protocol.
    pub const HIP: Self = Self(139);
    /// Shim6.
    pub const SHIM6: Self = Self(140);

    /// Whether this is an IPv6 extension header that this crate walks
    /// past to reach the upper layer (ESP is not: its contents are
    /// encrypted).
    #[must_use]
    pub const fn is_ipv6_extension(self) -> bool {
        matches!(self.0, 0 | 43 | 44 | 51 | 60 | 135 | 139 | 140)
    }

    /// A short name for well-known protocols.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0 => "HOPOPT",
            1 => "ICMP",
            2 => "IGMP",
            4 => "IPv4",
            6 => "TCP",
            17 => "UDP",
            41 => "IPv6",
            43 => "IPv6-Route",
            44 => "IPv6-Frag",
            47 => "GRE",
            50 => "ESP",
            51 => "AH",
            58 => "ICMPv6",
            59 => "IPv6-NoNxt",
            60 => "IPv6-Opts",
            132 => "SCTP",
            135 => "Mobility",
            139 => "HIP",
            140 => "Shim6",
            _ => return None,
        })
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "{}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(IpProtocol::TCP.to_string(), "TCP");
        assert_eq!(IpProtocol(253).to_string(), "253");
        assert!(IpProtocol::IPV6_FRAG.is_ipv6_extension());
        assert!(!IpProtocol::ESP.is_ipv6_extension());
        assert!(!IpProtocol::TCP.is_ipv6_extension());
    }
}
