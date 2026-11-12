//! EUI-48 ([`MacAddr`]) and EUI-64 ([`Eui64`]) values: parsing, formatting
//! and classification.

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use crate::Error;

/// Textual notation of an address, for [`MacAddr::format`] and
/// [`Eui64::format`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Notation {
    /// Octets separated by colons: `00:1b:63:84:45:e6` (IEEE 802 "bit-reversed"
    /// convention as used by Linux, BSD and most tools).
    #[default]
    Colon,
    /// Octets separated by hyphens: `00-1b-63-84-45-e6` (IEEE canonical form,
    /// Windows).
    Hyphen,
    /// Groups of four hex digits separated by dots: `001b.6384.45e6` (Cisco).
    Dot,
    /// Plain hex digits without separators: `001b638445e6`.
    Bare,
}

/// Letter case of hex digits, for [`MacAddr::format`] and [`Eui64::format`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Case {
    /// `a`–`f`.
    #[default]
    Lower,
    /// `A`–`F`.
    Upper,
}

/// Bit 0 of the first octet: individual/group (I/G).
const GROUP_BIT: u8 = 0x01;
/// Bit 1 of the first octet: universal/local (U/L).
const LOCAL_BIT: u8 = 0x02;

/// Decodes one ASCII hex digit.
const fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes a run of hex digits into an integer (at most 16 digits).
pub fn hex_u64(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() || digits.len() > 16 {
        return None;
    }
    digits
        .iter()
        .try_fold(0u64, |acc, &d| Some((acc << 4) | u64::from(hex_value(d)?)))
}

/// Parses `N` octets in colon, hyphen, dot or bare-hex notation.
fn parse_octets<const N: usize>(s: &str, kind: &'static str) -> Result<[u8; N], Error> {
    let err = |reason| Error::InvalidAddress { kind, reason };
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    let sep = bytes
        .iter()
        .copied()
        .find(|b| matches!(b, b':' | b'-' | b'.'));
    match sep {
        Some(sep @ (b':' | b'-')) => {
            // One or two digits per octet (`0:1b:…` is how macOS prints them).
            let mut count = 0;
            for group in bytes.split(|&b| b == sep) {
                let slot = out.get_mut(count).ok_or_else(|| err("too many octets"))?;
                if group.is_empty() || group.len() > 2 {
                    return Err(err("each octet must have one or two hex digits"));
                }
                // At most two digits, so the value fits in a byte.
                *slot = u8::try_from(hex_u64(group).ok_or_else(|| err("invalid hex digit"))?)
                    .map_err(|_| err("invalid hex digit"))?;
                count += 1;
            }
            if count != N {
                return Err(err("too few octets"));
            }
        }
        Some(_) => {
            // Dot notation: groups of exactly four digits.
            let mut count = 0;
            for group in bytes.split(|&b| b == b'.') {
                if group.len() != 4 {
                    return Err(err("dot notation needs groups of four hex digits"));
                }
                let [hi, lo] = out
                    .get_mut(count * 2..count * 2 + 2)
                    .and_then(|s| <&mut [u8; 2]>::try_from(s).ok())
                    .ok_or_else(|| err("too many groups"))?;
                let value = hex_u64(group).ok_or_else(|| err("invalid hex digit"))?;
                let [.., h, l] = value.to_be_bytes();
                *hi = h;
                *lo = l;
                count += 1;
            }
            if count * 2 != N {
                return Err(err("too few groups"));
            }
        }
        None => {
            if bytes.len() != N * 2 {
                return Err(err("wrong number of hex digits"));
            }
            for (i, slot) in out.iter_mut().enumerate() {
                let pair = bytes.get(i * 2..i * 2 + 2).unwrap_or_default();
                let value = hex_u64(pair).ok_or_else(|| err("invalid hex digit"))?;
                *slot = value.to_be_bytes()[7];
            }
        }
    }
    Ok(out)
}

/// Writes octets in the given notation and case.
fn write_octets(
    f: &mut impl fmt::Write,
    octets: &[u8],
    notation: Notation,
    case: Case,
) -> fmt::Result {
    let digit = |n: u8| -> char {
        let table: &[u8; 16] = match case {
            Case::Lower => b"0123456789abcdef",
            Case::Upper => b"0123456789ABCDEF",
        };
        char::from(table[usize::from(n & 0x0f)])
    };
    for (i, &octet) in octets.iter().enumerate() {
        let sep = match notation {
            Notation::Colon => Some(':'),
            Notation::Hyphen => Some('-'),
            Notation::Dot if i % 2 == 0 => Some('.'),
            Notation::Dot | Notation::Bare => None,
        };
        if let (true, Some(sep)) = (i > 0, sep) {
            f.write_char(sep)?;
        }
        f.write_char(digit(octet >> 4))?;
        f.write_char(digit(octet))?;
    }
    Ok(())
}

/// Methods shared by [`MacAddr`] and [`Eui64`].
macro_rules! common {
    ($ty:ident, $n:literal, $kind:literal) => {
        impl $ty {
            /// The address made of all-zero octets.
            pub const NIL: Self = Self([0; $n]);

            /// The octets, in transmission order.
            #[must_use]
            pub const fn octets(&self) -> [u8; $n] {
                self.0
            }

            /// The first three octets: the OUI (or CID) of a universally
            /// administered address.
            #[must_use]
            pub const fn oui(&self) -> [u8; 3] {
                [self.0[0], self.0[1], self.0[2]]
            }

            /// Whether the individual/group (I/G) bit is set: a group
            /// (multicast or broadcast) address.
            #[must_use]
            pub const fn is_multicast(&self) -> bool {
                self.0[0] & GROUP_BIT != 0
            }

            /// Whether the I/G bit is clear: an individual (unicast) address.
            #[must_use]
            pub const fn is_unicast(&self) -> bool {
                !self.is_multicast()
            }

            /// Whether the universal/local (U/L) bit is set: a locally
            /// administered address (randomised, virtual or CID-based).
            #[must_use]
            pub const fn is_local(&self) -> bool {
                self.0[0] & LOCAL_BIT != 0
            }

            /// Whether the U/L bit is clear: a universally administered
            /// address whose first octets are an IEEE assignment.
            #[must_use]
            pub const fn is_universal(&self) -> bool {
                !self.is_local()
            }

            /// Whether every octet is `ff` (the broadcast address).
            #[must_use]
            pub fn is_broadcast(&self) -> bool {
                self.0 == [0xff; $n]
            }

            /// Whether every octet is zero.
            #[must_use]
            pub fn is_nil(&self) -> bool {
                self.0 == [0; $n]
            }

            /// The address with the U/L bit set or cleared.
            #[must_use]
            pub const fn with_local(mut self, local: bool) -> Self {
                if local {
                    self.0[0] |= LOCAL_BIT;
                } else {
                    self.0[0] &= !LOCAL_BIT;
                }
                self
            }

            /// The address with the I/G bit set or cleared.
            #[must_use]
            pub const fn with_multicast(mut self, multicast: bool) -> Self {
                if multicast {
                    self.0[0] |= GROUP_BIT;
                } else {
                    self.0[0] &= !GROUP_BIT;
                }
                self
            }

            /// Formats the address in `notation` and `case`.
            ///
            /// [`Display`](fmt::Display) is the same as
            /// `format(Notation::Colon, Case::Lower)`.
            #[must_use]
            pub fn format(&self, notation: Notation, case: Case) -> String {
                let mut out = String::with_capacity($n * 3);
                // Writing into a String cannot fail.
                let _ = write_octets(&mut out, &self.0, notation, case);
                out
            }
        }

        impl From<[u8; $n]> for $ty {
            fn from(octets: [u8; $n]) -> Self {
                Self(octets)
            }
        }

        impl From<$ty> for [u8; $n] {
            fn from(addr: $ty) -> Self {
                addr.0
            }
        }

        impl TryFrom<&[u8]> for $ty {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> Result<Self, Error> {
                <[u8; $n]>::try_from(bytes)
                    .map(Self)
                    .map_err(|_| Error::InvalidAddress {
                        kind: $kind,
                        reason: "wrong number of octets",
                    })
            }
        }

        impl FromStr for $ty {
            type Err = Error;

            /// Parses colon (`00:1b:63:84:45:e6`, one or two digits per
            /// octet), hyphen (`00-1B-63-84-45-E6`), dot (`001b.6384.45e6`)
            /// or bare-hex (`001b638445e6`) notation, in either case.
            fn from_str(s: &str) -> Result<Self, Error> {
                parse_octets::<$n>(s, $kind).map(Self)
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_octets(f, &self.0, Notation::Colon, Case::Lower)
            }
        }
    };
}

/// A 48-bit IEEE 802 MAC address (EUI-48).
///
/// Parse with [`str::parse`], format with [`Display`](fmt::Display) (colon,
/// lower case) or [`MacAddr::format`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddr(pub [u8; 6]);

/// A 64-bit IEEE extended unique identifier (EUI-64), as used by IEEE
/// 802.15.4, `FireWire` and IPv6 interface identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Eui64(pub [u8; 8]);

common!(MacAddr, 6, "EUI-48");
common!(Eui64, 8, "EUI-64");

impl MacAddr {
    /// `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);

    /// The address as the low 48 bits of an integer.
    #[must_use]
    pub fn to_u64(&self) -> u64 {
        self.0.iter().fold(0, |acc, &b| (acc << 8) | u64::from(b))
    }

    /// The address from the low 48 bits of `value`; `None` if any higher
    /// bit is set.
    #[must_use]
    pub const fn from_u64(value: u64) -> Option<Self> {
        if value >> 48 != 0 {
            return None;
        }
        let b = value.to_be_bytes();
        Some(Self([b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// The EUI-64 made by inserting `ff:fe` between the OUI and the
    /// extension (IEEE "encapsulated EUI-48").
    #[must_use]
    pub const fn to_eui64(&self) -> Eui64 {
        let m = self.0;
        Eui64([m[0], m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]])
    }

    /// The *modified* EUI-64 IPv6 interface identifier: [`to_eui64`]
    /// with the U/L bit inverted ([RFC 4291, Appendix A]).
    ///
    /// [`to_eui64`]: MacAddr::to_eui64
    /// [RFC 4291, Appendix A]: https://www.rfc-editor.org/rfc/rfc4291#appendix-A
    #[must_use]
    pub const fn to_modified_eui64(&self) -> Eui64 {
        let mut e = self.to_eui64();
        e.0[0] ^= LOCAL_BIT;
        e
    }

    /// The SLAAC link-local IPv6 address `fe80::/64` + modified EUI-64
    /// ([RFC 4862], [RFC 4291]).
    ///
    /// [RFC 4862]: https://www.rfc-editor.org/rfc/rfc4862
    /// [RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291
    #[must_use]
    pub fn to_ipv6_link_local(&self) -> Ipv6Addr {
        let id = self.to_modified_eui64().0;
        let mut o = [0u8; 16];
        o[0] = 0xfe;
        o[1] = 0x80;
        o[8..].copy_from_slice(&id);
        Ipv6Addr::from(o)
    }

    /// Recovers the MAC address from an IPv6 address whose interface
    /// identifier is a modified EUI-64 built from an EUI-48 (`…ff:fe…` in
    /// the middle), as SLAAC without privacy extensions produces.
    #[must_use]
    pub fn from_ipv6_interface_id(addr: Ipv6Addr) -> Option<Self> {
        let o = addr.octets();
        let mut id = [0u8; 8];
        id.copy_from_slice(&o[8..]);
        id[0] ^= LOCAL_BIT;
        Eui64(id).to_mac()
    }
}

impl Eui64 {
    /// The address as a 64-bit integer.
    #[must_use]
    pub const fn to_u64(&self) -> u64 {
        u64::from_be_bytes(self.0)
    }

    /// The address from a 64-bit integer.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        Self(value.to_be_bytes())
    }

    /// The EUI-48 encapsulated in this EUI-64 (octets 4 and 5 are
    /// `ff:fe`), or `None` for a native EUI-64.
    #[must_use]
    pub const fn to_mac(&self) -> Option<MacAddr> {
        let e = self.0;
        if e[3] == 0xff && e[4] == 0xfe {
            Some(MacAddr([e[0], e[1], e[2], e[5], e[6], e[7]]))
        } else {
            None
        }
    }

    /// The identifier with the U/L bit inverted: converts between an
    /// EUI-64 and a modified EUI-64 interface identifier ([RFC 4291,
    /// Appendix A]), in either direction.
    ///
    /// [RFC 4291, Appendix A]: https://www.rfc-editor.org/rfc/rfc4291#appendix-A
    #[must_use]
    pub const fn toggle_modified(mut self) -> Self {
        self.0[0] ^= LOCAL_BIT;
        self
    }
}

impl From<MacAddr> for Eui64 {
    fn from(mac: MacAddr) -> Self {
        mac.to_eui64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: MacAddr = MacAddr([0x00, 0x1b, 0x63, 0x84, 0x45, 0xe6]);

    #[test]
    fn parses_every_notation() {
        for s in [
            "00:1b:63:84:45:e6",
            "00:1B:63:84:45:E6",
            "0:1b:63:84:45:e6",
            "00-1B-63-84-45-E6",
            "001b.6384.45e6",
            "001B.6384.45E6",
            "001b638445e6",
        ] {
            assert_eq!(s.parse::<MacAddr>(), Ok(MAC), "{s}");
        }
    }

    #[test]
    fn rejects_malformed() {
        for s in [
            "",
            "00:1b:63:84:45",
            "00:1b:63:84:45:e6:00",
            "00:1b:63:84:45:g6",
            "00:1b:63:84:45:e6:",
            "00:1b:63:84:045:e6",
            "00:1b-63:84:45:e6",
            "001b.6384.45e",
            "001b.6384",
            "001b63845e6",
            "+01b638445e6",
            "00:1b:63:84:45:+6",
            " 00:1b:63:84:45:e6",
            "001b:6384:45e6",
        ] {
            assert!(s.parse::<MacAddr>().is_err(), "{s}");
        }
    }

    #[test]
    fn formats_every_notation() {
        assert_eq!(MAC.to_string(), "00:1b:63:84:45:e6");
        assert_eq!(
            MAC.format(Notation::Hyphen, Case::Upper),
            "00-1B-63-84-45-E6"
        );
        assert_eq!(MAC.format(Notation::Dot, Case::Lower), "001b.6384.45e6");
        assert_eq!(MAC.format(Notation::Bare, Case::Upper), "001B638445E6");
        let e = MAC.to_eui64();
        assert_eq!(e.to_string(), "00:1b:63:ff:fe:84:45:e6");
        assert_eq!(e.format(Notation::Dot, Case::Lower), "001b.63ff.fe84.45e6");
    }

    #[test]
    fn eui64_parsing() {
        let e: Eui64 = "00-1B-63-FF-FE-84-45-E6".parse().unwrap();
        assert_eq!(e.to_mac(), Some(MAC));
        assert_eq!("001b63fffe8445e6".parse::<Eui64>(), Ok(e));
        assert_eq!("001b.63ff.fe84.45e6".parse::<Eui64>(), Ok(e));
        assert!("00:1b:63:84:45:e6".parse::<Eui64>().is_err());
        assert!("001b.63ff.fe84".parse::<Eui64>().is_err());
        assert_eq!("0011223344556677".parse::<Eui64>().unwrap().to_mac(), None);
    }

    #[test]
    fn classification() {
        assert!(MAC.is_unicast() && MAC.is_universal());
        let bcast = MacAddr::BROADCAST;
        assert!(bcast.is_broadcast() && bcast.is_multicast() && bcast.is_local());
        let mcast: MacAddr = "01:00:5e:00:00:fb".parse().unwrap();
        assert!(mcast.is_multicast() && mcast.is_universal() && !mcast.is_broadcast());
        let random: MacAddr = "da:a1:19:00:00:01".parse().unwrap();
        assert!(random.is_local() && random.is_unicast());
        assert!(MacAddr::NIL.is_nil() && !MAC.is_nil());
        assert_eq!(MAC.with_local(true).with_multicast(true).octets()[0], 0x03);
        assert_eq!(random.with_local(false).octets()[0], 0xd8);
        assert_eq!(MAC.oui(), [0x00, 0x1b, 0x63]);
    }

    #[test]
    fn ipv6_conversions() {
        // RFC 4291 Appendix A example style: 00:1b:63 -> 02:1b:63:ff:fe.
        let ll = MAC.to_ipv6_link_local();
        assert_eq!(ll, "fe80::21b:63ff:fe84:45e6".parse::<Ipv6Addr>().unwrap());
        assert_eq!(MacAddr::from_ipv6_interface_id(ll), Some(MAC));
        let privacy: Ipv6Addr = "fe80::1234:5678:9abc:def0".parse().unwrap();
        assert_eq!(MacAddr::from_ipv6_interface_id(privacy), None);
        assert_eq!(MAC.to_modified_eui64().toggle_modified(), MAC.to_eui64());
    }

    #[test]
    fn integer_conversions() {
        assert_eq!(MAC.to_u64(), 0x001b_6384_45e6);
        assert_eq!(MacAddr::from_u64(0x001b_6384_45e6), Some(MAC));
        assert_eq!(MacAddr::from_u64(1 << 48), None);
        assert_eq!(
            Eui64::from_u64(0x0102_0304_0506_0708).to_u64(),
            0x0102_0304_0506_0708
        );
        assert!(MacAddr::try_from(&[1u8, 2, 3][..]).is_err());
        assert_eq!(MacAddr::try_from(&MAC.0[..]), Ok(MAC));
    }
}
