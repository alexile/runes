//! The [`Asn`] type.

use std::fmt;
use std::str::FromStr;

use crate::Error;

/// A 32-bit autonomous system number ([RFC 6793]).
///
/// Parses `"AS13335"`, `"as13335"`, `"13335"` and the asdot notation of
/// [RFC 5396] (`"1.10"` is AS65546). Displays as `AS13335`.
///
/// ```
/// use rune_asn::Asn;
///
/// let asn: Asn = "AS13335".parse()?;
/// assert_eq!(asn.get(), 13335);
/// assert_eq!(asn.to_string(), "AS13335");
/// assert_eq!("1.10".parse::<Asn>()?, Asn::new(65546));
/// assert!(Asn::new(64512).is_private());
/// # Ok::<(), rune_asn::Error>(())
/// ```
///
/// [RFC 6793]: https://www.rfc-editor.org/rfc/rfc6793
/// [RFC 5396]: https://www.rfc-editor.org/rfc/rfc5396
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Asn(u32);

impl Asn {
    /// `AS_TRANS` (AS23456), the placeholder 2-byte speakers see for a
    /// 4-byte ASN ([RFC 6793]).
    ///
    /// [RFC 6793]: https://www.rfc-editor.org/rfc/rfc6793
    pub const TRANS: Self = Self(23456);

    /// Wrap a raw ASN.
    #[must_use]
    pub const fn new(asn: u32) -> Self {
        Self(asn)
    }

    /// The raw number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Whether the ASN is reserved for private use: AS64512–AS65534 and
    /// AS4200000000–AS4294967294 ([RFC 6996]).
    ///
    /// [RFC 6996]: https://www.rfc-editor.org/rfc/rfc6996
    #[must_use]
    pub const fn is_private(self) -> bool {
        matches!(self.0, 64_512..=65_534 | 4_200_000_000..=4_294_967_294)
    }

    /// Whether the ASN is reserved for documentation: AS64496–AS64511 and
    /// AS65536–AS65551 ([RFC 5398]).
    ///
    /// [RFC 5398]: https://www.rfc-editor.org/rfc/rfc5398
    #[must_use]
    pub const fn is_documentation(self) -> bool {
        matches!(self.0, 64_496..=64_511 | 65_536..=65_551)
    }

    /// Whether the ASN must never appear as a route origin: AS0
    /// ([RFC 7607]), `AS_TRANS`, the last 16- and 32-bit ASNs ([RFC 7300]),
    /// IANA-reserved AS65552–AS131071, and the private and documentation
    /// ranges.
    ///
    /// [RFC 7607]: https://www.rfc-editor.org/rfc/rfc7607
    /// [RFC 7300]: https://www.rfc-editor.org/rfc/rfc7300
    #[must_use]
    pub const fn is_reserved(self) -> bool {
        matches!(
            self.0,
            0 | 23_456 | 65_535 | 65_552..=131_071 | 4_294_967_295
        ) || self.is_private()
            || self.is_documentation()
    }
}

impl From<u32> for Asn {
    fn from(asn: u32) -> Self {
        Self(asn)
    }
}

impl From<Asn> for u32 {
    fn from(asn: Asn) -> Self {
        asn.0
    }
}

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AS{}", self.0)
    }
}

/// Parse decimal digits only (no sign, no whitespace).
fn digits<T: FromStr>(s: &str) -> Option<T> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

impl FromStr for Asn {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let body = match s.get(..2) {
            Some(p) if p.eq_ignore_ascii_case("as") => &s[2..],
            _ => s,
        };
        let value = match body.split_once('.') {
            Some((high, low)) => {
                let high: u16 = digits(high).ok_or(Error::InvalidAsn)?;
                let low: u16 = digits(low).ok_or(Error::InvalidAsn)?;
                (u32::from(high) << 16) | u32::from(low)
            }
            None => digits(body).ok_or(Error::InvalidAsn)?,
        };
        Ok(Self(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_prefixed_and_asdot_forms() {
        assert_eq!("13335".parse::<Asn>(), Ok(Asn(13335)));
        assert_eq!("AS13335".parse::<Asn>(), Ok(Asn(13335)));
        assert_eq!("as13335".parse::<Asn>(), Ok(Asn(13335)));
        assert_eq!("0.0".parse::<Asn>(), Ok(Asn(0)));
        assert_eq!("65535.65535".parse::<Asn>(), Ok(Asn(u32::MAX)));
        assert_eq!("4294967295".parse::<Asn>(), Ok(Asn(u32::MAX)));
    }

    #[test]
    fn rejects_malformed_numbers() {
        for bad in [
            "",
            "AS",
            "4294967296",
            "-1",
            "+1",
            " 1",
            "1.",
            ".1",
            "1.65536",
            "1.2.3",
            "ASx",
            "AS-1",
            "１２",
        ] {
            assert_eq!(bad.parse::<Asn>(), Err(Error::InvalidAsn), "{bad:?}");
        }
    }

    #[test]
    fn classifies_special_ranges() {
        assert!(Asn(0).is_reserved());
        assert!(Asn::TRANS.is_reserved());
        assert!(Asn(64_496).is_documentation() && Asn(64_496).is_reserved());
        assert!(Asn(65_000).is_private() && !Asn(65_000).is_documentation());
        assert!(Asn(4_200_000_000).is_private());
        assert!(Asn(100_000).is_reserved() && !Asn(100_000).is_private());
        assert!(!Asn(13_335).is_reserved());
        assert!(!Asn(131_072).is_reserved());
    }
}
