//! Ethernet II / IEEE 802.3 frames and IEEE 802.1Q / 802.1ad VLAN tags.

use std::fmt;

use crate::error::{Error, Layer, fixed, split};

/// A 48-bit IEEE MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);
    /// `00:00:00:00:00:00`.
    pub const ZERO: Self = Self([0; 6]);

    /// Whether this is the broadcast address.
    #[must_use]
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Whether the group (I/G) bit is set: multicast or broadcast.
    #[must_use]
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Whether the locally administered (U/L) bit is set.
    #[must_use]
    pub const fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, octet) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{octet:02x}")?;
        }
        Ok(())
    }
}

/// An `EtherType` (or, at 1500 and below, an IEEE 802.3 length).
///
/// Registry: <https://www.iana.org/assignments/ieee-802-numbers>.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EtherType(pub u16);

impl EtherType {
    /// IPv4.
    pub const IPV4: Self = Self(0x0800);
    /// ARP.
    pub const ARP: Self = Self(0x0806);
    /// IEEE 802.1Q customer VLAN tag.
    pub const VLAN: Self = Self(0x8100);
    /// IPv6.
    pub const IPV6: Self = Self(0x86dd);
    /// IEEE 802.1ad service VLAN tag (Q-in-Q).
    pub const QINQ: Self = Self(0x88a8);
    /// Legacy pre-standard Q-in-Q tag.
    pub const QINQ_LEGACY: Self = Self(0x9100);

    /// Whether the field is an 802.3 length (≤ 1500) rather than a type.
    #[must_use]
    pub const fn is_length(self) -> bool {
        self.0 <= 1500
    }

    /// Whether this value introduces a VLAN tag.
    #[must_use]
    pub const fn is_vlan(self) -> bool {
        matches!(self.0, 0x8100 | 0x88a8 | 0x9100)
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::IPV4 => "IPv4",
            Self::ARP => "ARP",
            Self::VLAN => "802.1Q",
            Self::IPV6 => "IPv6",
            Self::QINQ => "802.1ad",
            Self::QINQ_LEGACY => "Q-in-Q",
            _ => return write!(f, "0x{:04x}", self.0),
        };
        f.write_str(name)
    }
}

/// One IEEE 802.1Q / 802.1ad VLAN tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VlanTag {
    /// Tag protocol identifier, e.g. [`EtherType::VLAN`].
    pub tpid: EtherType,
    /// Priority code point (3 bits).
    pub pcp: u8,
    /// Drop eligible indicator.
    pub dei: bool,
    /// VLAN identifier (12 bits).
    pub vid: u16,
}

impl VlanTag {
    /// An 802.1Q tag for `vid` (masked to 12 bits), priority 0.
    #[must_use]
    pub const fn new(vid: u16) -> Self {
        Self {
            tpid: EtherType::VLAN,
            pcp: 0,
            dei: false,
            vid: vid & 0x0fff,
        }
    }

    /// The tag with a different TPID, e.g. [`EtherType::QINQ`].
    #[must_use]
    pub const fn with_tpid(mut self, tpid: EtherType) -> Self {
        self.tpid = tpid;
        self
    }

    /// The tag with a priority (masked to 3 bits).
    #[must_use]
    pub const fn with_pcp(mut self, pcp: u8) -> Self {
        self.pcp = pcp & 0x07;
        self
    }

    /// The tag with the drop-eligible bit set or cleared.
    #[must_use]
    pub const fn with_dei(mut self, dei: bool) -> Self {
        self.dei = dei;
        self
    }

    /// The 16-bit tag control information.
    #[must_use]
    pub const fn tci(&self) -> u16 {
        ((self.pcp as u16 & 0x07) << 13) | ((self.dei as u16) << 12) | (self.vid & 0x0fff)
    }

    const fn from_wire(tpid: EtherType, tci: u16) -> Self {
        Self {
            tpid,
            #[allow(clippy::cast_possible_truncation, reason = "3-bit field")]
            pcp: (tci >> 13) as u8,
            dei: tci & 0x1000 != 0,
            vid: tci & 0x0fff,
        }
    }
}

/// A parsed Ethernet frame, borrowing its payload from the input.
///
/// The frame check sequence is not expected: captures normally strip it.
/// Trailing padding stays in [`EthernetFrame::payload`]; the IP parsers
/// trim it using their own length fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    /// Destination address.
    pub dst: MacAddr,
    /// Source address.
    pub src: MacAddr,
    /// Type of the payload, after any VLAN tags.
    pub ethertype: EtherType,
    /// Bytes after the header (and tags).
    pub payload: &'a [u8],
    tags: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// Length of an untagged header.
    pub const HEADER_LEN: usize = 14;

    /// Parse a frame, following any number of stacked VLAN tags.
    ///
    /// For an IEEE 802.3 frame (type field ≤ 1500) the payload is cut to
    /// the declared length.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] if the header, a tag, or the declared 802.3
    /// length runs past the end of `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let header = fixed::<14>(data, Layer::Ethernet)?;
        let dst = MacAddr([
            header[0], header[1], header[2], header[3], header[4], header[5],
        ]);
        let src = MacAddr([
            header[6], header[7], header[8], header[9], header[10], header[11],
        ]);
        let mut ethertype = EtherType(u16::from_be_bytes([header[12], header[13]]));
        let mut offset = Self::HEADER_LEN;
        while ethertype.is_vlan() {
            let tag = data
                .get(offset..offset + 4)
                .and_then(|t| t.first_chunk::<4>())
                .ok_or_else(|| Error::truncated(Layer::Vlan, offset + 4, data.len()))?;
            ethertype = EtherType(u16::from_be_bytes([tag[2], tag[3]]));
            offset += 4;
        }
        let (_, mut payload) = split(data, offset, Layer::Ethernet)?;
        if ethertype.is_length() {
            let len = usize::from(ethertype.0);
            payload = payload
                .get(..len)
                .ok_or_else(|| Error::truncated(Layer::Ethernet, offset + len, data.len()))?;
        }
        Ok(Self {
            dst,
            src,
            ethertype,
            payload,
            tags: data.get(12..offset - 2).unwrap_or_default(),
        })
    }

    /// The VLAN tags, outermost first.
    #[must_use]
    pub const fn vlan_tags(&self) -> VlanTags<'a> {
        VlanTags { rest: self.tags }
    }

    /// Header length including VLAN tags.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        Self::HEADER_LEN + self.tags.len()
    }
}

/// Iterator over the VLAN tags of an [`EthernetFrame`].
#[derive(Debug, Clone)]
pub struct VlanTags<'a> {
    // Pairs of (TPID, TCI); the last TCI is followed by nothing.
    rest: &'a [u8],
}

impl Iterator for VlanTags<'_> {
    type Item = VlanTag;

    fn next(&mut self) -> Option<VlanTag> {
        let tag = self.rest.first_chunk::<4>()?;
        self.rest = self.rest.get(4..).unwrap_or_default();
        Some(VlanTag::from_wire(
            EtherType(u16::from_be_bytes([tag[0], tag[1]])),
            u16::from_be_bytes([tag[2], tag[3]]),
        ))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.rest.len() / 4;
        (n, Some(n))
    }
}

impl ExactSizeIterator for VlanTags<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    const DST: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const SRC: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];

    #[test]
    fn untagged() {
        let mut frame = DST.to_vec();
        frame.extend_from_slice(&SRC);
        frame.extend_from_slice(&[0x08, 0x00, 1, 2, 3]);
        let parsed = EthernetFrame::parse(&frame).unwrap();
        assert_eq!(parsed.dst, MacAddr(DST));
        assert_eq!(parsed.src.to_string(), "02:aa:bb:cc:dd:ee");
        assert!(parsed.src.is_local());
        assert_eq!(parsed.ethertype, EtherType::IPV4);
        assert_eq!(parsed.payload, &[1, 2, 3]);
        assert_eq!(parsed.vlan_tags().count(), 0);
        assert_eq!(parsed.header_len(), 14);
    }

    #[test]
    fn qinq() {
        let mut frame = DST.to_vec();
        frame.extend_from_slice(&SRC);
        frame.extend_from_slice(&[0x88, 0xa8, 0x00, 0x64]); // S-tag vid 100
        frame.extend_from_slice(&[0x81, 0x00, 0xb0, 0x0a]); // C-tag pcp 5, dei, vid 10
        frame.extend_from_slice(&[0x86, 0xdd, 9]);
        let parsed = EthernetFrame::parse(&frame).unwrap();
        assert_eq!(parsed.ethertype, EtherType::IPV6);
        assert_eq!(parsed.payload, &[9]);
        let tags: Vec<_> = parsed.vlan_tags().collect();
        assert_eq!(
            tags,
            [
                VlanTag::new(100).with_tpid(EtherType::QINQ),
                VlanTag::new(10).with_pcp(5).with_dei(true),
            ]
        );
        assert_eq!(tags[1].tci(), 0xb00a);
        assert_eq!(parsed.header_len(), 22);
    }

    #[test]
    fn truncated_tag_and_header() {
        let mut frame = DST.to_vec();
        frame.extend_from_slice(&SRC);
        assert_eq!(
            EthernetFrame::parse(&frame).unwrap_err(),
            Error::truncated(Layer::Ethernet, 14, 12)
        );
        frame.extend_from_slice(&[0x81, 0x00, 0x00]);
        assert_eq!(
            EthernetFrame::parse(&frame).unwrap_err(),
            Error::truncated(Layer::Vlan, 18, 15)
        );
    }

    #[test]
    fn ieee_802_3_length() {
        let mut frame = DST.to_vec();
        frame.extend_from_slice(&SRC);
        frame.extend_from_slice(&[0x00, 0x03, 0xaa, 0xaa, 0x03, 0, 0]);
        let parsed = EthernetFrame::parse(&frame).unwrap();
        assert!(parsed.ethertype.is_length());
        assert_eq!(parsed.payload, &[0xaa, 0xaa, 0x03]);
        frame.truncate(16);
        assert!(EthernetFrame::parse(&frame).unwrap_err().is_truncated());
    }

    #[test]
    fn mac_flags() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_multicast());
        assert!(!MacAddr(DST).is_multicast());
        assert_eq!(EtherType(0x1234).to_string(), "0x1234");
        assert_eq!(EtherType::ARP.to_string(), "ARP");
    }
}
