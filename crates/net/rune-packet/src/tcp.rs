//! TCP ([RFC 9293](https://www.rfc-editor.org/rfc/rfc9293)) headers and
//! options.

use std::fmt;
use std::ops::{BitOr, BitOrAssign};

use crate::checksum::PseudoHeader;
use crate::error::{Error, Layer, fixed};
use crate::ip::IpProtocol;

/// TCP control bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TcpFlags(pub u16);

impl TcpFlags {
    /// No more data from sender.
    pub const FIN: Self = Self(0x001);
    /// Synchronize sequence numbers.
    pub const SYN: Self = Self(0x002);
    /// Reset the connection.
    pub const RST: Self = Self(0x004);
    /// Push function.
    pub const PSH: Self = Self(0x008);
    /// Acknowledgment field is significant.
    pub const ACK: Self = Self(0x010);
    /// Urgent pointer field is significant.
    pub const URG: Self = Self(0x020);
    /// ECN-Echo ([RFC 3168](https://www.rfc-editor.org/rfc/rfc3168)).
    pub const ECE: Self = Self(0x040);
    /// Congestion window reduced.
    pub const CWR: Self = Self(0x080);
    /// Accurate ECN (formerly NS, RFC 3540).
    pub const AE: Self = Self(0x100);

    const NAMES: [(Self, &'static str); 9] = [
        (Self::FIN, "FIN"),
        (Self::SYN, "SYN"),
        (Self::RST, "RST"),
        (Self::PSH, "PSH"),
        (Self::ACK, "ACK"),
        (Self::URG, "URG"),
        (Self::ECE, "ECE"),
        (Self::CWR, "CWR"),
        (Self::AE, "AE"),
    ];

    /// Whether every bit of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for TcpFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for TcpFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl fmt::Display for TcpFlags {
    /// Set flag names joined by `|`, e.g. `SYN|ACK`; `-` for none.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (flag, name) in Self::NAMES {
            if self.contains(flag) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            f.write_str("-")?;
        }
        Ok(())
    }
}

/// A TCP option, borrowed from the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TcpOption<'a> {
    /// End of option list (kind 0). What follows is padding.
    EndOfOptions,
    /// No operation (kind 1).
    Nop,
    /// Maximum segment size (kind 2).
    MaxSegmentSize(u16),
    /// Window scale shift (kind 3, RFC 7323).
    WindowScale(u8),
    /// SACK permitted (kind 4, RFC 2018).
    SackPermitted,
    /// SACK blocks (kind 5, RFC 2018).
    Sack(SackBlocks<'a>),
    /// Timestamps (kind 8, RFC 7323).
    Timestamps {
        /// `TSval`.
        value: u32,
        /// `TSecr`.
        echo_reply: u32,
    },
    /// Any other option, with its data (after kind and length).
    Unknown {
        /// Option kind.
        kind: u8,
        /// Option data.
        data: &'a [u8],
    },
}

impl TcpOption<'_> {
    /// The option kind byte.
    #[must_use]
    pub const fn kind(&self) -> u8 {
        match self {
            Self::EndOfOptions => 0,
            Self::Nop => 1,
            Self::MaxSegmentSize(_) => 2,
            Self::WindowScale(_) => 3,
            Self::SackPermitted => 4,
            Self::Sack(_) => 5,
            Self::Timestamps { .. } => 8,
            Self::Unknown { kind, .. } => *kind,
        }
    }

    /// Append the wire form of the option to `out`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] if an unknown option's data exceeds 253 bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::EndOfOptions => out.push(0),
            Self::Nop => out.push(1),
            Self::MaxSegmentSize(mss) => {
                out.extend_from_slice(&[2, 4]);
                out.extend_from_slice(&mss.to_be_bytes());
            }
            Self::WindowScale(shift) => out.extend_from_slice(&[3, 3, *shift]),
            Self::SackPermitted => out.extend_from_slice(&[4, 2]),
            Self::Sack(blocks) => encode_tlv(out, 5, blocks.0)?,
            Self::Timestamps { value, echo_reply } => {
                out.extend_from_slice(&[8, 10]);
                out.extend_from_slice(&value.to_be_bytes());
                out.extend_from_slice(&echo_reply.to_be_bytes());
            }
            Self::Unknown { kind, data } => encode_tlv(out, *kind, data)?,
        }
        Ok(())
    }
}

fn encode_tlv(out: &mut Vec<u8>, kind: u8, data: &[u8]) -> Result<(), Error> {
    let len = u8::try_from(data.len() + 2).map_err(|_| Error::TooLarge {
        layer: Layer::Tcp,
        len: data.len() + 2,
        max: 255,
    })?;
    out.extend_from_slice(&[kind, len]);
    out.extend_from_slice(data);
    Ok(())
}

/// The left/right edge pairs of a SACK option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackBlocks<'a>(&'a [u8]);

impl<'a> SackBlocks<'a> {
    /// The raw option data (a multiple of 8 bytes).
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    /// Iterate over `(left edge, right edge)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (u32, u32)> + 'a {
        self.0.as_chunks::<8>().0.iter().map(|b| {
            (
                u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            )
        })
    }
}

/// Iterator over the options of a [`TcpSegment`].
///
/// A malformed option yields one error and ends the iteration.
#[derive(Debug, Clone)]
pub struct TcpOptions<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for TcpOptions<'a> {
    type Item = Result<TcpOption<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let (&kind, after) = self.rest.split_first()?;
        match kind {
            0 => {
                self.rest = &[];
                return Some(Ok(TcpOption::EndOfOptions));
            }
            1 => {
                self.rest = after;
                return Some(Ok(TcpOption::Nop));
            }
            _ => {}
        }
        let Some(&len) = after.first() else {
            self.rest = &[];
            return Some(Err(Error::malformed(Layer::Tcp, "option length missing")));
        };
        let len = usize::from(len);
        let Some(data) = self.rest.get(2..len.max(2)).filter(|_| len >= 2) else {
            self.rest = &[];
            return Some(Err(Error::malformed(
                Layer::Tcp,
                "option length out of bounds",
            )));
        };
        self.rest = self.rest.get(len..).unwrap_or_default();
        let option = match (kind, data.len()) {
            (2, 2) => TcpOption::MaxSegmentSize(u16::from_be_bytes([data[0], data[1]])),
            (3, 1) => TcpOption::WindowScale(data[0]),
            (4, 0) => TcpOption::SackPermitted,
            (5, n) if n % 8 == 0 && n > 0 => TcpOption::Sack(SackBlocks(data)),
            (8, 8) => TcpOption::Timestamps {
                value: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                echo_reply: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            },
            (2..=5 | 8, _) => {
                self.rest = &[];
                return Some(Err(Error::malformed(Layer::Tcp, "option has wrong length")));
            }
            _ => TcpOption::Unknown { kind, data },
        };
        Some(Ok(option))
    }
}

/// A parsed TCP segment, borrowing its options and payload from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgment number.
    pub ack: u32,
    /// Control bits.
    pub flags: TcpFlags,
    /// The three reserved bits (header bits 4–6).
    pub reserved: u8,
    /// Receive window.
    pub window: u16,
    /// Checksum as stored.
    pub checksum: u16,
    /// Urgent pointer.
    pub urgent_ptr: u16,
    /// Raw option bytes, padding included.
    pub options: &'a [u8],
    /// Data after the header.
    pub payload: &'a [u8],
    segment: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    /// Length of a header without options.
    pub const MIN_HEADER_LEN: usize = 20;

    /// Parse a TCP segment. Everything after the header is payload, so
    /// pass exactly the IP payload.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a data offset under 5 words;
    /// [`Error::Truncated`] if the header runs past `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let h = fixed::<20>(data, Layer::Tcp)?;
        let header_len = usize::from(h[12] >> 4) * 4;
        if header_len < Self::MIN_HEADER_LEN {
            return Err(Error::malformed(Layer::Tcp, "data offset under 5"));
        }
        let (header, payload) = data
            .split_at_checked(header_len)
            .ok_or_else(|| Error::truncated(Layer::Tcp, header_len, data.len()))?;
        Ok(Self {
            src_port: u16::from_be_bytes([h[0], h[1]]),
            dst_port: u16::from_be_bytes([h[2], h[3]]),
            seq: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
            ack: u32::from_be_bytes([h[8], h[9], h[10], h[11]]),
            flags: TcpFlags(u16::from_be_bytes([h[12] & 0x01, h[13]])),
            reserved: (h[12] >> 1) & 0x07,
            window: u16::from_be_bytes([h[14], h[15]]),
            checksum: u16::from_be_bytes([h[16], h[17]]),
            urgent_ptr: u16::from_be_bytes([h[18], h[19]]),
            options: header.get(Self::MIN_HEADER_LEN..).unwrap_or_default(),
            payload,
            segment: data,
        })
    }

    /// Header length in bytes.
    #[must_use]
    pub const fn header_len(&self) -> usize {
        self.segment.len() - self.payload.len()
    }

    /// The whole segment, header and payload.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.segment
    }

    /// The options, in wire order.
    #[must_use]
    pub const fn option_iter(&self) -> TcpOptions<'a> {
        TcpOptions { rest: self.options }
    }

    /// The maximum segment size option, if present and well formed.
    #[must_use]
    pub fn mss(&self) -> Option<u16> {
        self.option_iter()
            .map_while(Result::ok)
            .find_map(|o| match o {
                TcpOption::MaxSegmentSize(mss) => Some(mss),
                _ => None,
            })
    }

    /// The window scale option, if present and well formed.
    #[must_use]
    pub fn window_scale(&self) -> Option<u8> {
        self.option_iter()
            .map_while(Result::ok)
            .find_map(|o| match o {
                TcpOption::WindowScale(shift) => Some(shift),
                _ => None,
            })
    }

    /// Whether the checksum is correct under `pseudo` (the payload must be
    /// complete).
    #[must_use]
    pub fn verify_checksum(&self, pseudo: &PseudoHeader) -> bool {
        pseudo.compute(IpProtocol::TCP, self.segment) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A SYN with MSS 1460, SACK permitted, timestamps, NOP, window scale 7
    // (the Linux option layout), followed by 2 bytes of data.
    fn syn() -> Vec<u8> {
        let mut s = vec![
            0x9c, 0x40, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0xa0, 0x02, 0xfa, 0xf0, 0, 0, 0, 0,
        ];
        s.extend_from_slice(&[
            2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 7, 0, 0, 0, 0, 1, 3, 3, 7,
        ]);
        s.extend_from_slice(b"hi");
        s
    }

    #[test]
    fn header_and_options() {
        let data = syn();
        let tcp = TcpSegment::parse(&data).unwrap();
        assert_eq!(tcp.src_port, 40_000);
        assert_eq!(tcp.dst_port, 80);
        assert_eq!(tcp.seq, 1);
        assert_eq!(tcp.flags, TcpFlags::SYN);
        assert_eq!(tcp.window, 64_240);
        assert_eq!(tcp.header_len(), 40);
        assert_eq!(tcp.payload, b"hi");
        let options: Vec<_> = tcp.option_iter().collect::<Result<_, _>>().unwrap();
        assert_eq!(
            options,
            [
                TcpOption::MaxSegmentSize(1460),
                TcpOption::SackPermitted,
                TcpOption::Timestamps {
                    value: 7,
                    echo_reply: 0
                },
                TcpOption::Nop,
                TcpOption::WindowScale(7),
            ]
        );
        assert_eq!(tcp.mss(), Some(1460));
        assert_eq!(tcp.window_scale(), Some(7));
        let mut encoded = Vec::new();
        for option in &options {
            option.encode(&mut encoded).unwrap();
        }
        assert_eq!(encoded, tcp.options);
    }

    #[test]
    fn sack_and_unknown_options() {
        let raw = [
            1, 1, 5, 18, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 30, 3, 9, 0,
        ];
        let options: Vec<_> = TcpOptions { rest: &raw }.collect();
        let Ok(TcpOption::Sack(blocks)) = options[2] else {
            panic!("{options:?}");
        };
        assert_eq!(blocks.iter().collect::<Vec<_>>(), [(1, 2), (3, 4)]);
        assert_eq!(
            options[3],
            Ok(TcpOption::Unknown {
                kind: 30,
                data: &[9]
            })
        );
        assert_eq!(options[4], Ok(TcpOption::EndOfOptions));
        assert_eq!(options.len(), 5);
    }

    #[test]
    fn bad_options_end_iteration() {
        for raw in [
            &[2u8][..],
            &[2, 1],
            &[2, 9, 0, 0],
            &[2, 3, 0],
            &[5, 6, 0, 0, 0, 0],
        ] {
            let options: Vec<_> = TcpOptions { rest: raw }.collect();
            assert_eq!(options.len(), 1, "{raw:?}");
            assert!(options[0].is_err());
        }
    }

    #[test]
    fn flags_display() {
        assert_eq!((TcpFlags::SYN | TcpFlags::ACK).to_string(), "SYN|ACK");
        assert_eq!(TcpFlags::default().to_string(), "-");
        let mut f = TcpFlags::FIN;
        f |= TcpFlags::AE;
        assert!(f.contains(TcpFlags::AE));
        assert_eq!(f.to_string(), "FIN|AE");
    }

    #[test]
    fn errors() {
        let data = syn();
        assert!(TcpSegment::parse(&data[..19]).unwrap_err().is_truncated());
        assert!(TcpSegment::parse(&data[..39]).unwrap_err().is_truncated());
        let mut bad = data.clone();
        bad[12] = 0x40;
        assert!(matches!(
            TcpSegment::parse(&bad),
            Err(Error::Malformed { .. })
        ));
        let mut ns = data;
        ns[12] |= 0x01;
        assert!(TcpSegment::parse(&ns).unwrap().flags.contains(TcpFlags::AE));
    }
}
