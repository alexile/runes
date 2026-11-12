//! Classic libpcap files: the file header and per-packet records.
//!
//! Format: [draft-ietf-opsawg-pcap](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/)
//! and [pcap-savefile(5)](https://www.tcpdump.org/manpages/pcap-savefile.5.html).

use crate::endian::{Endian, array, len_u32};
use crate::error::Error;
use crate::linktype::LinkType;
use crate::time::Timestamp;

/// Magic number of a microsecond-resolution file.
pub const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
/// Magic number of a nanosecond-resolution file.
pub const MAGIC_NANOS: u32 = 0xa1b2_3c4d;
/// Magic number of Alexey Kuznetzov's modified format (microseconds,
/// 24-byte record headers). Read only.
pub const MAGIC_MODIFIED: u32 = 0xa1b2_cd34;

/// Length of the file header.
pub const FILE_HEADER_LEN: usize = 24;
/// Length of a standard record header.
pub const RECORD_HEADER_LEN: usize = 16;
const MODIFIED_RECORD_HEADER_LEN: usize = 24;

/// Snap length written by default: libpcap's `MAXIMUM_SNAPLEN`.
pub const DEFAULT_SNAPLEN: u32 = 262_144;

const FCS_PRESENT: u32 = 0x0400_0000;

/// Resolution of the sub-second part of classic pcap timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Precision {
    /// Microseconds (magic `0xa1b2c3d4`).
    #[default]
    Micros,
    /// Nanoseconds (magic `0xa1b23c4d`).
    Nanos,
}

/// The 24-byte header at the start of a classic pcap file.
///
/// Every packet in the file shares its link type, snap length, byte order
/// and timestamp precision.
///
/// ```
/// use rune_pcap::{Endian, LinkType, PcapHeader, Precision};
///
/// let header = PcapHeader::new(LinkType::ETHERNET).with_precision(Precision::Nanos);
/// let mut bytes = Vec::new();
/// header.encode(&mut bytes);
/// assert_eq!(&bytes[..4], [0x4d, 0x3c, 0xb2, 0xa1]);
/// assert_eq!(PcapHeader::parse(&bytes)?, header);
/// # Ok::<(), rune_pcap::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PcapHeader {
    /// Byte order of every field in the file.
    pub endian: Endian,
    /// Timestamp precision.
    pub precision: Precision,
    /// Major version, 2.
    pub version_major: u16,
    /// Minor version, 4.
    pub version_minor: u16,
    /// Time-zone correction in seconds (`thiszone`). Always 0 in practice;
    /// like libpcap, this crate keeps it but doesn't apply it.
    pub thiszone: i32,
    /// Timestamp accuracy (`sigfigs`); always 0 in practice.
    pub sigfigs: u32,
    /// Largest number of bytes captured per packet.
    pub snaplen: u32,
    /// Link-layer header type of every packet.
    pub link_type: LinkType,
    /// Length of the frame check sequence at the end of each packet, in
    /// bytes, when the file records it.
    pub fcs_len: Option<u8>,
    /// Whether this is the modified (Kuznetzov) format with longer record
    /// headers. Such files are read but never written.
    pub modified: bool,
}

impl PcapHeader {
    /// A version 2.4, little-endian, microsecond header for `link_type`
    /// with libpcap's default snap length.
    #[must_use]
    pub const fn new(link_type: LinkType) -> Self {
        Self {
            endian: Endian::Little,
            precision: Precision::Micros,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: DEFAULT_SNAPLEN,
            link_type,
            fcs_len: None,
            modified: false,
        }
    }

    /// Set the byte order.
    #[must_use]
    pub const fn with_endian(mut self, endian: Endian) -> Self {
        self.endian = endian;
        self
    }

    /// Set the timestamp precision.
    #[must_use]
    pub const fn with_precision(mut self, precision: Precision) -> Self {
        self.precision = precision;
        self
    }

    /// Set the snap length.
    #[must_use]
    pub const fn with_snaplen(mut self, snaplen: u32) -> Self {
        self.snaplen = snaplen;
        self
    }

    /// Record that packets end with an FCS of `bytes` bytes (an even
    /// number up to 30; odd values are rounded down).
    #[must_use]
    pub const fn with_fcs_len(mut self, bytes: u8) -> Self {
        self.fcs_len = Some(if bytes > 30 { 30 } else { bytes & !1 });
        self
    }

    /// Parse the file header from the first 24 bytes of `data`.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownFormat`] for an unknown magic number,
    /// [`Error::UnsupportedVersion`] for a major version other than 2,
    /// [`Error::Truncated`] if `data` is shorter than 24 bytes.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        const WHAT: &str = "pcap file header";
        let magic: [u8; 4] = array(data, 0, WHAT)?;
        let (endian, precision, modified) =
            match (u32::from_le_bytes(magic), u32::from_be_bytes(magic)) {
                (MAGIC_MICROS, _) => (Endian::Little, Precision::Micros, false),
                (_, MAGIC_MICROS) => (Endian::Big, Precision::Micros, false),
                (MAGIC_NANOS, _) => (Endian::Little, Precision::Nanos, false),
                (_, MAGIC_NANOS) => (Endian::Big, Precision::Nanos, false),
                (MAGIC_MODIFIED, _) => (Endian::Little, Precision::Micros, true),
                (_, MAGIC_MODIFIED) => (Endian::Big, Precision::Micros, true),
                _ => return Err(Error::UnknownFormat { magic }),
            };
        if data.len() < FILE_HEADER_LEN {
            return Err(Error::truncated(WHAT, FILE_HEADER_LEN, data.len()));
        }
        let version_major = endian.read_u16(data, 4, WHAT)?;
        let version_minor = endian.read_u16(data, 6, WHAT)?;
        if version_major != 2 {
            return Err(Error::UnsupportedVersion {
                what: "pcap",
                major: version_major,
                minor: version_minor,
            });
        }
        let thiszone = endian.read_u32(data, 8, WHAT)?.cast_signed();
        let sigfigs = endian.read_u32(data, 12, WHAT)?;
        let snaplen = endian.read_u32(data, 16, WHAT)?;
        let network = endian.read_u32(data, 20, WHAT)?;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "masked to the field's width"
        )]
        let (link_type, fcs) = ((network & 0xffff) as u16, (network >> 28) as u8);
        Ok(Self {
            endian,
            precision,
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snaplen,
            link_type: LinkType(link_type),
            fcs_len: (network & FCS_PRESENT != 0).then_some(fcs * 2),
            modified,
        })
    }

    /// Append the 24-byte file header to `out`.
    ///
    /// The modified format is written as a standard microsecond header,
    /// since this crate writes standard 16-byte record headers.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let e = self.endian;
        e.put_u32(
            out,
            match self.precision {
                Precision::Micros => MAGIC_MICROS,
                Precision::Nanos => MAGIC_NANOS,
            },
        );
        e.put_u16(out, self.version_major);
        e.put_u16(out, self.version_minor);
        e.put_u32(out, self.thiszone.cast_unsigned());
        e.put_u32(out, self.sigfigs);
        e.put_u32(out, self.snaplen);
        let fcs = self
            .fcs_len
            .map_or(0, |n| FCS_PRESENT | (u32::from(n.min(30) / 2) << 28));
        e.put_u32(out, u32::from(self.link_type.0) | fcs);
    }

    /// Length of each record header in this file: 16 bytes, or 24 in the
    /// modified format.
    #[must_use]
    pub const fn record_header_len(&self) -> usize {
        if self.modified {
            MODIFIED_RECORD_HEADER_LEN
        } else {
            RECORD_HEADER_LEN
        }
    }

    /// Parse a record header from the start of `data`.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] if `data` is shorter than
    /// [`record_header_len`](Self::record_header_len), [`Error::Malformed`]
    /// if the sub-second field is out of range.
    pub fn parse_record_header(&self, data: &[u8]) -> Result<RecordHeader, Error> {
        const WHAT: &str = "pcap record header";
        let len = self.record_header_len();
        if data.len() < len {
            return Err(Error::truncated(WHAT, len, data.len()));
        }
        let e = self.endian;
        let secs = u64::from(e.read_u32(data, 0, WHAT)?);
        let frac = e.read_u32(data, 4, WHAT)?;
        let timestamp = match self.precision {
            Precision::Micros if frac < 1_000_000 => Timestamp::from_micros(secs, frac),
            Precision::Nanos if frac < 1_000_000_000 => Timestamp::new(secs, frac),
            _ => return Err(Error::malformed(WHAT, "sub-second timestamp out of range")),
        };
        Ok(RecordHeader {
            timestamp,
            captured_len: e.read_u32(data, 8, WHAT)?,
            original_len: e.read_u32(data, 12, WHAT)?,
        })
    }

    /// Parse one record (header and packet data) from the start of `data`.
    /// Returns the record and the number of bytes it took.
    ///
    /// # Errors
    ///
    /// As [`parse_record_header`](Self::parse_record_header), and
    /// [`Error::Truncated`] if the packet data is cut short.
    pub fn parse_record<'a>(
        &self,
        data: &'a [u8],
    ) -> Result<(RecordHeader, &'a [u8], usize), Error> {
        let header = self.parse_record_header(data)?;
        let start = self.record_header_len();
        let end = usize::try_from(header.captured_len)
            .ok()
            .and_then(|n| n.checked_add(start))
            .unwrap_or(usize::MAX);
        let packet = data
            .get(start..end)
            .ok_or_else(|| Error::truncated("pcap record", end, data.len()))?;
        Ok((header, packet, end))
    }

    /// Append a record for `packet` to `out`: a 16-byte header with
    /// `timestamp` at this file's precision, then the bytes.
    ///
    /// `original_len` is the length of the packet on the wire; pass
    /// `packet.len()` unless the capture was cut short. The packet is
    /// written whole even if it is longer than [`snaplen`](Self::snaplen).
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] if the packet or the seconds field does not fit
    /// in 32 bits, [`Error::Malformed`] if `original_len` is shorter than
    /// the packet.
    pub fn encode_record(
        &self,
        timestamp: Timestamp,
        packet: &[u8],
        original_len: u32,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let captured_len = len_u32(packet.len(), "pcap record")?;
        if original_len < captured_len {
            return Err(Error::malformed(
                "pcap record",
                "original length shorter than captured data",
            ));
        }
        let ts = timestamp;
        let secs = u32::try_from(ts.secs).map_err(|_| Error::TimestampOutOfRange)?;
        let frac = match self.precision {
            Precision::Micros => ts.nanos / 1_000,
            Precision::Nanos => ts.nanos,
        };
        let e = self.endian;
        e.put_u32(out, secs);
        e.put_u32(out, frac);
        e.put_u32(out, captured_len);
        e.put_u32(out, original_len);
        out.extend_from_slice(packet);
        Ok(())
    }
}

/// The header of one packet record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RecordHeader {
    /// Capture time.
    pub timestamp: Timestamp,
    /// Bytes of packet data that follow.
    pub captured_len: u32,
    /// Length of the packet on the wire.
    pub original_len: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    // A file header written by libpcap 1.10 (`tcpdump -w`), Ethernet.
    const LIBPCAP_HEADER: [u8; 24] = [
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0,
    ];

    #[test]
    fn parses_libpcap_header() {
        let h = PcapHeader::parse(&LIBPCAP_HEADER).unwrap();
        assert_eq!(h, PcapHeader::new(LinkType::ETHERNET));
        let mut out = Vec::new();
        h.encode(&mut out);
        assert_eq!(out, LIBPCAP_HEADER);
    }

    #[test]
    fn all_magics_and_orders() {
        for endian in [Endian::Little, Endian::Big] {
            for precision in [Precision::Micros, Precision::Nanos] {
                let h = PcapHeader::new(LinkType::RAW)
                    .with_endian(endian)
                    .with_precision(precision)
                    .with_snaplen(65535)
                    .with_fcs_len(4);
                let mut out = Vec::new();
                h.encode(&mut out);
                assert_eq!(PcapHeader::parse(&out).unwrap(), h);
            }
        }
        let mut modified = LIBPCAP_HEADER;
        modified[..4].copy_from_slice(&MAGIC_MODIFIED.to_le_bytes());
        let h = PcapHeader::parse(&modified).unwrap();
        assert!(h.modified);
        assert_eq!(h.endian, Endian::Little);
        assert_eq!(h.record_header_len(), 24);
    }

    #[test]
    fn fcs_bits() {
        let mut header = LIBPCAP_HEADER;
        header[20..24].copy_from_slice(&(1u32 | FCS_PRESENT | (2 << 28)).to_le_bytes());
        assert_eq!(PcapHeader::parse(&header).unwrap().fcs_len, Some(4));
        assert_eq!(
            PcapHeader::new(LinkType::ETHERNET).with_fcs_len(99).fcs_len,
            Some(30)
        );
        assert_eq!(
            PcapHeader::new(LinkType::ETHERNET).with_fcs_len(5).fcs_len,
            Some(4)
        );
    }

    #[test]
    fn rejects_bad_headers() {
        assert!(matches!(
            PcapHeader::parse(b"GIF89a"),
            Err(Error::UnknownFormat { magic }) if &magic == b"GIF8"
        ));
        assert!(
            PcapHeader::parse(&LIBPCAP_HEADER[..23])
                .unwrap_err()
                .is_truncated()
        );
        assert!(
            PcapHeader::parse(&LIBPCAP_HEADER[..2])
                .unwrap_err()
                .is_truncated()
        );
        let mut v1 = LIBPCAP_HEADER;
        v1[4] = 1;
        assert!(matches!(
            PcapHeader::parse(&v1),
            Err(Error::UnsupportedVersion {
                major: 1,
                minor: 4,
                ..
            })
        ));
    }

    #[test]
    fn records_round_trip() {
        for precision in [Precision::Micros, Precision::Nanos] {
            let h = PcapHeader::new(LinkType::ETHERNET)
                .with_precision(precision)
                .with_endian(Endian::Big);
            let ts = Timestamp::new(1_700_000_000, 123_456_789);
            let mut out = Vec::new();
            h.encode_record(ts, b"abc", 60, &mut out).unwrap();
            out.push(0xff);
            let (rec, data, used) = h.parse_record(&out).unwrap();
            assert_eq!(used, 19);
            assert_eq!(data, b"abc");
            assert_eq!(rec.captured_len, 3);
            assert_eq!(rec.original_len, 60);
            let expect = match precision {
                Precision::Micros => Timestamp::new(1_700_000_000, 123_456_000),
                Precision::Nanos => ts,
            };
            assert_eq!(rec.timestamp, expect);
        }
    }

    #[test]
    fn record_errors() {
        let h = PcapHeader::new(LinkType::ETHERNET);
        let mut out = Vec::new();
        assert!(
            h.encode_record(Timestamp::new(1 << 32, 0), b"", 0, &mut out)
                .is_err()
        );
        assert!(
            h.encode_record(Timestamp::default(), b"ab", 1, &mut out)
                .is_err()
        );
        h.encode_record(Timestamp::default(), b"abcd", 4, &mut out)
            .unwrap();
        assert!(h.parse_record(&out[..19]).unwrap_err().is_truncated());
        assert!(h.parse_record(&out[..15]).unwrap_err().is_truncated());
        // Microseconds field of 10^6 or more.
        out[4..8].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert!(matches!(h.parse_record(&out), Err(Error::Malformed { .. })));
        // A huge captured length is truncation, not a panic.
        out[4..8].copy_from_slice(&[0; 4]);
        out[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(h.parse_record(&out).unwrap_err().is_truncated());
    }
}
