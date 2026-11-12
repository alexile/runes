//! Streaming readers over [`std::io::Read`].

use std::io::{self, Read};

use rune_packet::Packet;

use crate::endian::Endian;
use crate::error::Error;
use crate::linktype::LinkType;
use crate::pcap::{FILE_HEADER_LEN, PcapHeader};
use crate::pcapng::{self, Block, BlockType, RawBlock};
use crate::time::{Timestamp, TsResolution};

/// Default limit on the size of one record or block: 16 MiB.
pub const DEFAULT_MAX_RECORD_LEN: u32 = 16 << 20;

/// One captured packet, from either format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Record<'a> {
    /// Index of the interface in its pcapng section; 0 in a pcap file.
    pub interface_id: u32,
    /// Link-layer header type of `data`.
    pub link_type: LinkType,
    /// Capture time; `None` for a pcapng Simple Packet Block.
    pub timestamp: Option<Timestamp>,
    /// Captured bytes.
    pub data: &'a [u8],
    /// Length of the packet on the wire.
    pub original_len: u32,
}

impl<'a> Record<'a> {
    /// Whether fewer bytes were captured than were on the wire.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        u64::try_from(self.data.len()).unwrap_or(u64::MAX) < u64::from(self.original_len)
    }

    /// Dissect the packet with `rune-packet`; see [`LinkType::dissect`].
    #[must_use]
    pub fn dissect(&self) -> Option<Packet<'a>> {
        self.link_type.dissect(self.data)
    }
}

/// Fill `buf` from `r`. Returns how many bytes were read: fewer than
/// `buf.len()` only at end of input.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Read exactly `buf.len()` bytes, reporting a short read as truncation
/// of `what` (`already` bytes of which were read before).
fn read_exact(
    r: &mut impl Read,
    buf: &mut [u8],
    what: &'static str,
    already: usize,
) -> Result<(), Error> {
    let n = read_full(r, buf)?;
    if n < buf.len() {
        return Err(Error::truncated(what, already + buf.len(), already + n));
    }
    Ok(())
}

/// Grow `buf` to `len` bytes and read them in from position `from`,
/// without trusting `len` with one big allocation up front.
fn read_into(
    r: &mut impl Read,
    buf: &mut Vec<u8>,
    from: usize,
    len: usize,
    what: &'static str,
) -> Result<(), Error> {
    const CHUNK: usize = 64 << 10;
    buf.truncate(from);
    while buf.len() < len {
        let start = buf.len();
        let end = len.min(start.saturating_add(CHUNK));
        buf.resize(end, 0);
        let n = read_full(r, &mut buf[start..end])?;
        if n < end - start {
            return Err(Error::truncated(what, len, start + n));
        }
    }
    Ok(())
}

/// A streaming reader for classic pcap files.
///
/// It holds one record in memory at a time.
#[derive(Debug)]
pub struct PcapReader<R> {
    inner: R,
    header: PcapHeader,
    buf: Vec<u8>,
    max_record_len: u32,
}

impl<R: Read> PcapReader<R> {
    /// Read the file header.
    ///
    /// # Errors
    ///
    /// As [`PcapHeader::parse`], or [`Error::Io`].
    pub fn new(mut inner: R) -> Result<Self, Error> {
        let mut header = [0u8; FILE_HEADER_LEN];
        let n = read_full(&mut inner, &mut header)?;
        let header = PcapHeader::parse(&header[..n])?;
        Ok(Self::with_header(inner, header))
    }

    /// Continue reading after a file header that was already parsed.
    #[must_use]
    pub const fn with_header(inner: R, header: PcapHeader) -> Self {
        Self {
            inner,
            header,
            buf: Vec::new(),
            max_record_len: DEFAULT_MAX_RECORD_LEN,
        }
    }

    /// Refuse records with more than `max` bytes of packet data
    /// (default [`DEFAULT_MAX_RECORD_LEN`]).
    #[must_use]
    pub const fn with_max_record_len(mut self, max: u32) -> Self {
        self.max_record_len = max;
        self
    }

    /// The file header.
    #[must_use]
    pub const fn header(&self) -> &PcapHeader {
        &self.header
    }

    /// Read the next packet, or `None` at a clean end of file.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] if the file ends inside a record,
    /// [`Error::TooLarge`] for a record over the limit, as
    /// [`PcapHeader::parse_record_header`], or [`Error::Io`].
    pub fn next_packet(&mut self) -> Result<Option<Record<'_>>, Error> {
        let hlen = self.header.record_header_len();
        self.buf.resize(hlen, 0);
        let n = read_full(&mut self.inner, &mut self.buf)?;
        if n == 0 {
            return Ok(None);
        }
        let rec = self.header.parse_record_header(&self.buf[..n])?;
        if rec.captured_len > self.max_record_len {
            return Err(Error::TooLarge {
                what: "pcap record",
                len: u64::from(rec.captured_len),
                max: u64::from(self.max_record_len),
            });
        }
        let len = usize::try_from(rec.captured_len).unwrap_or(usize::MAX);
        read_into(&mut self.inner, &mut self.buf, 0, len, "pcap record")?;
        Ok(Some(Record {
            interface_id: 0,
            link_type: self.header.link_type,
            timestamp: Some(rec.timestamp),
            data: &self.buf,
            original_len: rec.original_len,
        }))
    }

    /// The underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// What a pcapng reader remembers about an interface.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Interface {
    /// Link-layer header type.
    pub link_type: LinkType,
    /// Snap length; 0 for none.
    pub snaplen: u32,
    /// Timestamp resolution.
    pub ts_resolution: TsResolution,
    /// Timestamp offset in seconds.
    pub ts_offset: i64,
    /// Bytes of FCS at the end of each packet, if recorded.
    pub fcs_len: Option<u8>,
    /// `if_name`.
    pub name: Option<String>,
    /// `if_description`.
    pub description: Option<String>,
}

impl Interface {
    fn from_block(idb: &pcapng::InterfaceDescription<'_>) -> Self {
        Self {
            link_type: idb.link_type,
            snaplen: idb.snaplen,
            ts_resolution: idb.ts_resolution(),
            ts_offset: idb.ts_offset(),
            fcs_len: idb.fcs_len(),
            name: idb.name().map(str::to_owned),
            description: idb.description().map(str::to_owned),
        }
    }
}

/// A streaming reader for pcapng files.
///
/// It holds one block in memory at a time, and tracks the byte order and
/// interfaces of the current section so it can resolve each packet's
/// link type and timestamp.
#[derive(Debug)]
pub struct PcapNgReader<R> {
    inner: R,
    endian: Endian,
    interfaces: Vec<Interface>,
    buf: Vec<u8>,
    max_block_len: u32,
    started: bool,
}

impl<R: Read> PcapNgReader<R> {
    /// A reader positioned at the first Section Header Block.
    ///
    /// Nothing is read until the first call to
    /// [`next_block`](Self::next_block) or
    /// [`next_packet`](Self::next_packet).
    #[must_use]
    pub const fn new(inner: R) -> Self {
        Self {
            inner,
            endian: Endian::Little,
            interfaces: Vec::new(),
            buf: Vec::new(),
            max_block_len: DEFAULT_MAX_RECORD_LEN,
            started: false,
        }
    }

    /// Refuse blocks longer than `max` bytes (default
    /// [`DEFAULT_MAX_RECORD_LEN`]).
    #[must_use]
    pub const fn with_max_block_len(mut self, max: u32) -> Self {
        self.max_block_len = max;
        self
    }

    /// Byte order of the current section.
    #[must_use]
    pub const fn endian(&self) -> Endian {
        self.endian
    }

    /// Interfaces declared so far in the current section.
    #[must_use]
    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    /// Read the next block into the buffer; returns its type, or `None`
    /// at a clean end of file. Updates the byte order and interface table.
    fn fill(&mut self) -> Result<Option<BlockType>, Error> {
        const WHAT: &str = "pcapng block";
        self.buf.resize(8, 0);
        let n = read_full(&mut self.inner, &mut self.buf)?;
        if n == 0 {
            return Ok(None);
        }
        if n < 8 {
            return Err(Error::truncated(WHAT, 8, n));
        }
        let is_shb = self.buf[..4] == BlockType::SECTION_HEADER.0.to_le_bytes();
        if !self.started && !is_shb {
            let mut magic = [0; 4];
            magic.copy_from_slice(&self.buf[..4]);
            return Err(Error::UnknownFormat { magic });
        }
        self.started = true;
        let endian = if is_shb {
            self.buf.resize(12, 0);
            read_exact(
                &mut self.inner,
                &mut self.buf[8..],
                "pcapng section header",
                8,
            )?;
            pcapng::section_endian(&self.buf, self.endian)?
        } else {
            self.endian
        };
        let total = endian.read_u32(&self.buf, 4, WHAT)?;
        pcapng::check_block_len(usize::try_from(total).unwrap_or(usize::MAX))?;
        if total > self.max_block_len {
            return Err(Error::TooLarge {
                what: WHAT,
                len: u64::from(total),
                max: u64::from(self.max_block_len),
            });
        }
        let have = self.buf.len();
        let len = usize::try_from(total).unwrap_or(usize::MAX);
        read_into(&mut self.inner, &mut self.buf, have, len, WHAT)?;
        let (raw, endian, _) = RawBlock::parse(&self.buf, endian)?;
        let block_type = raw.block_type;
        match Block::from_raw(raw, endian)? {
            Block::SectionHeader(_) => {
                self.endian = endian;
                self.interfaces.clear();
            }
            Block::InterfaceDescription(idb) => {
                let interface = Interface::from_block(&idb);
                self.interfaces.push(interface);
            }
            _ => {}
        }
        Ok(Some(block_type))
    }

    /// Read the next block of any type, or `None` at a clean end of file.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownFormat`] if the file does not start with a Section
    /// Header Block, [`Error::Truncated`] if it ends inside a block,
    /// [`Error::TooLarge`] for a block over the limit, as
    /// [`Block::parse`], or [`Error::Io`].
    pub fn next_block(&mut self) -> Result<Option<Block<'_>>, Error> {
        if self.fill()?.is_none() {
            return Ok(None);
        }
        let (block, _, _) = Block::parse(&self.buf, self.endian)?;
        Ok(Some(block))
    }

    /// Read blocks up to the next packet (Enhanced, Simple or obsolete
    /// Packet Block), or `None` at a clean end of file.
    ///
    /// # Errors
    ///
    /// As [`next_block`](Self::next_block), and
    /// [`Error::UnknownInterface`] for a packet on an undeclared interface.
    pub fn next_packet(&mut self) -> Result<Option<Record<'_>>, Error> {
        loop {
            match self.fill()? {
                None => return Ok(None),
                Some(
                    BlockType::ENHANCED_PACKET
                    | BlockType::SIMPLE_PACKET
                    | BlockType::OBSOLETE_PACKET,
                ) => break,
                Some(_) => {}
            }
        }
        let (block, _, _) = Block::parse(&self.buf, self.endian)?;
        let interface = |id: u32| {
            usize::try_from(id)
                .ok()
                .and_then(|i| self.interfaces.get(i))
                .ok_or(Error::UnknownInterface(id))
        };
        let record = match block {
            Block::EnhancedPacket(epb) => {
                let iface = interface(epb.interface_id)?;
                Record {
                    interface_id: epb.interface_id,
                    link_type: iface.link_type,
                    timestamp: Some(epb.timestamp(iface.ts_resolution, iface.ts_offset)),
                    data: epb.data,
                    original_len: epb.original_len,
                }
            }
            Block::ObsoletePacket(pb) => {
                let id = u32::from(pb.interface_id);
                let iface = interface(id)?;
                Record {
                    interface_id: id,
                    link_type: iface.link_type,
                    timestamp: Some(
                        iface
                            .ts_resolution
                            .to_timestamp(pb.ticks)
                            .offset_secs(iface.ts_offset),
                    ),
                    data: pb.data,
                    original_len: pb.original_len,
                }
            }
            Block::SimplePacket(spb) => {
                let iface = interface(0)?;
                Record {
                    interface_id: 0,
                    link_type: iface.link_type,
                    timestamp: None,
                    data: spb.packet(iface.snaplen),
                    original_len: spb.original_len,
                }
            }
            _ => return Err(Error::malformed("pcapng block", "expected a packet block")),
        };
        Ok(Some(record))
    }

    /// The underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Which format a [`CaptureReader`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// Classic libpcap.
    Pcap,
    /// pcapng.
    PcapNg,
}

/// A streaming reader for either format, detected from the magic number.
///
/// ```
/// use rune_pcap::{CaptureReader, LinkType, PcapHeader, PcapWriter, Timestamp};
///
/// let mut file = Vec::new();
/// let mut writer = PcapWriter::new(&mut file, PcapHeader::new(LinkType::RAW))?;
/// writer.write_packet(Timestamp::new(1, 0), &[0x45, 0, 0, 20])?;
///
/// let mut reader = CaptureReader::new(file.as_slice())?;
/// while let Some(record) = reader.next_packet()? {
///     assert_eq!(record.link_type, LinkType::RAW);
///     let packet = record.dissect().unwrap();
///     assert!(packet.error.unwrap().is_truncated());
/// }
/// # Ok::<(), rune_pcap::Error>(())
/// ```
#[derive(Debug)]
pub enum CaptureReader<R> {
    /// A classic pcap file.
    Pcap(PcapReader<R>),
    /// A pcapng file.
    PcapNg(PcapNgReader<io::Chain<io::Cursor<[u8; 4]>, R>>),
}

impl<R: Read> CaptureReader<R> {
    /// Detect the format and, for pcap, read the file header.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownFormat`] if the magic number is neither format's,
    /// [`Error::Truncated`] for a file under 4 bytes, otherwise as
    /// [`PcapReader::new`].
    pub fn new(mut inner: R) -> Result<Self, Error> {
        let mut magic = [0u8; 4];
        let n = read_full(&mut inner, &mut magic)?;
        if n < 4 {
            return Err(Error::truncated("capture file magic", 4, n));
        }
        if u32::from_le_bytes(magic) == BlockType::SECTION_HEADER.0 {
            return Ok(Self::PcapNg(PcapNgReader::new(
                io::Cursor::new(magic).chain(inner),
            )));
        }
        let mut header = [0u8; FILE_HEADER_LEN];
        header[..4].copy_from_slice(&magic);
        let n = read_full(&mut inner, &mut header[4..])?;
        let header = PcapHeader::parse(&header[..4 + n])?;
        Ok(Self::Pcap(PcapReader::with_header(inner, header)))
    }

    /// Refuse records and blocks longer than `max` bytes (default
    /// [`DEFAULT_MAX_RECORD_LEN`]).
    #[must_use]
    pub fn with_max_record_len(self, max: u32) -> Self {
        match self {
            Self::Pcap(r) => Self::Pcap(r.with_max_record_len(max)),
            Self::PcapNg(r) => Self::PcapNg(r.with_max_block_len(max)),
        }
    }

    /// The detected format.
    #[must_use]
    pub const fn format(&self) -> Format {
        match self {
            Self::Pcap(_) => Format::Pcap,
            Self::PcapNg(_) => Format::PcapNg,
        }
    }

    /// Read the next packet, or `None` at a clean end of file.
    ///
    /// # Errors
    ///
    /// As [`PcapReader::next_packet`] or [`PcapNgReader::next_packet`].
    pub fn next_packet(&mut self) -> Result<Option<Record<'_>>, Error> {
        match self {
            Self::Pcap(r) => r.next_packet(),
            Self::PcapNg(r) => r.next_packet(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcapng::{EnhancedPacketBuilder, InterfaceBuilder, SectionBuilder};
    use crate::{PcapHeader, PcapNgWriter, PcapWriter, Precision};

    /// Hands out one byte per `read` call, to exercise short reads.
    struct Trickle<'a>(&'a [u8]);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match (self.0.split_first(), buf.first_mut()) {
                (Some((b, rest)), Some(slot)) => {
                    *slot = *b;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    fn pcap_file() -> Vec<u8> {
        let mut w = PcapWriter::new(
            Vec::new(),
            PcapHeader::new(LinkType::RAW).with_precision(Precision::Nanos),
        )
        .unwrap();
        w.write_packet(Timestamp::new(1, 2), b"one").unwrap();
        w.write_truncated(Timestamp::new(3, 4), b"tw", 9).unwrap();
        w.into_inner()
    }

    fn pcapng_file() -> Vec<u8> {
        let mut w = PcapNgWriter::new(Vec::new(), &SectionBuilder::new()).unwrap();
        let a = w
            .add_interface(&InterfaceBuilder::new(LinkType::ETHERNET).with_name("a"))
            .unwrap();
        w.write_decryption_secrets(0x544c_534b, b"keys").unwrap();
        let b = w
            .add_interface(
                &InterfaceBuilder::new(LinkType::RAW)
                    .with_ts_resolution(TsResolution::NANOS)
                    .with_ts_offset(-5)
                    .with_fcs_len(0)
                    .with_description("tun"),
            )
            .unwrap();
        w.write_packet(b, Timestamp::new(10, 7), b"raw").unwrap();
        w.write(
            &EnhancedPacketBuilder::new(a, Timestamp::new(11, 0), b"eth").with_original_len(64),
        )
        .unwrap();
        w.new_section(&SectionBuilder::new().with_endian(Endian::Big))
            .unwrap();
        w.add_interface(&InterfaceBuilder::new(LinkType::IPV6).with_snaplen(2))
            .unwrap();
        // A Simple Packet Block on interface 0, cut to its snap length.
        let mut spb = Vec::new();
        Endian::Big.put_u32(&mut spb, 5);
        spb.extend_from_slice(b"hello");
        w.write_raw_block(BlockType::SIMPLE_PACKET, &spb).unwrap();
        w.into_inner()
    }

    #[test]
    fn reads_pcap_in_tiny_pieces() {
        let file = pcap_file();
        let mut r = CaptureReader::new(Trickle(&file)).unwrap();
        assert_eq!(r.format(), Format::Pcap);
        let rec = r.next_packet().unwrap().unwrap();
        assert_eq!((rec.data, rec.original_len), (&b"one"[..], 3));
        assert_eq!(rec.timestamp, Some(Timestamp::new(1, 2)));
        assert!(!rec.is_truncated());
        let rec = r.next_packet().unwrap().unwrap();
        assert_eq!((rec.data, rec.original_len), (&b"tw"[..], 9));
        assert!(rec.is_truncated());
        assert!(r.next_packet().unwrap().is_none());
        assert!(r.next_packet().unwrap().is_none());
    }

    #[test]
    fn reads_pcapng_sections_and_interfaces() {
        let file = pcapng_file();
        let mut r = CaptureReader::new(Trickle(&file)).unwrap();
        assert_eq!(r.format(), Format::PcapNg);
        let rec = r.next_packet().unwrap().unwrap();
        assert_eq!(rec.interface_id, 1);
        assert_eq!(rec.link_type, LinkType::RAW);
        assert_eq!(rec.data, b"raw");
        assert_eq!(rec.timestamp, Some(Timestamp::new(10, 7)));
        let rec = r.next_packet().unwrap().unwrap();
        assert_eq!((rec.interface_id, rec.link_type), (0, LinkType::ETHERNET));
        assert_eq!(rec.original_len, 64);
        let rec = r.next_packet().unwrap().unwrap();
        assert_eq!((rec.link_type, rec.timestamp), (LinkType::IPV6, None));
        assert_eq!((rec.data, rec.original_len), (&b"he"[..], 5));
        assert!(r.next_packet().unwrap().is_none());

        let mut r = PcapNgReader::new(file.as_slice());
        let mut types = Vec::new();
        while let Some(block) = r.next_block().unwrap() {
            types.push(block.block_type().0);
            if types.len() == 4 {
                assert_eq!(r.interfaces().len(), 2);
                assert_eq!(r.interfaces()[0].name.as_deref(), Some("a"));
                assert_eq!(r.interfaces()[1].description.as_deref(), Some("tun"));
                assert_eq!(r.interfaces()[1].ts_offset, -5);
                assert_eq!(r.interfaces()[1].fcs_len, Some(0));
            }
        }
        assert_eq!(types, [0x0a0d_0d0a, 1, 0x0a, 1, 6, 6, 0x0a0d_0d0a, 1, 3]);
        assert_eq!(r.endian(), Endian::Big);
        assert_eq!(r.interfaces().len(), 1);
        assert_eq!(r.into_inner().len(), 0);
    }

    #[test]
    fn truncation_anywhere_is_an_error() {
        for file in [pcap_file(), pcapng_file()] {
            for cut in 1..file.len() {
                let result = CaptureReader::new(&file[..cut]).and_then(|mut r| {
                    while r.next_packet()?.is_some() {}
                    Ok(())
                });
                // Cuts on a record boundary are a clean (shorter) file.
                if let Err(err) = result {
                    assert!(err.is_truncated(), "cut {cut}: {err}");
                }
            }
        }
        assert!(
            CaptureReader::new(&[0xd4, 0xc3][..])
                .unwrap_err()
                .is_truncated()
        );
    }

    #[test]
    fn limits_and_bad_files() {
        let (pcap, pcapng) = (pcap_file(), pcapng_file());
        let mut r = CaptureReader::new(pcap.as_slice())
            .unwrap()
            .with_max_record_len(2);
        assert!(matches!(
            r.next_packet(),
            Err(Error::TooLarge { len: 3, max: 2, .. })
        ));
        let mut r = CaptureReader::new(pcapng.as_slice())
            .unwrap()
            .with_max_record_len(40);
        assert!(matches!(r.next_packet(), Err(Error::TooLarge { .. })));
        let file = pcap_file();
        let mut r = PcapReader::new(file.as_slice()).unwrap();
        assert_eq!(r.header().link_type, LinkType::RAW);
        r.next_packet().unwrap();
        assert_ne!(r.into_inner().len(), 0);

        assert!(matches!(
            CaptureReader::new(&b"\x7fELF and more"[..]),
            Err(Error::UnknownFormat { .. })
        ));
        // pcapng that doesn't start with a section header.
        let mut r = PcapNgReader::new(&[1u8, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0][..]);
        assert!(matches!(r.next_block(), Err(Error::UnknownFormat { .. })));
        // A packet on an undeclared interface.
        let mut w = PcapNgWriter::new(Vec::new(), &SectionBuilder::new()).unwrap();
        let mut body = vec![0u8; 20];
        body[0] = 3;
        w.write_raw_block(BlockType::ENHANCED_PACKET, &body)
            .unwrap();
        assert!(
            w.write_raw_block(BlockType::INTERFACE_DESCRIPTION, &[])
                .is_err()
        );
        let file = w.into_inner();
        let mut r = PcapNgReader::new(file.as_slice());
        assert!(matches!(r.next_packet(), Err(Error::UnknownInterface(3))));
    }
}
