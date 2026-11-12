//! pcapng: blocks, options and their zero-copy views.
//!
//! Format: [draft-ietf-opsawg-pcapng](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/).
//! A file is a sequence of sections; each starts with a Section Header
//! Block that fixes the byte order, declares interfaces with Interface
//! Description Blocks, and carries packets in Enhanced (or Simple)
//! Packet Blocks.

mod write;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub use write::{Encoder, EnhancedPacketBuilder, InterfaceBuilder, SectionBuilder};

use crate::endian::{Endian, array, pad4};
use crate::error::Error;
use crate::linktype::LinkType;
use crate::time::{Timestamp, TsResolution};

/// The byte-order magic in every Section Header Block.
pub const BYTE_ORDER_MAGIC: u32 = 0x1a2b_3c4d;

/// Smallest possible block: type, two lengths.
pub const MIN_BLOCK_LEN: usize = 12;

/// A pcapng block type code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockType(pub u32);

impl BlockType {
    /// Section Header Block.
    pub const SECTION_HEADER: Self = Self(0x0a0d_0d0a);
    /// Interface Description Block.
    pub const INTERFACE_DESCRIPTION: Self = Self(1);
    /// Packet Block (obsolete).
    pub const OBSOLETE_PACKET: Self = Self(2);
    /// Simple Packet Block.
    pub const SIMPLE_PACKET: Self = Self(3);
    /// Name Resolution Block.
    pub const NAME_RESOLUTION: Self = Self(4);
    /// Interface Statistics Block.
    pub const INTERFACE_STATISTICS: Self = Self(5);
    /// Enhanced Packet Block.
    pub const ENHANCED_PACKET: Self = Self(6);
    /// Decryption Secrets Block.
    pub const DECRYPTION_SECRETS: Self = Self(0x0a);
    /// Custom Block that may be copied to new files.
    pub const CUSTOM: Self = Self(0x0000_0bad);
    /// Custom Block that must not be copied to new files.
    pub const CUSTOM_NO_COPY: Self = Self(0x4000_0bad);
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

/// Option codes shared by every block.
pub mod opt {
    /// End of options.
    pub const END: u16 = 0;
    /// `opt_comment`: UTF-8 text.
    pub const COMMENT: u16 = 1;
    /// Section Header Block: `shb_hardware`.
    pub const SHB_HARDWARE: u16 = 2;
    /// Section Header Block: `shb_os`.
    pub const SHB_OS: u16 = 3;
    /// Section Header Block: `shb_userappl`.
    pub const SHB_USERAPPL: u16 = 4;
    /// Interface: `if_name`.
    pub const IF_NAME: u16 = 2;
    /// Interface: `if_description`.
    pub const IF_DESCRIPTION: u16 = 3;
    /// Interface: `if_MACaddr`.
    pub const IF_MACADDR: u16 = 6;
    /// Interface: `if_speed` (bits per second).
    pub const IF_SPEED: u16 = 8;
    /// Interface: `if_tsresol`.
    pub const IF_TSRESOL: u16 = 9;
    /// Interface: `if_filter`.
    pub const IF_FILTER: u16 = 11;
    /// Interface: `if_os`.
    pub const IF_OS: u16 = 12;
    /// Interface: `if_fcslen` (bytes).
    pub const IF_FCSLEN: u16 = 13;
    /// Interface: `if_tsoffset` (seconds).
    pub const IF_TSOFFSET: u16 = 14;
    /// Interface: `if_hardware`.
    pub const IF_HARDWARE: u16 = 15;
    /// Enhanced Packet: `epb_flags`.
    pub const EPB_FLAGS: u16 = 2;
    /// Enhanced Packet: `epb_hash`.
    pub const EPB_HASH: u16 = 3;
    /// Enhanced Packet: `epb_dropcount`.
    pub const EPB_DROPCOUNT: u16 = 4;
    /// Enhanced Packet: `epb_packetid`.
    pub const EPB_PACKETID: u16 = 5;
    /// Enhanced Packet: `epb_queue`.
    pub const EPB_QUEUE: u16 = 6;
    /// Interface Statistics: `isb_starttime`.
    pub const ISB_STARTTIME: u16 = 2;
    /// Interface Statistics: `isb_endtime`.
    pub const ISB_ENDTIME: u16 = 3;
    /// Interface Statistics: `isb_ifrecv`.
    pub const ISB_IFRECV: u16 = 4;
    /// Interface Statistics: `isb_ifdrop`.
    pub const ISB_IFDROP: u16 = 5;
    /// Interface Statistics: `isb_filteraccept`.
    pub const ISB_FILTERACCEPT: u16 = 6;
    /// Interface Statistics: `isb_osdrop`.
    pub const ISB_OSDROP: u16 = 7;
    /// Interface Statistics: `isb_usrdeliv`.
    pub const ISB_USRDELIV: u16 = 8;
}

/// A block's type and body, framing checked but contents not parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawBlock<'a> {
    /// Block type.
    pub block_type: BlockType,
    /// Bytes between the leading length and the trailing length.
    pub body: &'a [u8],
}

impl<'a> RawBlock<'a> {
    /// Split the block at the start of `data`, read in byte order
    /// `endian`. A Section Header Block sets its own byte order from its
    /// magic, whatever `endian` says.
    ///
    /// Returns the block, the byte order now in force, and the bytes the
    /// block took.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] if `data` ends inside the block,
    /// [`Error::Malformed`] for a bad byte-order magic, a length below 12
    /// or not a multiple of 4, or trailing and leading lengths that differ.
    pub fn parse(data: &'a [u8], endian: Endian) -> Result<(Self, Endian, usize), Error> {
        const WHAT: &str = "pcapng block";
        let endian = section_endian(data, endian)?;
        let block_type = BlockType(endian.read_u32(data, 0, WHAT)?);
        let total = endian.read_u32(data, 4, WHAT)?;
        let len = usize::try_from(total).unwrap_or(usize::MAX);
        check_block_len(len)?;
        let block = data
            .get(..len)
            .ok_or_else(|| Error::truncated(WHAT, len, data.len()))?;
        if endian.read_u32(block, len - 4, WHAT)? != total {
            return Err(Error::malformed(
                WHAT,
                "trailing length differs from leading length",
            ));
        }
        let body = block.get(8..len - 4).unwrap_or_default();
        Ok((Self { block_type, body }, endian, len))
    }
}

/// The byte order a block at the start of `data` is read in: `current`,
/// or the one a Section Header Block declares.
pub(crate) fn section_endian(data: &[u8], current: Endian) -> Result<Endian, Error> {
    let ty: [u8; 4] = array(data, 0, "pcapng block")?;
    if u32::from_le_bytes(ty) != BlockType::SECTION_HEADER.0 {
        return Ok(current);
    }
    let bom: [u8; 4] = array(data, 8, "pcapng section header")?;
    if u32::from_le_bytes(bom) == BYTE_ORDER_MAGIC {
        Ok(Endian::Little)
    } else if u32::from_be_bytes(bom) == BYTE_ORDER_MAGIC {
        Ok(Endian::Big)
    } else {
        Err(Error::malformed(
            "pcapng section header",
            "bad byte-order magic",
        ))
    }
}

pub(crate) const fn check_block_len(len: usize) -> Result<(), Error> {
    if len < MIN_BLOCK_LEN || !len.is_multiple_of(4) {
        return Err(Error::malformed(
            "pcapng block",
            "length below 12 or not a multiple of 4",
        ));
    }
    Ok(())
}

/// One option: a code and its value (padding removed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawOption<'a> {
    /// Option code; its meaning depends on the block type.
    pub code: u16,
    /// Value bytes.
    pub value: &'a [u8],
}

/// The options of a block, read lazily.
///
/// [`iter`](Self::iter) yields each option until `opt_endofopt` or the
/// end of the block. A malformed option ends the iteration with one
/// `Err`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options<'a> {
    data: &'a [u8],
    endian: Endian,
}

impl<'a> Options<'a> {
    pub(crate) const fn new(data: &'a [u8], endian: Endian) -> Self {
        Self { data, endian }
    }

    /// No options.
    #[must_use]
    pub const fn empty() -> Self {
        Self::new(&[], Endian::Little)
    }

    /// Iterate over the options.
    #[must_use]
    pub const fn iter(&self) -> OptionsIter<'a> {
        OptionsIter {
            data: self.data,
            endian: self.endian,
        }
    }

    /// The raw option bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// The value of the first well-formed option with `code`.
    #[must_use]
    pub fn get(&self, code: u16) -> Option<&'a [u8]> {
        self.all(code).next()
    }

    /// The values of every well-formed option with `code`, in order.
    pub fn all(&self, code: u16) -> impl Iterator<Item = &'a [u8]> + use<'a> {
        self.iter()
            .map_while(Result::ok)
            .filter(move |o| o.code == code)
            .map(|o| o.value)
    }

    /// The first option with `code` as UTF-8 text (trailing NULs, which
    /// some writers add, removed).
    #[must_use]
    pub fn str(&self, code: u16) -> Option<&'a str> {
        self.get(code).and_then(utf8)
    }

    /// The first option with `code`, if its value is one byte.
    #[must_use]
    pub fn u8(&self, code: u16) -> Option<u8> {
        match self.get(code)? {
            &[b] => Some(b),
            _ => None,
        }
    }

    /// The first option with `code`, if its value is four bytes.
    #[must_use]
    pub fn u32(&self, code: u16) -> Option<u32> {
        let b: [u8; 4] = self.get(code)?.try_into().ok()?;
        Some(self.endian.u32(b))
    }

    /// The first option with `code`, if its value is eight bytes.
    #[must_use]
    pub fn u64(&self, code: u16) -> Option<u64> {
        let b: [u8; 8] = self.get(code)?.try_into().ok()?;
        Some(self.endian.u64(b))
    }

    /// Every `opt_comment`.
    pub fn comments(&self) -> impl Iterator<Item = &'a str> + use<'a> {
        self.all(opt::COMMENT).filter_map(utf8)
    }
}

fn utf8(b: &[u8]) -> Option<&str> {
    let end = b.iter().rposition(|&c| c != 0).map_or(0, |i| i + 1);
    std::str::from_utf8(b.get(..end)?).ok()
}

impl<'a> IntoIterator for &Options<'a> {
    type Item = Result<RawOption<'a>, Error>;
    type IntoIter = OptionsIter<'a>;

    fn into_iter(self) -> OptionsIter<'a> {
        self.iter()
    }
}

/// Iterator over [`Options`].
#[derive(Debug, Clone)]
pub struct OptionsIter<'a> {
    data: &'a [u8],
    endian: Endian,
}

impl<'a> Iterator for OptionsIter<'a> {
    type Item = Result<RawOption<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        const WHAT: &str = "pcapng option";
        if self.data.is_empty() {
            return None;
        }
        let parsed = (|| {
            let code = self.endian.read_u16(self.data, 0, WHAT)?;
            let len = usize::from(self.endian.read_u16(self.data, 2, WHAT)?);
            let value = self
                .data
                .get(4..4 + len)
                .ok_or_else(|| Error::truncated(WHAT, 4 + len, self.data.len()))?;
            Ok((code, value, 4 + pad4(len)))
        })();
        match parsed {
            Ok((opt::END, _, _)) => {
                self.data = &[];
                None
            }
            Ok((code, value, used)) => {
                self.data = self.data.get(used..).unwrap_or_default();
                Some(Ok(RawOption { code, value }))
            }
            Err(err) => {
                self.data = &[];
                Some(Err(err))
            }
        }
    }
}

/// Section Header Block: starts a section and fixes its byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SectionHeader<'a> {
    /// Byte order of every block in the section.
    pub endian: Endian,
    /// Major version, 1.
    pub version_major: u16,
    /// Minor version, 0 (2 in a few old files).
    pub version_minor: u16,
    /// Length of the section after this block, when the writer knew it.
    pub section_len: Option<u64>,
    /// Options.
    pub options: Options<'a>,
}

impl<'a> SectionHeader<'a> {
    fn parse(body: &'a [u8], endian: Endian) -> Result<Self, Error> {
        const WHAT: &str = "pcapng section header";
        let version_major = endian.read_u16(body, 4, WHAT)?;
        let version_minor = endian.read_u16(body, 6, WHAT)?;
        if version_major != 1 {
            return Err(Error::UnsupportedVersion {
                what: "pcapng",
                major: version_major,
                minor: version_minor,
            });
        }
        let section_len = endian.read_u64(body, 8, WHAT)?;
        Ok(Self {
            endian,
            version_major,
            version_minor,
            section_len: (section_len != u64::MAX).then_some(section_len),
            options: Options::new(body.get(16..).unwrap_or_default(), endian),
        })
    }

    /// `shb_hardware`: the capturing machine's hardware.
    #[must_use]
    pub fn hardware(&self) -> Option<&'a str> {
        self.options.str(opt::SHB_HARDWARE)
    }

    /// `shb_os`: the capturing machine's operating system.
    #[must_use]
    pub fn os(&self) -> Option<&'a str> {
        self.options.str(opt::SHB_OS)
    }

    /// `shb_userappl`: the application that wrote the section.
    #[must_use]
    pub fn user_application(&self) -> Option<&'a str> {
        self.options.str(opt::SHB_USERAPPL)
    }
}

/// Interface Description Block: declares the next interface of the
/// section. Interfaces are numbered from 0 in declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct InterfaceDescription<'a> {
    /// Link-layer header type of the interface's packets.
    pub link_type: LinkType,
    /// Largest number of bytes captured per packet; 0 for no limit.
    pub snaplen: u32,
    /// Options.
    pub options: Options<'a>,
}

impl<'a> InterfaceDescription<'a> {
    fn parse(body: &'a [u8], endian: Endian) -> Result<Self, Error> {
        const WHAT: &str = "pcapng interface description";
        Ok(Self {
            link_type: LinkType(endian.read_u16(body, 0, WHAT)?),
            snaplen: endian.read_u32(body, 4, WHAT)?,
            options: Options::new(body.get(8..).unwrap_or_default(), endian),
        })
    }

    /// `if_name`.
    #[must_use]
    pub fn name(&self) -> Option<&'a str> {
        self.options.str(opt::IF_NAME)
    }

    /// `if_description`.
    #[must_use]
    pub fn description(&self) -> Option<&'a str> {
        self.options.str(opt::IF_DESCRIPTION)
    }

    /// `if_os`.
    #[must_use]
    pub fn os(&self) -> Option<&'a str> {
        self.options.str(opt::IF_OS)
    }

    /// `if_hardware`.
    #[must_use]
    pub fn hardware(&self) -> Option<&'a str> {
        self.options.str(opt::IF_HARDWARE)
    }

    /// `if_MACaddr`.
    #[must_use]
    pub fn mac_addr(&self) -> Option<[u8; 6]> {
        self.options.get(opt::IF_MACADDR)?.try_into().ok()
    }

    /// `if_speed`, in bits per second.
    #[must_use]
    pub fn speed(&self) -> Option<u64> {
        self.options.u64(opt::IF_SPEED)
    }

    /// `if_filter`: the filter type byte (0 for a libpcap expression) and
    /// the filter.
    #[must_use]
    pub fn filter(&self) -> Option<(u8, &'a [u8])> {
        self.options
            .get(opt::IF_FILTER)?
            .split_first()
            .map(|(t, f)| (*t, f))
    }

    /// `if_tsresol`, or microseconds when absent.
    #[must_use]
    pub fn ts_resolution(&self) -> TsResolution {
        self.options
            .u8(opt::IF_TSRESOL)
            .map_or_else(TsResolution::default, TsResolution::from_byte)
    }

    /// `if_tsoffset`: seconds to add to every timestamp, 0 when absent.
    #[must_use]
    pub fn ts_offset(&self) -> i64 {
        self.options
            .u64(opt::IF_TSOFFSET)
            .map_or(0, u64::cast_signed)
    }

    /// `if_fcslen`: bytes of frame check sequence at the end of each
    /// packet.
    #[must_use]
    pub fn fcs_len(&self) -> Option<u8> {
        self.options.u8(opt::IF_FCSLEN)
    }
}

/// Enhanced Packet Block: one packet with its interface and timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnhancedPacket<'a> {
    /// Index of the interface (in its section) the packet was captured on.
    pub interface_id: u32,
    /// Timestamp in ticks of the interface's
    /// [`ts_resolution`](InterfaceDescription::ts_resolution).
    pub ticks: u64,
    /// Length of the packet on the wire.
    pub original_len: u32,
    /// Captured bytes.
    pub data: &'a [u8],
    /// Options.
    pub options: Options<'a>,
}

impl<'a> EnhancedPacket<'a> {
    fn parse(body: &'a [u8], endian: Endian) -> Result<Self, Error> {
        const WHAT: &str = "pcapng enhanced packet";
        let interface_id = endian.read_u32(body, 0, WHAT)?;
        let high = endian.read_u32(body, 4, WHAT)?;
        let low = endian.read_u32(body, 8, WHAT)?;
        let captured_len = endian.read_u32(body, 12, WHAT)?;
        let original_len = endian.read_u32(body, 16, WHAT)?;
        let (data, options) = packet_data(body, 20, captured_len, WHAT)?;
        Ok(Self {
            interface_id,
            ticks: (u64::from(high) << 32) | u64::from(low),
            original_len,
            data,
            options: Options::new(options, endian),
        })
    }

    /// The timestamp, given the interface's resolution and offset.
    #[must_use]
    pub fn timestamp(&self, resolution: TsResolution, offset: i64) -> Timestamp {
        resolution.to_timestamp(self.ticks).offset_secs(offset)
    }

    /// `epb_flags`: direction, reception type, FCS length and link-layer
    /// errors, as one word.
    #[must_use]
    pub fn flags(&self) -> Option<u32> {
        self.options.u32(opt::EPB_FLAGS)
    }

    /// `epb_dropcount`: packets lost between this one and the previous.
    #[must_use]
    pub fn drop_count(&self) -> Option<u64> {
        self.options.u64(opt::EPB_DROPCOUNT)
    }

    /// `epb_packetid`.
    #[must_use]
    pub fn packet_id(&self) -> Option<u64> {
        self.options.u64(opt::EPB_PACKETID)
    }

    /// `epb_queue`: the receive queue.
    #[must_use]
    pub fn queue(&self) -> Option<u32> {
        self.options.u32(opt::EPB_QUEUE)
    }
}

/// Split `body` after `at` into `len` bytes of packet data and the
/// options that follow its padding.
fn packet_data<'a>(
    body: &'a [u8],
    at: usize,
    len: u32,
    what: &'static str,
) -> Result<(&'a [u8], &'a [u8]), Error> {
    let len = usize::try_from(len).unwrap_or(usize::MAX);
    let end = at.saturating_add(len);
    let data = body
        .get(at..end)
        .ok_or_else(|| Error::truncated(what, end, body.len()))?;
    let options = body.get(at.saturating_add(pad4(len))..).unwrap_or_default();
    Ok((data, options))
}

/// Simple Packet Block: a packet on interface 0 with no timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SimplePacket<'a> {
    /// Length of the packet on the wire.
    pub original_len: u32,
    /// The rest of the block: the captured bytes and any padding.
    /// [`packet`](Self::packet) trims it.
    pub data: &'a [u8],
}

impl<'a> SimplePacket<'a> {
    fn parse(body: &'a [u8], endian: Endian) -> Result<Self, Error> {
        Ok(Self {
            original_len: endian.read_u32(body, 0, "pcapng simple packet")?,
            data: body.get(4..).unwrap_or_default(),
        })
    }

    /// The captured bytes, given interface 0's snap length: the shortest
    /// of the original length, the snap length (0 is no limit) and the
    /// block.
    #[must_use]
    pub fn packet(&self, snaplen: u32) -> &'a [u8] {
        let snap = if snaplen == 0 { u32::MAX } else { snaplen };
        let len = usize::try_from(self.original_len.min(snap)).unwrap_or(usize::MAX);
        self.data.get(..len).unwrap_or(self.data)
    }
}

/// Packet Block (obsolete, superseded by the Enhanced Packet Block).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObsoletePacket<'a> {
    /// Interface index.
    pub interface_id: u16,
    /// Packets dropped since the previous one.
    pub drops_count: u16,
    /// Timestamp in ticks of the interface's resolution.
    pub ticks: u64,
    /// Length of the packet on the wire.
    pub original_len: u32,
    /// Captured bytes.
    pub data: &'a [u8],
    /// Options.
    pub options: Options<'a>,
}

impl<'a> ObsoletePacket<'a> {
    fn parse(body: &'a [u8], endian: Endian) -> Result<Self, Error> {
        const WHAT: &str = "pcapng packet block";
        let interface_id = endian.read_u16(body, 0, WHAT)?;
        let drops_count = endian.read_u16(body, 2, WHAT)?;
        let high = endian.read_u32(body, 4, WHAT)?;
        let low = endian.read_u32(body, 8, WHAT)?;
        let captured_len = endian.read_u32(body, 12, WHAT)?;
        let original_len = endian.read_u32(body, 16, WHAT)?;
        let (data, options) = packet_data(body, 20, captured_len, WHAT)?;
        Ok(Self {
            interface_id,
            drops_count,
            ticks: (u64::from(high) << 32) | u64::from(low),
            original_len,
            data,
            options: Options::new(options, endian),
        })
    }
}

/// Name Resolution Block: address-to-name mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NameResolution<'a> {
    /// The records, without the end-of-records marker.
    pub records: NameRecords<'a>,
    /// Options.
    pub options: Options<'a>,
}

impl<'a> NameResolution<'a> {
    fn parse(body: &'a [u8], endian: Endian) -> Result<Self, Error> {
        const WHAT: &str = "pcapng name resolution";
        let mut at = 0;
        loop {
            let ty = endian.read_u16(body, at, WHAT)?;
            let len = usize::from(endian.read_u16(body, at + 2, WHAT)?);
            if ty == 0 {
                return Ok(Self {
                    records: NameRecords {
                        data: body.get(..at).unwrap_or_default(),
                        endian,
                    },
                    options: Options::new(
                        body.get(at + 4 + pad4(len)..).unwrap_or_default(),
                        endian,
                    ),
                });
            }
            let next = at + 4 + pad4(len);
            if body.len() < at + 4 + len {
                return Err(Error::truncated(WHAT, at + 4 + len, body.len()));
            }
            at = next;
        }
    }
}

/// The records of a [`NameResolution`] block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameRecords<'a> {
    data: &'a [u8],
    endian: Endian,
}

impl<'a> NameRecords<'a> {
    /// Iterate over the records.
    #[must_use]
    pub const fn iter(&self) -> NameRecordsIter<'a> {
        NameRecordsIter {
            data: self.data,
            endian: self.endian,
        }
    }
}

impl<'a> IntoIterator for &NameRecords<'a> {
    type Item = NameRecord<'a>;
    type IntoIter = NameRecordsIter<'a>;

    fn into_iter(self) -> NameRecordsIter<'a> {
        self.iter()
    }
}

/// Iterator over [`NameRecords`].
#[derive(Debug, Clone)]
pub struct NameRecordsIter<'a> {
    data: &'a [u8],
    endian: Endian,
}

impl<'a> Iterator for NameRecordsIter<'a> {
    type Item = NameRecord<'a>;

    fn next(&mut self) -> Option<NameRecord<'a>> {
        let record_type = self.endian.read_u16(self.data, 0, "").ok()?;
        let len = usize::from(self.endian.read_u16(self.data, 2, "").ok()?);
        let value = self.data.get(4..4 + len)?;
        self.data = self.data.get(4 + pad4(len)..).unwrap_or_default();
        Some(NameRecord { record_type, value })
    }
}

/// One name resolution record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameRecord<'a> {
    /// 1 for IPv4, 2 for IPv6, 3 for EUI-48, 4 for EUI-64.
    pub record_type: u16,
    /// The address followed by NUL-terminated names.
    pub value: &'a [u8],
}

impl<'a> NameRecord<'a> {
    /// The IP address of an IPv4 or IPv6 record.
    #[must_use]
    pub fn ip_addr(&self) -> Option<IpAddr> {
        match self.record_type {
            1 => array::<4>(self.value, 0, "")
                .ok()
                .map(|a| Ipv4Addr::from(a).into()),
            2 => array::<16>(self.value, 0, "")
                .ok()
                .map(|a| Ipv6Addr::from(a).into()),
            _ => None,
        }
    }

    /// The names of an IPv4 or IPv6 record (entries that are not UTF-8
    /// are skipped).
    pub fn names(&self) -> impl Iterator<Item = &'a str> + use<'a> {
        let skip = match self.record_type {
            1 => 4,
            2 => 16,
            _ => self.value.len(),
        };
        self.value
            .get(skip..)
            .unwrap_or_default()
            .split(|&b| b == 0)
            .filter(|n| !n.is_empty())
            .filter_map(|n| std::str::from_utf8(n).ok())
    }
}

/// Interface Statistics Block: counters for one interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct InterfaceStatistics<'a> {
    /// Interface index.
    pub interface_id: u32,
    /// When the statistics were taken, in the interface's ticks.
    pub ticks: u64,
    /// Options.
    pub options: Options<'a>,
}

impl<'a> InterfaceStatistics<'a> {
    fn parse(body: &'a [u8], endian: Endian) -> Result<Self, Error> {
        const WHAT: &str = "pcapng interface statistics";
        let interface_id = endian.read_u32(body, 0, WHAT)?;
        let high = endian.read_u32(body, 4, WHAT)?;
        let low = endian.read_u32(body, 8, WHAT)?;
        Ok(Self {
            interface_id,
            ticks: (u64::from(high) << 32) | u64::from(low),
            options: Options::new(body.get(12..).unwrap_or_default(), endian),
        })
    }

    /// `isb_ifrecv`: packets received by the interface.
    #[must_use]
    pub fn received(&self) -> Option<u64> {
        self.options.u64(opt::ISB_IFRECV)
    }

    /// `isb_ifdrop`: packets the interface dropped.
    #[must_use]
    pub fn dropped(&self) -> Option<u64> {
        self.options.u64(opt::ISB_IFDROP)
    }

    /// `isb_osdrop`: packets the operating system dropped.
    #[must_use]
    pub fn os_dropped(&self) -> Option<u64> {
        self.options.u64(opt::ISB_OSDROP)
    }

    /// `isb_filteraccept`: packets the capture filter accepted.
    #[must_use]
    pub fn filter_accepted(&self) -> Option<u64> {
        self.options.u64(opt::ISB_FILTERACCEPT)
    }

    /// `isb_usrdeliv`: packets delivered to the capturing application.
    #[must_use]
    pub fn delivered(&self) -> Option<u64> {
        self.options.u64(opt::ISB_USRDELIV)
    }
}

/// Decryption Secrets Block: key material for decrypting traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecryptionSecrets<'a> {
    /// What the secrets are, e.g. [`DecryptionSecrets::TLS_KEY_LOG`].
    pub secrets_type: u32,
    /// The secrets.
    pub data: &'a [u8],
    /// Options.
    pub options: Options<'a>,
}

impl<'a> DecryptionSecrets<'a> {
    /// NSS key log format (`SSLKEYLOGFILE`) for TLS.
    pub const TLS_KEY_LOG: u32 = 0x544c_534b;
    /// `WireGuard` key log.
    pub const WIREGUARD_KEY_LOG: u32 = 0x5747_4b4c;
    /// `ZigBee` network key.
    pub const ZIGBEE_NWK_KEY: u32 = 0x5a4e_574b;
    /// `ZigBee` application support link key.
    pub const ZIGBEE_APS_KEY: u32 = 0x5a41_5053;
    /// OPC UA key log.
    pub const OPCUA_KEY_LOG: u32 = 0x554b_4c47;

    fn parse(body: &'a [u8], endian: Endian) -> Result<Self, Error> {
        const WHAT: &str = "pcapng decryption secrets";
        let secrets_type = endian.read_u32(body, 0, WHAT)?;
        let len = endian.read_u32(body, 4, WHAT)?;
        let (data, options) = packet_data(body, 8, len, WHAT)?;
        Ok(Self {
            secrets_type,
            data,
            options: Options::new(options, endian),
        })
    }
}

/// A parsed pcapng block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Block<'a> {
    /// Section Header Block.
    SectionHeader(SectionHeader<'a>),
    /// Interface Description Block.
    InterfaceDescription(InterfaceDescription<'a>),
    /// Enhanced Packet Block.
    EnhancedPacket(EnhancedPacket<'a>),
    /// Simple Packet Block.
    SimplePacket(SimplePacket<'a>),
    /// Packet Block (obsolete).
    ObsoletePacket(ObsoletePacket<'a>),
    /// Name Resolution Block.
    NameResolution(NameResolution<'a>),
    /// Interface Statistics Block.
    InterfaceStatistics(InterfaceStatistics<'a>),
    /// Decryption Secrets Block.
    DecryptionSecrets(DecryptionSecrets<'a>),
    /// Any other block, including custom blocks.
    Other(RawBlock<'a>),
}

impl<'a> Block<'a> {
    /// Parse the block at the start of `data`; see [`RawBlock::parse`].
    /// Returns the block, the byte order now in force, and the bytes it
    /// took.
    ///
    /// # Errors
    ///
    /// As [`RawBlock::parse`], plus [`Error::Truncated`] when the body is
    /// too short for its block type and [`Error::UnsupportedVersion`] for
    /// a section of major version other than 1.
    pub fn parse(data: &'a [u8], endian: Endian) -> Result<(Self, Endian, usize), Error> {
        let (raw, endian, used) = RawBlock::parse(data, endian)?;
        Ok((Self::from_raw(raw, endian)?, endian, used))
    }

    /// Parse the body of a block already split with [`RawBlock::parse`].
    ///
    /// # Errors
    ///
    /// As [`parse`](Self::parse).
    pub fn from_raw(raw: RawBlock<'a>, endian: Endian) -> Result<Self, Error> {
        let body = raw.body;
        Ok(match raw.block_type {
            BlockType::SECTION_HEADER => Self::SectionHeader(SectionHeader::parse(body, endian)?),
            BlockType::INTERFACE_DESCRIPTION => {
                Self::InterfaceDescription(InterfaceDescription::parse(body, endian)?)
            }
            BlockType::ENHANCED_PACKET => {
                Self::EnhancedPacket(EnhancedPacket::parse(body, endian)?)
            }
            BlockType::SIMPLE_PACKET => Self::SimplePacket(SimplePacket::parse(body, endian)?),
            BlockType::OBSOLETE_PACKET => {
                Self::ObsoletePacket(ObsoletePacket::parse(body, endian)?)
            }
            BlockType::NAME_RESOLUTION => {
                Self::NameResolution(NameResolution::parse(body, endian)?)
            }
            BlockType::INTERFACE_STATISTICS => {
                Self::InterfaceStatistics(InterfaceStatistics::parse(body, endian)?)
            }
            BlockType::DECRYPTION_SECRETS => {
                Self::DecryptionSecrets(DecryptionSecrets::parse(body, endian)?)
            }
            _ => Self::Other(raw),
        })
    }

    /// The block's type.
    #[must_use]
    pub const fn block_type(&self) -> BlockType {
        match self {
            Self::SectionHeader(_) => BlockType::SECTION_HEADER,
            Self::InterfaceDescription(_) => BlockType::INTERFACE_DESCRIPTION,
            Self::EnhancedPacket(_) => BlockType::ENHANCED_PACKET,
            Self::SimplePacket(_) => BlockType::SIMPLE_PACKET,
            Self::ObsoletePacket(_) => BlockType::OBSOLETE_PACKET,
            Self::NameResolution(_) => BlockType::NAME_RESOLUTION,
            Self::InterfaceStatistics(_) => BlockType::INTERFACE_STATISTICS,
            Self::DecryptionSecrets(_) => BlockType::DECRYPTION_SECRETS,
            Self::Other(raw) => raw.block_type,
        }
    }
}

#[cfg(test)]
mod tests;
