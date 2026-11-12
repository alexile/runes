//! Encoding pcapng blocks.

use super::{BYTE_ORDER_MAGIC, BlockType, opt};
use crate::endian::{Endian, len_u32, pad4};
use crate::error::Error;
use crate::linktype::LinkType;
use crate::time::{Timestamp, TsResolution};

/// An option value waiting for the byte order to encode it in.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Bytes(Vec<u8>),
    U32(u32),
    U64(u64),
}

/// Options for a block being written, in order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct OptionList(Vec<(u16, Value)>);

impl OptionList {
    fn push(&mut self, code: u16, value: Value) {
        self.0.push((code, value));
    }

    fn bytes(&mut self, code: u16, value: &[u8]) {
        self.push(code, Value::Bytes(value.to_vec()));
    }

    /// Append the options and `opt_endofopt` (if there were any).
    fn encode(&self, endian: Endian, out: &mut Vec<u8>) -> Result<(), Error> {
        for (code, value) in &self.0 {
            let mut buf = [0u8; 8];
            let bytes: &[u8] = match value {
                Value::Bytes(b) => b,
                Value::U32(v) => {
                    let mut tmp = Vec::with_capacity(4);
                    endian.put_u32(&mut tmp, *v);
                    buf[..4].copy_from_slice(&tmp);
                    &buf[..4]
                }
                Value::U64(v) => {
                    let mut tmp = Vec::with_capacity(8);
                    endian.put_u64(&mut tmp, *v);
                    buf.copy_from_slice(&tmp);
                    &buf
                }
            };
            let len = u16::try_from(bytes.len()).map_err(|_| Error::TooLarge {
                what: "pcapng option",
                len: bytes.len() as u64,
                max: u64::from(u16::MAX),
            })?;
            endian.put_u16(out, *code);
            endian.put_u16(out, len);
            out.extend_from_slice(bytes);
            out.resize(out.len() + pad4(bytes.len()) - bytes.len(), 0);
        }
        if !self.0.is_empty() {
            endian.put_u32(out, 0);
        }
        Ok(())
    }
}

/// Append a block of `block_type` whose body `body` writes, filling in
/// both lengths. On error `out` is left as it was.
fn block(
    endian: Endian,
    block_type: BlockType,
    out: &mut Vec<u8>,
    body: impl FnOnce(&mut Vec<u8>) -> Result<(), Error>,
) -> Result<(), Error> {
    let start = out.len();
    let result = (|| {
        endian.put_u32(out, block_type.0);
        endian.put_u32(out, 0);
        body(out)?;
        out.resize(start + pad4(out.len() - start), 0);
        let total = len_u32(out.len() - start + 4, "pcapng block")?;
        endian.put_u32(out, total);
        let mut len = Vec::with_capacity(4);
        endian.put_u32(&mut len, total);
        out[start + 4..start + 8].copy_from_slice(&len);
        Ok(())
    })();
    if result.is_err() {
        out.truncate(start);
    }
    result
}

/// A Section Header Block to write.
///
/// ```
/// use rune_pcap::pcapng::SectionBuilder;
///
/// let shb = SectionBuilder::new().with_user_application("my-tool 1.0");
/// let mut out = Vec::new();
/// shb.encode(&mut out)?;
/// assert_eq!(&out[..4], [0x0a, 0x0d, 0x0d, 0x0a]);
/// # Ok::<(), rune_pcap::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SectionBuilder {
    endian: Endian,
    options: OptionList,
}

impl SectionBuilder {
    /// A little-endian section header with no options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the section's byte order.
    #[must_use]
    pub const fn with_endian(mut self, endian: Endian) -> Self {
        self.endian = endian;
        self
    }

    /// The section's byte order.
    #[must_use]
    pub const fn endian(&self) -> Endian {
        self.endian
    }

    /// Add `shb_hardware`.
    #[must_use]
    pub fn with_hardware(mut self, hardware: &str) -> Self {
        self.options.bytes(opt::SHB_HARDWARE, hardware.as_bytes());
        self
    }

    /// Add `shb_os`.
    #[must_use]
    pub fn with_os(mut self, os: &str) -> Self {
        self.options.bytes(opt::SHB_OS, os.as_bytes());
        self
    }

    /// Add `shb_userappl`.
    #[must_use]
    pub fn with_user_application(mut self, application: &str) -> Self {
        self.options
            .bytes(opt::SHB_USERAPPL, application.as_bytes());
        self
    }

    /// Add an `opt_comment`.
    #[must_use]
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.options.bytes(opt::COMMENT, comment.as_bytes());
        self
    }

    /// Add any option, with its value already in the section's byte order.
    #[must_use]
    pub fn with_option(mut self, code: u16, value: &[u8]) -> Self {
        self.options.bytes(code, value);
        self
    }

    /// Append the block (version 1.0, section length unknown) to `out`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] if an option is longer than 65 535 bytes.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let e = self.endian;
        block(e, BlockType::SECTION_HEADER, out, |out| {
            e.put_u32(out, BYTE_ORDER_MAGIC);
            e.put_u16(out, 1);
            e.put_u16(out, 0);
            e.put_u64(out, u64::MAX);
            self.options.encode(e, out)
        })
    }
}

/// An Interface Description Block to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceBuilder {
    link_type: LinkType,
    snaplen: u32,
    ts_resolution: TsResolution,
    ts_offset: i64,
    options: OptionList,
}

impl InterfaceBuilder {
    /// An interface of `link_type` with no snap length limit and
    /// microsecond timestamps.
    #[must_use]
    pub fn new(link_type: LinkType) -> Self {
        Self {
            link_type,
            snaplen: 0,
            ts_resolution: TsResolution::default(),
            ts_offset: 0,
            options: OptionList::default(),
        }
    }

    /// Set the snap length (0 for none).
    #[must_use]
    pub const fn with_snaplen(mut self, snaplen: u32) -> Self {
        self.snaplen = snaplen;
        self
    }

    /// Set the timestamp resolution (`if_tsresol`, written only when it is
    /// not microseconds).
    #[must_use]
    pub const fn with_ts_resolution(mut self, resolution: TsResolution) -> Self {
        self.ts_resolution = resolution;
        self
    }

    /// Set the timestamp offset in seconds (`if_tsoffset`, written only
    /// when non-zero). Packet timestamps are stored relative to it.
    #[must_use]
    pub const fn with_ts_offset(mut self, offset: i64) -> Self {
        self.ts_offset = offset;
        self
    }

    /// Add `if_name`.
    #[must_use]
    pub fn with_name(mut self, name: &str) -> Self {
        self.options.bytes(opt::IF_NAME, name.as_bytes());
        self
    }

    /// Add `if_description`.
    #[must_use]
    pub fn with_description(mut self, description: &str) -> Self {
        self.options
            .bytes(opt::IF_DESCRIPTION, description.as_bytes());
        self
    }

    /// Add `if_os`.
    #[must_use]
    pub fn with_os(mut self, os: &str) -> Self {
        self.options.bytes(opt::IF_OS, os.as_bytes());
        self
    }

    /// Add `if_hardware`.
    #[must_use]
    pub fn with_hardware(mut self, hardware: &str) -> Self {
        self.options.bytes(opt::IF_HARDWARE, hardware.as_bytes());
        self
    }

    /// Add `if_filter` with a libpcap filter expression.
    #[must_use]
    pub fn with_filter(mut self, expression: &str) -> Self {
        self.options
            .bytes(opt::IF_FILTER, &[&[0], expression.as_bytes()].concat());
        self
    }

    /// Add `if_fcslen`.
    #[must_use]
    pub fn with_fcs_len(mut self, bytes: u8) -> Self {
        self.options.bytes(opt::IF_FCSLEN, &[bytes]);
        self
    }

    /// Add `if_speed` in bits per second.
    #[must_use]
    pub fn with_speed(mut self, bits_per_second: u64) -> Self {
        self.options
            .push(opt::IF_SPEED, Value::U64(bits_per_second));
        self
    }

    /// Add an `opt_comment`.
    #[must_use]
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.options.bytes(opt::COMMENT, comment.as_bytes());
        self
    }

    /// Add any option, with its value already in the section's byte order.
    #[must_use]
    pub fn with_option(mut self, code: u16, value: &[u8]) -> Self {
        self.options.bytes(code, value);
        self
    }

    /// The link type.
    #[must_use]
    pub const fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// The timestamp resolution.
    #[must_use]
    pub const fn ts_resolution(&self) -> TsResolution {
        self.ts_resolution
    }

    /// The timestamp offset in seconds.
    #[must_use]
    pub const fn ts_offset(&self) -> i64 {
        self.ts_offset
    }

    /// Append the block to `out` in byte order `endian`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] if an option is longer than 65 535 bytes.
    pub fn encode(&self, endian: Endian, out: &mut Vec<u8>) -> Result<(), Error> {
        let e = endian;
        block(e, BlockType::INTERFACE_DESCRIPTION, out, |out| {
            e.put_u16(out, self.link_type.0);
            e.put_u16(out, 0);
            e.put_u32(out, self.snaplen);
            let mut options = OptionList::default();
            if self.ts_resolution != TsResolution::MICROS {
                options.bytes(opt::IF_TSRESOL, &[self.ts_resolution.to_byte()]);
            }
            if self.ts_offset != 0 {
                options.push(opt::IF_TSOFFSET, Value::U64(self.ts_offset.cast_unsigned()));
            }
            options.0.extend(self.options.0.iter().cloned());
            options.encode(e, out)
        })
    }
}

/// An Enhanced Packet Block to write.
///
/// The timestamp is a [`Timestamp`]; it is converted to the interface's
/// resolution and offset when encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnhancedPacketBuilder<'a> {
    interface_id: u32,
    timestamp: Timestamp,
    data: &'a [u8],
    original_len: Option<u32>,
    options: OptionList,
}

impl<'a> EnhancedPacketBuilder<'a> {
    /// A packet of `data`, captured whole on `interface_id` at
    /// `timestamp`.
    #[must_use]
    pub fn new(interface_id: u32, timestamp: Timestamp, data: &'a [u8]) -> Self {
        Self {
            interface_id,
            timestamp,
            data,
            original_len: None,
            options: OptionList::default(),
        }
    }

    /// Set the length on the wire, for a packet cut short by the snap
    /// length. Defaults to the data's length.
    #[must_use]
    pub const fn with_original_len(mut self, len: u32) -> Self {
        self.original_len = Some(len);
        self
    }

    /// Add `epb_flags`.
    #[must_use]
    pub fn with_flags(mut self, flags: u32) -> Self {
        self.options.push(opt::EPB_FLAGS, Value::U32(flags));
        self
    }

    /// Add `epb_dropcount`.
    #[must_use]
    pub fn with_drop_count(mut self, count: u64) -> Self {
        self.options.push(opt::EPB_DROPCOUNT, Value::U64(count));
        self
    }

    /// Add `epb_packetid`.
    #[must_use]
    pub fn with_packet_id(mut self, id: u64) -> Self {
        self.options.push(opt::EPB_PACKETID, Value::U64(id));
        self
    }

    /// Add `epb_queue`.
    #[must_use]
    pub fn with_queue(mut self, queue: u32) -> Self {
        self.options.push(opt::EPB_QUEUE, Value::U32(queue));
        self
    }

    /// Add an `opt_comment`.
    #[must_use]
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.options.bytes(opt::COMMENT, comment.as_bytes());
        self
    }

    /// Add any option, with its value already in the section's byte order.
    #[must_use]
    pub fn with_option(mut self, code: u16, value: &[u8]) -> Self {
        self.options.bytes(code, value);
        self
    }

    /// The interface index.
    #[must_use]
    pub const fn interface_id(&self) -> u32 {
        self.interface_id
    }

    /// Append the block to `out`, in byte order `endian`, with the
    /// timestamp at `resolution` relative to `ts_offset` seconds.
    ///
    /// # Errors
    ///
    /// [`Error::TimestampOutOfRange`] if the timestamp does not fit,
    /// [`Error::TooLarge`] for a packet over 4 GiB or an option over
    /// 65 535 bytes, [`Error::Malformed`] if the original length is
    /// shorter than the data.
    pub fn encode(
        &self,
        endian: Endian,
        resolution: TsResolution,
        ts_offset: i64,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let captured = len_u32(self.data.len(), "pcapng enhanced packet")?;
        let original = self.original_len.unwrap_or(captured);
        if original < captured {
            return Err(Error::malformed(
                "pcapng enhanced packet",
                "original length shorter than captured data",
            ));
        }
        let shifted = self
            .timestamp
            .secs
            .checked_add_signed(ts_offset.checked_neg().ok_or(Error::TimestampOutOfRange)?)
            .ok_or(Error::TimestampOutOfRange)?;
        let ticks = resolution.to_ticks(Timestamp::new(shifted, self.timestamp.nanos))?;
        let e = endian;
        block(e, BlockType::ENHANCED_PACKET, out, |out| {
            e.put_u32(out, self.interface_id);
            #[allow(
                clippy::cast_possible_truncation,
                reason = "splitting into 32-bit halves"
            )]
            {
                e.put_u32(out, (ticks >> 32) as u32);
                e.put_u32(out, ticks as u32);
            }
            e.put_u32(out, captured);
            e.put_u32(out, original);
            out.extend_from_slice(self.data);
            out.resize(out.len() + pad4(self.data.len()) - self.data.len(), 0);
            self.options.encode(e, out)
        })
    }
}

/// A sans-I/O pcapng encoder: it appends blocks to a buffer and tracks
/// the interfaces of the current section, so packets can be checked
/// against them and their timestamps converted.
///
/// ```
/// use rune_pcap::pcapng::{Encoder, EnhancedPacketBuilder, InterfaceBuilder, SectionBuilder};
/// use rune_pcap::{LinkType, Timestamp, TsResolution};
///
/// let mut out = Vec::new();
/// let mut enc = Encoder::new(&SectionBuilder::new(), &mut out)?;
/// let eth = enc.interface(
///     &InterfaceBuilder::new(LinkType::ETHERNET).with_ts_resolution(TsResolution::NANOS),
///     &mut out,
/// )?;
/// enc.packet(&EnhancedPacketBuilder::new(eth, Timestamp::new(1, 5), &[0u8; 14]), &mut out)?;
/// // Section header, interface (with `if_tsresol`), packet.
/// assert_eq!(out.len(), 28 + 32 + 48);
/// # Ok::<(), rune_pcap::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoder {
    endian: Endian,
    interfaces: Vec<(TsResolution, i64)>,
}

impl Encoder {
    /// Start a file: append `section`'s header to `out`.
    ///
    /// # Errors
    ///
    /// As [`SectionBuilder::encode`].
    pub fn new(section: &SectionBuilder, out: &mut Vec<u8>) -> Result<Self, Error> {
        section.encode(out)?;
        Ok(Self {
            endian: section.endian,
            interfaces: Vec::new(),
        })
    }

    /// Start a new section. Its interfaces start again from 0.
    ///
    /// # Errors
    ///
    /// As [`SectionBuilder::encode`].
    pub fn section(&mut self, section: &SectionBuilder, out: &mut Vec<u8>) -> Result<(), Error> {
        section.encode(out)?;
        self.endian = section.endian;
        self.interfaces.clear();
        Ok(())
    }

    /// The current section's byte order.
    #[must_use]
    pub const fn endian(&self) -> Endian {
        self.endian
    }

    /// Number of interfaces declared in the current section.
    #[must_use]
    pub const fn interface_count(&self) -> usize {
        self.interfaces.len()
    }

    /// Declare an interface; returns its index.
    ///
    /// # Errors
    ///
    /// As [`InterfaceBuilder::encode`], and [`Error::TooLarge`] past
    /// 2<sup>32</sup> interfaces.
    pub fn interface(
        &mut self,
        interface: &InterfaceBuilder,
        out: &mut Vec<u8>,
    ) -> Result<u32, Error> {
        let id = len_u32(self.interfaces.len(), "pcapng interface table")?;
        interface.encode(self.endian, out)?;
        self.interfaces
            .push((interface.ts_resolution, interface.ts_offset));
        Ok(id)
    }

    /// Append a packet.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownInterface`] if its interface was not declared in
    /// this section, otherwise as [`EnhancedPacketBuilder::encode`].
    pub fn packet(
        &self,
        packet: &EnhancedPacketBuilder<'_>,
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let id = packet.interface_id;
        let (resolution, offset) = usize::try_from(id)
            .ok()
            .and_then(|i| self.interfaces.get(i))
            .copied()
            .ok_or(Error::UnknownInterface(id))?;
        packet.encode(self.endian, resolution, offset, out)
    }

    /// Append a Decryption Secrets Block, such as a TLS key log
    /// ([`DecryptionSecrets::TLS_KEY_LOG`](super::DecryptionSecrets::TLS_KEY_LOG)).
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] for secrets over 4 GiB.
    pub fn decryption_secrets(
        &self,
        secrets_type: u32,
        secrets: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let e = self.endian;
        let len = len_u32(secrets.len(), "pcapng decryption secrets")?;
        block(e, BlockType::DECRYPTION_SECRETS, out, |out| {
            e.put_u32(out, secrets_type);
            e.put_u32(out, len);
            out.extend_from_slice(secrets);
            Ok(())
        })
    }

    /// Append a block of any type with `body` (padded to 4 bytes) as its
    /// contents, already in the section's byte order.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] for a body over 4 GiB.
    pub fn raw_block(
        &self,
        block_type: BlockType,
        body: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        block(self.endian, block_type, out, |out| {
            out.extend_from_slice(body);
            Ok(())
        })
    }
}
