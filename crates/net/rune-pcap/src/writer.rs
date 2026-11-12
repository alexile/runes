//! Writers over [`std::io::Write`].

use std::io::Write;

use crate::error::Error;
use crate::linktype::LinkType;
use crate::pcap::PcapHeader;
use crate::pcapng::{BlockType, Encoder, EnhancedPacketBuilder, InterfaceBuilder, SectionBuilder};
use crate::time::Timestamp;

/// Writes a classic pcap file.
///
/// Wrap unbuffered writers such as files in a [`std::io::BufWriter`].
#[derive(Debug)]
pub struct PcapWriter<W: Write> {
    inner: W,
    header: PcapHeader,
    buf: Vec<u8>,
}

impl<W: Write> PcapWriter<W> {
    /// Write the file header.
    ///
    /// Files are always written with standard 16-byte record headers,
    /// so `header.modified` is ignored.
    ///
    /// # Errors
    ///
    /// [`Error::Io`].
    pub fn new(mut inner: W, mut header: PcapHeader) -> Result<Self, Error> {
        header.modified = false;
        let mut buf = Vec::with_capacity(64);
        header.encode(&mut buf);
        inner.write_all(&buf)?;
        Ok(Self { inner, header, buf })
    }

    /// The file header.
    #[must_use]
    pub const fn header(&self) -> &PcapHeader {
        &self.header
    }

    /// Write a packet captured whole.
    ///
    /// # Errors
    ///
    /// As [`PcapHeader::encode_record`], or [`Error::Io`].
    pub fn write_packet(&mut self, timestamp: Timestamp, data: &[u8]) -> Result<(), Error> {
        let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
        self.write_truncated(timestamp, data, len)
    }

    /// Write a packet that was `original_len` bytes on the wire, of which
    /// `data` was captured.
    ///
    /// # Errors
    ///
    /// As [`PcapHeader::encode_record`], or [`Error::Io`].
    pub fn write_truncated(
        &mut self,
        timestamp: Timestamp,
        data: &[u8],
        original_len: u32,
    ) -> Result<(), Error> {
        self.buf.clear();
        self.header
            .encode_record(timestamp, data, original_len, &mut self.buf)?;
        self.inner.write_all(&self.buf)?;
        Ok(())
    }

    /// Flush the underlying writer.
    ///
    /// # Errors
    ///
    /// [`Error::Io`].
    pub fn flush(&mut self) -> Result<(), Error> {
        Ok(self.inner.flush()?)
    }

    /// The underlying writer (not flushed).
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Writes a pcapng file.
///
/// ```
/// use rune_pcap::pcapng::{EnhancedPacketBuilder, InterfaceBuilder, SectionBuilder};
/// use rune_pcap::{CaptureReader, LinkType, PcapNgWriter, Timestamp};
///
/// let mut file = Vec::new();
/// let mut w = PcapNgWriter::new(&mut file, &SectionBuilder::new().with_os("Linux"))?;
/// let eth = w.add_interface(&InterfaceBuilder::new(LinkType::ETHERNET).with_name("eth0"))?;
/// w.write(&EnhancedPacketBuilder::new(eth, Timestamp::new(1_700_000_000, 0), &[0; 60]).with_comment("hi"))?;
///
/// let mut r = CaptureReader::new(file.as_slice())?;
/// let rec = r.next_packet()?.unwrap();
/// assert_eq!(rec.data.len(), 60);
/// assert_eq!(rec.timestamp, Some(Timestamp::new(1_700_000_000, 0)));
/// # Ok::<(), rune_pcap::Error>(())
/// ```
#[derive(Debug)]
pub struct PcapNgWriter<W: Write> {
    inner: W,
    encoder: Encoder,
    buf: Vec<u8>,
}

impl<W: Write> PcapNgWriter<W> {
    /// Write the first Section Header Block.
    ///
    /// # Errors
    ///
    /// As [`SectionBuilder::encode`], or [`Error::Io`].
    pub fn new(mut inner: W, section: &SectionBuilder) -> Result<Self, Error> {
        let mut buf = Vec::with_capacity(256);
        let encoder = Encoder::new(section, &mut buf)?;
        inner.write_all(&buf)?;
        Ok(Self {
            inner,
            encoder,
            buf,
        })
    }

    /// The encoder, for its byte order and interface count.
    #[must_use]
    pub const fn encoder(&self) -> &Encoder {
        &self.encoder
    }

    fn emit(
        &mut self,
        f: impl FnOnce(&mut Encoder, &mut Vec<u8>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.buf.clear();
        f(&mut self.encoder, &mut self.buf)?;
        self.inner.write_all(&self.buf)?;
        Ok(())
    }

    /// Start a new section; interface numbering restarts at 0.
    ///
    /// # Errors
    ///
    /// As [`Encoder::section`], or [`Error::Io`].
    pub fn new_section(&mut self, section: &SectionBuilder) -> Result<(), Error> {
        self.emit(|e, out| e.section(section, out))
    }

    /// Declare an interface; returns its index for packets to refer to.
    ///
    /// # Errors
    ///
    /// As [`Encoder::interface`], or [`Error::Io`].
    pub fn add_interface(&mut self, interface: &InterfaceBuilder) -> Result<u32, Error> {
        let mut id = 0;
        self.emit(|e, out| {
            id = e.interface(interface, out)?;
            Ok(())
        })?;
        Ok(id)
    }

    /// Write an Enhanced Packet Block.
    ///
    /// # Errors
    ///
    /// As [`Encoder::packet`], or [`Error::Io`].
    pub fn write(&mut self, packet: &EnhancedPacketBuilder<'_>) -> Result<(), Error> {
        self.emit(|e, out| e.packet(packet, out))
    }

    /// Write a packet captured whole, with no options.
    ///
    /// # Errors
    ///
    /// As [`write`](Self::write).
    pub fn write_packet(
        &mut self,
        interface_id: u32,
        timestamp: Timestamp,
        data: &[u8],
    ) -> Result<(), Error> {
        self.write(&EnhancedPacketBuilder::new(interface_id, timestamp, data))
    }

    /// Write a Decryption Secrets Block.
    ///
    /// # Errors
    ///
    /// As [`Encoder::decryption_secrets`], or [`Error::Io`].
    pub fn write_decryption_secrets(
        &mut self,
        secrets_type: u32,
        secrets: &[u8],
    ) -> Result<(), Error> {
        self.emit(|e, out| e.decryption_secrets(secrets_type, secrets, out))
    }

    /// Write a block of any other type; see [`Encoder::raw_block`].
    ///
    /// # Errors
    ///
    /// As [`Encoder::raw_block`], [`Error::Malformed`] for a Section
    /// Header or Interface Description block (use
    /// [`new_section`](Self::new_section) and
    /// [`add_interface`](Self::add_interface)), or [`Error::Io`].
    pub fn write_raw_block(&mut self, block_type: BlockType, body: &[u8]) -> Result<(), Error> {
        if matches!(
            block_type,
            BlockType::SECTION_HEADER | BlockType::INTERFACE_DESCRIPTION
        ) {
            return Err(Error::malformed(
                "pcapng block",
                "section headers and interfaces go through their own methods",
            ));
        }
        self.emit(|e, out| e.raw_block(block_type, body, out))
    }

    /// Flush the underlying writer.
    ///
    /// # Errors
    ///
    /// [`Error::Io`].
    pub fn flush(&mut self) -> Result<(), Error> {
        Ok(self.inner.flush()?)
    }

    /// The underlying writer (not flushed).
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Write a pcap file of `link_type` from `(timestamp, data)` pairs: a
/// one-call way to turn crafted packets into a test fixture.
///
/// # Errors
///
/// As [`PcapWriter::write_packet`].
pub fn write_pcap<'a, W: Write>(
    inner: W,
    link_type: LinkType,
    packets: impl IntoIterator<Item = (Timestamp, &'a [u8])>,
) -> Result<W, Error> {
    let mut w = PcapWriter::new(inner, PcapHeader::new(link_type))?;
    for (ts, data) in packets {
        w.write_packet(ts, data)?;
    }
    w.flush()?;
    Ok(w.into_inner())
}
