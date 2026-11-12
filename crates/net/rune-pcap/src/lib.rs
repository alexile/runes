//! Streaming pcap and pcapng reading and writing, with link-type aware
//! dissection by [`rune_packet`].
//!
//! - **Formats.** Classic libpcap files (microsecond and nanosecond,
//!   either byte order, plus reading the modified "Kuznetzov" variant) and
//!   pcapng (several sections, interfaces with their own link types and
//!   timestamp resolutions, Enhanced / Simple / obsolete Packet Blocks,
//!   Name Resolution, Interface Statistics and Decryption Secrets Blocks;
//!   other blocks are kept raw).
//! - **Streaming.** [`CaptureReader`] (either format, detected from the
//!   magic number), [`PcapReader`] and [`PcapNgReader`] read from any
//!   [`std::io::Read`] and hold one record in memory at a time; each
//!   [`Record`] borrows from the reader. Record and block lengths are
//!   capped, so a hostile file can't make the reader allocate gigabytes.
//! - **Sans-I/O core.** [`PcapHeader`] and the [`pcapng`] module parse and
//!   encode headers, records and blocks on byte slices; the readers and
//!   [`PcapWriter`] / [`PcapNgWriter`] are thin layers over them.
//! - **Dissection.** [`Record::dissect`] hands the frame to
//!   [`rune_packet::Packet`] according to its [`LinkType`]: Ethernet, raw
//!   IP, BSD loopback and Linux cooked captures (SLL and SLL2).
//! - **Timestamps** become a common [`Timestamp`] (seconds and
//!   nanoseconds), whatever the file's resolution ([`TsResolution`]).
//!
//! Malformed input gives an [`Error`], never a panic.
//!
//! Specifications: [draft-ietf-opsawg-pcap](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/),
//! [draft-ietf-opsawg-pcapng](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/),
//! and the [link-layer header type registry](https://www.tcpdump.org/linktypes.html).
//!
//! # Example
//!
//! ```
//! use rune_pcap::pcapng::{EnhancedPacketBuilder, InterfaceBuilder, SectionBuilder};
//! use rune_pcap::{CaptureReader, LinkType, PcapNgWriter, Timestamp, TsResolution};
//!
//! // An IPv4/UDP datagram from 192.0.2.1:53 to 198.51.100.7:4242.
//! let ip = [
//!     0x45, 0, 0, 28, 0, 0, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 7,
//!     0, 53, 0x10, 0x92, 0, 8, 0, 0,
//! ];
//!
//! // Write a pcapng file with one raw-IP interface at nanosecond resolution.
//! let mut file = Vec::new();
//! let mut writer = PcapNgWriter::new(&mut file, &SectionBuilder::new())?;
//! let tun = writer.add_interface(
//!     &InterfaceBuilder::new(LinkType::RAW)
//!         .with_name("tun0")
//!         .with_ts_resolution(TsResolution::NANOS),
//! )?;
//! let ts = Timestamp::new(1_700_000_000, 123_456_789);
//! writer.write(&EnhancedPacketBuilder::new(tun, ts, &ip).with_comment("dns reply"))?;
//!
//! // Stream it back and dissect each packet.
//! let mut reader = CaptureReader::new(file.as_slice())?;
//! let record = reader.next_packet()?.unwrap();
//! assert_eq!(record.timestamp, Some(ts));
//! assert_eq!(record.link_type, LinkType::RAW);
//! let packet = record.dissect().unwrap();
//! assert_eq!(packet.ip.unwrap().src().to_string(), "192.0.2.1");
//! assert_eq!(packet.transport.unwrap().src_port(), Some(53));
//! assert!(reader.next_packet()?.is_none());
//! # Ok::<(), rune_pcap::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod endian;
mod error;
mod linktype;
pub mod pcap;
pub mod pcapng;
mod reader;
mod time;
mod writer;

pub use endian::Endian;
pub use error::Error;
pub use linktype::LinkType;
pub use pcap::{PcapHeader, Precision, RecordHeader};
pub use reader::{
    CaptureReader, DEFAULT_MAX_RECORD_LEN, Format, Interface, PcapNgReader, PcapReader, Record,
};
pub use time::{Timestamp, TsResolution};
pub use writer::{PcapNgWriter, PcapWriter, write_pcap};
