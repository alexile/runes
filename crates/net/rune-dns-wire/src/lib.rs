//! Sans-I/O DNS message parser and builder.
//!
//! `rune-dns-wire` turns DNS messages into values and back, and nothing
//! else: no sockets, no timers, no resolver logic. Bring your own UDP, TCP,
//! `DoH` or `DoT` transport (see `rune-dns-resolver`) and hand this crate the
//! bytes.
//!
//! - [`Message::decode`] parses a whole message: header, question, answer,
//!   authority and additional sections, with name decompression and the
//!   EDNS(0) `OPT` pseudo-record lifted into [`Message::edns`].
//! - [`Message::encode`] writes it back, compressing names where RFC 3597
//!   allows it; [`Message::encode_with_limit`] also truncates to a size limit
//!   and sets `TC`, as a UDP responder must.
//! - [`Message::query`] and [`Message::response_to`] start queries and
//!   responses; `with_*` methods fill them in.
//!
//! # Untrusted input
//!
//! The decoder is written for hostile packets. It never panics,
//! never allocates more than the input justifies, and rejects:
//!
//! - compression pointers that do not point strictly backwards (which rules
//!   out loops), point into the header, or chain more than 128 times;
//! - names longer than 255 octets (after decompression) and the reserved
//!   label types `0x40` and `0x80`;
//! - RDATA whose length does not match its type's layout;
//! - more than one `OPT` record, an `OPT` outside the additional section or
//!   with a non-root owner;
//! - bytes left over after the last section.
//!
//! # Record types
//!
//! `A`, `AAAA`, `NS`, `CNAME`, `PTR`, `MX`, `TXT`, `SOA`, `SRV`, `CAA`,
//! `TLSA`, `DS`, `DNSKEY` and `RRSIG` are decoded into [`RData`] variants.
//! Every other type is kept as opaque bytes in [`RData::Unknown`]
//! (RFC 3597), so messages with new record types still round-trip.
//!
//! # Specifications
//!
//! - [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035): message format,
//!   name compression, the original record types.
//! - [RFC 3596](https://www.rfc-editor.org/rfc/rfc3596) (`AAAA`),
//!   [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782) (`SRV`),
//!   [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659) (`CAA`),
//!   [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) (`TLSA`),
//!   [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034) (`DS`, `DNSKEY`,
//!   `RRSIG`).
//! - [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891): EDNS(0).
//! - [RFC 3597](https://www.rfc-editor.org/rfc/rfc3597): unknown record
//!   types and which names may be compressed.
//! - [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181) §9: truncation.
//!
//! # Example
//!
//! ```
//! use std::net::Ipv4Addr;
//! use rune_dns_wire::{Message, Name, Question, RData, Record, RecordType, Rcode};
//!
//! // A client builds a query...
//! let name: Name = "abc123.oob.example".parse()?;
//! let query = Message::query(0x1234, Question::new(name, RecordType::A));
//! let wire = query.encode()?;
//!
//! // ...a server parses it and answers it...
//! let received = Message::decode(&wire)?;
//! let question = &received.questions[0];
//! assert_eq!(question.name.labels().next(), Some(&b"abc123"[..]));
//! let response = Message::response_to(&received)
//!     .with_authoritative(true)
//!     .with_answer(Record::new(
//!         question.name.clone(),
//!         60,
//!         RData::A(Ipv4Addr::new(192, 0, 2, 1)),
//!     ));
//! let wire = response.encode()?;
//!
//! // ...and the client reads the answer.
//! let answer = Message::decode(&wire)?;
//! assert_eq!(answer.header.id, 0x1234);
//! assert_eq!(answer.header.rcode, Rcode::NOERROR);
//! assert_eq!(answer.answers[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
//! # Ok::<(), rune_dns_wire::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod message;
mod name;
mod rdata;
mod types;
mod wire;

pub use message::{Edns, EdnsOption, Header, Message, Question, Record};
pub use name::{Labels, MAX_LABEL_LEN, MAX_NAME_LEN, Name};
pub use rdata::{Caa, Dnskey, Ds, Mx, RData, Rrsig, Soa, Srv, Tlsa};
pub use types::{Class, Opcode, Rcode, RecordType};

/// Largest DNS message: the 16-bit length prefix of DNS over TCP.
pub const MAX_MESSAGE_LEN: usize = 65_535;

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before the structure being read did.
    #[error("message truncated at offset {offset}")]
    Truncated {
        /// Offset at which more bytes were needed.
        offset: usize,
    },
    /// Bytes are left over after the last section.
    #[error("{len} trailing bytes after the last record, at offset {offset}")]
    TrailingData {
        /// Offset of the first unread byte.
        offset: usize,
        /// Number of unread bytes.
        len: usize,
    },
    /// A label uses the reserved `0x40` or `0x80` label type.
    #[error("reserved label type {byte:#04x} at offset {offset}")]
    BadLabelType {
        /// Offset of the label's length byte.
        offset: usize,
        /// The length byte.
        byte: u8,
    },
    /// A compression pointer does not point strictly backwards, or points
    /// into the header.
    #[error("invalid compression pointer at offset {offset} to offset {target}")]
    BadPointer {
        /// Offset of the pointer.
        offset: usize,
        /// Offset it points to.
        target: usize,
    },
    /// A name follows more compression pointers than any valid name needs.
    #[error("too many compression pointers in the name at offset {offset}")]
    TooManyPointers {
        /// Offset at which the name starts.
        offset: usize,
    },
    /// A label is longer than [`MAX_LABEL_LEN`] octets.
    #[error("label of {len} octets is longer than 63")]
    LabelTooLong {
        /// Length of the label.
        len: usize,
    },
    /// A name is longer than [`MAX_NAME_LEN`] octets in wire form.
    #[error("name is longer than 255 octets")]
    NameTooLong,
    /// A name in text form is malformed (empty label, bad escape).
    #[error("invalid name: {reason}")]
    InvalidName {
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A record type, class, opcode or response code in text form is
    /// neither a known mnemonic nor the generic `TYPE<n>`-style form.
    #[error("unknown {kind} mnemonic")]
    UnknownMnemonic {
        /// Which kind of value was being parsed.
        kind: &'static str,
    },
    /// RDATA does not match the layout of its record type.
    #[error("invalid {rtype} RDATA: {reason}")]
    InvalidRdata {
        /// The record type.
        rtype: RecordType,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A message has more than one `OPT` record, an `OPT` record outside the
    /// additional section, or one whose owner is not the root.
    #[error("invalid OPT record: {reason}")]
    InvalidOpt {
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A `<character-string>` is longer than 255 octets.
    #[error("character string of {len} octets is longer than 255")]
    CharacterStringTooLong {
        /// Length of the string.
        len: usize,
    },
    /// Encoded RDATA is longer than 65 535 octets.
    #[error("RDATA of {len} octets is longer than 65535")]
    RdataTooLong {
        /// Length of the RDATA.
        len: usize,
    },
    /// A header field holds a value that does not fit its wire field, such
    /// as an opcode above 15 or an `RCODE` above 15 without EDNS.
    #[error("{field} value {value} does not fit its wire field")]
    OutOfRange {
        /// The field.
        field: &'static str,
        /// The value.
        value: u32,
    },
    /// A section holds more than 65 535 entries.
    #[error("section has {count} entries, more than 65535")]
    TooManyRecords {
        /// Number of entries.
        count: usize,
    },
    /// The encoded message would be longer than the limit.
    #[error("message of at least {len} octets is longer than the limit of {max}")]
    MessageTooLong {
        /// Length reached when the limit was exceeded.
        len: usize,
        /// The limit.
        max: usize,
    },
}
