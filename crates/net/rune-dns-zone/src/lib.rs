//! Sans-I/O DNS zone files and zone transfers.
//!
//! `rune-dns-zone` reads and writes the RFC 1035 §5 master-file format and
//! reassembles AXFR and IXFR response streams, on top of the message codec
//! in [`rune_dns_wire`]. It does no I/O: hand it text and DNS messages, and
//! bring your own files and sockets.
//!
//! - [`parse`] turns zone-file text into a [`Zone`]: `$ORIGIN`, `$TTL`,
//!   relative and absolute names, `@`, blank owners, parentheses, comments,
//!   BIND-style TTL units (`1h30m`) and the RFC 3597 `\# <len> <hex>`
//!   generic form. [`parse_with_includes`] also follows `$INCLUDE` through a
//!   loader you supply.
//! - [`Zone::to_master_file`] (and [`Zone`]'s `Display`) writes it back, so
//!   that parsing the output gives the same records.
//! - [`Axfr`] and [`Ixfr`] validate and reassemble zone-transfer responses
//!   that span any number of messages; [`TcpFrames`] splits a DNS-over-TCP
//!   byte stream into those messages; [`axfr_query`] and [`ixfr_query`]
//!   build the requests.
//!
//! # Record types
//!
//! Every type [`rune_dns_wire::RData`] models is parsed into its typed
//! variant: `A`, `AAAA`, `NS`, `CNAME`, `PTR`, `MX`, `TXT`, `SOA`, `SRV`,
//! `CAA`, `TLSA`, `DS`, `DNSKEY`, `RRSIG`. These are also understood in
//! presentation form and kept as RFC 3597 opaque RDATA
//! ([`RData::Unknown`](rune_dns_wire::RData::Unknown)): `HINFO`, `MINFO`,
//! `RP`, `AFSDB`, `LOC`, `KX`, `CERT`, `DNAME`, `NAPTR`, `SSHFP`, `NSEC`,
//! `NSEC3`, `NSEC3PARAM`, `SMIMEA`, `CDS`, `CDNSKEY`, `OPENPGPKEY`,
//! `ZONEMD`, `SPF` and `URI`. Any other type is accepted in the generic
//! `\#` form, and written back in it.
//!
//! # Untrusted input
//!
//! Zone files and transfer streams come from hosts you may not control. The
//! parsers never panic, bound `$INCLUDE` nesting, and cap the number of
//! records ([`ParseOptions::with_max_records`], [`Axfr::with_max_records`]),
//! so a hostile server cannot make a transfer grow without bound.
//!
//! # Specifications
//!
//! - [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) §5: master files.
//! - [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308) §4: `$TTL`.
//! - [RFC 3597](https://www.rfc-editor.org/rfc/rfc3597) §5: generic RDATA.
//! - [RFC 5936](https://www.rfc-editor.org/rfc/rfc5936): AXFR.
//! - [RFC 1995](https://www.rfc-editor.org/rfc/rfc1995): IXFR.
//! - [RFC 1876](https://www.rfc-editor.org/rfc/rfc1876) (`LOC`),
//!   [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034) (`NSEC`),
//!   [RFC 5155](https://www.rfc-editor.org/rfc/rfc5155) (`NSEC3`),
//!   [RFC 4398](https://www.rfc-editor.org/rfc/rfc4398) (`CERT`),
//!   [RFC 3403](https://www.rfc-editor.org/rfc/rfc3403) (`NAPTR`),
//!   [RFC 7553](https://www.rfc-editor.org/rfc/rfc7553) (`URI`).
//!
//! # Example
//!
//! ```
//! use rune_dns_wire::{Name, RData, RecordType};
//! use rune_dns_zone::{ParseOptions, parse};
//!
//! let text = r#"
//! $ORIGIN example.com.
//! $TTL 1h
//! @       IN SOA ns1 hostmaster (
//!                2026111101 ; serial
//!                2h 15m 2w 5m )
//!         IN NS  ns1
//!         IN MX  10 mail
//! ns1     IN A   192.0.2.53
//! mail 300 IN A  192.0.2.25
//! ftp     IN CNAME @
//! www     IN A    192.0.2.80
//!         IN AAAA 2001:db8::80 ; blank owner: www again
//! "#;
//! let zone = parse(text, &ParseOptions::default())?;
//! assert_eq!(zone.records.len(), 8);
//! assert_eq!(zone.records[7].name.to_string(), "www.example.com");
//! assert_eq!(zone.origin(), Some(&"example.com".parse::<Name>()?));
//! assert_eq!(zone.soa().map(|soa| soa.serial), Some(2_026_111_101));
//!
//! let mail = &zone.records[4];
//! assert_eq!((mail.ttl, mail.rtype()), (300, RecordType::A));
//! assert_eq!(zone.records[5].data, RData::Cname("example.com".parse()?));
//!
//! // Writing it back and parsing the result gives the same records.
//! let written = zone.to_master_file();
//! assert_eq!(parse(&written, &ParseOptions::default())?, zone);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod lexer;
mod parser;
mod present;
mod transfer;
mod types;
mod zone;

pub use parser::{ParseOptions, parse, parse_with_includes};
pub use present::rdata_to_text;
pub use transfer::{Axfr, Ixfr, IxfrDiff, IxfrOutcome, Status, TcpFrames, axfr_query, ixfr_query};
pub use types::{parse_record_type, record_type_name};
pub use zone::Zone;

use rune_dns_wire::{Rcode, RecordType};

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The zone file is malformed at `line`.
    #[error("line {line}: {reason}")]
    Syntax {
        /// 1-based line number.
        line: usize,
        /// What is wrong.
        reason: &'static str,
    },
    /// A name, RDATA or record is invalid at `line`, as reported by
    /// `rune-dns-wire`.
    #[error("line {line}: {source}")]
    Wire {
        /// 1-based line number.
        line: usize,
        /// The underlying error.
        source: rune_dns_wire::Error,
    },
    /// A record type mnemonic is not known; write the type as `TYPE<n>`.
    #[error("line {line}: unknown record type {text:?}")]
    UnknownType {
        /// 1-based line number.
        line: usize,
        /// The mnemonic.
        text: String,
    },
    /// The type has no presentation-format parser here; write its RDATA in
    /// the RFC 3597 `\# <length> <hex>` form.
    #[error("line {line}: no presentation format for {rtype}; use the \\# generic form")]
    UnsupportedType {
        /// 1-based line number.
        line: usize,
        /// The record type.
        rtype: RecordType,
    },
    /// A `$` directive other than `$ORIGIN`, `$TTL` and `$INCLUDE`.
    #[error("line {line}: unsupported directive {directive}")]
    UnsupportedDirective {
        /// 1-based line number.
        line: usize,
        /// The directive, `$` included.
        directive: String,
    },
    /// A relative name appears before any origin is known.
    #[error("line {line}: relative name without an origin")]
    NoOrigin {
        /// 1-based line number.
        line: usize,
    },
    /// A record has no TTL, and neither `$TTL`, an earlier record nor
    /// [`ParseOptions::default_ttl`] supplies one.
    #[error("line {line}: record without a TTL and no default")]
    NoTtl {
        /// 1-based line number.
        line: usize,
    },
    /// A record with a blank owner field is the first record.
    #[error("line {line}: blank owner with no previous owner")]
    NoOwner {
        /// 1-based line number.
        line: usize,
    },
    /// An `$INCLUDE` could not be read, or no loader was configured.
    #[error("line {line}: cannot include {path:?}: {reason}")]
    Include {
        /// 1-based line number of the directive.
        line: usize,
        /// The path as written.
        path: String,
        /// Why it could not be read.
        reason: String,
    },
    /// `$INCLUDE`s are nested deeper than [`ParseOptions::max_include_depth`].
    #[error("line {line}: $INCLUDE nested too deeply")]
    IncludeDepth {
        /// 1-based line number of the directive.
        line: usize,
    },
    /// An error inside an included file.
    #[error("in {path:?}: {source}")]
    InInclude {
        /// The path as written in the `$INCLUDE`.
        path: String,
        /// The error, with a line number inside that file.
        source: Box<Self>,
    },
    /// More records than the configured maximum.
    #[error("more than {max} records")]
    TooManyRecords {
        /// The limit.
        max: usize,
    },
    /// A transfer message could not be decoded.
    #[error("invalid transfer message: {0}")]
    Decode(rune_dns_wire::Error),
    /// The server answered the transfer with an error code (`REFUSED` and
    /// `NOTAUTH` mean "transfers are not allowed").
    #[error("transfer refused with {0}")]
    Rcode(Rcode),
    /// A transfer response breaks RFC 5936 or RFC 1995.
    #[error("invalid transfer: {reason}")]
    Transfer {
        /// What is wrong.
        reason: &'static str,
    },
}
