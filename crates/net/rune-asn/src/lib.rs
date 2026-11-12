//! IP→ASN and ASN→prefix lookup over BGP and RIR datasets.
//!
//! Recon and enrichment tools want to know which autonomous system
//! announces an address, and which prefixes an AS announces. `rune-asn`
//! answers both from routing data the caller supplies:
//!
//! - **Routes** (prefix → origin AS): CAIDA `RouteViews` `pfx2as`
//!   ([`parse_pfx2as`]), RIPE RIS `riswhoisdump` ([`parse_riswhois`]),
//!   `bgpdump -m` output of any MRT RIB or update file ([`parse_bgpdump`]),
//!   and iptoasn.com range tables ([`parse_ip2asn`]).
//! - **AS metadata**: RIR delegated statistics ([`parse_delegated`]) for
//!   registry, country and allocation date, and AS-name lists
//!   ([`parse_asnames`]).
//!
//! The core is sans-I/O and ships no data: download (and decompress) the
//! files yourself, pass their text to a parser, and load the records into
//! an [`AsnDb`]. Lookups use longest-prefix match (built on
//! [`rune_cidr::Cidr`]), so a more specific announcement wins, as in BGP.
//!
//! # Example
//!
//! ```
//! use rune_asn::{parse_asnames, parse_pfx2as, Asn, AsnDb};
//!
//! // Normally the text of routeviews-rv2-YYYYMMDD-HHMM.pfx2as.
//! let pfx2as = "1.1.1.0\t24\t13335\n8.0.0.0\t9\t3356\n8.8.8.0\t24\t15169\n";
//! let mut db = AsnDb::new();
//! db.try_extend(parse_pfx2as(pfx2as))?;
//! for name in parse_asnames("15169 GOOGLE, US\n") {
//!     db.insert_name(name?);
//! }
//!
//! let hit = db.lookup("8.8.8.8".parse().unwrap()).unwrap();
//! assert_eq!(hit.prefix.to_string(), "8.8.8.0/24");
//! assert_eq!(hit.origin(), Some(Asn::new(15169)));
//! assert_eq!(db.info(Asn::new(15169)).unwrap().name, Some("GOOGLE"));
//!
//! // ASN → announced prefixes.
//! let prefixes: Vec<String> = db.prefixes(Asn::new(3356)).map(|p| p.to_string()).collect();
//! assert_eq!(prefixes, ["8.0.0.0/9"]);
//! # Ok::<(), rune_asn::Error>(())
//! ```
//!
//! ASNs follow [RFC 6793] (4-byte) and [RFC 5396] (textual notation);
//! special ranges follow [RFC 6996], [RFC 5398] and [RFC 7607].
//!
//! [RFC 6793]: https://www.rfc-editor.org/rfc/rfc6793
//! [RFC 5396]: https://www.rfc-editor.org/rfc/rfc5396
//! [RFC 6996]: https://www.rfc-editor.org/rfc/rfc6996
//! [RFC 5398]: https://www.rfc-editor.org/rfc/rfc5398
//! [RFC 7607]: https://www.rfc-editor.org/rfc/rfc7607

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod asn;
mod db;
mod parse;
mod table;

pub use asn::Asn;
pub use db::{AsnDb, AsnInfo, Match};
pub use parse::{
    AsName, Delegation, RangeRecord, Resource, Route, parse_asnames, parse_bgpdump,
    parse_delegated, parse_ip2asn, parse_pfx2as, parse_riswhois,
};

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A string is not a valid AS number.
    #[error("invalid AS number")]
    InvalidAsn,
    /// A dataset line could not be parsed.
    #[error("line {line}: {reason}")]
    Parse {
        /// 1-based line number in the input text.
        line: usize,
        /// What was wrong with the line.
        reason: &'static str,
    },
}
