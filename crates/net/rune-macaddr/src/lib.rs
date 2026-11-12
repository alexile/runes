//! MAC address (EUI-48 / EUI-64) parsing, formatting and classification,
//! with OUI vendor lookup over IEEE registry data the caller supplies.
//!
//! - [`MacAddr`] and [`Eui64`] parse colon (`00:1b:63:84:45:e6`, also with
//!   single-digit octets), hyphen (`00-1B-63-84-45-E6`), Cisco dot
//!   (`001b.6384.45e6`) and bare-hex (`001b638445e6`) notation, and format
//!   in any of them ([`Notation`], [`Case`]).
//! - Classification: unicast/multicast (I/G bit), universal/local (U/L
//!   bit), broadcast, nil; EUI-48 ↔ EUI-64 and modified EUI-64 / IPv6
//!   SLAAC link-local conversion ([RFC 4291, Appendix A]).
//! - [`OuiDb`]: longest-prefix vendor lookup over MA-L (`/24`), MA-M
//!   (`/28`), MA-S/IAB (`/36`) and CID assignments, loaded from the IEEE
//!   RA CSV or text files or a Wireshark `manuf` file ([`parse_registry`]).
//! - [`well_known`]: a small built-in table of protocol-defined ranges
//!   (broadcast, IEEE 802.1 reserved group addresses, IPv4/IPv6/MPLS
//!   multicast, VRRP, IANA), written from the standards themselves.
//!
//! # Vendor data is not embedded
//!
//! The IEEE Registration Authority publishes the registry listings
//! (<https://standards-oui.ieee.org/oui/oui.csv>, `mam.csv`, `oui36.csv`,
//! `iab.csv`, `cid.csv`) for download but states no licence for
//! redistributing them, so this crate does not ship a copy. Download the
//! files you need (or use the `ieee-data` package of your distribution, or
//! Wireshark's `manuf`) and pass their text to [`OuiDb::load`]; refreshing
//! is a matter of loading a newer file. The full set of registries is a few
//! megabytes of CSV and some tens of thousands of assignments, so it is
//! loaded at run time rather than compiled in.
//!
//! # Example
//!
//! ```
//! use rune_macaddr::{Case, MacAddr, Notation, OuiDb};
//!
//! let mac: MacAddr = "001B.6384.45E6".parse()?;
//! assert_eq!(mac.to_string(), "00:1b:63:84:45:e6");
//! assert_eq!(mac.format(Notation::Hyphen, Case::Upper), "00-1B-63-84-45-E6");
//! assert!(mac.is_unicast() && mac.is_universal());
//! assert_eq!(mac.to_ipv6_link_local().to_string(), "fe80::21b:63ff:fe84:45e6");
//!
//! // Normally the text of oui.csv from the IEEE RA.
//! let csv = "Registry,Assignment,Organization Name,Organization Address\n\
//!            MA-L,001B63,\"Apple, Inc.\",1 Infinite Loop Cupertino CA US 95014\n";
//! let mut db = OuiDb::new();
//! db.load(csv)?;
//! assert_eq!(db.vendor(&mac), Some("Apple, Inc."));
//! # Ok::<(), rune_macaddr::Error>(())
//! ```
//!
//! [RFC 4291, Appendix A]: https://www.rfc-editor.org/rfc/rfc4291#appendix-A

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod mac;
mod oui;
mod parse;
mod wellknown;

pub use mac::{Case, Eui64, MacAddr, Notation};
pub use oui::{OuiDb, OuiPrefix, OuiRecord, Registry};
pub use parse::{
    Records, RegistryFormat, parse_ieee_csv, parse_ieee_txt, parse_manuf, parse_registry,
};
pub use wellknown::{WELL_KNOWN, WellKnown, well_known};

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A string is not a valid EUI-48 or EUI-64 address.
    #[error("invalid {kind} address: {reason}")]
    InvalidAddress {
        /// `"EUI-48"` or `"EUI-64"`.
        kind: &'static str,
        /// What was wrong.
        reason: &'static str,
    },
    /// A string or value is not a valid address prefix or registry name.
    #[error("invalid prefix: {0}")]
    InvalidPrefix(&'static str),
    /// A registry file line could not be parsed.
    #[error("line {line}: {reason}")]
    Parse {
        /// 1-based line number in the input text.
        line: usize,
        /// What was wrong with the line.
        reason: String,
    },
}
