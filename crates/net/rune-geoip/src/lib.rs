//! Pure-Rust [MaxMind DB] (MMDB) reader for GeoLite2/GeoIP2 and DB-IP
//! databases: offline IP geolocation and ASN data.
//!
//! - [`Reader`] opens a database held in any `AsRef<[u8]>` buffer (a
//!   `Vec<u8>` you read, a memory map), validates its [`Metadata`], and
//!   answers [`lookup`](Reader::lookup)s with the matching network and its
//!   decoded [`Value`]. [`Reader::networks`] walks every network.
//! - Typed views for the common record shapes: [`CityRecord`],
//!   [`CountryRecord`] and [`AsnRecord`] (`MaxMind` GeoIP2/GeoLite2 and the
//!   DB-IP "lite" databases share them).
//! - [`Writer`] builds small databases: test fixtures, or custom
//!   enrichment tables any MMDB reader can load.
//!
//! The crate ships no data (the datasets are licensed; download them from
//! `MaxMind` or DB-IP) and does no I/O. Every read of the file is
//! bounds-checked and decoding is depth- and size-limited, so a corrupt or
//! hostile database yields an [`Error`], not a panic.
//!
//! Addresses go through [`rune_ip::canonical`] first, so IPv4-mapped IPv6
//! addresses are looked up as IPv4; networks are [`rune_cidr::Cidr`]s.
//!
//! [MaxMind DB]: https://maxmind.github.io/`MaxMind`-DB/
//!
//! # Example
//!
//! ```
//! use std::collections::BTreeMap;
//! use rune_geoip::{Reader, Value, Writer};
//!
//! // Normally `std::fs::read("GeoLite2-Country.mmdb")?`.
//! let map = |pairs: &[(&str, Value)]| Value::Map(
//!     pairs.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect::<BTreeMap<_, _>>(),
//! );
//! let mut writer = Writer::new("GeoLite2-Country", 6).with_languages(["en"]);
//! writer.insert("81.2.69.0/24".parse()?, &map(&[
//!     ("country", map(&[
//!         ("iso_code", Value::from("GB")),
//!         ("names", map(&[("en", Value::from("United Kingdom"))])),
//!     ])),
//!     ("continent", map(&[("code", Value::from("EU"))])),
//! ]))?;
//! let bytes = writer.to_bytes()?;
//!
//! let reader = Reader::from_source(bytes)?;
//! assert_eq!(reader.metadata().database_type, "GeoLite2-Country");
//!
//! let entry = reader.lookup("81.2.69.160".parse()?)?.unwrap();
//! assert_eq!(entry.network.to_string(), "81.2.69.0/24");
//! assert_eq!(entry.data.path(&["country", "iso_code"]).and_then(Value::as_str), Some("GB"));
//!
//! let country = reader.country("::ffff:81.2.69.1".parse()?)?.unwrap();
//! assert_eq!(country.country.names.en(), Some("United Kingdom"));
//! assert_eq!(country.continent.code.as_deref(), Some("EU"));
//!
//! assert!(reader.lookup("8.8.8.8".parse()?)?.is_none());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod decode;
mod encode;
mod metadata;
mod reader;
mod records;
mod value;
mod writer;

use std::net::Ipv6Addr;

pub use metadata::Metadata;
pub use reader::{Entry, Networks, Reader};
pub use records::{
    AsnRecord, City, CityRecord, Continent, Country, CountryRecord, Location, Names, Subdivision,
    Traits,
};
pub use value::Value;
pub use writer::Writer;

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The file has no metadata marker in its last 128 KiB: not a `MaxMind`
    /// DB file.
    #[error("not a MaxMind DB file: metadata marker not found")]
    MissingMetadata,
    /// A required metadata field is missing or invalid.
    #[error("invalid metadata field: {0}")]
    InvalidMetadata(&'static str),
    /// The format major version is not 2.
    #[error("unsupported MaxMind DB format version {0}")]
    UnsupportedVersion(u16),
    /// The search tree is corrupt.
    #[error("invalid search tree: {0}")]
    InvalidTree(&'static str),
    /// A data-section value is corrupt.
    #[error("invalid data at offset {offset}: {reason}")]
    InvalidData {
        /// Offset of the bad value in its section.
        offset: usize,
        /// What was wrong.
        reason: &'static str,
    },
    /// An IPv6 address was looked up in an IPv4-only database.
    #[error("cannot look up IPv6 address {0} in an IPv4-only database")]
    Ipv6InIpv4Database(Ipv6Addr),
    /// [`Writer`] or [`Value::encode`] could not build the output.
    #[error("cannot build database: {0}")]
    Build(&'static str),
}
