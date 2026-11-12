//! Database metadata (spec, "Database Metadata").

use std::collections::BTreeMap;

use crate::Error;
use crate::decode::Decoder;
use crate::value::Value;

/// The marker that precedes the metadata map.
pub const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

/// How far from the end of the file the metadata marker may start.
const METADATA_WINDOW: usize = 128 * 1024;

/// The metadata section of a database.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Metadata {
    /// Number of nodes in the search tree.
    pub node_count: u32,
    /// Bits per search-tree record: 24, 28 or 32.
    pub record_size: u16,
    /// 4 for an IPv4-only tree, 6 for an IPv6 tree (which may hold IPv4
    /// networks under `::/96`).
    pub ip_version: u16,
    /// Database type, such as `GeoLite2-City` or `DBIP-ASN-Lite (compat=GeoLite2-ASN)`.
    pub database_type: String,
    /// Locale codes the records have names for.
    pub languages: Vec<String>,
    /// Format major version (always 2).
    pub binary_format_major_version: u16,
    /// Format minor version.
    pub binary_format_minor_version: u16,
    /// Build time, in seconds since the Unix epoch.
    pub build_epoch: u64,
    /// Description by locale code.
    pub description: BTreeMap<String, String>,
}

/// Finds the start of the metadata map: just past the last marker in the
/// final 128 KiB. Returns `(marker_start, metadata_start)`.
pub fn locate(buf: &[u8]) -> Result<(usize, usize), Error> {
    let window_start = buf.len().saturating_sub(METADATA_WINDOW);
    buf[window_start..]
        .windows(METADATA_MARKER.len())
        .rposition(|w| w == METADATA_MARKER)
        .map(|i| {
            let start = window_start + i;
            (start, start + METADATA_MARKER.len())
        })
        .ok_or(Error::MissingMetadata)
}

fn uint<T: TryFrom<u64>>(map: &BTreeMap<String, Value>, key: &'static str) -> Result<T, Error> {
    map.get(key)
        .ok_or(Error::InvalidMetadata(key))?
        .as_u64()
        .and_then(|n| T::try_from(n).ok())
        .ok_or(Error::InvalidMetadata(key))
}

impl Metadata {
    /// Decodes and validates the metadata map at the end of `buf`.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), Error> {
        let (marker_start, start) = locate(buf)?;
        let value = Decoder::new(&buf[start..]).decode(0)?;
        let Value::Map(map) = value else {
            return Err(Error::InvalidMetadata("metadata is not a map"));
        };
        let strings = |key: &str| -> Vec<String> {
            map.get(key)
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let metadata = Self {
            node_count: uint(&map, "node_count")?,
            record_size: uint(&map, "record_size")?,
            ip_version: uint(&map, "ip_version")?,
            database_type: map
                .get("database_type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            languages: strings("languages"),
            binary_format_major_version: uint(&map, "binary_format_major_version")?,
            binary_format_minor_version: uint(&map, "binary_format_minor_version")
                .unwrap_or_default(),
            build_epoch: uint(&map, "build_epoch").unwrap_or_default(),
            description: map
                .get("description")
                .and_then(Value::as_map)
                .map(|d| {
                    d.iter()
                        .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                        .collect()
                })
                .unwrap_or_default(),
        };
        if metadata.binary_format_major_version != 2 {
            return Err(Error::UnsupportedVersion(
                metadata.binary_format_major_version,
            ));
        }
        if !matches!(metadata.record_size, 24 | 28 | 32) {
            return Err(Error::InvalidMetadata("record_size"));
        }
        if !matches!(metadata.ip_version, 4 | 6) {
            return Err(Error::InvalidMetadata("ip_version"));
        }
        Ok((metadata, marker_start))
    }

    /// Size of the search tree in bytes.
    #[must_use]
    pub fn search_tree_size(&self) -> u64 {
        u64::from(self.node_count) * u64::from(self.record_size) / 4
    }
}
