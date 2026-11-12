//! [`Writer`]: builds small `MaxMind` DB files (test fixtures, custom
//! enrichment tables).

use std::collections::{BTreeMap, HashMap};

use rune_cidr::Cidr;

use crate::Error;
use crate::metadata::METADATA_MARKER;
use crate::value::Value;

/// A binary trie of networks; leaves index into the writer's values.
#[derive(Debug, Clone)]
enum Trie {
    Empty,
    Data(usize),
    Node(Box<Self>, Box<Self>),
}

/// Builds a `MaxMind` DB file in memory.
///
/// Networks are inserted in order and a later insert wins where networks
/// overlap. In an IPv6 database, IPv4 networks are stored under `::/96`,
/// where readers look for them; no `::ffff:0:0/96` alias is written (this
/// crate's [`Reader`](crate::Reader) unwraps mapped addresses itself).
/// Identical records are stored once.
///
/// ```
/// use std::collections::BTreeMap;
/// use rune_geoip::{Reader, Value, Writer};
///
/// let mut writer = Writer::new("Test-ASN", 6);
/// let record = |asn: u32, org: &str| Value::Map(BTreeMap::from([
///     ("autonomous_system_number".to_owned(), Value::Uint32(asn)),
///     ("autonomous_system_organization".to_owned(), Value::from(org)),
/// ]));
/// writer.insert("1.1.1.0/24".parse()?, &record(13335, "CLOUDFLARENET"))?;
/// writer.insert("2606:4700::/32".parse()?, &record(13335, "CLOUDFLARENET"))?;
///
/// let reader = Reader::from_source(writer.to_bytes()?)?;
/// let asn = reader.asn("1.1.1.1".parse()?)?.unwrap();
/// assert_eq!(asn.autonomous_system_number, Some(13335));
/// assert_eq!(reader.networks().count(), 2);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct Writer {
    database_type: String,
    ip_version: u16,
    record_size: u16,
    languages: Vec<String>,
    description: BTreeMap<String, String>,
    build_epoch: u64,
    values: Vec<Vec<u8>>,
    value_index: HashMap<Vec<u8>, usize>,
    root: Trie,
}

impl Writer {
    /// A writer for an IPv4 (`ip_version` 4) or IPv6 (any other value)
    /// database, with 28-bit records.
    #[must_use]
    pub fn new(database_type: impl Into<String>, ip_version: u16) -> Self {
        Self {
            database_type: database_type.into(),
            ip_version: if ip_version == 4 { 4 } else { 6 },
            record_size: 28,
            languages: Vec::new(),
            description: BTreeMap::new(),
            build_epoch: 0,
            values: Vec::new(),
            value_index: HashMap::new(),
            root: Trie::Empty,
        }
    }

    /// Sets the record size: 24, 28 or 32 bits (others are ignored).
    #[must_use]
    pub const fn with_record_size(mut self, bits: u16) -> Self {
        if matches!(bits, 24 | 28 | 32) {
            self.record_size = bits;
        }
        self
    }

    /// Sets the locale codes listed in the metadata.
    #[must_use]
    pub fn with_languages<I, L>(mut self, languages: I) -> Self
    where
        I: IntoIterator<Item = L>,
        L: Into<String>,
    {
        self.languages = languages.into_iter().map(Into::into).collect();
        self
    }

    /// Adds a description in `locale`.
    #[must_use]
    pub fn with_description(mut self, locale: impl Into<String>, text: impl Into<String>) -> Self {
        self.description.insert(locale.into(), text.into());
        self
    }

    /// Sets the build time (Unix seconds).
    #[must_use]
    pub const fn with_build_epoch(mut self, epoch: u64) -> Self {
        self.build_epoch = epoch;
        self
    }

    /// Stores `data` for `network`, replacing what earlier inserts stored
    /// for the addresses it covers.
    ///
    /// # Errors
    ///
    /// [`Error::Build`] for an IPv6 network in an IPv4 database, or a
    /// value too large to encode.
    pub fn insert(&mut self, network: Cidr, data: &Value) -> Result<(), Error> {
        let (bits, len) = match network.trunc() {
            Cidr::V4(addr, len) if self.ip_version == 4 => (u128::from(addr) << 96, len),
            Cidr::V4(addr, len) => (u128::from(addr), len + 96),
            Cidr::V6(addr, len) if self.ip_version == 6 => (addr, len),
            Cidr::V6(..) => return Err(Error::Build("IPv6 network in an IPv4 database")),
        };
        let encoded = data.encode()?;
        let index = if let Some(&index) = self.value_index.get(&encoded) {
            index
        } else {
            self.values.push(encoded.clone());
            self.value_index.insert(encoded, self.values.len() - 1);
            self.values.len() - 1
        };
        let mut node = &mut self.root;
        for depth in 0..len {
            if !matches!(node, Trie::Node(..)) {
                let leaf = std::mem::replace(node, Trie::Empty);
                *node = Trie::Node(Box::new(leaf.clone()), Box::new(leaf));
            }
            let Trie::Node(left, right) = node else {
                return Err(Error::Build("trie invariant"));
            };
            node = if (bits >> (127 - depth)) & 1 == 1 {
                right
            } else {
                left
            };
        }
        *node = Trie::Data(index);
        Ok(())
    }

    /// Serializes the database.
    ///
    /// # Errors
    ///
    /// [`Error::Build`] when the tree or data section is too large for
    /// the record size.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        // The root must be a node, even for an empty or `/0` database.
        let root = match &self.root {
            Trie::Node(..) => self.root.clone(),
            leaf => Trie::Node(Box::new(leaf.clone()), Box::new(leaf.clone())),
        };
        // Number the nodes in breadth-first order.
        let mut nodes: Vec<&Trie> = vec![&root];
        let mut i = 0;
        while let Some(node) = nodes.get(i).copied() {
            if let Trie::Node(left, right) = node {
                for child in [left, right] {
                    if matches!(**child, Trie::Node(..)) {
                        nodes.push(child);
                    }
                }
            }
            i += 1;
        }
        let node_count = u32::try_from(nodes.len()).map_err(|_| Error::Build("too many nodes"))?;

        // Data section, with the offset of each value.
        let mut data = Vec::new();
        let mut offsets = Vec::with_capacity(self.values.len());
        for value in &self.values {
            offsets.push(data.len() as u64);
            data.extend_from_slice(value);
        }

        let max_record = (1u64 << self.record_size) - 1;
        let mut next_node = 1u64;
        let mut tree = Vec::with_capacity(nodes.len() * usize::from(self.record_size) / 4);
        for node in &nodes {
            let Trie::Node(left, right) = node else {
                return Err(Error::Build("trie invariant"));
            };
            let mut record = |child: &Trie| -> Result<u64, Error> {
                let value = match child {
                    Trie::Empty => u64::from(node_count),
                    Trie::Data(index) => {
                        let offset = offsets.get(*index).copied().unwrap_or(0);
                        u64::from(node_count) + 16 + offset
                    }
                    Trie::Node(..) => {
                        next_node += 1;
                        next_node - 1
                    }
                };
                if value > max_record {
                    return Err(Error::Build("database too large for the record size"));
                }
                Ok(value)
            };
            let (l, r) = (record(left)?, record(right)?);
            write_node(&mut tree, self.record_size, l, r);
        }

        let mut out = tree;
        out.extend_from_slice(&[0; 16]);
        out.extend_from_slice(&data);
        out.extend_from_slice(METADATA_MARKER);
        let metadata = Value::Map(BTreeMap::from([
            ("node_count".to_owned(), Value::Uint32(node_count)),
            ("record_size".to_owned(), Value::Uint16(self.record_size)),
            ("ip_version".to_owned(), Value::Uint16(self.ip_version)),
            (
                "database_type".to_owned(),
                Value::from(self.database_type.as_str()),
            ),
            (
                "languages".to_owned(),
                Value::Array(
                    self.languages
                        .iter()
                        .map(|l| Value::from(l.as_str()))
                        .collect(),
                ),
            ),
            ("binary_format_major_version".to_owned(), Value::Uint16(2)),
            ("binary_format_minor_version".to_owned(), Value::Uint16(0)),
            ("build_epoch".to_owned(), Value::Uint64(self.build_epoch)),
            (
                "description".to_owned(),
                Value::Map(
                    self.description
                        .iter()
                        .map(|(k, v)| (k.clone(), Value::from(v.as_str())))
                        .collect(),
                ),
            ),
        ]));
        out.extend_from_slice(&metadata.encode()?);
        Ok(out)
    }
}

/// Appends one node with records `left` and `right`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "records are checked against the record size before this"
)]
fn write_node(out: &mut Vec<u8>, record_size: u16, left: u64, right: u64) {
    let be = |n: u64, len: usize| n.to_be_bytes()[8 - len..].to_vec();
    match record_size {
        24 => {
            out.extend(be(left, 3));
            out.extend(be(right, 3));
        }
        28 => {
            out.extend(be(left & 0xff_ffff, 3));
            out.push((((left >> 24) as u8) << 4) | ((right >> 24) as u8 & 0x0f));
            out.extend(be(right & 0xff_ffff, 3));
        }
        _ => {
            out.extend(be(left, 4));
            out.extend(be(right, 4));
        }
    }
}
