//! [`Reader`]: the search tree, lookups and network iteration.

use std::net::IpAddr;

use rune_cidr::Cidr;

use crate::Error;
use crate::decode::Decoder;
use crate::metadata::Metadata;
use crate::records::{AsnRecord, CityRecord, CountryRecord};
use crate::value::Value;

/// Bytes of zeros between the search tree and the data section.
const SEPARATOR: usize = 16;

/// A network from the database and the data stored for it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Entry {
    /// The network the record covers. IPv4 networks of an IPv6 database
    /// are reported as IPv4.
    pub network: Cidr,
    /// The record.
    pub data: Value,
}

/// A `MaxMind` DB reader over a caller-supplied buffer.
///
/// `S` is anything that derefs to the database bytes: a `Vec<u8>` read
/// from disk, a `&[u8]`, a memory map. The reader does no I/O of its own,
/// validates the metadata up front and bounds-checks every later read, so
/// a corrupt or hostile file yields [`Error`]s, never a panic.
#[derive(Debug, Clone)]
pub struct Reader<S> {
    source: S,
    metadata: Metadata,
    data_start: usize,
    data_end: usize,
    /// Node reached after 96 zero bits in an IPv6 tree (`::/96`), and how
    /// many bits it took (less than 96 when the walk hit a record first).
    ipv4_start: u32,
    ipv4_start_depth: u8,
}

impl<S: AsRef<[u8]>> Reader<S> {
    /// Opens a database held in memory.
    ///
    /// # Errors
    ///
    /// [`Error::MissingMetadata`], [`Error::InvalidMetadata`] or
    /// [`Error::UnsupportedVersion`] when the metadata is absent or
    /// unusable, and [`Error::InvalidTree`] when the search tree does not
    /// fit before it.
    pub fn from_source(source: S) -> Result<Self, Error> {
        let buf = source.as_ref();
        let (metadata, marker_start) = Metadata::parse(buf)?;
        let data_start = usize::try_from(metadata.search_tree_size())
            .ok()
            .and_then(|size| size.checked_add(SEPARATOR))
            .filter(|&start| start <= marker_start)
            .ok_or(Error::InvalidTree(
                "search tree is larger than the file allows",
            ))?;
        let mut reader = Self {
            source,
            metadata,
            data_start,
            data_end: marker_start,
            ipv4_start: 0,
            ipv4_start_depth: 0,
        };
        if reader.metadata.ip_version == 6 {
            let mut node = 0;
            let mut depth = 0;
            while depth < 96 && node < reader.metadata.node_count {
                node = reader.record(node, 0)?;
                depth += 1;
            }
            reader.ipv4_start = node;
            reader.ipv4_start_depth = depth;
        }
        Ok(reader)
    }

    /// The database metadata.
    #[must_use]
    pub const fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// The underlying buffer.
    #[must_use]
    pub const fn source(&self) -> &S {
        &self.source
    }

    /// Reads one record of a node: `bit` 0 is the left record, 1 the right.
    fn record(&self, node: u32, bit: u8) -> Result<u32, Error> {
        let buf = self.source.as_ref();
        let node = node as usize;
        let bytes = |offset: usize, len: usize| {
            buf.get(offset..offset + len)
                .ok_or(Error::InvalidTree("node outside the search tree"))
        };
        let be = |b: &[u8]| b.iter().fold(0u32, |acc, &x| (acc << 8) | u32::from(x));
        match self.metadata.record_size {
            24 => bytes(node * 6 + usize::from(bit) * 3, 3).map(be),
            28 => {
                let b = bytes(node * 7, 7)?;
                Ok(if bit == 0 {
                    (u32::from(b[3] & 0xf0) << 20) | be(&b[..3])
                } else {
                    (u32::from(b[3] & 0x0f) << 24) | be(&b[4..])
                })
            }
            _ => bytes(node * 8 + usize::from(bit) * 4, 4).map(be),
        }
    }

    /// Decodes the data a terminal record points to.
    fn resolve(&self, record: u32) -> Result<Value, Error> {
        let offset = (record - self.metadata.node_count) as usize;
        let offset = offset
            .checked_sub(SEPARATOR)
            .ok_or(Error::InvalidTree("record points into the separator"))?;
        let data = &self.source.as_ref()[self.data_start..self.data_end];
        if offset >= data.len() {
            return Err(Error::InvalidTree("record points past the data section"));
        }
        Decoder::new(data).decode(offset)
    }

    /// Walks the tree for `ip`; returns the terminal record and the
    /// network it covers.
    fn find(&self, ip: IpAddr) -> Result<(u32, Cidr), Error> {
        let ip = rune_ip::canonical(ip);
        let node_count = self.metadata.node_count;
        let (bits, width, mut node, base) = match ip {
            IpAddr::V4(v4) if self.metadata.ip_version == 6 => (
                u128::from(u32::from(v4)),
                32u8,
                self.ipv4_start,
                self.ipv4_start_depth,
            ),
            IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32, 0, 0),
            IpAddr::V6(v6) if self.metadata.ip_version == 6 => (u128::from(v6), 128, 0, 0),
            IpAddr::V6(v6) => return Err(Error::Ipv6InIpv4Database(v6)),
        };
        let mut depth = 0u8;
        // An IPv4 walk that ends before `::/96` matches every IPv4 address.
        if base < 96 && width == 32 && self.metadata.ip_version == 6 {
            return Ok((node, Cidr::V4(0, 0)));
        }
        while node < node_count {
            if depth == width {
                return Err(Error::InvalidTree("search tree is deeper than the address"));
            }
            let bit = u8::from((bits >> (width - 1 - depth)) & 1 == 1);
            node = self.record(node, bit)?;
            depth += 1;
        }
        let cidr = match width {
            32 => Cidr::V4(u32::try_from(bits).unwrap_or(0), depth),
            _ => Cidr::V6(bits, depth),
        };
        Ok((node, cidr.trunc()))
    }

    /// Looks up an address.
    ///
    /// IPv4-mapped and IPv4-compatible IPv6 addresses are looked up as
    /// IPv4 ([`rune_ip::canonical`]). In an IPv6 database, IPv4 addresses
    /// are found under `::/96`, as the reference readers do.
    ///
    /// Returns `Ok(None)` when the database has no record for the address.
    ///
    /// # Errors
    ///
    /// [`Error::Ipv6InIpv4Database`] for an IPv6 address in an IPv4-only
    /// database, and [`Error::InvalidTree`] or [`Error::InvalidData`] when
    /// the file is corrupt.
    pub fn lookup(&self, ip: IpAddr) -> Result<Option<Entry>, Error> {
        let (record, network) = self.find(ip)?;
        if record == self.metadata.node_count {
            return Ok(None);
        }
        let data = self.resolve(record)?;
        Ok(Some(Entry { network, data }))
    }

    /// Looks up an address in a City database (GeoLite2/GeoIP2-City,
    /// DB-IP City): see [`CityRecord`].
    ///
    /// # Errors
    ///
    /// As [`lookup`](Self::lookup).
    pub fn city(&self, ip: IpAddr) -> Result<Option<CityRecord>, Error> {
        Ok(self.lookup(ip)?.map(|e| CityRecord::from_value(&e.data)))
    }

    /// Looks up an address in a Country (or City) database: see
    /// [`CountryRecord`].
    ///
    /// # Errors
    ///
    /// As [`lookup`](Self::lookup).
    pub fn country(&self, ip: IpAddr) -> Result<Option<CountryRecord>, Error> {
        Ok(self.lookup(ip)?.map(|e| CountryRecord::from_value(&e.data)))
    }

    /// Looks up an address in an ASN database (GeoLite2-ASN, DB-IP ASN):
    /// see [`AsnRecord`].
    ///
    /// # Errors
    ///
    /// As [`lookup`](Self::lookup).
    pub fn asn(&self, ip: IpAddr) -> Result<Option<AsnRecord>, Error> {
        Ok(self.lookup(ip)?.map(|e| AsnRecord::from_value(&e.data)))
    }

    /// Every network with data, in address order (IPv4 networks of an
    /// IPv6 database come first, as IPv4).
    ///
    /// The aliases `MaxMind` adds to IPv6 databases (`::ffff:0:0/96`,
    /// `2002::/16` and similar subtrees that point back to the IPv4 tree)
    /// are skipped, so each network is listed once. The iterator yields an
    /// error and stops when the tree is corrupt, including when it visits
    /// more nodes than a tree of `node_count` nodes can have.
    #[must_use]
    pub fn networks(&self) -> Networks<'_, S> {
        let width = if self.metadata.ip_version == 6 {
            128
        } else {
            32
        };
        Networks {
            reader: self,
            stack: vec![(0, 0, 0)],
            width,
            budget: u64::from(self.metadata.node_count) * 2 + 2,
            done: false,
        }
    }
}

/// Iterator over the networks of a database; see [`Reader::networks`].
#[derive(Debug)]
pub struct Networks<'a, S> {
    reader: &'a Reader<S>,
    /// `(node, network bits so far, depth)`.
    stack: Vec<(u32, u128, u8)>,
    width: u8,
    budget: u64,
    done: bool,
}

impl<S: AsRef<[u8]>> Networks<'_, S> {
    fn step(&mut self) -> Result<Option<Entry>, Error> {
        let reader = self.reader;
        let node_count = reader.metadata.node_count;
        while let Some((node, bits, depth)) = self.stack.pop() {
            if node < node_count {
                let aliased = self.width == 128
                    && depth > 0
                    && node == reader.ipv4_start
                    && reader.ipv4_start_depth == 96
                    && !(depth == 96 && bits == 0);
                if aliased {
                    continue;
                }
                self.budget = self.budget.checked_sub(1).ok_or(Error::InvalidTree(
                    "search tree has cycles or shared subtrees",
                ))?;
                if depth == self.width {
                    return Err(Error::InvalidTree("search tree is deeper than the address"));
                }
                let shift = self.width - 1 - depth;
                let right = reader.record(node, 1)?;
                let left = reader.record(node, 0)?;
                self.stack.push((right, bits | (1u128 << shift), depth + 1));
                self.stack.push((left, bits, depth + 1));
                continue;
            }
            if node == node_count {
                continue;
            }
            let network = if self.width == 32 {
                Cidr::V4(u32::try_from(bits).unwrap_or(0), depth)
            } else if depth >= 96 && bits >> 32 == 0 {
                Cidr::V4(u32::try_from(bits).unwrap_or(0), depth - 96)
            } else {
                Cidr::V6(bits, depth)
            };
            let data = reader.resolve(node)?;
            return Ok(Some(Entry { network, data }));
        }
        Ok(None)
    }
}

impl<S: AsRef<[u8]>> Iterator for Networks<'_, S> {
    type Item = Result<Entry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let item = self.step().transpose();
        if !matches!(item, Some(Ok(_))) {
            self.done = true;
        }
        item
    }
}

impl<S: AsRef<[u8]>> std::iter::FusedIterator for Networks<'_, S> {}
