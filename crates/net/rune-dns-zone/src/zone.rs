//! A parsed zone and its master-file writer.

use core::fmt;
use core::str::FromStr;

use rune_dns_wire::{Name, RData, Record, Soa};

use crate::Error;
use crate::parser::{ParseOptions, parse};
use crate::present::{absolute, rdata_to_text};
use crate::types::record_type_name;

/// The records of a zone, in file (or transfer) order.
///
/// `Display` (and [`Zone::to_master_file`]) writes RFC 1035 master-file
/// text: an `$ORIGIN` line for the zone apex, then one record per line with
/// an explicit TTL and class. Owners inside the origin are written relative
/// to it, RDATA names absolute. Parsing that text gives back the same
/// records.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Zone {
    /// The records.
    pub records: Vec<Record>,
}

impl Zone {
    /// A zone holding `records`.
    #[must_use]
    pub const fn new(records: Vec<Record>) -> Self {
        Self { records }
    }

    /// The first `SOA` record, if any.
    #[must_use]
    pub fn soa_record(&self) -> Option<&Record> {
        self.records
            .iter()
            .find(|record| matches!(record.data, RData::Soa(_)))
    }

    /// The data of the first `SOA` record.
    #[must_use]
    pub fn soa(&self) -> Option<&Soa> {
        match &self.soa_record()?.data {
            RData::Soa(soa) => Some(soa),
            _ => None,
        }
    }

    /// The zone apex: the owner of the first `SOA` record.
    #[must_use]
    pub fn origin(&self) -> Option<&Name> {
        self.soa_record().map(|record| &record.name)
    }

    /// The zone as master-file text.
    #[must_use]
    pub fn to_master_file(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Zone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let origin = self.origin();
        if let Some(origin) = origin {
            writeln!(f, "$ORIGIN {}", absolute(origin))?;
        }
        for record in &self.records {
            writeln!(
                f,
                "{}\t{}\t{}\t{}\t{}",
                owner_text(&record.name, origin),
                record.ttl,
                record.class,
                record_type_name(record.rtype()),
                rdata_to_text(&record.data)
            )?;
        }
        Ok(())
    }
}

impl FromStr for Zone {
    type Err = Error;

    /// Parses with [`ParseOptions::default`].
    fn from_str(text: &str) -> Result<Self, Error> {
        parse(text, &ParseOptions::default())
    }
}

/// The owner relative to `origin` when it ends in exactly the origin's
/// labels (case included, so the text parses back to the same name),
/// otherwise absolute.
fn owner_text(name: &Name, origin: Option<&Name>) -> String {
    let Some(origin) = origin else {
        return absolute(name);
    };
    let labels: Vec<&[u8]> = name.labels().collect();
    let suffix: Vec<&[u8]> = origin.labels().collect();
    let Some(split) = labels.len().checked_sub(suffix.len()) else {
        return absolute(name);
    };
    let (prefix, tail) = labels.split_at(split);
    if tail != suffix.as_slice() {
        return absolute(name);
    }
    if prefix.is_empty() {
        return "@".to_owned();
    }
    Name::from_labels(prefix).map_or_else(|_| absolute(name), |relative| relative.to_string())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    #[test]
    fn writes_relative_owners() {
        let origin = name("Example.com");
        assert_eq!(owner_text(&name("Example.com"), Some(&origin)), "@");
        assert_eq!(owner_text(&name("a.b.Example.com"), Some(&origin)), "a.b");
        // A different case is not the same text: written absolute.
        assert_eq!(
            owner_text(&name("a.example.com"), Some(&origin)),
            "a.example.com."
        );
        assert_eq!(owner_text(&name("other.net"), Some(&origin)), "other.net.");
        assert_eq!(owner_text(&name("a.b"), None), "a.b.");
        assert_eq!(owner_text(&name("@.$x"), None), "\\@.\\$x.");
    }

    #[test]
    fn zone_without_soa() {
        let zone = Zone::new(vec![Record::new(
            name("host.example"),
            60,
            RData::A(Ipv4Addr::LOCALHOST),
        )]);
        assert_eq!(zone.origin(), None);
        assert_eq!(zone.soa(), None);
        let text = zone.to_master_file();
        assert_eq!(text, "host.example.\t60\tIN\tA\t127.0.0.1\n");
        assert_eq!(text.parse::<Zone>().unwrap(), zone);
        assert_eq!("".parse::<Zone>().unwrap(), Zone::default());
    }
}
