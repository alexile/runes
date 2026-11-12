//! The [`AsnDb`] lookup table.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use rune_cidr::Cidr;

use crate::parse::{AsName, Delegation, RangeRecord, Resource, Route};
use crate::table::PrefixTable;
use crate::{Asn, Error};

/// The routing entry that matched a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Match<'a> {
    /// The matching announced prefix.
    pub prefix: Cidr,
    /// Its origin ASes, sorted (more than one for a multi-origin prefix).
    pub origins: &'a [Asn],
}

impl Match<'_> {
    /// The lowest-numbered origin AS. Every stored prefix has at least one.
    #[must_use]
    pub const fn origin(&self) -> Option<Asn> {
        self.origins.first().copied()
    }
}

/// What the loaded datasets say about one AS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AsnInfo<'a> {
    /// The AS.
    pub asn: Asn,
    /// Name from an AS-name list or iptoasn description.
    pub name: Option<&'a str>,
    /// Holder's country: the RIR delegation's, else the AS-name list's.
    pub country: Option<&'a str>,
    /// Delegating registry (`arin`, `ripencc`, …).
    pub registry: Option<&'a str>,
    /// Delegation status (`allocated`, `assigned`, …).
    pub status: Option<&'a str>,
    /// Delegation date as `YYYYMMDD`.
    pub date: Option<&'a str>,
}

#[derive(Debug, Clone, Default)]
struct NameEntry {
    name: Option<String>,
    country: Option<String>,
}

#[derive(Debug, Clone)]
struct RirEntry {
    last: u32,
    registry: String,
    country: Option<String>,
    status: String,
    date: Option<String>,
}

/// IP→ASN and ASN→prefix lookup table, filled from parsed datasets.
///
/// Lookups use longest-prefix match over the announced prefixes, so a more
/// specific announcement wins over its covering aggregate, as it does in
/// BGP forwarding. IPv4-mapped and IPv4-compatible IPv6 addresses are
/// unwrapped first ([`rune_ip::canonical`]).
///
/// ```
/// use rune_asn::{parse_pfx2as, Asn, AsnDb};
///
/// let mut db = AsnDb::new();
/// db.try_extend(parse_pfx2as("104.16.0.0\t12\t13335\n104.18.0.0\t20\t209242\n"))?;
///
/// let hit = db.lookup("104.18.1.1".parse().unwrap()).unwrap();
/// assert_eq!(hit.prefix.to_string(), "104.18.0.0/20");
/// assert_eq!(db.origin("::ffff:104.17.0.1".parse().unwrap()), Some(Asn::new(13335)));
/// assert_eq!(db.prefixes(Asn::new(13335)).count(), 1);
/// # Ok::<(), rune_asn::Error>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct AsnDb {
    routes: PrefixTable<Vec<Asn>>,
    by_asn: HashMap<Asn, BTreeSet<Cidr>>,
    names: HashMap<Asn, NameEntry>,
    /// RIR ASN blocks keyed by their first ASN.
    rir: BTreeMap<u32, RirEntry>,
}

impl AsnDb {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `origin` as an origin of `prefix` (host bits are cleared).
    /// Adding the same pair twice is a no-op.
    pub fn insert_origin(&mut self, prefix: Cidr, origin: Asn) {
        let prefix = prefix.trunc();
        let origins = self.routes.entry(prefix, Vec::new);
        if let Err(pos) = origins.binary_search(&origin) {
            origins.insert(pos, origin);
        }
        self.by_asn.entry(origin).or_default().insert(prefix);
    }

    /// Add a route, merging its origins with any already stored for the
    /// same prefix. A route with no origins is ignored.
    pub fn insert(&mut self, route: Route) {
        for origin in route.origins {
            self.insert_origin(route.prefix, origin);
        }
    }

    /// Add every route from a parser, stopping at the first error. Returns
    /// the number of routes added.
    ///
    /// To skip bad lines instead, filter them out and use [`Extend`]:
    /// `db.extend(parse_pfx2as(text).filter_map(Result::ok))`.
    pub fn try_extend<I>(&mut self, routes: I) -> Result<usize, Error>
    where
        I: IntoIterator<Item = Result<Route, Error>>,
    {
        let mut added = 0;
        for route in routes {
            self.insert(route?);
            added += 1;
        }
        Ok(added)
    }

    /// Add an iptoasn.com range row: its range becomes CIDR prefixes
    /// originated by its AS, and its description and country become the
    /// AS's name and country unless already known. Rows for `AS0` (space
    /// that is not routed) are skipped; returns whether the row was used.
    pub fn insert_range(&mut self, record: &RangeRecord) -> bool {
        if record.asn.get() == 0 {
            return false;
        }
        for prefix in record.cidrs() {
            self.insert_origin(prefix, record.asn);
        }
        let entry = self.names.entry(record.asn).or_default();
        if entry.name.is_none() {
            entry.name.clone_from(&record.description);
        }
        if entry.country.is_none() {
            entry.country.clone_from(&record.country);
        }
        true
    }

    /// Record an AS name (and country, when the line had one), replacing
    /// any earlier name for the AS.
    pub fn insert_name(&mut self, name: AsName) {
        let entry = self.names.entry(name.asn).or_default();
        entry.name = Some(name.name).filter(|n| !n.is_empty());
        if name.country.is_some() {
            entry.country = name.country;
        }
    }

    /// Record the registry, country, status and date of a RIR ASN
    /// delegation. Address delegations carry no ASN and are ignored; returns
    /// whether the record was used.
    pub fn insert_delegation(&mut self, record: &Delegation) -> bool {
        let Resource::Asn { first, .. } = record.resource else {
            return false;
        };
        let Some((_, last)) = record.asn_range() else {
            return false;
        };
        self.rir.insert(
            first.get(),
            RirEntry {
                last: last.get(),
                registry: record.registry.clone(),
                country: record.country.clone(),
                status: record.status.clone(),
                date: record.date.clone(),
            },
        );
        true
    }

    /// The most specific announced prefix covering `ip`, with its origins.
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Option<Match<'_>> {
        self.routes
            .longest_match(rune_ip::canonical(ip))
            .map(|(prefix, origins)| Match {
                prefix,
                origins: origins.as_slice(),
            })
    }

    /// Every announced prefix covering `ip`, least specific first.
    pub fn lookup_all(&self, ip: IpAddr) -> impl Iterator<Item = Match<'_>> {
        self.routes
            .matches(rune_ip::canonical(ip))
            .map(|(prefix, origins)| Match {
                prefix,
                origins: origins.as_slice(),
            })
    }

    /// The origin AS of the most specific prefix covering `ip` (the lowest
    /// one, for a multi-origin prefix).
    #[must_use]
    pub fn origin(&self, ip: IpAddr) -> Option<Asn> {
        self.lookup(ip).and_then(|m| m.origin())
    }

    /// The origins stored for exactly `prefix` (host bits ignored).
    #[must_use]
    pub fn origins_of(&self, prefix: Cidr) -> Option<&[Asn]> {
        self.routes.get(prefix).map(Vec::as_slice)
    }

    /// Every prefix `asn` originates, in address order (IPv4 first).
    pub fn prefixes(&self, asn: Asn) -> impl Iterator<Item = Cidr> + '_ {
        self.by_asn.get(&asn).into_iter().flatten().copied()
    }

    /// What the loaded name lists and RIR files say about `asn`, or `None`
    /// when nothing is known beyond the routes.
    #[must_use]
    pub fn info(&self, asn: Asn) -> Option<AsnInfo<'_>> {
        let names = self.names.get(&asn);
        let rir = self
            .rir
            .range(..=asn.get())
            .next_back()
            .map(|(_, e)| e)
            .filter(|e| e.last >= asn.get());
        if names.is_none() && rir.is_none() {
            return None;
        }
        Some(AsnInfo {
            asn,
            name: names.and_then(|n| n.name.as_deref()),
            country: rir
                .and_then(|r| r.country.as_deref())
                .or_else(|| names.and_then(|n| n.country.as_deref())),
            registry: rir.map(|r| r.registry.as_str()),
            status: rir.map(|r| r.status.as_str()),
            date: rir.and_then(|r| r.date.as_deref()),
        })
    }

    /// Every AS that originates at least one prefix, in no particular order.
    pub fn asns(&self) -> impl Iterator<Item = Asn> + '_ {
        self.by_asn.keys().copied()
    }

    /// Every stored prefix with its origins, in no particular order.
    pub fn routes(&self) -> impl Iterator<Item = Match<'_>> {
        self.routes.iter().map(|(prefix, origins)| Match {
            prefix,
            origins: origins.as_slice(),
        })
    }

    /// Number of distinct prefixes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether no prefix is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Extend<Route> for AsnDb {
    fn extend<T: IntoIterator<Item = Route>>(&mut self, iter: T) {
        for route in iter {
            self.insert(route);
        }
    }
}

impl FromIterator<Route> for AsnDb {
    fn from_iter<T: IntoIterator<Item = Route>>(iter: T) -> Self {
        let mut db = Self::new();
        db.extend(iter);
        db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{parse_asnames, parse_bgpdump, parse_delegated, parse_ip2asn};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn c(s: &str) -> Cidr {
        s.parse().unwrap()
    }

    const RIB: &str = "\
TABLE_DUMP2|1700000000|B|192.0.2.1|64496|8.8.8.0/24|64496 3356 15169|IGP|192.0.2.1|0|0||NAG||
TABLE_DUMP2|1700000000|B|192.0.2.2|64497|8.8.8.0/24|64497 15169|IGP|192.0.2.2|0|0||NAG||
TABLE_DUMP2|1700000000|B|192.0.2.1|64496|8.0.0.0/9|64496 3356|IGP|192.0.2.1|0|0||NAG||
TABLE_DUMP2|1700000000|B|192.0.2.1|64496|198.51.100.0/24|64496 64511|IGP|192.0.2.1|0|0||NAG||
TABLE_DUMP2|1700000000|B|192.0.2.2|64497|198.51.100.0/24|64497 64510|IGP|192.0.2.2|0|0||NAG||
TABLE_DUMP2|1700000000|B|192.0.2.1|64496|2001:4860::/32|64496 15169|IGP|192.0.2.1|0|0||NAG||
";

    fn rib() -> AsnDb {
        let mut db = AsnDb::new();
        assert_eq!(db.try_extend(parse_bgpdump(RIB)).unwrap(), 6);
        db
    }

    #[test]
    fn longest_prefix_wins_and_duplicates_merge() {
        let db = rib();
        assert_eq!(db.len(), 4);
        assert_eq!(db.origin(ip("8.8.8.8")), Some(Asn::new(15169)));
        assert_eq!(db.origin(ip("8.8.9.9")), Some(Asn::new(3356)));
        assert_eq!(db.origin(ip("9.0.0.0")), None);
        let all: Vec<_> = db.lookup_all(ip("8.8.8.8")).map(|m| m.prefix).collect();
        assert_eq!(all, [c("8.0.0.0/9"), c("8.8.8.0/24")]);
        let moas = db.lookup(ip("198.51.100.7")).unwrap();
        assert_eq!(moas.origins, [Asn::new(64510), Asn::new(64511)]);
        assert_eq!(db.origin(ip("2001:4860::8888")), Some(Asn::new(15169)));
        assert_eq!(
            db.origins_of(c("8.8.8.77/24")),
            Some(&[Asn::new(15169)][..])
        );
    }

    #[test]
    fn mapped_ipv6_addresses_are_unwrapped() {
        let db = rib();
        assert_eq!(db.origin(ip("::ffff:8.8.8.8")), Some(Asn::new(15169)));
    }

    #[test]
    fn prefixes_lists_an_asns_announcements_in_order() {
        let db = rib();
        let p: Vec<_> = db.prefixes(Asn::new(15169)).collect();
        assert_eq!(p, [c("8.8.8.0/24"), c("2001:4860::/32")]);
        assert_eq!(db.prefixes(Asn::new(1)).count(), 0);
        let mut asns: Vec<_> = db.asns().collect();
        asns.sort_unstable();
        assert_eq!(asns.len(), 4);
        assert_eq!(db.routes().count(), 4);
    }

    #[test]
    fn ranges_names_and_delegations_feed_info() {
        let mut db = AsnDb::new();
        let rows = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n";
        let used: Vec<_> = parse_ip2asn(rows)
            .map(|r| db.insert_range(&r.unwrap()))
            .collect();
        assert_eq!(used, [true, false]);
        assert_eq!(db.origin(ip("1.0.0.1")), Some(Asn::new(13335)));
        assert_eq!(db.origin(ip("1.0.2.1")), None);

        let info = db.info(Asn::new(13335)).unwrap();
        assert_eq!(info.name, Some("CLOUDFLARENET"));
        assert_eq!(info.country, Some("US"));
        assert_eq!(info.registry, None);

        for rec in parse_delegated(
            "arin|CA|asn|13330|10|20100714|assigned|x\narin|US|ipv4|1.0.0.0|256|20100714|assigned|x\n",
        ) {
            db.insert_delegation(&rec.unwrap());
        }
        for name in parse_asnames("13335 CLOUDFLARENET - Cloudflare, Inc., US\n") {
            db.insert_name(name.unwrap());
        }
        let info = db.info(Asn::new(13335)).unwrap();
        assert_eq!(info.name, Some("CLOUDFLARENET - Cloudflare, Inc."));
        assert_eq!(info.country, Some("CA"));
        assert_eq!(info.registry, Some("arin"));
        assert_eq!(info.status, Some("assigned"));
        assert_eq!(info.date, Some("20100714"));
        assert_eq!(db.info(Asn::new(13339)).unwrap().registry, Some("arin"));
        assert!(db.info(Asn::new(13340)).is_none());
        assert!(db.info(Asn::new(1)).is_none());
    }

    #[test]
    fn try_extend_stops_at_the_first_error() {
        let mut db = AsnDb::new();
        let text =
            "TABLE_DUMP2|1|B|x|1|1.0.0.0/8|1 2|IGP\nbad\nTABLE_DUMP2|1|B|x|1|2.0.0.0/8|1 3|IGP\n";
        assert_eq!(
            db.try_extend(parse_bgpdump(text)),
            Err(Error::Parse {
                line: 2,
                reason: "not a bgpdump -m line"
            })
        );
        assert_eq!(db.len(), 1);
        let lenient: AsnDb = parse_bgpdump(text).filter_map(Result::ok).collect();
        assert_eq!(lenient.len(), 2);
        assert!(AsnDb::new().is_empty());
    }
}
