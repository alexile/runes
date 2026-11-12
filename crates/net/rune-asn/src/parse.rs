//! Parsers for the published BGP and RIR dataset formats.
//!
//! Every parser takes the whole text of a file and returns a lazy iterator
//! with one `Result` per data line, so a caller can abort on the first
//! error or skip bad lines. Blank lines and `#` comments are skipped, and
//! errors carry the 1-based line number. Nothing here does I/O: the caller
//! downloads or reads the file (and decompresses it) first.

use std::net::{IpAddr, Ipv4Addr};

use rune_cidr::Cidr;

use crate::table::{ip_parts, range_to_cidrs};
use crate::{Asn, Error};

/// One announced prefix and its origin AS(es).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Route {
    /// The announced prefix, host bits cleared.
    pub prefix: Cidr,
    /// The origin ASes: usually one, more for a multi-origin (MOAS) prefix
    /// or an `AS_SET` at the end of the path. Sorted and deduplicated.
    pub origins: Vec<Asn>,
}

impl Route {
    /// A route for `prefix` originated by `origins` (sorted and deduplicated
    /// here; host bits are cleared).
    #[must_use]
    pub fn new(prefix: Cidr, origins: impl IntoIterator<Item = Asn>) -> Self {
        let mut origins: Vec<Asn> = origins.into_iter().collect();
        origins.sort_unstable();
        origins.dedup();
        Self {
            prefix: prefix.trunc(),
            origins,
        }
    }
}

/// One row of an iptoasn.com-style range table: an address range, the AS
/// announcing it, and the AS's country and description.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RangeRecord {
    /// First address of the range.
    pub first: IpAddr,
    /// Last address of the range (inclusive, same family as `first`).
    pub last: IpAddr,
    /// The announcing AS. `AS0` marks space that is not routed.
    pub asn: Asn,
    /// Two-letter country code of the AS, when given (`None` for `None`,
    /// `ZZ`, or an empty field).
    pub country: Option<String>,
    /// AS description, when given (`None` for `Not routed`/`None`).
    pub description: Option<String>,
}

impl RangeRecord {
    /// The range as the smallest list of CIDR prefixes covering it.
    #[must_use]
    pub fn cidrs(&self) -> Vec<Cidr> {
        let (bits, first) = ip_parts(self.first);
        let (_, last) = ip_parts(self.last);
        range_to_cidrs(bits, first, last)
    }
}

/// The resource a RIR delegation line describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Resource {
    /// A block of `count` consecutive ASNs starting at `first`.
    Asn {
        /// First ASN of the block.
        first: Asn,
        /// Number of ASNs in the block (at least 1).
        count: u32,
    },
    /// `count` IPv4 addresses starting at `start` (not necessarily a CIDR
    /// block; see [`Delegation::cidrs`]).
    Ipv4 {
        /// First address.
        start: Ipv4Addr,
        /// Number of addresses (at least 1).
        count: u32,
    },
    /// An IPv6 prefix.
    Ipv6(Cidr),
}

/// One record of a RIR "delegated" statistics file (the NRO
/// `delegated-<rir>-extended-latest` and `delegated-<rir>-latest` files).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Delegation {
    /// The registry: `afrinic`, `apnic`, `arin`, `iana`, `lacnic` or
    /// `ripencc`.
    pub registry: String,
    /// ISO 3166 country code of the holder (`None` when empty or `ZZ`).
    pub country: Option<String>,
    /// The delegated resource.
    pub resource: Resource,
    /// Allocation date as `YYYYMMDD` (`None` when empty or all zeros).
    pub date: Option<String>,
    /// `allocated`, `assigned`, `available` or `reserved`.
    pub status: String,
    /// The extended format's opaque holder ID, linking a holder's ASNs to
    /// its address blocks.
    pub opaque_id: Option<String>,
}

impl Delegation {
    /// The ASNs of an ASN record as an inclusive range, or `None` for an
    /// address record.
    #[must_use]
    pub const fn asn_range(&self) -> Option<(Asn, Asn)> {
        match self.resource {
            Resource::Asn { first, count } => {
                let last = first.get().saturating_add(count.saturating_sub(1));
                Some((first, Asn::new(last)))
            }
            _ => None,
        }
    }

    /// The address block of an IPv4 or IPv6 record as CIDR prefixes (empty
    /// for an ASN record). IPv4 counts need not be powers of two, so one
    /// record can yield several prefixes.
    #[must_use]
    pub fn cidrs(&self) -> Vec<Cidr> {
        match self.resource {
            Resource::Asn { .. } | Resource::Ipv4 { count: 0, .. } => Vec::new(),
            Resource::Ipv4 { start, count } => {
                let first = u128::from(u32::from(start));
                let last = (first + u128::from(count) - 1).min(u128::from(u32::MAX));
                range_to_cidrs(32, first, last)
            }
            Resource::Ipv6(prefix) => vec![prefix],
        }
    }
}

/// One line of an AS-name list: an ASN, its name and, when the line ends
/// in `, CC`, the holder's country.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AsName {
    /// The ASN.
    pub asn: Asn,
    /// The name, with any trailing `, CC` removed.
    pub name: String,
    /// The two-letter country code, when the line ends in one.
    pub country: Option<String>,
}

/// Data lines of `text` as (1-based line number, trimmed line): blank lines
/// and `#` comments removed.
fn data_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
}

const fn err(line: usize, reason: &'static str) -> Error {
    Error::Parse { line, reason }
}

fn parse_asn(line: usize, s: &str) -> Result<Asn, Error> {
    s.parse().map_err(|_| err(line, "invalid AS number"))
}

fn parse_prefix(line: usize, s: &str) -> Result<Cidr, Error> {
    if !s.contains('/') {
        return Err(err(line, "prefix has no length"));
    }
    Cidr::parse(s)
        .map(|c| c.trunc())
        .map_err(|_| err(line, "invalid prefix"))
}

/// Parse a list of origin ASNs separated by `_` (multi-origin) and `,`
/// (AS set), optionally wrapped in `{}`, `[]` or `()`.
fn parse_origins(line: usize, s: &str) -> Result<Vec<Asn>, Error> {
    let s = s.trim_matches(|c| matches!(c, '{' | '}' | '[' | ']' | '(' | ')'));
    let origins = s
        .split(['_', ','])
        .map(|a| parse_asn(line, a.trim()))
        .collect::<Result<Vec<_>, _>>()?;
    if origins.is_empty() {
        return Err(err(line, "no origin AS"));
    }
    Ok(origins)
}

/// The text field, or `None` when it is empty or one of `placeholders`.
fn optional(s: &str, placeholders: &[&str]) -> Option<String> {
    let s = s.trim();
    (!s.is_empty() && !placeholders.iter().any(|p| s.eq_ignore_ascii_case(p))).then(|| s.to_owned())
}

/// Parse a CAIDA `RouteViews` prefix-to-AS file (`routeviews-rv2-*.pfx2as`):
/// `prefix <TAB> length <TAB> origins`, where origins are separated by `_`
/// for a multi-origin prefix and by `,` inside an AS set.
///
/// ```
/// let text = "1.0.0.0\t24\t13335\n8.8.8.0\t24\t15169_15169\n";
/// let routes: Vec<_> = rune_asn::parse_pfx2as(text).collect::<Result<_, _>>()?;
/// assert_eq!(routes[0].prefix.to_string(), "1.0.0.0/24");
/// assert_eq!(routes[0].origins, [rune_asn::Asn::new(13335)]);
/// # Ok::<(), rune_asn::Error>(())
/// ```
///
/// Format: <https://www.caida.org/catalog/datasets/routeviews-prefix2as/>.
pub fn parse_pfx2as(text: &str) -> impl Iterator<Item = Result<Route, Error>> + '_ {
    data_lines(text).map(|(n, line)| {
        let mut fields = line.split_whitespace();
        let (Some(addr), Some(len), Some(origins), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(err(n, "expected 3 fields: prefix, length, origins"));
        };
        if len.is_empty() || !len.bytes().all(|b| b.is_ascii_digit()) {
            return Err(err(n, "invalid prefix length"));
        }
        let prefix = parse_prefix(n, &format!("{addr}/{len}"))?;
        Ok(Route::new(prefix, parse_origins(n, origins)?))
    })
}

/// Parse a RIPE RIS `riswhoisdump` file (`riswhoisdump.IPv4`/`.IPv6`):
/// `origin <TAB> prefix <TAB> peers-seeing`. The third column is optional
/// here; origins may be an AS set (`{1,2}`).
///
/// ```
/// let text = "% comment\n13335\t1.1.1.0/24\t350\n";
/// let routes: Vec<_> = rune_asn::parse_riswhois(text).collect::<Result<_, _>>()?;
/// assert_eq!(routes[0].prefix.to_string(), "1.1.1.0/24");
/// # Ok::<(), rune_asn::Error>(())
/// ```
///
/// Format: <https://www.ris.ripe.net/dumps/>.
pub fn parse_riswhois(text: &str) -> impl Iterator<Item = Result<Route, Error>> + '_ {
    data_lines(text)
        .filter(|(_, l)| !l.starts_with('%'))
        .map(|(n, line)| {
            let mut fields = line.split_whitespace();
            let (Some(origins), Some(prefix)) = (fields.next(), fields.next()) else {
                return Err(err(n, "expected origin and prefix fields"));
            };
            if fields.nth(1).is_some() {
                return Err(err(n, "too many fields"));
            }
            Ok(Route::new(
                parse_prefix(n, prefix)?,
                parse_origins(n, origins)?,
            ))
        })
}

/// Parse `bgpdump -m` (one-line, pipe-separated) output of an MRT RIB dump
/// or update file, from `RouteViews` or RIPE RIS:
/// `TABLE_DUMP2|time|B|peer-ip|peer-as|prefix|as-path|origin|...`.
///
/// Announcements (`B` RIB entries and `A` updates) yield a route whose
/// origin is the last AS-path element; an `AS_SET` there (`{1,2}`) yields
/// several origins. Withdrawals and state changes are skipped. A full RIB
/// lists each prefix once per peer, so expect duplicates; [`AsnDb`]
/// merges them.
///
/// ```
/// let text = "TABLE_DUMP2|1700000000|B|192.0.2.1|64496|1.1.1.0/24|64496 13335|IGP|192.0.2.1|0|0||NAG||\n";
/// let routes: Vec<_> = rune_asn::parse_bgpdump(text).collect::<Result<_, _>>()?;
/// assert_eq!(routes[0].origins, [rune_asn::Asn::new(13335)]);
/// # Ok::<(), rune_asn::Error>(())
/// ```
///
/// [`AsnDb`]: crate::AsnDb
pub fn parse_bgpdump(text: &str) -> impl Iterator<Item = Result<Route, Error>> + '_ {
    data_lines(text).filter_map(|(n, line)| {
        let fields: Vec<&str> = line.split('|').collect();
        match fields.get(2) {
            Some(&("B" | "A")) => {}
            Some(_) => return None,
            None => return Some(Err(err(n, "not a bgpdump -m line"))),
        }
        let (Some(prefix), Some(path)) = (fields.get(5), fields.get(6)) else {
            return Some(Err(err(n, "missing prefix or AS path")));
        };
        let route = parse_prefix(n, prefix).and_then(|prefix| {
            let origin = path
                .split_whitespace()
                .next_back()
                .ok_or_else(|| err(n, "empty AS path"))?;
            Ok(Route::new(prefix, parse_origins(n, origin)?))
        });
        Some(route)
    })
}

/// Parse an iptoasn.com range table (`ip2asn-v4.tsv`, `ip2asn-v6.tsv`,
/// `ip2asn-combined.tsv`):
/// `first <TAB> last <TAB> asn <TAB> country <TAB> description`.
///
/// ```
/// let text = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n";
/// let rows: Vec<_> = rune_asn::parse_ip2asn(text).collect::<Result<_, _>>()?;
/// assert_eq!(rows[0].cidrs()[0].to_string(), "1.0.0.0/24");
/// assert_eq!(rows[0].country.as_deref(), Some("US"));
/// # Ok::<(), rune_asn::Error>(())
/// ```
///
/// Format: <https://iptoasn.com/>.
pub fn parse_ip2asn(text: &str) -> impl Iterator<Item = Result<RangeRecord, Error>> + '_ {
    data_lines(text).map(|(n, line)| {
        let mut fields = line.split('\t');
        let (Some(first), Some(last), Some(asn)) = (fields.next(), fields.next(), fields.next())
        else {
            return Err(err(n, "expected at least 3 tab-separated fields"));
        };
        let first: IpAddr = first
            .trim()
            .parse()
            .map_err(|_| err(n, "invalid first address"))?;
        let last: IpAddr = last
            .trim()
            .parse()
            .map_err(|_| err(n, "invalid last address"))?;
        if first.is_ipv4() != last.is_ipv4() {
            return Err(err(n, "range mixes address families"));
        }
        if ip_parts(first).1 > ip_parts(last).1 {
            return Err(err(n, "range ends before it starts"));
        }
        Ok(RangeRecord {
            first,
            last,
            asn: parse_asn(n, asn.trim())?,
            country: fields.next().and_then(|c| optional(c, &["None", "ZZ"])),
            description: fields
                .next()
                .and_then(|d| optional(d, &["None", "Not routed"])),
        })
    })
}

/// Parse a RIR delegated statistics file, standard or extended:
/// `registry|cc|type|start|value|date|status[|opaque-id[|extensions]]`.
/// The version header and `summary` lines are skipped.
///
/// ```
/// let text = "2|ripencc|20261111|3|19830705|20261110|+0100\n\
///             ripencc|*|asn|*|1|summary\n\
///             ripencc|NL|asn|3333|1|19930901|allocated|abc-123\n\
///             ripencc|NL|ipv4|193.0.0.0|2048|19930901|allocated|abc-123\n";
/// let recs: Vec<_> = rune_asn::parse_delegated(text).collect::<Result<_, _>>()?;
/// assert_eq!(recs.len(), 2);
/// assert_eq!(recs[1].cidrs()[0].to_string(), "193.0.0.0/21");
/// # Ok::<(), rune_asn::Error>(())
/// ```
///
/// Format: <https://www.nro.net/wp-content/uploads/nro-extended-stats-readme5.txt>.
pub fn parse_delegated(text: &str) -> impl Iterator<Item = Result<Delegation, Error>> + '_ {
    data_lines(text).filter_map(|(n, line)| {
        let fields: Vec<&str> = line.split('|').collect();
        // Version line: `version|registry|serial|records|start|end|UTCoffset`.
        if fields
            .first()
            .is_some_and(|f| f.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
        {
            return None;
        }
        if fields.get(5) == Some(&"summary") {
            return None;
        }
        Some(delegation(n, &fields))
    })
}

fn delegation(n: usize, fields: &[&str]) -> Result<Delegation, Error> {
    let &[
        registry,
        cc,
        kind,
        start,
        value,
        date,
        status,
        ref rest @ ..,
    ] = fields
    else {
        return Err(err(n, "expected at least 7 pipe-separated fields"));
    };
    let resource = match kind {
        "asn" => {
            let first = parse_asn(n, start)?;
            let count: u32 = value.parse().map_err(|_| err(n, "invalid ASN count"))?;
            if count == 0 || first.get().checked_add(count - 1).is_none() {
                return Err(err(n, "ASN count out of range"));
            }
            Resource::Asn { first, count }
        }
        "ipv4" => {
            let start: Ipv4Addr = start.parse().map_err(|_| err(n, "invalid IPv4 start"))?;
            let count: u32 = value
                .parse()
                .map_err(|_| err(n, "invalid IPv4 address count"))?;
            if count == 0 || u32::from(start).checked_add(count - 1).is_none() {
                return Err(err(n, "IPv4 address count out of range"));
            }
            Resource::Ipv4 { start, count }
        }
        "ipv6" => {
            if !start.contains(':') {
                return Err(err(n, "invalid IPv6 start"));
            }
            Resource::Ipv6(parse_prefix(n, &format!("{start}/{value}"))?)
        }
        _ => return Err(err(n, "unknown resource type")),
    };
    Ok(Delegation {
        registry: registry.to_owned(),
        country: optional(cc, &["ZZ", "*"]),
        resource,
        date: optional(date, &["00000000"]),
        status: status.to_owned(),
        opaque_id: rest.first().and_then(|id| optional(id, &[])),
    })
}

/// Parse an AS-name list: one AS per line.
///
/// Each line is the number (with or without an `AS` prefix), whitespace and
/// the name, optionally ending in `, CC`. This covers RIPE's `asn.txt` (`13335 CLOUDFLARENET, US`) and
/// APNIC/potaroo `asnames.txt` (`AS13335  CLOUDFLARENET - Cloudflare, Inc., US`).
///
/// ```
/// let names: Vec<_> = rune_asn::parse_asnames("AS13335  CLOUDFLARENET - Cloudflare, Inc., US\n")
///     .collect::<Result<_, _>>()?;
/// assert_eq!(names[0].name, "CLOUDFLARENET - Cloudflare, Inc.");
/// assert_eq!(names[0].country.as_deref(), Some("US"));
/// # Ok::<(), rune_asn::Error>(())
/// ```
pub fn parse_asnames(text: &str) -> impl Iterator<Item = Result<AsName, Error>> + '_ {
    data_lines(text).map(|(n, line)| {
        let (asn, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let asn = parse_asn(n, asn)?;
        let rest = rest.trim();
        let (name, country) = match rest.rsplit_once(',') {
            Some((name, cc))
                if cc.trim().len() == 2 && cc.trim().bytes().all(|b| b.is_ascii_alphabetic()) =>
            {
                (name.trim(), Some(cc.trim().to_ascii_uppercase()))
            }
            _ => (rest, None),
        };
        Ok(AsName {
            asn,
            name: name.to_owned(),
            country,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(n: u32) -> Asn {
        Asn::new(n)
    }

    #[test]
    fn pfx2as_handles_moas_and_as_sets() {
        let text = "# header\n\n1.0.0.0\t24\t13335\n\
                    41.78.236.0\t22\t36924_37053\n\
                    2001:db8::\t32\t64500,64501_64502\n";
        let routes: Vec<_> = parse_pfx2as(text).collect::<Result<_, _>>().unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[1].origins, [a(36924), a(37053)]);
        assert_eq!(routes[2].prefix.to_string(), "2001:db8::/32");
        assert_eq!(routes[2].origins, [a(64500), a(64501), a(64502)]);
    }

    #[test]
    fn pfx2as_reports_line_numbers() {
        let text = "1.0.0.0\t24\t13335\n1.0.0.0\t33\t1\n";
        let errs: Vec<_> = parse_pfx2as(text).filter_map(Result::err).collect();
        assert_eq!(
            errs,
            [Error::Parse {
                line: 2,
                reason: "invalid prefix"
            }]
        );
        for bad in [
            "1.0.0.0\t24",
            "1.0.0.0\t+4\t1",
            "x\t24\t1",
            "1.0.0.0\t24\tASx",
            "1.0.0.0\t24\t1\t2",
        ] {
            assert!(parse_pfx2as(bad).next().unwrap().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn riswhois_skips_percent_comments() {
        let text =
            "% This file is made by RIS\n13335\t1.1.1.0/24\t350\n{64500,64501}\t2001:db8::/32\t1\n";
        let routes: Vec<_> = parse_riswhois(text).collect::<Result<_, _>>().unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[1].origins, [a(64500), a(64501)]);
        assert!(parse_riswhois("13335\t1.1.1.0\t1").next().unwrap().is_err());
        assert!(
            parse_riswhois("13335\t1.1.1.0/24\t1\t2")
                .next()
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn bgpdump_takes_the_last_path_element() {
        let text = "\
TABLE_DUMP2|1700000000|B|192.0.2.1|64496|8.8.8.0/24|64496 3356 15169|IGP|192.0.2.1|0|0||NAG||
TABLE_DUMP2|1700000000|B|192.0.2.1|64496|203.0.113.0/24|64496 64497 {64510,64511}|INCOMPLETE|192.0.2.1|0|0||NAG||
BGP4MP|1700000000|W|192.0.2.1|64496|8.8.8.0/24
BGP4MP|1700000000|STATE|192.0.2.1|64496|1|2
BGP4MP|1700000000|A|192.0.2.1|64496|2001:db8::/32|64496 64499|IGP|192.0.2.1|0|0||NAG||
";
        let routes: Vec<_> = parse_bgpdump(text).collect::<Result<_, _>>().unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].origins, [a(15169)]);
        assert_eq!(routes[1].origins, [a(64510), a(64511)]);
        assert_eq!(routes[2].origins, [a(64499)]);
        assert!(
            parse_bgpdump("TABLE_DUMP2|1|B|x|1|1.0.0.0/8||IGP")
                .next()
                .unwrap()
                .is_err()
        );
        assert!(parse_bgpdump("garbage").next().unwrap().is_err());
    }

    #[test]
    fn ip2asn_parses_ranges_and_placeholders() {
        let text = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n\
                    1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n\
                    2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t64500\tZZ\t\n";
        let rows: Vec<_> = parse_ip2asn(text).collect::<Result<_, _>>().unwrap();
        assert_eq!(rows[0].description.as_deref(), Some("CLOUDFLARENET"));
        assert_eq!(rows[1].asn, a(0));
        assert_eq!(rows[1].country, None);
        assert_eq!(rows[1].description, None);
        let cidrs: Vec<_> = rows[1].cidrs().iter().map(ToString::to_string).collect();
        assert_eq!(cidrs, ["1.0.1.0/24", "1.0.2.0/23"]);
        assert_eq!(rows[2].cidrs()[0].to_string(), "2001:db8::/32");
        assert!(parse_ip2asn("1.0.0.9\t1.0.0.1\t1").next().unwrap().is_err());
        assert!(parse_ip2asn("1.0.0.0\t::1\t1").next().unwrap().is_err());
    }

    #[test]
    fn delegated_parses_all_resource_kinds() {
        let text = "\
2.3|arin|1731283200|3|19700101|20261111|-0500
arin|*|ipv4|*|1|summary
arin|US|asn|13335|1|20100714|assigned|abc
arin|US|ipv4|104.16.0.0|1048576|20140325|allocated|abc
arin|US|ipv6|2606:4700::|32|20110831|allocated|abc
arin||ipv4|23.0.0.0|768|00000000|available|
arin|ZZ|asn|64000|10|20000101|reserved
";
        let recs: Vec<_> = parse_delegated(text).collect::<Result<_, _>>().unwrap();
        assert_eq!(recs.len(), 5);
        assert_eq!(recs[0].asn_range(), Some((a(13335), a(13335))));
        assert_eq!(recs[0].opaque_id.as_deref(), Some("abc"));
        assert_eq!(recs[1].cidrs()[0].to_string(), "104.16.0.0/12");
        assert_eq!(recs[2].cidrs()[0].to_string(), "2606:4700::/32");
        let odd: Vec<_> = recs[3].cidrs().iter().map(ToString::to_string).collect();
        assert_eq!(odd, ["23.0.0.0/23", "23.0.2.0/24"]);
        assert_eq!(recs[3].country, None);
        assert_eq!(recs[3].date, None);
        assert_eq!(recs[4].asn_range(), Some((a(64000), a(64009))));
        assert_eq!(recs[4].opaque_id, None);
        assert!(recs[1].asn_range().is_none() && recs[0].cidrs().is_empty());
        for bad in [
            "arin|US|asn|1|0|0|x",
            "arin|US|asn|4294967295|2|0|x",
            "arin|US|ipv4|255.255.255.0|512|0|x",
            "arin|US|ipv6|1.2.3.4|32|0|x",
            "arin|US|fqdn|x|1|0|x",
            "arin|US|asn|1|1",
        ] {
            assert!(parse_delegated(bad).next().unwrap().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn asnames_parses_both_layouts() {
        let text = "13335 CLOUDFLARENET, US\nAS15169  GOOGLE - Google LLC, us\nAS64512\nAS1 LVLT-1, Level 3\n";
        let names: Vec<_> = parse_asnames(text).collect::<Result<_, _>>().unwrap();
        assert_eq!(names[0].name, "CLOUDFLARENET");
        assert_eq!(names[1].name, "GOOGLE - Google LLC");
        assert_eq!(names[1].country.as_deref(), Some("US"));
        assert_eq!(names[2].name, "");
        assert_eq!(names[3].country, None);
        assert_eq!(names[3].name, "LVLT-1, Level 3");
        assert!(parse_asnames("ASx name").next().unwrap().is_err());
    }
}
