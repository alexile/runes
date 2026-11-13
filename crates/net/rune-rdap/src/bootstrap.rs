//! IANA RDAP bootstrap registries
//! ([RFC 9224](https://www.rfc-editor.org/rfc/rfc9224)) and object-tag
//! routing for entity handles
//! ([RFC 8521](https://www.rfc-editor.org/rfc/rfc8521)).
//!
//! A [`Registry`] is one parsed bootstrap file (`dns.json`, `ipv4.json`,
//! `ipv6.json`, `asn.json` or `object-tags.json`). A [`Bootstrap`] holds
//! the set and answers "which servers serve this [`Query`]?" with the
//! RFC 9224 matching rules: the longest DNS label suffix, the longest IP
//! prefix, the ASN range that contains the number, and the object tag
//! after the last `-` of an entity handle.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use serde::Deserialize;

use crate::query::{normalize_name, prefix_mask_u32, prefix_mask_u128};
use crate::{Error, Query};

/// Where IANA publishes the bootstrap files.
pub const IANA_BASE: &str = "https://data.iana.org/rdap/";

/// Largest bootstrap file accepted (IANA's `dns.json` is about 70 KiB).
pub const MAX_REGISTRY_LEN: usize = 4 * 1024 * 1024;

/// The five IANA bootstrap registries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegistryKind {
    /// Top-level domains (`dns.json`), for domain and nameserver queries.
    Dns,
    /// IPv4 address blocks (`ipv4.json`).
    Ipv4,
    /// IPv6 address blocks (`ipv6.json`).
    Ipv6,
    /// Autonomous system number ranges (`asn.json`).
    Asn,
    /// Service-provider object tags (`object-tags.json`), for entity
    /// handles.
    ObjectTags,
}

impl RegistryKind {
    /// Every registry kind.
    pub const ALL: [Self; 5] = [
        Self::Dns,
        Self::Ipv4,
        Self::Ipv6,
        Self::Asn,
        Self::ObjectTags,
    ];

    /// The file name IANA publishes the registry under.
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Dns => "dns.json",
            Self::Ipv4 => "ipv4.json",
            Self::Ipv6 => "ipv6.json",
            Self::Asn => "asn.json",
            Self::ObjectTags => "object-tags.json",
        }
    }

    /// The registry's URL under [`IANA_BASE`].
    #[must_use]
    pub fn iana_url(self) -> String {
        format!("{IANA_BASE}{}", self.file_name())
    }

    /// The registry that routes `query`.
    #[must_use]
    pub const fn for_query(query: &Query) -> Self {
        match query {
            Query::Domain(_) | Query::Nameserver(_) => Self::Dns,
            Query::Ip(IpAddr::V4(_))
            | Query::Network {
                addr: IpAddr::V4(_),
                ..
            } => Self::Ipv4,
            Query::Ip(IpAddr::V6(_))
            | Query::Network {
                addr: IpAddr::V6(_),
                ..
            } => Self::Ipv6,
            Query::Autnum(_) => Self::Asn,
            Query::Entity(_) => Self::ObjectTags,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Asn => "asn",
            Self::ObjectTags => "object-tags",
        }
    }
}

impl fmt::Display for RegistryKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One service: the entries it covers and the base URLs that serve them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Service {
    /// Contact addresses (object-tag registry only).
    pub contacts: Vec<String>,
    /// The entries as published: TLDs, CIDR blocks, ASN ranges or tags.
    pub entries: Vec<String>,
    /// Base URLs, `https` first, each ending in `/`.
    pub urls: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Matcher {
    /// Lower-case label suffix → service index.
    Dns(HashMap<String, usize>),
    /// `(network, prefix, service)`, as 128-bit values for both families.
    Ip(Vec<(u128, u8, usize)>),
    /// `(first, last, service)`.
    Asn(Vec<(u32, u32, usize)>),
    /// Upper-case tag → service index.
    Tags(HashMap<String, usize>),
}

/// One parsed bootstrap registry file.
///
/// ```
/// use rune_rdap::bootstrap::{Registry, RegistryKind};
/// use rune_rdap::Query;
///
/// let json = r#"{"version":"1.0","publication":"2024-01-01T00:00:00Z","services":[
///   [["64512-65534"],["http://rdap.example.net/","https://rdap.example.net/"]]]}"#;
/// let asn = Registry::parse(RegistryKind::Asn, json.as_bytes())?;
/// let urls = asn.lookup(&Query::Autnum(64_600)).unwrap();
/// assert_eq!(urls[0], "https://rdap.example.net/");
/// assert!(asn.lookup(&Query::Autnum(1)).is_none());
/// # Ok::<(), rune_rdap::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registry {
    kind: RegistryKind,
    version: String,
    publication: Option<String>,
    description: Option<String>,
    services: Vec<Service>,
    matcher: Matcher,
}

#[derive(Deserialize)]
struct RawRegistry {
    version: String,
    #[serde(default)]
    publication: Option<String>,
    #[serde(default)]
    description: Option<String>,
    services: Vec<Vec<Vec<String>>>,
}

impl Registry {
    /// Parses and indexes a bootstrap file of the given kind.
    ///
    /// Entries that do not parse (a malformed CIDR block or ASN range) make
    /// the whole file invalid; base URLs that are not `http(s)` are dropped,
    /// and services left with no URL are ignored.
    pub fn parse(kind: RegistryKind, json: &[u8]) -> Result<Self, Error> {
        if json.len() > MAX_REGISTRY_LEN {
            return Err(Error::TooLarge {
                limit: MAX_REGISTRY_LEN,
            });
        }
        let raw: RawRegistry =
            serde_json::from_slice(json).map_err(|e| Error::InvalidBootstrap(e.to_string()))?;
        let mut services = Vec::with_capacity(raw.services.len());
        for mut parts in raw.services {
            let (contacts, entries, urls) = match (kind, parts.len()) {
                (RegistryKind::ObjectTags, 3) => {
                    let urls = parts.pop().unwrap_or_default();
                    let entries = parts.pop().unwrap_or_default();
                    let contacts = parts.pop().unwrap_or_default();
                    (contacts, entries, urls)
                }
                (RegistryKind::ObjectTags, _) => {
                    return Err(Error::InvalidBootstrap(
                        "object-tag services have three arrays".into(),
                    ));
                }
                (_, 2) => {
                    let urls = parts.pop().unwrap_or_default();
                    let entries = parts.pop().unwrap_or_default();
                    (Vec::new(), entries, urls)
                }
                _ => {
                    return Err(Error::InvalidBootstrap(
                        "services have two arrays: entries and URLs".into(),
                    ));
                }
            };
            let urls = clean_urls(urls);
            if !urls.is_empty() {
                services.push(Service {
                    contacts,
                    entries,
                    urls,
                });
            }
        }
        let matcher = build_matcher(kind, &services)?;
        Ok(Self {
            kind,
            version: raw.version,
            publication: raw.publication,
            description: raw.description,
            services,
            matcher,
        })
    }

    /// Which registry this is.
    #[must_use]
    pub const fn kind(&self) -> RegistryKind {
        self.kind
    }

    /// The file's `version` (`"1.0"`).
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The file's `publication` timestamp (RFC 3339), if present.
    #[must_use]
    pub fn publication(&self) -> Option<&str> {
        self.publication.as_deref()
    }

    /// The file's `description`, if present.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// The services, in file order (those with no `http(s)` URL removed).
    #[must_use]
    pub fn services(&self) -> &[Service] {
        &self.services
    }

    /// The base URLs (`https` first) of the service that covers `query`,
    /// or `None` when this registry has no entry for it (or routes another
    /// kind of query).
    #[must_use]
    pub fn lookup(&self, query: &Query) -> Option<&[String]> {
        if RegistryKind::for_query(query) != self.kind {
            return None;
        }
        let index = match (&self.matcher, query) {
            (Matcher::Dns(map), Query::Domain(name) | Query::Nameserver(name)) => {
                lookup_dns(map, name)
            }
            (Matcher::Ip(nets), Query::Ip(ip)) => {
                lookup_ip(nets, ip_bits(*ip), prefix_in_128(*ip, max_len(*ip)))
            }
            (Matcher::Ip(nets), Query::Network { addr, prefix }) if *prefix <= max_len(*addr) => {
                lookup_ip(nets, ip_bits(*addr), prefix_in_128(*addr, *prefix))
            }
            (Matcher::Asn(ranges), Query::Autnum(asn)) => ranges
                .iter()
                .filter(|(lo, hi, _)| (lo..=hi).contains(&asn))
                .min_by_key(|(lo, hi, _)| hi - lo)
                .map(|&(_, _, i)| i),
            (Matcher::Tags(map), Query::Entity(handle)) => {
                let (_, tag) = handle.rsplit_once('-')?;
                map.get(&tag.to_ascii_uppercase()).copied()
            }
            _ => None,
        }?;
        self.services.get(index).map(|s| s.urls.as_slice())
    }
}

/// Keeps `http(s)` URLs, `https` first, each ending in `/`.
fn clean_urls(urls: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = urls
        .into_iter()
        .filter_map(|u| {
            let parsed = url::Url::parse(&u).ok()?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
                return None;
            }
            Some(if u.ends_with('/') { u } else { format!("{u}/") })
        })
        .collect();
    out.sort_by_key(|u| !u.starts_with("https:"));
    out
}

fn build_matcher(kind: RegistryKind, services: &[Service]) -> Result<Matcher, Error> {
    let bad = |what: &str, entry: &str| Error::InvalidBootstrap(format!("bad {what} {entry:?}"));
    Ok(match kind {
        RegistryKind::Dns => {
            let mut map = HashMap::new();
            for (i, s) in services.iter().enumerate() {
                for entry in &s.entries {
                    // The root zone is published as "" in some files.
                    let key = if entry.is_empty() || entry == "." {
                        String::new()
                    } else {
                        normalize_name(entry).map_err(|_| bad("TLD", entry))?
                    };
                    map.entry(key).or_insert(i);
                }
            }
            Matcher::Dns(map)
        }
        RegistryKind::Ipv4 | RegistryKind::Ipv6 => {
            let mut nets = Vec::new();
            for (i, s) in services.iter().enumerate() {
                for entry in &s.entries {
                    let (addr, len) = entry.split_once('/').ok_or_else(|| bad("CIDR", entry))?;
                    let addr: IpAddr = addr.parse().map_err(|_| bad("CIDR", entry))?;
                    let len: u8 = len.parse().map_err(|_| bad("CIDR", entry))?;
                    if addr.is_ipv6() != (kind == RegistryKind::Ipv6) || len > max_len(addr) {
                        return Err(bad("CIDR", entry));
                    }
                    let bits = ip_bits(addr) & mask_bits(addr, len);
                    nets.push((bits, prefix_in_128(addr, len), i));
                }
            }
            Matcher::Ip(nets)
        }
        RegistryKind::Asn => {
            let mut ranges = Vec::new();
            for (i, s) in services.iter().enumerate() {
                for entry in &s.entries {
                    let (lo, hi) = entry.split_once('-').unwrap_or((entry, entry));
                    let lo: u32 = lo.trim().parse().map_err(|_| bad("ASN range", entry))?;
                    let hi: u32 = hi.trim().parse().map_err(|_| bad("ASN range", entry))?;
                    if lo > hi {
                        return Err(bad("ASN range", entry));
                    }
                    ranges.push((lo, hi, i));
                }
            }
            Matcher::Asn(ranges)
        }
        RegistryKind::ObjectTags => {
            let mut map = HashMap::new();
            for (i, s) in services.iter().enumerate() {
                for entry in &s.entries {
                    map.entry(entry.to_ascii_uppercase()).or_insert(i);
                }
            }
            Matcher::Tags(map)
        }
    })
}

/// Longest label-wise suffix of `name` present in `map`.
fn lookup_dns(map: &HashMap<String, usize>, name: &str) -> Option<usize> {
    let mut rest = name;
    loop {
        if let Some(&i) = map.get(rest) {
            return Some(i);
        }
        match rest.split_once('.') {
            Some((_, tail)) => rest = tail,
            None => return map.get("").copied(),
        }
    }
}

/// Longest prefix in `nets` that covers the network `bits/len`, all in the
/// 128-bit representation of [`ip_bits`] and [`prefix_in_128`].
fn lookup_ip(nets: &[(u128, u8, usize)], bits: u128, len: u8) -> Option<usize> {
    nets.iter()
        .filter(|&&(net, plen, _)| {
            plen <= len && prefix_mask_u128(plen).is_some_and(|m| bits & m == net)
        })
        .max_by_key(|&&(_, plen, _)| plen)
        .map(|&(_, _, i)| i)
}

/// An address as a 128-bit value; IPv4 sits in the low 32 bits.
fn ip_bits(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

const fn max_len(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn mask_bits(addr: IpAddr, len: u8) -> u128 {
    match addr {
        IpAddr::V4(_) => prefix_mask_u32(len).map_or(0, u128::from),
        IpAddr::V6(_) => prefix_mask_u128(len).unwrap_or(0),
    }
}

/// An IPv4 prefix length expressed against the 128-bit value that holds the
/// address in its low 32 bits.
const fn prefix_in_128(addr: IpAddr, len: u8) -> u8 {
    match addr {
        IpAddr::V4(_) => len + 96,
        IpAddr::V6(_) => len,
    }
}

/// The set of bootstrap registries used to route queries.
///
/// ```
/// use rune_rdap::bootstrap::{Bootstrap, Registry, RegistryKind};
/// use rune_rdap::Query;
///
/// let dns = r#"{"version":"1.0","services":[
///   [["com","net"],["https://rdap.verisign.example/com/v1/"]]]}"#;
/// let mut bootstrap = Bootstrap::new();
/// bootstrap.insert(Registry::parse(RegistryKind::Dns, dns.as_bytes())?);
///
/// let q = Query::parse("www.example.com")?;
/// assert_eq!(
///     bootstrap.urls(&q)?,
///     ["https://rdap.verisign.example/com/v1/domain/www.example.com"]
/// );
/// # Ok::<(), rune_rdap::Error>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bootstrap {
    registries: HashMap<RegistryKind, Registry>,
}

impl Bootstrap {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds (or replaces) a registry, returning the one it replaced.
    pub fn insert(&mut self, registry: Registry) -> Option<Registry> {
        self.registries.insert(registry.kind(), registry)
    }

    /// Builder form of [`insert`](Self::insert).
    #[must_use]
    pub fn with(mut self, registry: Registry) -> Self {
        self.insert(registry);
        self
    }

    /// The registry of `kind`, if loaded.
    #[must_use]
    pub fn get(&self, kind: RegistryKind) -> Option<&Registry> {
        self.registries.get(&kind)
    }

    /// The base URLs (`https` first) of the service for `query`.
    pub fn base_urls(&self, query: &Query) -> Result<&[String], Error> {
        let kind = RegistryKind::for_query(query);
        let registry = self
            .get(kind)
            .ok_or_else(|| Error::MissingRegistry(kind.name()))?;
        registry.lookup(query).ok_or_else(|| Error::NoService {
            query: query.path(),
        })
    }

    /// The full query URLs, one per base URL (`https` first).
    pub fn urls(&self, query: &Query) -> Result<Vec<String>, Error> {
        self.base_urls(query)?
            .iter()
            .map(|base| query_url(base, query))
            .collect()
    }
}

/// Joins a base URL and a query's path, percent-encoding each segment.
///
/// ```
/// use rune_rdap::{Query, bootstrap::query_url};
///
/// let q = Query::entity("odd/handle-ARIN")?;
/// assert_eq!(
///     query_url("https://rdap.example/registry", &q)?,
///     "https://rdap.example/registry/entity/odd%2Fhandle-ARIN"
/// );
/// # Ok::<(), rune_rdap::Error>(())
/// ```
pub fn query_url(base: &str, query: &Query) -> Result<String, Error> {
    let mut url = url::Url::parse(base)
        .map_err(|e| Error::InvalidBootstrap(format!("bad base URL {base:?}: {e}")))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| Error::InvalidBootstrap(format!("base URL {base:?} cannot be a base")))?;
        segments.pop_if_empty();
        for segment in query.segments() {
            segments.push(&segment);
        }
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(kind: RegistryKind, services: &str) -> Registry {
        let json = format!(r#"{{"version":"1.0","services":{services}}}"#);
        Registry::parse(kind, json.as_bytes()).unwrap()
    }

    #[test]
    fn dns_longest_suffix() {
        let r = reg(
            RegistryKind::Dns,
            r#"[[["uk"],["https://a.example/"]],[["co.uk"],["https://b.example"]]]"#,
        );
        let q = |s| Query::domain(s).unwrap();
        assert_eq!(r.lookup(&q("x.co.uk")).unwrap(), ["https://b.example/"]);
        assert_eq!(r.lookup(&q("x.org.uk")).unwrap(), ["https://a.example/"]);
        assert_eq!(r.lookup(&q("uk")).unwrap(), ["https://a.example/"]);
        assert!(r.lookup(&q("example.com")).is_none());
        // Labels, not characters: "kuk" is not under "uk".
        assert!(r.lookup(&q("kuk")).is_none());
    }

    #[test]
    fn out_of_range_network_prefix_finds_nothing() {
        // `Query::Network` can be built without `Query::network`'s check.
        let r = reg(
            RegistryKind::Ipv4,
            r#"[[["0.0.0.0/0"],["https://all.example/"]]]"#,
        );
        let addr = "192.0.2.0".parse().unwrap();
        for prefix in [33, 200, u8::MAX] {
            assert!(r.lookup(&Query::Network { addr, prefix }).is_none());
        }
        let r = reg(
            RegistryKind::Ipv6,
            r#"[[["::/0"],["https://all.example/"]]]"#,
        );
        let addr = "2001:db8::".parse().unwrap();
        assert!(r.lookup(&Query::Network { addr, prefix: 129 }).is_none());
    }

    #[test]
    fn ip_longest_prefix_and_families() {
        let v4 = reg(
            RegistryKind::Ipv4,
            r#"[[["10.0.0.0/8"],["https://wide/"]],[["10.1.0.0/16"],["https://narrow/"]]]"#,
        );
        let ip = |s: &str| Query::Ip(s.parse().unwrap());
        assert_eq!(v4.lookup(&ip("10.1.2.3")).unwrap(), ["https://narrow/"]);
        assert_eq!(v4.lookup(&ip("10.2.0.1")).unwrap(), ["https://wide/"]);
        assert!(v4.lookup(&ip("11.0.0.1")).is_none());
        assert!(
            v4.lookup(&ip("::a01:203")).is_none(),
            "IPv6 goes to ipv6.json"
        );
        // A network wider than every entry has no single service.
        let wide = Query::network("10.0.0.0".parse().unwrap(), 7).unwrap();
        assert!(v4.lookup(&wide).is_none());
        let inside = Query::network("10.1.0.0".parse().unwrap(), 20).unwrap();
        assert_eq!(v4.lookup(&inside).unwrap(), ["https://narrow/"]);

        let v6 = reg(
            RegistryKind::Ipv6,
            r#"[[["2001:db8::/32"],["https://v6/"]],[["::/0"],["https://all/"]]]"#,
        );
        assert_eq!(v6.lookup(&ip("2001:db8::1")).unwrap(), ["https://v6/"]);
        assert_eq!(v6.lookup(&ip("2001:db9::1")).unwrap(), ["https://all/"]);
    }

    #[test]
    fn asn_smallest_range() {
        let r = reg(
            RegistryKind::Asn,
            r#"[[["1-100000"],["https://big/"]],[["64496-64511"],["https://doc/"]],[["7"],["https://one/"]]]"#,
        );
        assert_eq!(r.lookup(&Query::Autnum(64_500)).unwrap(), ["https://doc/"]);
        assert_eq!(r.lookup(&Query::Autnum(7)).unwrap(), ["https://one/"]);
        assert_eq!(r.lookup(&Query::Autnum(8)).unwrap(), ["https://big/"]);
        assert!(r.lookup(&Query::Autnum(0)).is_none());
    }

    #[test]
    fn object_tags() {
        let json = br#"{"version":"1.0","services":[[["ops@example"],["ARIN"],["https://rdap.arin.example/registry/"]]]}"#;
        let r = Registry::parse(RegistryKind::ObjectTags, json).unwrap();
        assert_eq!(r.services()[0].contacts, ["ops@example"]);
        let q = Query::entity("ZG39-arin").unwrap();
        assert_eq!(
            r.lookup(&q).unwrap(),
            ["https://rdap.arin.example/registry/"]
        );
        assert!(r.lookup(&Query::entity("NOTAG").unwrap()).is_none());
    }

    #[test]
    fn urls_are_cleaned_and_ordered() {
        let r = reg(
            RegistryKind::Dns,
            r#"[[["test"],["http://plain.example/x","ftp://nope/","https://secure.example/x/"]],[["gone"],["mailto:x@y"]]]"#,
        );
        assert_eq!(
            r.services()[0].urls,
            ["https://secure.example/x/", "http://plain.example/x/"]
        );
        assert_eq!(r.services().len(), 1);
    }

    #[test]
    fn rejects_malformed_files() {
        for (kind, json) in [
            (RegistryKind::Dns, "{}"),
            (RegistryKind::Dns, "not json"),
            (
                RegistryKind::Dns,
                r#"{"version":"1.0","services":[[["com"]]]}"#,
            ),
            (
                RegistryKind::Ipv4,
                r#"{"version":"1.0","services":[[["10.0.0.0"],["https://x/"]]]}"#,
            ),
            (
                RegistryKind::Ipv4,
                r#"{"version":"1.0","services":[[["::/0"],["https://x/"]]]}"#,
            ),
            (
                RegistryKind::Ipv4,
                r#"{"version":"1.0","services":[[["10.0.0.0/33"],["https://x/"]]]}"#,
            ),
            (
                RegistryKind::Asn,
                r#"{"version":"1.0","services":[[["9-1"],["https://x/"]]]}"#,
            ),
            (
                RegistryKind::ObjectTags,
                r#"{"version":"1.0","services":[[["A"],["https://x/"]]]}"#,
            ),
        ] {
            assert!(Registry::parse(kind, json.as_bytes()).is_err(), "{json}");
        }
    }

    #[test]
    fn bootstrap_errors() {
        let b = Bootstrap::new().with(reg(RegistryKind::Dns, r#"[[["com"],["https://c/"]]]"#));
        assert!(matches!(
            b.urls(&Query::Autnum(1)),
            Err(Error::MissingRegistry("asn"))
        ));
        assert!(matches!(
            b.urls(&Query::domain("example.org").unwrap()),
            Err(Error::NoService { .. })
        ));
        assert_eq!(
            b.urls(&Query::nameserver("ns1.example.com").unwrap())
                .unwrap(),
            ["https://c/nameserver/ns1.example.com"]
        );
    }

    #[test]
    fn query_urls() {
        let q = Query::network("2001:db8::".parse().unwrap(), 32).unwrap();
        assert_eq!(
            query_url("https://rdap.example/rdap/?x=1", &q).unwrap(),
            "https://rdap.example/rdap/ip/2001:db8::/32"
        );
        assert!(query_url("not a url", &q).is_err());
        assert!(query_url("mailto:x@y", &q).is_err());
    }
}
