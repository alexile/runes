//! Cloud and CDN IP-range datasets with provider, service and CDN lookup.
//!
//! Exposure scanners need to tell an origin server reached directly from
//! one sitting "behind the CDN", and to attribute an address to AWS,
//! Google, Azure, Cloudflare, Fastly, Oracle or `DigitalOcean`. Those
//! operators publish their ranges; this crate parses the published files
//! ([`parse_aws`], [`parse_google`], [`parse_azure`], [`parse_fastly`],
//! [`parse_oracle`], [`parse_digitalocean`], [`parse_cidr_list`]) and
//! answers lookups with longest-prefix match over [`rune_cidr::Cidr`].
//!
//! The crate does no I/O and embeds no data, because the lists change
//! weekly or faster: fetch each [`Source`] in [`SOURCES`] with your own
//! client, then load the parsed [`Dataset`]s into [`CloudRanges`].
//!
//! # Example
//!
//! ```
//! use rune_cloud_ranges::{parse_aws, parse_cidr_list, CloudRanges, Provider};
//!
//! let aws = r#"{"syncToken":"1","prefixes":[
//!     {"ip_prefix":"3.5.140.0/22","region":"ap-northeast-2","service":"EC2"},
//!     {"ip_prefix":"13.32.0.0/15","region":"GLOBAL","service":"CLOUDFRONT"}],
//!     "ipv6_prefixes":[]}"#;
//! let mut ranges = CloudRanges::new();
//! ranges.extend(parse_aws(aws)?.ranges);
//! ranges.extend(parse_cidr_list("104.16.0.0/13\n", &Provider::Cloudflare)?.ranges);
//!
//! let origin = "3.5.141.10".parse().unwrap();
//! assert_eq!(ranges.which_provider(origin), Some(&Provider::Aws));
//! assert!(!ranges.is_cdn(origin));
//!
//! assert!(ranges.is_cdn("104.17.2.3".parse().unwrap()));
//! let edge = ranges.lookup("13.33.0.1".parse().unwrap()).next().unwrap();
//! assert_eq!(edge.service.as_deref(), Some("CLOUDFRONT"));
//!
//! assert_eq!(ranges.which_provider("192.0.2.1".parse().unwrap()), None);
//! # Ok::<(), rune_cloud_ranges::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod parse;
mod provider;
mod table;

use std::net::IpAddr;

pub use parse::{
    Dataset, parse_aws, parse_azure, parse_cidr_list, parse_digitalocean, parse_fastly,
    parse_google, parse_oracle,
};
pub use provider::{Format, Provider, Range, SOURCES, Source};

use table::PrefixTable;

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The file is not valid JSON of the expected shape.
    #[error("invalid JSON: {0}")]
    Json(String),
    /// A prefix in the file is not a valid CIDR.
    #[error("invalid prefix in entry {entry}")]
    InvalidPrefix {
        /// 1-based position: the line for text files, the prefix's position
        /// in the file for JSON.
        entry: usize,
    },
}

/// A lookup table of provider ranges.
///
/// Several entries may share a prefix (AWS lists most prefixes under
/// `AMAZON` and a specific service; Azure's broad tags overlap the narrow
/// ones), and all of them are kept.
#[derive(Debug, Clone, Default)]
pub struct CloudRanges {
    table: PrefixTable<Vec<Range>>,
}

impl CloudRanges {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a range. An entry identical to one already stored is ignored.
    pub fn insert(&mut self, range: Range) {
        let entries = self.table.entry(range.prefix, Vec::new);
        if !entries.contains(&range) {
            entries.push(range);
        }
    }

    /// Every entry covering `ip`, most specific prefix first. IPv4-mapped
    /// IPv6 addresses are unwrapped first ([`rune_ip::canonical`]).
    pub fn lookup(&self, ip: IpAddr) -> impl Iterator<Item = &Range> {
        let mut hits: Vec<_> = self.table.matches(rune_ip::canonical(ip)).collect();
        hits.reverse();
        hits.into_iter().flat_map(|(_, entries)| entries)
    }

    /// The entries for the most specific prefix covering `ip` (empty when
    /// no range covers it).
    #[must_use]
    pub fn longest(&self, ip: IpAddr) -> &[Range] {
        self.table
            .longest_match(rune_ip::canonical(ip))
            .map_or(&[], |(_, entries)| entries.as_slice())
    }

    /// The operator of the most specific range covering `ip`.
    #[must_use]
    pub fn which_provider(&self, ip: IpAddr) -> Option<&Provider> {
        self.longest(ip).first().map(|r| &r.provider)
    }

    /// Whether any range covering `ip` is a CDN or reverse-proxy edge.
    #[must_use]
    pub fn is_cdn(&self, ip: IpAddr) -> bool {
        self.lookup(ip).any(|r| r.cdn)
    }

    /// Whether any loaded range covers `ip`.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.table.longest_match(rune_ip::canonical(ip)).is_some()
    }

    /// Every stored range of `provider`, in no particular order.
    pub fn ranges<'a>(&'a self, provider: &'a Provider) -> impl Iterator<Item = &'a Range> {
        self.iter().filter(move |r| &r.provider == provider)
    }

    /// Every stored range, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &Range> {
        self.table.iter().flat_map(|(_, entries)| entries)
    }

    /// Number of distinct prefixes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Whether no range is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Extend<Range> for CloudRanges {
    fn extend<T: IntoIterator<Item = Range>>(&mut self, iter: T) {
        for range in iter {
            self.insert(range);
        }
    }
}

impl FromIterator<Range> for CloudRanges {
    fn from_iter<T: IntoIterator<Item = Range>>(iter: T) -> Self {
        let mut table = Self::new();
        table.extend(iter);
        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sample() -> CloudRanges {
        let mut t = CloudRanges::new();
        let aws = r#"{"syncToken":"1","prefixes":[
            {"ip_prefix":"13.32.0.0/15","region":"GLOBAL","service":"AMAZON"},
            {"ip_prefix":"13.32.0.0/15","region":"GLOBAL","service":"CLOUDFRONT"},
            {"ip_prefix":"13.32.0.0/15","region":"GLOBAL","service":"CLOUDFRONT"},
            {"ip_prefix":"3.0.0.0/9","region":"us-east-1","service":"AMAZON"},
            {"ip_prefix":"3.5.140.0/22","region":"ap-northeast-2","service":"EC2"}],
            "ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/24","region":"us-east-1","service":"AMAZON"}]}"#;
        t.extend(parse_aws(aws).unwrap().ranges);
        t.extend(
            parse_cidr_list("104.16.0.0/13\n2400:cb00::/32\n", &Provider::Cloudflare)
                .unwrap()
                .ranges,
        );
        t
    }

    #[test]
    fn most_specific_range_decides_the_provider() {
        let t = sample();
        assert_eq!(t.len(), 6);
        assert_eq!(
            t.longest(ip("3.5.140.1"))[0].service.as_deref(),
            Some("EC2")
        );
        let services: Vec<_> = t
            .lookup(ip("3.5.140.1"))
            .map(|r| r.service.as_deref().unwrap())
            .collect();
        assert_eq!(services, ["EC2", "AMAZON"]);
        assert_eq!(t.which_provider(ip("3.100.0.1")), Some(&Provider::Aws));
        assert_eq!(t.which_provider(ip("2600:1f00::1")), Some(&Provider::Aws));
        assert_eq!(
            t.which_provider(ip("2400:cb00::1")),
            Some(&Provider::Cloudflare)
        );
        assert_eq!(t.which_provider(ip("198.51.100.1")), None);
        assert_eq!(t.longest(ip("198.51.100.1")), []);
    }

    #[test]
    fn cdn_detection_and_duplicates() {
        let t = sample();
        assert!(t.is_cdn(ip("13.33.1.1")));
        assert!(t.is_cdn(ip("::ffff:104.18.0.1")));
        assert!(!t.is_cdn(ip("3.5.140.1")));
        assert!(t.contains(ip("3.5.140.1")) && !t.contains(ip("9.9.9.9")));
        // AMAZON + CLOUDFRONT, the duplicate CLOUDFRONT line dropped.
        assert_eq!(t.longest(ip("13.32.0.1")).len(), 2);
        assert_eq!(t.ranges(&Provider::Cloudflare).count(), 2);
        assert_eq!(t.ranges(&Provider::Aws).count(), 5);
        assert_eq!(t.iter().count(), 7);
    }

    #[test]
    fn custom_providers_and_collect() {
        let other = Provider::Other("hetzner".into());
        let t: CloudRanges = parse_cidr_list("# Hetzner\n5.9.0.0/16\n", &other)
            .unwrap()
            .ranges
            .into_iter()
            .collect();
        assert_eq!(t.which_provider(ip("5.9.1.1")), Some(&other));
        assert!(!t.is_cdn(ip("5.9.1.1")));
        assert!(CloudRanges::new().is_empty());
    }
}
