//! Providers, ranges, and the published sources they come from.

use std::fmt;

use rune_cidr::Cidr;

use crate::Error;
use crate::parse::{
    Dataset, parse_aws, parse_azure, parse_cidr_list, parse_digitalocean, parse_fastly,
    parse_google, parse_oracle,
};

/// A cloud or CDN operator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Provider {
    /// Amazon Web Services (`CloudFront` included).
    Aws,
    /// Google, including Google Cloud.
    Google,
    /// Microsoft Azure (Front Door included).
    Azure,
    /// Cloudflare.
    Cloudflare,
    /// Fastly.
    Fastly,
    /// Oracle Cloud Infrastructure.
    Oracle,
    /// `DigitalOcean`.
    DigitalOcean,
    /// Akamai (no official list is published; load your own).
    Akamai,
    /// Any other operator, by name.
    Other(String),
}

impl Provider {
    /// A short lowercase name: `aws`, `google`, `azure`, `cloudflare`,
    /// `fastly`, `oracle`, `digitalocean`, `akamai`, or the custom name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Aws => "aws",
            Self::Google => "google",
            Self::Azure => "azure",
            Self::Cloudflare => "cloudflare",
            Self::Fastly => "fastly",
            Self::Oracle => "oracle",
            Self::DigitalOcean => "digitalocean",
            Self::Akamai => "akamai",
            Self::Other(name) => name,
        }
    }

    /// Whether every address the operator publishes is a CDN or reverse
    /// proxy edge (Cloudflare, Fastly, Akamai). For mixed operators such as
    /// AWS the answer depends on the service; see [`Range::cdn`].
    #[must_use]
    pub const fn is_cdn(&self) -> bool {
        matches!(self, Self::Cloudflare | Self::Fastly | Self::Akamai)
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One published address range and what it is used for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Range {
    /// The prefix, host bits cleared.
    pub prefix: Cidr,
    /// Who operates it.
    pub provider: Provider,
    /// The provider's service label (`EC2`, `CLOUDFRONT`,
    /// `AzureFrontDoor.Frontend`, `Google Cloud`, …), when it has one.
    pub service: Option<String>,
    /// The provider's region (`us-east-1`, `europe-west1`, …), when it has
    /// one.
    pub region: Option<String>,
    /// Whether the range serves CDN or reverse-proxy edges, so traffic to it
    /// is "behind the CDN" rather than reaching an origin directly.
    pub cdn: bool,
}

impl Range {
    /// A range of `provider` with no service or region; `cdn` starts as
    /// [`Provider::is_cdn`].
    #[must_use]
    pub fn new(prefix: Cidr, provider: Provider) -> Self {
        Self {
            prefix: prefix.trunc(),
            cdn: provider.is_cdn(),
            provider,
            service: None,
            region: None,
        }
    }

    /// Set the service label.
    #[must_use]
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Set the region.
    #[must_use]
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Mark the range as a CDN edge or not.
    #[must_use]
    pub const fn with_cdn(mut self, cdn: bool) -> Self {
        self.cdn = cdn;
        self
    }
}

/// The layout of a published range file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// AWS `ip-ranges.json` ([`parse_aws`]).
    Aws,
    /// Google `cloud.json` / `goog.json` ([`parse_google`]).
    Google,
    /// Azure Service Tags JSON ([`parse_azure`]).
    Azure,
    /// Fastly `public-ip-list` JSON ([`parse_fastly`]).
    Fastly,
    /// Oracle `public_ip_ranges.json` ([`parse_oracle`]).
    Oracle,
    /// `DigitalOcean` geofeed CSV ([`parse_digitalocean`]).
    DigitalOcean,
    /// One CIDR per line ([`parse_cidr_list`]).
    CidrList,
}

/// Where a provider publishes its ranges, and how to parse the file.
///
/// The crate does no I/O: fetch [`Source::url`] with your own HTTP client
/// (on a schedule, to refresh) and pass the body to [`Source::parse`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Source {
    /// The operator.
    pub provider: Provider,
    /// The download URL.
    pub url: &'static str,
    /// The file's layout.
    pub format: Format,
    /// Whether `url` is the file itself. Azure publishes a download page
    /// whose JSON link changes weekly; the caller must follow it.
    pub direct: bool,
}

impl Source {
    /// Parse a downloaded copy of this source.
    pub fn parse(&self, text: &str) -> Result<Dataset, Error> {
        match self.format {
            Format::Aws => parse_aws(text),
            Format::Google => parse_google(text),
            Format::Azure => parse_azure(text),
            Format::Fastly => parse_fastly(text),
            Format::Oracle => parse_oracle(text),
            Format::DigitalOcean => parse_digitalocean(text),
            Format::CidrList => parse_cidr_list(text, &self.provider),
        }
    }
}

const fn source(provider: Provider, url: &'static str, format: Format) -> Source {
    Source {
        provider,
        url,
        format,
        direct: true,
    }
}

/// The official range lists, as of 2026. Akamai publishes none.
pub const SOURCES: &[Source] = &[
    source(
        Provider::Aws,
        "https://ip-ranges.amazonaws.com/ip-ranges.json",
        Format::Aws,
    ),
    source(
        Provider::Google,
        "https://www.gstatic.com/ipranges/cloud.json",
        Format::Google,
    ),
    source(
        Provider::Google,
        "https://www.gstatic.com/ipranges/goog.json",
        Format::Google,
    ),
    Source {
        provider: Provider::Azure,
        url: "https://www.microsoft.com/en-us/download/details.aspx?id=56519",
        format: Format::Azure,
        direct: false,
    },
    source(
        Provider::Cloudflare,
        "https://www.cloudflare.com/ips-v4",
        Format::CidrList,
    ),
    source(
        Provider::Cloudflare,
        "https://www.cloudflare.com/ips-v6",
        Format::CidrList,
    ),
    source(
        Provider::Fastly,
        "https://api.fastly.com/public-ip-list",
        Format::Fastly,
    ),
    source(
        Provider::Oracle,
        "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
        Format::Oracle,
    ),
    source(
        Provider::DigitalOcean,
        "https://digitalocean.com/geo/google.csv",
        Format::DigitalOcean,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_cdn_flags() {
        assert_eq!(Provider::Aws.to_string(), "aws");
        assert_eq!(Provider::Other("hetzner".into()).name(), "hetzner");
        assert!(Provider::Cloudflare.is_cdn() && !Provider::Aws.is_cdn());
        let r = Range::new("104.16.0.7/13".parse().unwrap(), Provider::Cloudflare);
        assert_eq!(r.prefix.to_string(), "104.16.0.0/13");
        assert!(r.cdn);
        assert!(!r.with_cdn(false).cdn);
    }

    #[test]
    fn every_source_is_https_and_parses_empty_input_as_an_error_or_nothing() {
        for s in SOURCES {
            assert!(s.url.starts_with("https://"), "{}", s.url);
            if let Ok(ds) = s.parse("") {
                assert_eq!(ds.ranges, []);
            }
        }
    }
}
