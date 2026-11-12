//! Parsers for the providers' published range files.
//!
//! Each parser takes the downloaded text and returns a [`Dataset`]. They are
//! strict: one malformed prefix fails the whole file, since a truncated or
//! tampered download should not silently shrink the table. A leading UTF-8
//! byte-order mark (Azure ships one) is ignored.

use serde::Deserialize;

use rune_cidr::Cidr;

use crate::{Error, Provider, Range};

/// The ranges from one published file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Dataset {
    /// The file's version stamp, when it has one: AWS and Google
    /// `syncToken`, Azure `changeNumber`, Oracle `last_updated_timestamp`.
    /// Compare it between downloads to skip reloading an unchanged file.
    pub version: Option<String>,
    /// The ranges, in file order.
    pub ranges: Vec<Range>,
}

fn json<'a, T: Deserialize<'a>>(text: &'a str) -> Result<T, Error> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    serde_json::from_str(text).map_err(|e| Error::Json(e.to_string()))
}

/// Parse one prefix; `entry` is its 1-based position for the error.
fn prefix(s: &str, entry: usize) -> Result<Cidr, Error> {
    Cidr::parse(s.trim())
        .map(|c| c.trunc())
        .map_err(|_| Error::InvalidPrefix { entry })
}

fn non_empty(s: String) -> Option<String> {
    (!s.trim().is_empty()).then_some(s)
}

#[derive(Deserialize)]
struct AwsFile {
    #[serde(rename = "syncToken", default)]
    sync_token: Option<String>,
    #[serde(default)]
    prefixes: Vec<AwsPrefix>,
    #[serde(default)]
    ipv6_prefixes: Vec<AwsPrefix>,
}

#[derive(Deserialize)]
struct AwsPrefix {
    #[serde(alias = "ipv6_prefix")]
    ip_prefix: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    service: String,
}

/// Parse AWS `ip-ranges.json`.
///
/// Every entry keeps its `service` (`AMAZON`, `EC2`, `S3`, `CLOUDFRONT`, …)
/// and `region`; AWS lists most prefixes twice, once as `AMAZON` and once
/// under the specific service. `CLOUDFRONT` and `CLOUDFRONT_ORIGIN_FACING`
/// ranges are marked as CDN.
///
/// ```
/// let text = r#"{"syncToken":"1700000000","prefixes":[
///   {"ip_prefix":"13.32.0.0/15","region":"GLOBAL","service":"CLOUDFRONT"}],
///   "ipv6_prefixes":[]}"#;
/// let ds = rune_cloud_ranges::parse_aws(text)?;
/// assert_eq!(ds.version.as_deref(), Some("1700000000"));
/// assert!(ds.ranges[0].cdn);
/// # Ok::<(), rune_cloud_ranges::Error>(())
/// ```
///
/// Format: <https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html>.
pub fn parse_aws(text: &str) -> Result<Dataset, Error> {
    let file: AwsFile = json(text)?;
    let ranges = file
        .prefixes
        .into_iter()
        .chain(file.ipv6_prefixes)
        .enumerate()
        .map(|(i, p)| {
            let cdn = matches!(
                p.service.as_str(),
                "CLOUDFRONT" | "CLOUDFRONT_ORIGIN_FACING"
            );
            Ok(Range {
                service: non_empty(p.service),
                region: non_empty(p.region),
                ..Range::new(prefix(&p.ip_prefix, i + 1)?, Provider::Aws).with_cdn(cdn)
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(Dataset {
        version: file.sync_token,
        ranges,
    })
}

#[derive(Deserialize)]
struct GoogleFile {
    #[serde(rename = "syncToken", default)]
    sync_token: Option<String>,
    #[serde(default)]
    prefixes: Vec<GooglePrefix>,
}

#[derive(Deserialize)]
struct GooglePrefix {
    #[serde(rename = "ipv4Prefix", alias = "ipv6Prefix")]
    prefix: String,
    #[serde(default)]
    service: String,
    #[serde(default)]
    scope: String,
}

/// Parse Google's `cloud.json` (Google Cloud customer ranges, with
/// `service` and `scope` → region) or `goog.json` (every Google range).
/// Google does not separate Cloud CDN, so nothing is marked as CDN.
///
/// ```
/// let text = r#"{"syncToken":"1","prefixes":[
///   {"ipv4Prefix":"34.1.208.0/20","service":"Google Cloud","scope":"africa-south1"},
///   {"ipv6Prefix":"2600:1900:8000::/44","service":"Google Cloud","scope":"us-east1"}]}"#;
/// let ds = rune_cloud_ranges::parse_google(text)?;
/// assert_eq!(ds.ranges[0].region.as_deref(), Some("africa-south1"));
/// # Ok::<(), rune_cloud_ranges::Error>(())
/// ```
///
/// Format: <https://cloud.google.com/compute/docs/faq#find_ip_range>.
pub fn parse_google(text: &str) -> Result<Dataset, Error> {
    let file: GoogleFile = json(text)?;
    let ranges = file
        .prefixes
        .into_iter()
        .enumerate()
        .map(|(i, p)| {
            Ok(Range {
                service: non_empty(p.service),
                region: non_empty(p.scope),
                ..Range::new(prefix(&p.prefix, i + 1)?, Provider::Google)
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(Dataset {
        version: file.sync_token,
        ranges,
    })
}

#[derive(Deserialize)]
struct AzureFile {
    #[serde(rename = "changeNumber", default)]
    change_number: Option<u64>,
    #[serde(default)]
    values: Vec<AzureTag>,
}

#[derive(Deserialize)]
struct AzureTag {
    name: String,
    properties: AzureProperties,
}

#[derive(Deserialize)]
struct AzureProperties {
    #[serde(default)]
    region: String,
    #[serde(rename = "systemService", default)]
    system_service: String,
    #[serde(rename = "addressPrefixes", default)]
    address_prefixes: Vec<String>,
}

/// Parse an Azure Service Tags file (`ServiceTags_Public_YYYYMMDD.json`, or
/// the sovereign-cloud variants).
///
/// The service is the tag name (`AzureCloud.eastus`, `Storage.WestEurope`,
/// `AzureFrontDoor.Frontend`, …) and the region is the tag's region. Tags
/// of the `AzureFrontDoor` system service are marked as CDN. Broad tags
/// such as `AzureCloud` overlap the specific ones.
///
/// ```
/// let text = r#"{"changeNumber":42,"cloud":"Public","values":[{"name":"AzureFrontDoor.Frontend",
///   "id":"AzureFrontDoor.Frontend","properties":{"region":"","systemService":"AzureFrontDoor",
///   "addressPrefixes":["13.107.208.0/24","2620:1ec:bdf::/48"]}}]}"#;
/// let ds = rune_cloud_ranges::parse_azure(text)?;
/// assert_eq!(ds.version.as_deref(), Some("42"));
/// assert!(ds.ranges.iter().all(|r| r.cdn));
/// # Ok::<(), rune_cloud_ranges::Error>(())
/// ```
///
/// Format: <https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview>.
pub fn parse_azure(text: &str) -> Result<Dataset, Error> {
    let file: AzureFile = json(text)?;
    let mut ranges = Vec::new();
    for tag in file.values {
        let props = tag.properties;
        let cdn =
            props.system_service == "AzureFrontDoor" || tag.name.starts_with("AzureFrontDoor");
        for p in &props.address_prefixes {
            let range = Range::new(prefix(p, ranges.len() + 1)?, Provider::Azure)
                .with_service(tag.name.as_str())
                .with_cdn(cdn);
            ranges.push(Range {
                region: non_empty(props.region.clone()),
                ..range
            });
        }
    }
    Ok(Dataset {
        version: file.change_number.map(|n| n.to_string()),
        ranges,
    })
}

#[derive(Deserialize)]
struct FastlyFile {
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    ipv6_addresses: Vec<String>,
}

/// Parse Fastly's `public-ip-list` JSON. Every range is a CDN edge.
///
/// ```
/// let ds = rune_cloud_ranges::parse_fastly(r#"{"addresses":["151.101.0.0/16"],"ipv6_addresses":["2a04:4e40::/32"]}"#)?;
/// assert_eq!(ds.ranges.len(), 2);
/// assert!(ds.ranges[0].cdn);
/// # Ok::<(), rune_cloud_ranges::Error>(())
/// ```
///
/// Format: <https://www.fastly.com/documentation/reference/api/utils/public-ip-list/>.
pub fn parse_fastly(text: &str) -> Result<Dataset, Error> {
    let file: FastlyFile = json(text)?;
    let ranges = file
        .addresses
        .iter()
        .chain(&file.ipv6_addresses)
        .enumerate()
        .map(|(i, p)| Ok(Range::new(prefix(p, i + 1)?, Provider::Fastly)))
        .collect::<Result<_, _>>()?;
    Ok(Dataset {
        version: None,
        ranges,
    })
}

#[derive(Deserialize)]
struct OracleFile {
    #[serde(default)]
    last_updated_timestamp: Option<String>,
    #[serde(default)]
    regions: Vec<OracleRegion>,
}

#[derive(Deserialize)]
struct OracleRegion {
    #[serde(default)]
    region: String,
    #[serde(default)]
    cidrs: Vec<OracleCidr>,
}

#[derive(Deserialize)]
struct OracleCidr {
    cidr: String,
    #[serde(default)]
    tags: Vec<String>,
}

/// Parse Oracle Cloud's `public_ip_ranges.json`. The service is the
/// entry's tags joined with `,` (`OCI`, `OSN`, `OBJECT_STORAGE`).
///
/// ```
/// let text = r#"{"last_updated_timestamp":"2026-11-01T00:00:00.000000","regions":[
///   {"region":"us-phoenix-1","cidrs":[{"cidr":"129.146.0.0/21","tags":["OCI"]}]}]}"#;
/// let ds = rune_cloud_ranges::parse_oracle(text)?;
/// assert_eq!(ds.ranges[0].service.as_deref(), Some("OCI"));
/// # Ok::<(), rune_cloud_ranges::Error>(())
/// ```
///
/// Format: <https://docs.oracle.com/en-us/iaas/Content/General/Concepts/addressranges.htm>.
pub fn parse_oracle(text: &str) -> Result<Dataset, Error> {
    let file: OracleFile = json(text)?;
    let mut ranges = Vec::new();
    for region in file.regions {
        for c in region.cidrs {
            let range = Range::new(prefix(&c.cidr, ranges.len() + 1)?, Provider::Oracle);
            ranges.push(Range {
                service: non_empty(c.tags.join(",")),
                region: non_empty(region.region.clone()),
                ..range
            });
        }
    }
    Ok(Dataset {
        version: file.last_updated_timestamp,
        ranges,
    })
}

/// Data lines of a text file as (1-based line number, trimmed line), with
/// blank lines and `#` comments removed.
fn data_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.strip_prefix('\u{feff}')
        .unwrap_or(text)
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
}

/// Parse `DigitalOcean`'s geofeed CSV ([RFC 8805]:
/// `prefix,country,region,city,postal`). The region is the ISO 3166-2
/// subdivision code.
///
/// ```
/// let ds = rune_cloud_ranges::parse_digitalocean("5.101.96.0/21,NL,NL-NH,Amsterdam,1098 XG\n")?;
/// assert_eq!(ds.ranges[0].region.as_deref(), Some("NL-NH"));
/// # Ok::<(), rune_cloud_ranges::Error>(())
/// ```
///
/// [RFC 8805]: https://www.rfc-editor.org/rfc/rfc8805
pub fn parse_digitalocean(text: &str) -> Result<Dataset, Error> {
    let ranges = data_lines(text)
        .map(|(n, line)| {
            let mut fields = line.split(',');
            let p = prefix(fields.next().unwrap_or_default(), n)?;
            let region = fields.nth(1).map(str::trim).filter(|r| !r.is_empty());
            Ok(Range {
                region: region.map(str::to_owned),
                ..Range::new(p, Provider::DigitalOcean)
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(Dataset {
        version: None,
        ranges,
    })
}

/// Parse a plain list with one CIDR per line (Cloudflare's `ips-v4` and
/// `ips-v6`, or any list you maintain) as ranges of `provider`. Blank lines
/// and `#` comments are skipped; `cdn` follows [`Provider::is_cdn`].
///
/// ```
/// use rune_cloud_ranges::{parse_cidr_list, Provider};
///
/// let ds = parse_cidr_list("173.245.48.0/20\n2400:cb00::/32\n", &Provider::Cloudflare)?;
/// assert_eq!(ds.ranges.len(), 2);
/// assert!(ds.ranges.iter().all(|r| r.cdn));
/// # Ok::<(), rune_cloud_ranges::Error>(())
/// ```
pub fn parse_cidr_list(text: &str, provider: &Provider) -> Result<Dataset, Error> {
    let ranges = data_lines(text)
        .map(|(n, line)| Ok(Range::new(prefix(line, n)?, provider.clone())))
        .collect::<Result<_, _>>()?;
    Ok(Dataset {
        version: None,
        ranges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AWS: &str = r#"{
  "syncToken": "1762900000",
  "createDate": "2026-11-11-22-30-00",
  "prefixes": [
    {"ip_prefix": "3.5.140.0/22", "region": "ap-northeast-2", "service": "AMAZON", "network_border_group": "ap-northeast-2"},
    {"ip_prefix": "3.5.140.0/22", "region": "ap-northeast-2", "service": "S3", "network_border_group": "ap-northeast-2"},
    {"ip_prefix": "130.176.0.0/18", "region": "GLOBAL", "service": "CLOUDFRONT_ORIGIN_FACING", "network_border_group": "GLOBAL"}
  ],
  "ipv6_prefixes": [
    {"ipv6_prefix": "2600:9000:3000::/36", "region": "GLOBAL", "service": "CLOUDFRONT", "network_border_group": "GLOBAL"}
  ]
}"#;

    #[test]
    fn aws_keeps_services_regions_and_cdn_flags() {
        let ds = parse_aws(AWS).unwrap();
        assert_eq!(ds.version.as_deref(), Some("1762900000"));
        assert_eq!(ds.ranges.len(), 4);
        assert_eq!(ds.ranges[1].service.as_deref(), Some("S3"));
        assert_eq!(ds.ranges[1].region.as_deref(), Some("ap-northeast-2"));
        let cdn: Vec<bool> = ds.ranges.iter().map(|r| r.cdn).collect();
        assert_eq!(cdn, [false, false, true, true]);
        assert!(ds.ranges[3].prefix.is_ipv6());
    }

    #[test]
    fn bad_prefixes_and_json_fail_the_file() {
        let bad = r#"{"prefixes":[{"ip_prefix":"3.5.140.0/22"},{"ip_prefix":"3.5.140.0/99"}]}"#;
        assert_eq!(parse_aws(bad), Err(Error::InvalidPrefix { entry: 2 }));
        assert!(matches!(parse_aws("{"), Err(Error::Json(_))));
        assert!(matches!(parse_aws("42"), Err(Error::Json(_))));
        assert!(matches!(
            parse_google(r#"{"prefixes":[{"service":"x"}]}"#),
            Err(Error::Json(_))
        ));
        assert_eq!(
            parse_cidr_list("1.0.0.0/8\nnope\n", &Provider::Akamai),
            Err(Error::InvalidPrefix { entry: 2 })
        );
    }

    #[test]
    fn google_handles_both_files() {
        let goog = r#"{"syncToken":"9","creationTime":"x","prefixes":[{"ipv4Prefix":"8.8.4.0/24"},{"ipv6Prefix":"2001:4860::/32"}]}"#;
        let ds = parse_google(goog).unwrap();
        assert_eq!(ds.ranges.len(), 2);
        assert_eq!(ds.ranges[0].service, None);
        assert_eq!(ds.ranges[1].prefix.to_string(), "2001:4860::/32");
        assert!(!ds.ranges[0].cdn);
    }

    #[test]
    fn azure_strips_the_bom_and_flags_front_door() {
        let text = "\u{feff}{\"changeNumber\":7,\"cloud\":\"Public\",\"values\":[\
            {\"name\":\"AzureCloud.eastus\",\"id\":\"AzureCloud.eastus\",\"properties\":{\"changeNumber\":3,\
             \"region\":\"eastus\",\"regionId\":32,\"platform\":\"Azure\",\"systemService\":\"\",\
             \"addressPrefixes\":[\"20.42.0.0/17\"],\"networkFeatures\":[\"API\"]}},\
            {\"name\":\"AzureFrontDoor.Backend\",\"id\":\"x\",\"properties\":{\"region\":\"\",\
             \"systemService\":\"AzureFrontDoor\",\"addressPrefixes\":[\"147.243.0.0/16\"]}}]}";
        let ds = parse_azure(text).unwrap();
        assert_eq!(ds.version.as_deref(), Some("7"));
        assert_eq!(ds.ranges[0].service.as_deref(), Some("AzureCloud.eastus"));
        assert_eq!(ds.ranges[0].region.as_deref(), Some("eastus"));
        assert!(!ds.ranges[0].cdn);
        assert!(ds.ranges[1].cdn);
        assert_eq!(ds.ranges[1].region, None);
    }

    #[test]
    fn oracle_and_digitalocean() {
        let text = r#"{"last_updated_timestamp":"t","regions":[{"region":"eu-frankfurt-1","cidrs":[
            {"cidr":"130.61.0.0/16","tags":["OCI"]},{"cidr":"134.70.24.0/21","tags":["OBJECT_STORAGE","OSN"]}]}]}"#;
        let ds = parse_oracle(text).unwrap();
        assert_eq!(ds.version.as_deref(), Some("t"));
        assert_eq!(ds.ranges[1].service.as_deref(), Some("OBJECT_STORAGE,OSN"));
        assert_eq!(ds.ranges[1].region.as_deref(), Some("eu-frankfurt-1"));

        let csv = "# geofeed\n5.101.96.0/21,NL,NL-NH,Amsterdam,1098 XG\n2a03:b0c0::/32,NL,,,\n";
        let ds = parse_digitalocean(csv).unwrap();
        assert_eq!(ds.ranges.len(), 2);
        assert_eq!(ds.ranges[1].region, None);
        assert_eq!(
            parse_digitalocean("x,NL\n"),
            Err(Error::InvalidPrefix { entry: 1 })
        );
    }
}
