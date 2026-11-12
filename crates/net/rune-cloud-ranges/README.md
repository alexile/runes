# rune-cloud-ranges

> Cloud and CDN IP-range datasets (AWS, Google, Azure, Cloudflare, Fastly, Oracle, DigitalOcean) with provider, service and CDN lookup

[![crates.io](https://img.shields.io/crates/v/rune-cloud-ranges)](https://crates.io/crates/rune-cloud-ranges)
[![docs.rs](https://img.shields.io/docsrs/rune-cloud-ranges)](https://docs.rs/rune-cloud-ranges)
[![license](https://img.shields.io/crates/l/rune-cloud-ranges)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Is this address an origin server, or a CDN edge in front of one? Which
cloud runs it, in which region, for which service? `rune-cloud-ranges`
parses the range files that cloud and CDN operators publish and answers
those questions with longest-prefix match (built on `rune-cidr`).

| Provider | Parser | Published file |
| --- | --- | --- |
| AWS (CloudFront marked CDN) | `parse_aws` | `https://ip-ranges.amazonaws.com/ip-ranges.json` |
| Google / Google Cloud | `parse_google` | `https://www.gstatic.com/ipranges/cloud.json`, `goog.json` |
| Azure (Front Door marked CDN) | `parse_azure` | Service Tags JSON, linked weekly from `https://www.microsoft.com/en-us/download/details.aspx?id=56519` |
| Cloudflare (CDN) | `parse_cidr_list` | `https://www.cloudflare.com/ips-v4`, `ips-v6` |
| Fastly (CDN) | `parse_fastly` | `https://api.fastly.com/public-ip-list` |
| Oracle Cloud | `parse_oracle` | `https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json` |
| DigitalOcean | `parse_digitalocean` | `https://digitalocean.com/geo/google.csv` |
| Anything else (Akamai, your own lists) | `parse_cidr_list` | one CIDR per line |

The crate does no I/O and embeds no data, because the lists change weekly
or faster. `SOURCES` lists the URLs and formats: fetch them with your own
client on a schedule, compare `Dataset::version` to skip unchanged files,
and load the ranges into a `CloudRanges` table.

## Installation

```toml
[dependencies]
rune-cloud-ranges = "0.1"
```

The `rune-cloud-ranges` command-line tool is behind the opt-in `cli`
feature:

```bash
cargo install rune-cloud-ranges --features cli
```

## Usage

### Library

```rust
use rune_cloud_ranges::{parse_aws, parse_cidr_list, CloudRanges, Provider};

let aws = r#"{"syncToken":"1","prefixes":[
    {"ip_prefix":"3.5.140.0/22","region":"ap-northeast-2","service":"EC2"},
    {"ip_prefix":"13.32.0.0/15","region":"GLOBAL","service":"CLOUDFRONT"}],
    "ipv6_prefixes":[]}"#;
let mut ranges = CloudRanges::new();
ranges.extend(parse_aws(aws)?.ranges);
ranges.extend(parse_cidr_list("104.16.0.0/13\n", &Provider::Cloudflare)?.ranges);

let origin = "3.5.141.10".parse().unwrap();
assert_eq!(ranges.which_provider(origin), Some(&Provider::Aws));
assert!(!ranges.is_cdn(origin)); // a direct origin
assert!(ranges.is_cdn("104.17.2.3".parse().unwrap())); // behind Cloudflare
# Ok::<(), rune_cloud_ranges::Error>(())
```

`lookup` returns every covering entry, most specific first, with its
service and region. Parsers are strict: a malformed prefix fails the whole
file, so a truncated download cannot silently shrink the table.

### CLI

```bash
rune-cloud-ranges --sources            # print the URLs to download
rune-cloud-ranges --aws ip-ranges.json --cloudflare ips-v4 13.33.0.1 104.17.2.3 192.0.2.1
# 13.33.0.1	aws	13.32.0.0/15	region=GLOBAL	service=AMAZON,CLOUDFRONT	cdn=true
# 104.17.2.3	cloudflare	104.16.0.0/13	region=-	service=-	cdn=true
# 192.0.2.1	-
```

## License

MIT
