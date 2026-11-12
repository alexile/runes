# rune-url

> URL canonicalization, dedup keys, same-origin/same-site tests and scope matching for crawlers and scanners

[![crates.io](https://img.shields.io/crates/v/rune-url)](https://crates.io/crates/rune-url)
[![docs.rs](https://img.shields.io/docsrs/rune-url)](https://docs.rs/rune-url)
[![license](https://img.shields.io/crates/l/rune-url)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A crawler, a site map and a scan engine have to agree on whether two URLs
name the same thing, and on whether a URL is in scope. This crate gives
them one answer. It is a thin layer over the [`url`](https://crates.io/crates/url)
crate (parsing per the [WHATWG URL Standard](https://url.spec.whatwg.org/))
that adds the [RFC 3986 §6](https://www.rfc-editor.org/rfc/rfc3986#section-6)
normalizations `url` leaves out, plus crawler policy. Sans-I/O: no DNS, no
requests.

| Need | API |
| --- | --- |
| Canonical URL | `canonicalize`, `canonicalize_url`, `resolve`, `Options` |
| Dedup key | `dedup_key`, `KeyOptions`, `QueryKey`, `DedupKey` |
| Query parameters | `split_query`, `join_query`, `QueryParams`, `ParamFilter` |
| Origin and site | `same_origin`, `same_site`, `schemelessly_same_site`, `site`, `registrable_domain` |
| Scope | `Scope`, `ScopeRule`, `is_internal_host`, `host_ip` |
| Display | `display_host`, `to_display_string` |

What gets normalized:

| Step | `Options::default()` | `Options::crawler()` |
| --- | --- | --- |
| Scheme and host case, IDNA, IPv4/IPv6 forms, default port, dot segments (by `url`) | yes | yes |
| Percent-encoding: decode unreserved, uppercase hex (RFC 3986 §6.2.2.2) | yes | yes |
| Lowercase opaque hosts of non-special schemes | yes | yes |
| Remove fragment, empty `?`, host trailing dot | no | yes |
| Drop tracking parameters (`utm_*`, `gclid`, `fbclid` …) | no | yes |
| IPv4-mapped IPv6 host → IPv4 (via `rune-ip`) | no | yes |
| Sort query, drop user info, drop session ids | opt-in | opt-in |

The defaults only apply steps that never change which resource a URL names.
The dedup key (`KeyOptions::default()`) uses `Options::crawler()` and sorts
query parameters; it can also ignore the scheme, `www.`, trailing slashes,
path case, or parameter values.

Same-site tests and `site` use the Public Suffix List from
[`rune-psl`](../../common/rune-psl). Scope rules reuse
[`rune-host-match`](../../common/rune-host-match) patterns,
[`rune-cidr`](../../common/rune-cidr) ranges and
[`rune-ip`](../rune-ip) to recognise internal addresses; Unicode host names
are converted with [`rune-idna`](../rune-idna).

## Installation

```toml
[dependencies]
rune-url = "0.1"
```

The `rune-url` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-url --features cli
```

## Usage

### Library

```rust
use rune_url::{
    KeyOptions, Options, ParamFilter, QueryKey, Scope, Url, canonicalize, dedup_key, resolve,
    same_site, split_query,
};

// Canonical form: never changes the resource.
let url = canonicalize("HTTP://Example.COM:80/a/./b/../%7Euser?q=%41#top", &Options::default())?;
assert_eq!(url.as_str(), "http://example.com/a/~user?q=A#top");

// Crawler: resolve an href and drop what does not matter to the server.
let page = Url::parse("https://shop.example.com/catalog/")?;
let link = resolve(&page, "../item?id=7&utm_source=mail#reviews", &Options::crawler())?;
assert_eq!(link.as_str(), "https://shop.example.com/item?id=7");

// Dedup key, shared by the crawler and the site map.
let keys = KeyOptions::default();
assert_eq!(
    dedup_key("https://shop.example.com/s?b=2&a=1", &keys)?,
    dedup_key("https://SHOP.example.com:443/s?a=1&b=2#x", &keys)?,
);
// One key per endpoint and parameter set, whatever the values.
let per_endpoint = KeyOptions::default().with_query(QueryKey::Names);
assert_eq!(dedup_key("https://h/s?id=1", &per_endpoint)?.as_str(), "https://h/s?id");

// Query parameters, order preserved.
let mut params = split_query("b=2&sid=abc&a=1");
params.remove_matching(&ParamFilter::session_ids());
assert_eq!(params.to_string(), "b=2&a=1");

// Sites and scope.
assert!(same_site(&link, &Url::parse("https://example.com/")?));
let scope = Scope::parse([".example.com", "10.0.0.0/8"], ["https://shop.example.com/logout"])?;
assert!(scope.contains(&link));
assert!(!scope.contains_str("https://shop.example.com/logout/../logout?x=1"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

### CLI

```bash
rune-url canon --crawler 'HTTP://Example.com:80/a/../b?utm_source=x&id=1#top'
# http://example.com/b?id=1

rune-url key --ignore-www 'https://www.example.com/s?b=2&a=1'
# https://example.com/s?a=1&b=2

rune-url site https://docs.rust-lang.org/std
# https://rust-lang.org

rune-url scope -i .example.com -x admin.example.com https://www.example.com/ https://admin.example.com/
# in	https://www.example.com/
# out	https://admin.example.com/
```

## License

MIT
