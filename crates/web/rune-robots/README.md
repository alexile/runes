# rune-robots

> Parse robots.txt (RFC 9309) and sitemap.xml / sitemap index files (plain or gzipped), and match paths against robots rules

[![crates.io](https://img.shields.io/crates/v/rune-robots)](https://crates.io/crates/rune-robots)
[![docs.rs](https://img.shields.io/docsrs/rune-robots)](https://docs.rs/rune-robots)
[![license](https://img.shields.io/crates/l/rune-robots)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Two small formats every crawler and content-discovery tool needs:

- **robots.txt** ([RFC 9309](https://www.rfc-editor.org/rfc/rfc9309)) —
  user-agent groups, `Allow` / `Disallow` with `*` and `$` wildcards,
  `Crawl-delay` and `Sitemap`. Matching follows the RFC and Google's
  reference parser: the longest pattern wins and `Allow` wins ties, groups
  naming the same product token are merged, `*` is the fallback, and
  `/robots.txt` is always allowed. Parsing never fails; the first 500 KiB
  are read, and common misspellings (`disalow`, `useragent`, `site-map`)
  and a missing colon are tolerated.
- **Sitemaps** ([sitemaps.org](https://www.sitemaps.org/protocol.html)) —
  `<urlset>` (with `lastmod`, `changefreq`, `priority`), `<sitemapindex>`
  and the plain-text format, gzipped or not. Extension elements (images,
  video, news) are skipped. Size (50 MiB, after decompression) and entry
  (50 000) limits are enforced, so a gzip bomb cannot exhaust memory.

The crate is sans-I/O: you fetch the bytes, it interprets them.
`Robots::from_response(status, body)` applies the RFC 9309 status rules
(2xx parse, 4xx allow everything, 5xx disallow everything).

## Installation

```toml
[dependencies]
rune-robots = "0.1"
```

Gzip support is the default `gzip` feature; turn default features off to
drop the `flate2` dependency.

The `rune-robots` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-robots --features cli
```

## Usage

### Library

```rust
use rune_robots::{Robots, Sitemap};

let robots = Robots::parse(
    "User-agent: *\n\
     Disallow: /search\n\
     Allow: /search/about\n\
     Disallow: /*.pdf$\n\
     Crawl-delay: 1\n\
     Sitemap: https://example.com/sitemap_index.xml\n",
);
assert!(!robots.is_allowed("MyCrawler", "/search?q=rust"));
assert!(robots.is_allowed("MyCrawler", "/search/about"));
assert!(!robots.is_allowed("MyCrawler", "https://example.com/files/report.pdf"));

let verdict = robots.verdict("MyCrawler", "/search?q=rust");
println!("blocked by line {}", verdict.rule.unwrap().line);

for url in &robots.sitemaps {
    // fetch `url`, then:
    let body = br#"<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <sitemap><loc>https://example.com/sitemap-1.xml.gz</loc></sitemap>
    </sitemapindex>"#;
    let sitemap = Sitemap::parse(body).expect("valid sitemap");
    assert!(sitemap.is_index());
    for loc in sitemap.locations() {
        println!("{url} -> {loc}");
    }
}
```

### CLI

```bash
rune-robots check robots.txt --agent Googlebot /private/x https://example.com/
# disallow  /private/x  (line 3: /private/)
# allow     https://example.com/

rune-robots show robots.txt          # groups, rules, crawl delays, sitemaps
rune-robots sitemap sitemap.xml.gz   # one <loc> per line
```

`check` exits with status 1 when any path is disallowed.

## License

MIT
