# rune-tech-detect

> Wappalyzer-style technology fingerprinting engine: header, cookie, HTML, script, meta, URL and favicon-hash rules with versions and confidence

[![crates.io](https://img.shields.io/crates/v/rune-tech-detect)](https://crates.io/crates/rune-tech-detect)
[![docs.rs](https://img.shields.io/docsrs/rune-tech-detect)](https://docs.rs/rune-tech-detect)
[![license](https://img.shields.io/crates/l/rune-tech-detect)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Detects the web servers, languages, frameworks, CMSs and libraries behind
an HTTP response (the httpx `-tech-detect` / webanalyze class), with
versions, confidence and the evidence for each.

- **Rules** match response headers, cookies, `<meta>` tags, the HTML body,
  `<script src>` URLs, the URL and the Shodan-style favicon hash
  ([`rune-favicon-hash`](../rune-favicon-hash)). Patterns are regexes with
  optional `\;version:\1` and `\;confidence:50` tags (ternary
  `\1?yes:no` too); technologies can `implies`, `requires` and `excludes`
  each other.
- **Rule files** in the Wappalyzer JSON format load at run time, split
  across several files if needed, plus `categories.json`. `favicon` (an
  array of hashes) is an extension of the format. Browser-only fields
  (`js`, `dom`, `css`, `xhr`) need a rendered page and are ignored.
- **Safe on untrusted rules and pages.** Regexes are case-insensitive,
  linear-time and size-limited like [`rune-matchers`](../../net/rune-matchers);
  JavaScript-only syntax (lookaround, backreferences) is skipped and
  reported, or rejected with `Detector::strict`. HTML is scanned with a
  forgiving, bounded tag scanner.
- **Sans-I/O.** Input is a [`rune-http-model`](../../net/rune-http-model)
  exchange or a hand-built `Page`.

## Installation

```toml
[dependencies]
rune-tech-detect = "0.1"
```

Feature `serde` serializes rules and detections.

## Usage

```rust
use rune_tech_detect::{Detector, Page, Ruleset};

// The built-in ruleset (small, written for this crate)...
let page = Page::new("https://blog.example.test/")
    .with_header("Server", "nginx/1.25.3")
    .with_header("Set-Cookie", "PHPSESSID=1; path=/")
    .with_html(r#"<meta name="generator" content="WordPress 6.4.2">"#);
for detection in Detector::builtin().detect(&page) {
    println!("{} {:?} {}%", detection.name, detection.version, detection.confidence);
}

// ...or your own Wappalyzer-format rules.
let rules = Ruleset::from_wappalyzer_json(r#"{
  "Acme": { "headers": { "X-Acme": "^([\\d.]+)\\;version:\\1" } }
}"#)?;
let found = Detector::strict(&rules)?.detect(&Page::new("u").with_header("X-Acme", "2.1"));
assert_eq!(found[0].version.as_deref(), Some("2.1"));
# Ok::<(), rune_tech_detect::Error>(())
```

## Rule data and licences

The crate bundles **no third-party fingerprint data**. The built-in set
(`BUILTIN_TECHNOLOGIES`, 18 technologies) was written for this crate from
publicly visible markers and is meant as a working example and test
fixture. Maintained Wappalyzer-format rule sets carry their own licences —
the community fork of the Wappalyzer rules is GPL-3.0, for example — so
load them at run time from your own distribution and check their terms;
do not vendor them into this crate.

## License

MIT
