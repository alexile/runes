# rune-hsts

> Parse and analyze Strict-Transport-Security headers and check HSTS preload-list eligibility and membership

[![crates.io](https://img.shields.io/crates/v/rune-hsts)](https://crates.io/crates/rune-hsts)
[![docs.rs](https://img.shields.io/docsrs/rune-hsts)](https://docs.rs/rune-hsts)
[![license](https://img.shields.io/crates/l/rune-hsts)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A sans-I/O parser and analyzer for
[HTTP Strict Transport Security (RFC 6797)](https://www.rfc-editor.org/rfc/rfc6797)
and the [HSTS preload list](https://hstspreload.org/).

- **Parse** a header value the way browsers do: case-insensitive names,
  quoted values, required `max-age`, no repeated `max-age` or
  `includeSubDomains`, valueless `includeSubDomains`, unknown directives
  kept and ignored. A header browsers would ignore is an `Error`. The
  canonical form (`max-age=N; includeSubDomains; preload`) round-trips.
- **Analyze**: missing or ignored header, `max-age=0`, short `max-age`, no
  `includeSubDomains`, `preload` without the requirements behind it,
  misspelled (`include_subdomains`), valued, repeated and unknown
  directives, several header fields, a header sent over plain HTTP.
- **Preload eligibility**: check a site's observations (domain, HTTPS
  header, what `http://` does) against the
  [submission requirements](https://hstspreload.org/#submission-requirements):
  registrable domain (eTLD+1, via `rune-psl`), HTTP redirects to HTTPS on
  the same host, `max-age` ≥ one year, `includeSubDomains`, `preload`.
  Certificate validity and HTTPS on every subdomain are left to the caller.
- **Preload membership**: look hosts up in a list you load — a plain domain
  list, or Chromium's `transport_security_state_static.json` (feature
  `chromium`), following Chromium's most-specific-entry rule. Nothing is
  fetched.
- **Report** each problem as a `rune_finding::Finding` (`hsts.<kind>` and
  `hsts.preload_<kind>`, CWE-693 plus CWE-319, remediation and references).

## Installation

```toml
[dependencies]
rune-hsts = "0.1"
```

Features: `psl` (default) checks the eTLD+1 requirement with the embedded
Public Suffix List; `chromium` adds `PreloadList::from_chromium_json`.

The `rune-hsts` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-hsts --features cli
```

## Usage

### Library

```rust
use rune_finding::Location;
use rune_hsts::{HttpBehavior, Options, PreloadList, Site, check_preload, run};

let report = run("max-age=86400; include_subdomains", &Options::default());
let findings = report.to_findings::<()>(&Location::url("https://example.com/"));
assert!(findings.iter().any(|f| f.check_id == "hsts.misspelled_directive"));
assert!(findings.iter().any(|f| f.check_id == "hsts.short_max_age"));

let site = Site::new("example.com")
    .with_https_header("max-age=63072000; includeSubDomains; preload")
    .with_http(HttpBehavior::NotListening);
assert!(check_preload(&site).is_eligible());

let list = PreloadList::parse("example.com include_subdomains\n").expect("valid list");
assert!(list.is_preloaded("login.example.com"));
```

### CLI

```bash
rune-hsts "max-age=300; preload"
# max-age=300; preload
# medium        hsts.short_max_age               max-age=300 is below the recommended 31536000 seconds; ...
# low           hsts.missing_include_subdomains  No includeSubDomains: ...
# low           hsts.preload_ineligible          preload is set but the header is not preload-eligible: ...

curl -sI https://example.com | sed -n 's/^strict-transport-security: //Ip' \
  | rune-hsts --preload example.com --http-redirect https://example.com/

rune-hsts --list transport_security_state_static.json --lookup accounts.google.com
```

## License

MIT
