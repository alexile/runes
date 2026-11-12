# rune-csp

> Parse, analyze and canonicalize Content-Security-Policy headers, reporting weaknesses as rune-finding findings

[![crates.io](https://img.shields.io/crates/v/rune-csp)](https://crates.io/crates/rune-csp)
[![docs.rs](https://img.shields.io/docsrs/rune-csp)](https://docs.rs/rune-csp)
[![license](https://img.shields.io/crates/l/rune-csp)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A sans-I/O parser and analyzer for
[Content Security Policy Level 3](https://www.w3.org/TR/CSP3/). It is the
reading side of the setter in `rune-axum-helmet`.

- **Parse** a header value into policies, directives and typed source
  expressions (`'self'`, nonces, hashes, `https:`, `https://*.example.com:443/path`),
  following the browser algorithm: duplicates and invalid directive names
  are skipped and recorded. A strict `str::parse::<Policy>()` rejects them.
- **Canonicalize**: lowercase names, keywords, schemes and hosts, single
  spaces, `"; "` between directives. The canonical form is a fixed point.
- **Analyze**: `'unsafe-inline'` (aware of nonce/hash/`'strict-dynamic'`
  neutralization), `'unsafe-eval'`, wildcard and `data:`/`blob:` script
  sources, plain-HTTP sources, missing `script-src` / `object-src` /
  `base-uri` / `frame-ancestors` / reporting, short nonces, malformed or
  misplaced hashes, `'none'` mixed with sources, unquoted keywords, unknown
  and deprecated directives, report-only delivery.
- **Report** each weakness as a `rune_finding::Finding` (`csp.<kind>`, CWE-693
  plus CWE-79 or CWE-1021, remediation and references).

## Installation

```toml
[dependencies]
rune-csp = "0.1"
```

The `rune-csp` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-csp --features cli
```

## Usage

### Library

```rust
use rune_csp::{Options, Policy, WeaknessKind, run};
use rune_finding::Location;

let report = run(
    "default-src 'self'; script-src 'self' 'unsafe-inline' data:",
    &Options::default(),
);
assert!(report.weaknesses.iter().any(|w| w.kind == WeaknessKind::UnsafeInline));

let findings = report.to_findings::<()>(&Location::url("https://example.com/"));
assert!(findings.iter().any(|f| f.check_id == "csp.unsafe_scheme"));

// Canonical form.
let policy = Policy::parse("Script-Src 'SELF'  HTTPS://CDN.Example.com");
assert_eq!(policy.to_string(), "script-src 'self' https://cdn.example.com");
```

### CLI

```bash
rune-csp "script-src 'self' 'unsafe-inline'; object-src 'none'"
# script-src 'self' 'unsafe-inline'; object-src 'none'
# high          csp.unsafe_inline            'unsafe-inline' in script-src allows injected inline scripts
# low           csp.missing_base_uri         No base-uri: an injected <base> tag can redirect relative script URLs
# ...

curl -sI https://example.com | sed -n 's/^content-security-policy: //Ip' | rune-csp --canonical
```

## License

MIT
