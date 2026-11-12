# rune-referrer-policy

> Parse and analyze Referrer-Policy headers and meta values, flagging leak-prone policies as rune-finding findings

[![crates.io](https://img.shields.io/crates/v/rune-referrer-policy)](https://crates.io/crates/rune-referrer-policy)
[![docs.rs](https://img.shields.io/docsrs/rune-referrer-policy)](https://docs.rs/rune-referrer-policy)
[![license](https://img.shields.io/crates/l/rune-referrer-policy)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A sans-I/O analyzer for [Referrer Policy](https://www.w3.org/TR/referrer-policy/).

- **Parse** a `Referrer-Policy` header the way browsers do: comma-separated
  tokens, ASCII case ignored, unknown tokens skipped, the last recognised
  one wins (so `no-referrer, strict-origin-when-cross-origin` works as a
  fallback list). Several header fields combine. `<meta name="referrer">`
  values are read too, legacy keywords (`never`, `always`, `default`,
  `origin-when-crossorigin`) included.
- **Model** what each policy sends — nothing, the origin or the full URL —
  for same-origin, cross-origin and HTTPS → HTTP requests, and rate it:

  | Policy                            | Same-origin | Cross-origin | Downgrade | Finding                      |
  | --------------------------------- | ----------- | ------------ | --------- | ---------------------------- |
  | `no-referrer`                     | —           | —            | —         |                              |
  | `same-origin`                     | full        | —            | —         |                              |
  | `strict-origin`                   | origin      | origin       | —         |                              |
  | `strict-origin-when-cross-origin` | full        | origin       | —         |                              |
  | `origin`                          | origin      | origin       | origin    | `origin_on_downgrade` (low)  |
  | `origin-when-cross-origin`        | full        | origin       | origin    | `origin_on_downgrade` (low)  |
  | `no-referrer-when-downgrade`      | full        | full         | —         | `full_url_cross_origin` (medium) |
  | `unsafe-url`                      | full        | full         | full      | `unsafe_url` (high)          |

- **Analyze** also a missing or unrecognised policy, unknown tokens,
  fallback lists that end weaker than they start, and legacy meta
  keywords. Severities drop one step for pages that never reach other
  origins (`Options::with_cross_origin(false)`).
- **Report** each problem as a `rune_finding::Finding`
  (`referrer_policy.<kind>`, CWE-200 plus CWE-319 / CWE-598 where they
  apply, remediation and references).

## Installation

```toml
[dependencies]
rune-referrer-policy = "0.1"
```

The `rune-referrer-policy` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-referrer-policy --features cli
```

## Usage

### Library

```rust
use rune_finding::Location;
use rune_referrer_policy::{Options, ReferrerPolicy, run, run_fields};

let report = run("no-referrer-when-downgrade", &Options::default());
let findings = report.to_findings::<()>(&Location::url("https://example.com/"));
assert_eq!(findings[0].check_id, "referrer_policy.full_url_cross_origin");

// No header: the browser default applies, and the gap is reported.
let report = run_fields([], &Options::default());
assert_eq!(report.effective(), ReferrerPolicy::StrictOriginWhenCrossOrigin);
assert_eq!(report.weaknesses[0].kind.check_id(), "referrer_policy.missing_header");
```

### CLI

```bash
rune-referrer-policy 'no-referrer, unsafe-url'
# unsafe-url: SameOrigin=Full CrossOrigin=Full Downgrade=Full
# high          referrer_policy.unsafe_url             unsafe-url sends full URLs, ...
# low           referrer_policy.weaker_fallback        unsafe-url is the effective policy, ...

rune-referrer-policy --meta never
```

## License

MIT
