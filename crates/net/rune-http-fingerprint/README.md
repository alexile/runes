# rune-http-fingerprint

> Passive HTTP server and stack fingerprint from header order, casing, status-line and error-page quirks

[![crates.io](https://img.shields.io/crates/v/rune-http-fingerprint)](https://crates.io/crates/rune-http-fingerprint)
[![docs.rs](https://img.shields.io/docsrs/rune-http-fingerprint)](https://docs.rs/rune-http-fingerprint)
[![license](https://img.shields.io/crates/l/rune-http-fingerprint)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Servers give away their implementation in *how* they answer: the order
and capitalisation of the headers they emit, how they write the status
line, their default `404` page, the methods they allow and how they refuse
an unknown one. This crate turns a few responses into:

- a stable **stack fingerprint** `a_b_c` (server-side, in the spirit of
  JA4H) that clusters hosts running the same stack even when the `Server`
  header is stripped or forged, and
- a ranked list of **candidate products** with version and evidence, from
  a small database of signatures whose clues are
  [`rune-matchers`](../rune-matchers) rules plus header-order and casing
  checks.

It is sans-I/O: `probe_plan` lists the requests to send (baseline `GET`,
a `404` probe, `OPTIONS`, an unknown method, HTTP/1.0 without `Host`), you
send them with any client and record the responses as
[`rune-http-model`](../rune-http-model) values. Any subset works,
including a single passively captured response. When responses carry
their `raw` bytes, wire-level quirks (bare `LF`, missing reason phrase,
`Name:value` without a space, folding, …) are added.

| Section | Content |
| --- | --- |
| `a` | primary response version (`10`, `11`, `20`, …), casing code (`l`ower, `u`pper, `t`itle, `c`apitalized, `m`ixed, `n`one), header count, reason form (`s`tandard, `n`on-standard, `x` missing) |
| `b` | 12 hex of SHA-256 over the lowercase header order |
| `c` | 12 hex of SHA-256 over per-probe `status:reason:casing:quirks` and the allowed methods |

Header values and bodies are left out of the fingerprint on purpose (they
change with dates, lengths and content); the signature database looks at
them instead.

## Installation

```toml
[dependencies]
rune-http-fingerprint = "0.1"
```

Feature `serde` serializes signatures, features and reports, so signature
sets can be stored as JSON.

## Usage

```rust
use rune_http_fingerprint::{Database, Observations, ProbeKind, analyze, probe_plan};
use rune_http_model::HttpResponse;

// 1. What to send (the nonce makes the 404 path unique).
let plan = probe_plan("https://www.example.test/", "k3J9q")?;
assert_eq!(plan.len(), 5);

// 2. What came back (written by hand here).
let observations = Observations::new().with_response(
    ProbeKind::NotFound,
    HttpResponse::new(404)
        .with_reason("Not Found")
        .with_header("Server", "nginx/1.24.0")
        .with_body("<hr><center>nginx/1.24.0</center>"),
);

// 3. Fingerprint and identify.
let report = analyze(&observations, &Database::builtin());
println!("{}", report.fingerprint);
assert_eq!(report.candidates[0].name, "nginx");
assert_eq!(report.candidates[0].version.as_deref(), Some("1.24.0"));
# Ok::<(), rune_http_fingerprint::Error>(())
```

## Built-in signatures

The built-in set is small and was written for this crate from documented,
widely observed default behaviour (`Server` tokens, default error pages,
vendor headers): nginx, OpenResty, Apache HTTP Server, Microsoft IIS,
lighttpd, Caddy, LiteSpeed, Apache Tomcat, Eclipse Jetty, Kestrel, Go
`net/http`, Express, Python `http.server`, Werkzeug, Gunicorn, Envoy and
Cloudflare. No third-party fingerprint data is bundled. Header-order and
casing clues only add confidence; a candidate needs at least one matcher
clue.

## License

MIT
