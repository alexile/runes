# rune-cookie-sec

> Analyze Set-Cookie headers for weak security attributes, reporting rune-finding findings

[![crates.io](https://img.shields.io/crates/v/rune-cookie-sec)](https://crates.io/crates/rune-cookie-sec)
[![docs.rs](https://img.shields.io/docsrs/rune-cookie-sec)](https://docs.rs/rune-cookie-sec)
[![license](https://img.shields.io/crates/l/rune-cookie-sec)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A sans-I/O security analyzer for `Set-Cookie` headers, built on
[`rune-cookie`](../../net/rune-cookie) (which parses them as browsers do,
per [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265), keeping every raw
attribute) and the
[RFC 6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis)
rules browsers enforce.

- **Missing protections**: no `Secure`, `HttpOnly` or `SameSite`;
  `SameSite=None`; cookies set over plain HTTP.
- **Scope**: `Domain` shares a cookie with every subdomain; with the
  request URL, a `Domain` that is a public suffix or does not cover the
  host (browsers reject it); no valid `Path`.
- **Session cookies**: names matching session/credential patterns
  (`sess`, `sid`, `auth`, `token`, … — configurable) get stricter
  severities, a 30-day lifetime limit (400 days for others) and a hint to
  use `__Host-`. Anti-CSRF cookies (`csrf`, `xsrf`) are not asked for
  `HttpOnly`.
- **Prefixes**: `__Secure-` / `__Host-` cookies that break their rules.
- **Syntax**: names and values outside the strict RFC 6265 §4.1.1 grammar,
  ignored `Expires` / `Max-Age` / `Path` values, valued flags, misspelled
  (`Http-Only`), repeated and unknown attributes, unparseable headers, the
  same cookie set twice.
- Cookies that delete themselves are only checked against the rules that
  make browsers reject them.
- **Report** each problem as a `rune_finding::Finding` with check id
  `cookie.<kind>` (CWE-614, -1004, -1275, -352, -319, -613 or -693, with
  remediation and references).

## Installation

```toml
[dependencies]
rune-cookie-sec = "0.1"
```

The `rune-cookie-sec` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-cookie-sec --features cli
```

## Usage

### Library

```rust
use rune_cookie_sec::{Options, run, run_response};
use rune_finding::Location;
use rune_http_model::HttpResponse;

let report = run("sessionid=abc; Domain=example.com", &Options::default());
let findings = report.to_findings::<()>(&Location::url("https://example.com/"));
assert!(findings.iter().any(|f| f.check_id == "cookie.missing_secure"));
assert!(findings.iter().any(|f| f.check_id == "cookie.broad_domain"));

let response = HttpResponse::new(200)
    .with_header("Set-Cookie", "__Host-sid=1; Path=/; Secure; HttpOnly; SameSite=Lax");
let options = Options::default().with_request_url("https://example.com/".parse().unwrap());
assert!(run_response(&response, &options).is_clean());
```

### CLI

```bash
rune-cookie-sec "sessionid=abc; Path=/; SameSite=None"
# medium        cookie.same_site_none_without_secure Cookie sessionid has SameSite=None without Secure; ...
# medium        cookie.missing_secure                Cookie sessionid has no Secure attribute ...
# medium        cookie.missing_http_only             Cookie sessionid has no HttpOnly attribute; ...

curl -sI https://example.com | grep -i '^set-cookie:' \
  | rune-cookie-sec --url https://example.com/
```

## License

MIT
