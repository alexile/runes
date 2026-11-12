# rune-cors

> Analyze CORS response headers for dangerous origin, credential and allowlist combinations, reporting rune-finding findings

[![crates.io](https://img.shields.io/crates/v/rune-cors)](https://crates.io/crates/rune-cors)
[![docs.rs](https://img.shields.io/docsrs/rune-cors)](https://docs.rs/rune-cors)
[![license](https://img.shields.io/crates/l/rune-cors)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A sans-I/O analyzer for the
[CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol). It is
the reading side of the CORS layer in `rune-axum-cors`.

- **Parse** `Access-Control-*` and `Vary` response headers from pairs or a
  raw header block, combining repeats as browsers do.
- **Check**: run the Fetch CORS check for a request origin and get the
  exposure — none, anonymous, or credentialed.
- **Classify** request origins relative to the site and its trusted
  origins: same origin, trusted, subdomain, plain-`http` variant,
  unanchored-suffix (`evilexample.com`) and -prefix
  (`example.com.evil.net`) lookalikes, `null`, arbitrary. `probes` lists
  one origin of each class to send.
- **Analyze** a table of (request origin, response headers) exchanges:

  | Combination                                        | Check id                              | Severity (credentials / none) |
  | -------------------------------------------------- | ------------------------------------- | ----------------------------- |
  | Arbitrary origin reflected                         | `cors.origin_reflection`              | critical / low                |
  | `null` allowed                                     | `cors.null_origin`                    | high / low                    |
  | Lookalike passes an unanchored allowlist           | `cors.unanchored_allowlist`           | high / low                    |
  | `http://` variant of a secure origin allowed       | `cors.insecure_origin`                | medium / info                 |
  | Arbitrary subdomain reflected                      | `cors.subdomain_origin`               | low / info                    |
  | Private network access to an attacker origin       | `cors.private_network_access`         | medium                        |
  | `*` with `Access-Control-Allow-Credentials: true`  | `cors.wildcard_with_credentials`      | low                           |
  | `*`                                                | `cors.wildcard_origin`                | info                          |
  | Echoed origin without `Vary: Origin`               | `cors.missing_vary_origin`            | low                           |
  | Allow-Origin that can never match                  | `cors.invalid_allow_origin`           | info                          |
  | Allow-Credentials other than `true`                | `cors.invalid_allow_credentials`      | info                          |
  | `*` in method/header lists on credentialed replies | `cors.wildcard_list_with_credentials` | info                          |

- **Report** each weakness as a `rune_finding::Finding` (`cors.<kind>`,
  CWE-942, CWE-346 or CWE-524, remediation and references).

## Installation

```toml
[dependencies]
rune-cors = "0.1"
```

The `rune-cors` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-cors --features cli
```

## Usage

### Library

```rust
use rune_cors::{CorsHeaders, Exchange, Options, WeaknessKind, probes, run};
use rune_finding::{Location, Severity};

let target = "https://bank.example".parse().unwrap();
let options = Options::for_target(target);

// Send each probe origin, then feed the responses back in.
let exchanges: Vec<Exchange> = probes(options.target.as_ref().unwrap())
    .iter()
    .map(|p| {
        // Stand-in for a real response from a server that reflects everything.
        let headers = CorsHeaders::from_pairs([
            ("Access-Control-Allow-Origin", p.origin.as_str()),
            ("Access-Control-Allow-Credentials", "true"),
        ]);
        Exchange::new(Some(&p.origin), headers)
    })
    .collect();

let report = run(&exchanges, &options);
assert_eq!(report.max_severity(), Some(Severity::Critical));
assert!(report.weaknesses.iter().any(|w| w.kind == WeaknessKind::NullOrigin));

let findings = report.to_findings::<()>(&Location::url("https://bank.example/api"));
assert!(findings.iter().any(|f| f.check_id == "cors.origin_reflection"));
```

### CLI

```bash
rune-cors --target https://bank.example --probes
# same_origin        https://bank.example
# arbitrary          https://rune-cors-probe.example
# null               null
# ...

curl -sI -H 'Origin: https://rune-cors-probe.example' https://bank.example/api \
  | rune-cors --target https://bank.example --origin https://rune-cors-probe.example
# origin=https://rune-cors-probe.example class=arbitrary reflected=true exposure=credentialed
# critical      cors.origin_reflection               Arbitrary origin https://rune-cors-probe.example is reflected with credentials: ...
```

## License

MIT
