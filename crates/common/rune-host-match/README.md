# rune-host-match

> Hostname pattern matching: exact, *.suffix egress allowlists and RFC 6125 certificate wildcards

[![crates.io](https://img.shields.io/crates/v/rune-host-match)](https://crates.io/crates/rune-host-match)
[![docs.rs](https://img.shields.io/docsrs/rune-host-match)](https://docs.rs/rune-host-match)
[![license](https://img.shields.io/crates/l/rune-host-match)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Egress allowlists and TLS certificate names both use `*.example.com`, but
they mean different things. This crate gives each its own type, so neither
gets the other's rules by accident:

| `*.example.com` against | `HostPattern` (allowlist) | `CertName` (certificate) |
| ----------------------- | ------------------------- | ------------------------ |
| `api.example.com`       | matches                   | matches                  |
| `a.b.example.com`       | matches (any depth)       | no (one label only)      |
| `example.com` (apex)    | no                        | no                       |
| `evilexample.com`       | no                        | no                       |

- **`Hostname`**: a validated, normalized name. It is ASCII-lowercased and
  drops one trailing dot. Labels follow RFC 1123 (plus `_`), with the
  RFC 1035 length limits. IP literals are rejected; match those with
  `rune-cidr`.
- **`HostPattern` / `HostAllowlist`**: allowlist semantics. A pattern is an
  exact name (`example.com`), `*.suffix` (every subdomain, never the apex),
  or whole-label wildcards (`api.*.example.com`, where each `*` is one
  label). Partial wildcards (`f*o`) and unanchored ones (`*`, `example.*`)
  are rejected.
- **`CertName` / `cert_name_matches` / `cert_names_match`**: certificate
  semantics per [RFC 6125 §6.4.3](https://www.rfc-editor.org/rfc/rfc6125#section-6.4.3)
  and [RFC 9525 §6.3](https://www.rfc-editor.org/rfc/rfc9525#section-6.3).
  The wildcard must be the single left-most label and covers exactly one
  label. `*.com` is rejected as too broad.
- **Public suffixes** (feature `psl`): without the Public Suffix List,
  `*.co.uk` looks like any other wildcard. The `psl` feature uses
  [`rune-psl`](../rune-psl) to reject it: `CertName::parse_with_psl` and
  `cert_names_match_with_psl` for certificates, and
  `HostPattern::is_public_suffix_wildcard` to vet allowlists and scan
  scopes.

Malformed patterns are errors at parse time. A malformed host never matches.
The crate does no I/O. By default it has no dependencies beyond `thiserror`.

## Installation

```toml
[dependencies]
rune-host-match = "0.1"
```

Enable the `serde` feature to read patterns from configuration files. Each
type is (de)serialized as a string, and an allowlist as a list of strings.
Deserialization validates every value.

Enable the `psl` feature for the Public Suffix List checks. It brings in
`rune-psl` with its embedded list, which is re-exported as
`rune_host_match::rune_psl`.

## Usage

```rust
use rune_host_match::{cert_names_match, HostAllowlist, HostPattern, PatternKind};

// Egress allowlist (e.g. a CONNECT proxy).
let allow = HostAllowlist::parse_all(["api.anthropic.com", "*.github.com"]).unwrap();
assert!(allow.allows("API.Anthropic.com."));
assert!(allow.allows("codeload.github.com"));
assert!(!allow.allows("github.com"));
assert!(!allow.allows("evilgithub.com"));
assert_eq!(
    allow.matching("codeload.github.com").map(HostPattern::kind),
    Some(PatternKind::Subdomains)
);

// TLS: does any SAN cover the server name?
let sans = ["example.com", "*.example.com"];
assert!(cert_names_match(sans, "www.example.com"));
assert!(!cert_names_match(sans, "a.b.example.com"));
```

With the `psl` feature:

```rust,ignore
use rune_host_match::{cert_names_match_with_psl, CertName, Error, HostPattern};
use rune_host_match::rune_psl::List;

// Browsers check certificate wildcards against the ICANN section only, so
// `*.github.io` (a private suffix) stays valid.
let icann = List::embedded().with_private_rules(false);
assert_eq!(CertName::parse_with_psl("*.co.uk", &icann), Err(Error::PublicSuffixWildcard));
assert!(!cert_names_match_with_psl(["*.co.uk"], "example.co.uk", &icann));
assert!(cert_names_match_with_psl(["*.github.io"], "rune.github.io", &icann));

// An allowlist entry that covers every customer of a hosting provider.
let full = List::embedded();
assert!(HostPattern::parse("*.github.io").unwrap().is_public_suffix_wildcard(&full));
```

## License

MIT
