# rune-permissions-policy

> Parse, analyze and canonicalize Permissions-Policy and legacy Feature-Policy headers, flagging over-permissive grants as rune-finding findings

[![crates.io](https://img.shields.io/crates/v/rune-permissions-policy)](https://crates.io/crates/rune-permissions-policy)
[![docs.rs](https://img.shields.io/docsrs/rune-permissions-policy)](https://docs.rs/rune-permissions-policy)
[![license](https://img.shields.io/crates/l/rune-permissions-policy)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A sans-I/O parser and analyzer for
[Permissions Policy](https://www.w3.org/TR/permissions-policy/) headers
(RFC 8941 structured-field dictionaries) and the legacy
[Feature Policy](https://wicg.github.io/feature-policy/) syntax.

- **Parse** `Permissions-Policy` strictly, as browsers do (a syntax error
  means the whole header is ignored), and `Feature-Policy` leniently, into
  feature → allowlist (`*`, `self`, `src`, origins, ignored members) with
  the `report-to` parameter. Repeated features follow each syntax's rule
  (last wins in a dictionary, first in Feature-Policy).
- **Serialize** the canonical form, which round-trips, and migrate a
  Feature-Policy to Permissions-Policy syntax.
- **Analyze**: `*` grants of powerful features rated by a built-in feature
  registry (camera, microphone, geolocation, payment, USB… high; sensors,
  clipboard writes, ad APIs… moderate), `http://` origins, members browsers
  ignore (`"self"`, `none`, non-origin strings), `src` in a header,
  redundant members, duplicate, unknown and deprecated features, the
  legacy header, and optionally features that must be declared.
- **Report** each problem as a `rune_finding::Finding`
  (`permissions_policy.<kind>`, CWE-693 plus CWE-732 for over-broad grants,
  remediation and references).

## Installation

```toml
[dependencies]
rune-permissions-policy = "0.1"
```

The `rune-permissions-policy` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-permissions-policy --features cli
```

## Usage

### Library

```rust
use rune_finding::Location;
use rune_permissions_policy::{Options, PermissionsPolicy, RECOMMENDED_RESTRICTED, run};

let policy = PermissionsPolicy::parse("camera=(), geolocation=(self \"https://maps.example\")")
    .expect("valid header");
assert!(policy.get("camera").is_some_and(|d| d.allowlist.is_none()));

let options = Options::default().with_restricted_features(RECOMMENDED_RESTRICTED.iter().copied());
let report = run("camera=*, microphone=none", &options);
let findings = report.to_findings::<()>(&Location::url("https://example.com/"));
assert!(findings.iter().any(|f| f.check_id == "permissions_policy.allow_all"));
assert!(findings.iter().any(|f| f.check_id == "permissions_policy.invalid_member"));
assert!(findings.iter().any(|f| f.check_id == "permissions_policy.unrestricted_feature"));
```

### CLI

```bash
rune-permissions-policy 'camera=*, geolocation="self"'
# camera=*, geolocation=("self")
# medium        permissions_policy.allow_all               camera=* lets every origin use camera ...
# low           permissions_policy.invalid_member          geolocation: member "self" is ignored ...

rune-permissions-policy --feature-policy --migrate "camera 'none'; usb 'self'"
# camera=(), usb=(self)
# informational permissions_policy.legacy_feature_policy   Feature-Policy is deprecated; ...
```

## License

MIT
