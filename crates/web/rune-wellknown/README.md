# rune-wellknown

> Discover and parse /.well-known resources (security.txt, change-password, MTA-STS, OpenID configuration, assetlinks, apple-app-site-association) into typed models

[![crates.io](https://img.shields.io/crates/v/rune-wellknown)](https://crates.io/crates/rune-wellknown)
[![docs.rs](https://img.shields.io/docsrs/rune-wellknown)](https://docs.rs/rune-wellknown)
[![license](https://img.shields.io/crates/l/rune-wellknown)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Typed parsers for the common [`/.well-known`](https://www.rfc-editor.org/rfc/rfc8615)
resources a site publishes:

| Resource | Model | Specification |
| --- | --- | --- |
| `security.txt` | `rune_securitytxt::SecurityTxt` | [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) |
| `change-password` | `ChangePassword` (redirect / page / unsupported) | [W3C Change Password URL](https://w3c.github.io/webappsec-change-password-url/) |
| `mta-sts.txt` | `MtaStsPolicy` (with MX matching) | [RFC 8461](https://www.rfc-editor.org/rfc/rfc8461#section-3.2) |
| `openid-configuration` | `OpenIdConfiguration` | [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) |
| `assetlinks.json` | `AssetLinks` | [Digital Asset Links](https://developers.google.com/digital-asset-links/v1/statements) |
| `apple-app-site-association` | `AppleAppSiteAssociation` | [Apple associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains) |

`parse(path, &response)` dispatches on the request path; any other path is
returned raw as `Resource::Unknown`. The core is sans-I/O: you hand it the
status, headers and body you received. Bodies are capped at 1 MiB (64 KiB
for MTA-STS) and must be UTF-8.

Optional fetching helpers:

- `fetch` — `fetch::discover` / `fetch::fetch` over any client that
  implements `fetch::Fetcher` (one `GET`, no redirects), plus URL helpers.
  No extra dependencies.
- `reqwest` — `fetch::ReqwestFetcher`, a ready-made `Fetcher` on reqwest
  (needs a Tokio runtime).

## Installation

```toml
[dependencies]
rune-wellknown = { version = "0.1", features = ["reqwest"] }
```

The `rune-wellknown` command-line tool (parses a saved resource) is behind
the opt-in `cli` feature:

```bash
cargo install rune-wellknown --features cli
```

## Usage

### Library

```rust
use rune_wellknown::{Resource, Response, WellKnown, parse};

let body = r#"[{"relation":["delegate_permission/common.handle_all_urls"],
  "target":{"namespace":"android_app","package_name":"com.example.app",
            "sha256_cert_fingerprints":["14:6D:E9"]}}]"#;
let response = Response::new(200, body).with_header("Content-Type", "application/json");
match parse(&WellKnown::AssetLinks.path(), &response).expect("valid assetlinks") {
    Resource::AssetLinks(links) => {
        let apps = links.android_apps(rune_wellknown::HANDLE_ALL_URLS);
        assert_eq!(apps[0].0, "com.example.app");
    }
    other => unreachable!("{other:?}"),
}
```

With the `reqwest` feature:

```rust,ignore
use rune_wellknown::{WellKnown, fetch::{ReqwestFetcher, discover}};

let fetcher = ReqwestFetcher::new()?;
for found in discover(&fetcher, "https://example.com", &WellKnown::ALL).await {
    println!("{} {}: {:?}", found.kind, found.url, found.result.map(|r| r.kind()));
}
```

### CLI

```bash
curl -s https://mta-sts.example.com/.well-known/mta-sts.txt | rune-wellknown mta-sts.txt
rune-wellknown assetlinks.json saved/assetlinks.json
```

## License

MIT
