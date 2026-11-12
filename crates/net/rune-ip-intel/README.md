# rune-ip-intel

> IP-reputation provider trait with AbuseIPDB, GreyNoise, Shodan InternetDB and Censys adapters, normalized verdicts, caching and rate limits over a caller-supplied transport

[![crates.io](https://img.shields.io/crates/v/rune-ip-intel)](https://crates.io/crates/rune-ip-intel)
[![docs.rs](https://img.shields.io/docsrs/rune-ip-intel)](https://docs.rs/rune-ip-intel)
[![license](https://img.shields.io/crates/l/rune-ip-intel)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Enrich an IP address from several reputation and exposure sources behind
one interface.

- `ReputationProvider` splits each source into a sans-I/O request builder
  and a response parser that returns a normalized `Verdict`:
  classification (`unknown` / `benign` / `suspicious` / `malicious`), 0-100
  score, categories, tags, last-seen time, open ports, host names, CVEs,
  AS, organization, country, and the provider's raw JSON.
- `Enricher` asks every configured provider, caches verdicts for a TTL,
  paces each provider (minimum interval, back-off on 429 / `Retry-After`),
  refuses non-global addresses (via `rune-ip`, so private addressing never
  leaks to a third party), and merges the answers into a `Summary`.
- No HTTP client and no I/O: you supply a `Transport` (any
  `Fn(&HttpRequest) -> Result<HttpResponse, TransportError>`), or drive
  `request`/`parse` from an async client yourself.
- API keys are `rune_secret_ref::SecretValue`s, sent only in headers that
  `Debug` redacts.

| Adapter | Feature | Credentials | Endpoint |
| --- | --- | --- | --- |
| `AbuseIpDb` | `abuseipdb` | API key | [`/api/v2/check`](https://docs.abuseipdb.com/#check-endpoint) (verbose, for categories) |
| `GreyNoise` | `greynoise` | optional key | [Community API v3](https://docs.greynoise.io/reference/get_v3-community-ip) |
| `ShodanInternetDb` | `shodan` | none | [InternetDB](https://internetdb.shodan.io/docs) |
| `Censys` | `censys` | API ID + secret | [Search API v2 host view](https://search.censys.io/api#/hosts/viewHost) |

All four adapters are default features; disable the ones you do not use.
Each takes `with_base_url` for proxies and mocks.

## Installation

```toml
[dependencies]
rune-ip-intel = "0.1"
```

## Usage

```rust
use std::time::{Duration, Instant};
use rune_ip_intel::{
    Classification, Enricher, GreyNoise, HttpRequest, HttpResponse, Options,
    ShodanInternetDb, TransportError,
};

let mut enricher = Enricher::new(Options::default().with_cache_ttl(Duration::from_secs(3600)))
    // GreyNoise Community: at most one request every 2 seconds.
    .with_provider(GreyNoise::new(), Duration::from_secs(2))
    .with_provider(ShodanInternetDb::new(), Duration::ZERO);

// Wrap your HTTP client; this stand-in answers offline.
let transport = |request: &HttpRequest| -> Result<HttpResponse, TransportError> {
    Ok(if request.url.contains("greynoise") {
        HttpResponse::new(200).with_body(
            r#"{"noise":true,"riot":false,"classification":"malicious","last_seen":"2024-05-01"}"#,
        )
    } else {
        HttpResponse::new(404).with_body(r#"{"detail":"No information available"}"#)
    })
};

let summary = enricher.enrich("8.8.4.4".parse()?, &transport, Instant::now())?;
assert_eq!(summary.classification, Classification::Malicious);
assert_eq!(summary.tags, ["scanner"]);
for (provider, error) in &summary.errors {
    eprintln!("{provider}: {error}");
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

With keys from configuration:

```rust,no_run
use rune_ip_intel::{AbuseIpDb, Censys};
use rune_secret_ref::{ResolveOptions, SecretRef};

let options = ResolveOptions::default();
let env = |name: &str| std::env::var(name).ok();
let secret = |reference: &str| -> Result<_, Box<dyn std::error::Error>> {
    Ok(reference.parse::<SecretRef>()?.resolve(&options, env)?)
};
let abuse = AbuseIpDb::new(secret("env:ABUSEIPDB_KEY")?);
let censys = Censys::new(&secret("env:CENSYS_API_ID")?, &secret("env:CENSYS_API_SECRET")?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Implement `ReputationProvider` for an in-house feed and add it to the same
`Enricher`.

## License

MIT
