# rune-secret-vault

> Secret providers (env, file, OS keyring, HashiCorp Vault) with TTL caching over rune-secret-ref

[![crates.io](https://img.shields.io/crates/v/rune-secret-vault)](https://crates.io/crates/rune-secret-vault)
[![docs.rs](https://img.shields.io/docsrs/rune-secret-vault)](https://docs.rs/rune-secret-vault)
[![license](https://img.shields.io/crates/l/rune-secret-vault)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

[`rune-secret-ref`](../rune-secret-ref) parses secret references such as
`env:API_TOKEN` or `vault:secret/app#token`. This crate resolves them: a
`SecretProvider` trait with one adapter per backend, a `SecretResolver` that
routes each reference to the provider for its scheme, and a
`CachedProvider` that keeps resolved secrets for a time-to-live.

| Scheme | Provider | Feature |
|---|---|---|
| `env:VAR` | `EnvProvider` (you pass the lookup function) | — |
| `file:PATH` | `FileProvider` (owner-only permissions on unix) | — |
| `cmd:PROGRAM ARG…` | `CommandProvider` (registering it is the opt-in) | — |
| `keychain:SERVICE/ACCOUNT` | `KeyringProvider` over a [keyring-core](https://crates.io/crates/keyring-core) store you choose | `keyring` |
| `vault:MOUNT/PATH#FIELD` | `VaultProvider`, Vault KV v1/v2, bring your own token | `vault` |
| | `UreqTransport`, blocking HTTPS (rustls) for `VaultProvider` | `vault-ureq` |

Every secret is a `SecretValue` that prints as `<redacted>`. The crate does
no logging, and no error message, `Debug` output or cache dump contains a
secret or the Vault token. Failed lookups are never cached.

## Installation

```toml
[dependencies]
rune-secret-vault = { version = "0.1", features = ["vault-ureq", "keyring"] }
```

## Usage

```rust
use std::time::Duration;
use rune_secret_vault::{
    CachedProvider, EnvProvider, FileProvider, SecretProvider, SecretResolver,
};

let resolver = SecretResolver::new()
    .with_provider(EnvProvider::new(|name| std::env::var(name).ok()))
    .with_provider(FileProvider::default());
let secrets = CachedProvider::new(resolver, Duration::from_secs(300));

let token = secrets.resolve(&"file:/run/secrets/api".parse()?)?;
send(token.expose());
# fn send(_: &str) {}
# Ok::<(), rune_secret_vault::ProviderError>(())
```

### Vault

`vault:MOUNT/PATH#FIELD` reads one field of a KV secret. The mount is the
first path segment unless a longer one is registered with `with_mount`;
KV v2 is the default (`with_kv_version` / `with_mount(…, KvVersion::V1)`
for v1). `#FIELD` may be omitted when the secret has a single field.

```rust,no_run
use rune_secret_vault::{
    KvVersion, SecretProvider, SecretValue, UreqTransport, VaultConfig, VaultProvider,
};

let token = SecretValue::new(std::env::var("VAULT_TOKEN")?);
let config = VaultConfig::new("https://vault.example:8200", token)?
    .with_namespace("team-a")
    .with_mount("legacy", KvVersion::V1);
let vault = VaultProvider::new(config, UreqTransport::new());

let password = vault.resolve(&"vault:secret/app/db#password".parse()?)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The core is sans-I/O: `VaultConfig::request` builds the URL and headers and
`VaultConfig::parse_response` extracts the secret, so any HTTP client works.
A `VaultTransport` is any `Fn(&VaultRequest) -> Result<VaultResponse, BoxError>`;
it must not follow redirects (`UreqTransport` does not, so the token never
leaves for another host).

### Keyring

```rust,ignore
let store = apple_native_keyring_store::keychain::Store::new()?; // or another keyring-core store
let keyring = KeyringProvider::new(store);
let key = keyring.resolve(&"keychain:myapp/api".parse()?)?;
```

The provider uses the store it is given, never keyring-core's process-wide
default unless you call `KeyringProvider::from_default_store()`.

## Features

- `keyring` — `KeyringProvider` (keyring-core; platform store crates are yours to pick).
- `vault` — `VaultProvider`, `VaultConfig` and the `VaultTransport` trait (adds `serde_json`).
- `vault-ureq` — `UreqTransport` (adds `ureq` with rustls and webpki roots).

All are off by default. Tests run offline: Vault through an in-memory
transport and a loopback HTTP server, the keyring through keyring-core's
mock store.
