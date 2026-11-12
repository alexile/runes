//! Secret providers for [`rune_secret_ref`] references: environment,
//! files, commands, the OS keyring and Vault, with TTL caching.
//!
//! `rune-secret-ref` parses `scheme:location` references and resolves the
//! local ones; this crate adds a [`SecretProvider`] trait with one adapter
//! per backend, a [`SecretResolver`] that routes each reference to the
//! provider for its [scheme](SecretRef::scheme), and a [`CachedProvider`]
//! that keeps resolved secrets for a time-to-live.
//!
//! | Scheme | Provider | Feature |
//! |---|---|---|
//! | `env:VAR` | [`EnvProvider`] (lookup function you pass) | — |
//! | `file:PATH` | [`FileProvider`] | — |
//! | `cmd:PROGRAM ARG…` | [`CommandProvider`] (registering it is the opt-in) | — |
//! | `keychain:SERVICE/ACCOUNT` | `KeyringProvider` (bring your own keyring-core store) | `keyring` |
//! | `vault:MOUNT/PATH#FIELD` | `VaultProvider` (KV v1/v2, bring your own token) | `vault` |
//! | | `UreqTransport`, a blocking HTTPS transport for it | `vault-ureq` |
//!
//! Every secret comes back as a [`SecretValue`], which prints as
//! `<redacted>`. The crate does no logging, and no error, `Debug` output
//! or cache dump contains a secret or the Vault token.
//!
//! # Example
//!
//! ```
//! use std::time::Duration;
//! use rune_secret_vault::{CachedProvider, EnvProvider, FileProvider, SecretResolver};
//! use rune_secret_vault::SecretProvider;
//!
//! // In a real program: `|name| std::env::var(name).ok()`.
//! let env = |name: &str| (name == "API_TOKEN").then(|| "tok-123".to_owned());
//!
//! let resolver = SecretResolver::new()
//!     .with_provider(EnvProvider::new(env))
//!     .with_provider(FileProvider::default());
//! let secrets = CachedProvider::new(resolver, Duration::from_secs(300));
//!
//! let token = secrets.resolve(&"env:API_TOKEN".parse()?)?;
//! assert_eq!(token.expose(), "tok-123");
//! assert_eq!(format!("{token:?}"), "SecretValue(<redacted>)");
//! # Ok::<(), rune_secret_vault::ProviderError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod cache;
mod error;
#[cfg(feature = "keyring")]
mod keyring;
mod provider;
mod resolver;
#[cfg(feature = "vault")]
mod vault;

pub use cache::{CachedProvider, Clock, SystemClock};
pub use error::{BoxError, ProviderError};
#[cfg(feature = "keyring")]
pub use keyring::KeyringProvider;
pub use provider::{CommandProvider, EnvProvider, FileProvider, SecretProvider};
pub use resolver::SecretResolver;
pub use rune_secret_ref::{ResolveOptions, SecretError, SecretRef, SecretValue};
#[cfg(feature = "vault-ureq")]
pub use vault::UreqTransport;
#[cfg(feature = "vault")]
pub use vault::{
    KvVersion, VaultConfig, VaultProvider, VaultRequest, VaultResponse, VaultTransport,
};
