//! Layered TOML configuration (defaults, files, environment, CLI) with
//! per-key source tracking.
//!
//! A [`ConfigLoader`] stacks ordered layers, each overriding the ones
//! before it: built-in defaults, the user file
//! ([`default_user_config_path`]), the project file, environment variables
//! ([`EnvMapping`]) and command-line flags ([`CliOverrides`]). Tables merge
//! deeply; every leaf value remembers which layer set it. The result, a
//! [`LoadedConfig`], deserializes into your own `serde` type, and every
//! problem, from a syntax error to a type mismatch, comes back as a
//! [`ConfigIssue`] that names the offending layer and key.
//!
//! The library performs no hidden I/O: it never reads the environment, and
//! it reads files only when you add a file layer.
//!
//! # Example
//!
//! ```
//! use rune_config::{CliOverrides, ConfigLoader, EnvMapping, Source, ValueKind};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Default, Deserialize, Serialize)]
//! #[serde(deny_unknown_fields)]
//! struct Config {
//!     scan: Scan,
//! }
//!
//! #[derive(Debug, Deserialize, Serialize)]
//! #[serde(deny_unknown_fields)]
//! struct Scan {
//!     rate_limit: u32,
//!     concurrency: u32,
//!     profile: String,
//! }
//!
//! impl Default for Scan {
//!     fn default() -> Self {
//!         Self { rate_limit: 5, concurrency: 8, profile: "standard".into() }
//!     }
//! }
//!
//! let project = Source::Inline("app.toml".into());
//! let env = [("APP_SCAN__CONCURRENCY", "2"), ("APP_PROFILE", "quick")];
//! let mapping = EnvMapping::new()
//!     .prefix("APP_")
//!     .var_as("APP_PROFILE", "scan.profile", ValueKind::String);
//!
//! let loaded = ConfigLoader::new()
//!     .with_defaults_from(&Config::default())
//!     .with_toml(project.clone(), "[scan]\nrate_limit = 10\n")
//!     .with_env(env, &mapping)
//!     .with_cli(&CliOverrides::new().set_opt("--rps", "scan.rate_limit", Some(20)))
//!     .load()?;
//!
//! let config: Config = loaded.deserialize()?;
//! assert_eq!(config.scan.rate_limit, 20);
//! assert_eq!(config.scan.concurrency, 2);
//! assert_eq!(config.scan.profile, "quick");
//! assert_eq!(loaded.source_of("scan.rate_limit"), Some(&Source::Cli("--rps".into())));
//!
//! // A bad value is reported against the layer that set it.
//! let errors = ConfigLoader::new()
//!     .with_defaults_from(&Config::default())
//!     .with_toml(project.clone(), "[scan]\nrate_limit = \"fast\"\n")
//!     .load()?
//!     .deserialize::<Config>()
//!     .unwrap_err();
//! let issue = &errors.issues()[0];
//! assert_eq!(issue.source, project);
//! assert_eq!(issue.key.as_deref(), Some("scan.rate_limit"));
//! # Ok::<(), rune_config::ConfigErrors>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod issue;
mod key;
mod loader;
mod overrides;
mod paths;
mod value;

pub use issue::{ConfigErrors, ConfigIssue, Source};
pub use key::{format_key, parse_key};
pub use loader::{ConfigLoader, LoadedConfig, parse_toml};
pub use overrides::{CliOverrides, EnvMapping};
pub use paths::{Platform, default_user_config_path, user_config_path_for};
pub use toml::{Table, Value};
pub use value::ValueKind;
