//! Layered configuration with per-key source tracking, a `.env` parser and
//! environment-to-struct deserialization.
//!
//! - [`Dotenv`] parses `.env` text (quotes, escapes, multiline values,
//!   comments, `export`, opt-in `${VAR}` expansion, never command
//!   substitution) with line/column errors and the line of every variable.
//! - [`EnvReader`] and [`from_env`] deserialize environment variables into a
//!   `serde` type: `APP_DB__HOST` sets `db.host`, lists are comma-separated
//!   or JSON, and errors name the variable.
//! - [`ConfigLoader`] stacks ordered layers, each overriding the ones
//!   before it: built-in defaults, the user file
//!   ([`default_user_config_path`]), the project file, a `.env` file
//!   ([`ConfigLoader::with_dotenv_file`]), environment variables
//!   ([`EnvMapping`]) and explicit overrides such as command-line flags
//!   ([`CliOverrides`]). Tables merge deeply; every leaf value remembers
//!   which layer set it, and [`LoadedConfig::report`] lists them with
//!   secret-looking values hidden ([`is_secret_key`]). The result
//!   deserializes into your own `serde` type, and every problem comes back
//!   as a [`ConfigIssue`] that names the offending layer and key.
//!
//! The library performs no hidden I/O: it reads the process environment
//! only in [`from_env`], [`EnvReader::from_env`] and
//! [`ConfigLoader::with_process_env`], reads files only for the file layers
//! you add (each limited to [`DEFAULT_MAX_FILE_SIZE`] by default), and
//! writes the environment only in the `unsafe`
//! [`Dotenv::load_into_process_env`].
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

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod dotenv;
mod env;
mod issue;
mod key;
mod loader;
mod overrides;
mod paths;
mod read;
mod redact;
mod value;

pub use dotenv::{Dotenv, DotenvEntry, DotenvError, DotenvErrorKind, DotenvOptions, format_dotenv};
pub use env::{EnvError, EnvReader, from_env};
pub use issue::{ConfigErrors, ConfigIssue, Source};
pub use key::{format_key, parse_key};
pub use loader::{ConfigLoader, ConfigReport, LoadedConfig, ReportEntry, parse_toml};
pub use overrides::{CliOverrides, EnvMapping};
pub use paths::{Platform, default_user_config_path, user_config_path_for};
pub use read::DEFAULT_MAX_FILE_SIZE;
pub use redact::{REDACTED, is_secret_key};
pub use toml::{Table, Value};
pub use value::ValueKind;
