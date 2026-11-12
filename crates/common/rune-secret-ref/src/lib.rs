//! Secret references (`env:`, `file:`, `cmd:`) resolved into a redacting
//! [`SecretValue`].
//!
//! Configuration should never hold a credential inline, only a reference
//! to where it lives. A [`SecretRef`] is that reference, written as a
//! `scheme:location` string:
//!
//! - `env:API_TOKEN` — an environment variable,
//! - `file:/run/secrets/token` — a file (one trailing newline stripped; on
//!   unix it must not be readable by group or others),
//! - `cmd:pass show work/api` — a program's standard output (opt-in, see
//!   [`ResolveOptions::allow_command`]),
//! - `keychain:service/account` and `vault:path` — parsed here and
//!   resolved by a secret provider such as `rune-secret-vault`.
//!
//! Anything else is rejected as an inline secret ([`SecretError::Inline`]).
//! [`SecretRef::resolve`] produces a [`SecretValue`], whose `Debug`,
//! `Display` and `Serialize` output is always `<redacted>`; the plain text
//! is reachable only through [`SecretValue::expose`]. No error message
//! contains secret material.
//!
//! With the `serde` feature a `SecretRef` deserializes from a string or a
//! one-key table, so it can sit in a config struct loaded by
//! `rune-config` from any layer (file, environment variable, CLI flag).
//! The `zeroize` feature wipes secret buffers on drop.
//!
//! # Example
//!
//! ```
//! use rune_secret_ref::{ResolveOptions, SecretError, SecretRef};
//!
//! let reference: SecretRef = "env:API_TOKEN".parse()?;
//! assert_eq!(reference.scheme(), "env");
//!
//! // The caller supplies the environment; here, an in-memory map.
//! let env = |name: &str| (name == "API_TOKEN").then(|| "tok-123".to_owned());
//! let token = reference.resolve(&ResolveOptions::default(), env)?;
//!
//! assert_eq!(token.expose(), "tok-123");
//! assert_eq!(format!("{token:?}"), "SecretValue(<redacted>)");
//! assert_eq!(token.to_string(), "<redacted>");
//!
//! // A pasted credential is refused, and the error does not repeat it.
//! let error = "tok-123".parse::<SecretRef>().unwrap_err();
//! assert!(matches!(error, SecretError::Inline));
//! assert!(!error.to_string().contains("tok-123"));
//! # Ok::<(), SecretError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod reference;
mod resolve;
#[cfg(feature = "serde")]
mod serde_impl;
mod value;

pub use error::SecretError;
pub use reference::SecretRef;
pub use resolve::ResolveOptions;
pub use value::{REDACTED, SecretValue};
