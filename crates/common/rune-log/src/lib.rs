//! A structured-logging layer for [`tracing`](https://docs.rs/tracing) that
//! keeps secrets and PII out of logs.
//!
//! [`LogConfig`] picks a level filter, an output format ([`LogFormat`]: full
//! text, compact text or JSON lines) and a [`Redactor`] from
//! [`rune_redact`], and builds one `tracing-subscriber` layer from them.
//! Every value an event or span carries goes through the redactor before it
//! is written:
//!
//! - **Text formats** reuse `rune-redact`'s tracing integration:
//!   [`RedactingFields`](rune_redact::RedactingFields) for fields
//!   ([`RedactionScope::Fields`], the default) or
//!   [`RedactingMakeWriter`](rune_redact::RedactingMakeWriter) for the whole
//!   line ([`RedactionScope::Line`]).
//! - **JSON** uses this crate's [`JsonFormat`] and [`JsonFields`], which
//!   redact each value *before* escaping it, so the output stays valid JSON
//!   and numbers that look like card numbers or SSNs are caught too.
//!
//! Filter, format and scope can come from environment-style variables
//! (`RUST_LOG`, `LOG_FORMAT`, `LOG_REDACT`, or custom [`EnvKeys`]); the
//! library never reads the environment itself, the caller passes a lookup.
//!
//! This crate is only the logging layer. Metrics and trace export belong in
//! other layers on the same [`Registry`](tracing_subscriber::Registry):
//! [`LogConfig::layer`] returns a plain boxed layer to compose with them.
//!
//! # Example
//!
//! ```rust
//! use rune_log::{LogConfig, LogFormat};
//! # use std::sync::{Arc, Mutex};
//! # #[derive(Clone, Default)]
//! # struct Buf(Arc<Mutex<Vec<u8>>>);
//! # impl std::io::Write for Buf {
//! #     fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { self.0.lock().unwrap().extend_from_slice(b); Ok(b.len()) }
//! #     fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
//! # }
//! # impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buf {
//! #     type Writer = Self;
//! #     fn make_writer(&'a self) -> Self { self.clone() }
//! # }
//! # let buf = Buf::default();
//! # let sink = buf.clone();
//!
//! // In a binary: `.with_env(|k| std::env::var(k).ok())?` and `std::io::stderr`.
//! let config = LogConfig::default()
//!     .with_env(|k| (k == "LOG_FORMAT").then(|| "json".to_owned()))?
//!     .with_timestamps(false);
//! assert_eq!(config.format(), LogFormat::Json);
//!
//! tracing::subscriber::with_default(config.subscriber(sink), || {
//!     tracing::info!(target: "app", user = "bob@example.com", "login from 10.0.0.7");
//!     tracing::debug!("filtered out at the default `info` level");
//! });
//!
//! # let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
//! assert_eq!(
//!     out,
//!     "{\"level\":\"INFO\",\"target\":\"app\",\
//!      \"fields\":{\"message\":\"login from [IP]\",\"user\":\"[EMAIL]\"}}\n",
//! );
//! # Ok::<(), rune_log::Error>(())
//! ```
//!
//! To install it for the whole process, call
//! [`LogConfig::try_init`] once at the top of `main`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod config;
mod error;
mod json;

pub use config::{BoxedLayer, EnvKeys, LogConfig, LogFormat, RedactionScope};
pub use error::Error;
pub use json::{JsonFields, JsonFormat};
pub use rune_redact::{Policy, Redactor, Replacement};
