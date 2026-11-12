//! One-call `tracing` setup with optional OTLP trace export.
//!
//! [`init`] reads `RUST_LOG`, `RUST_LOG_FORMAT` and the standard `OTEL_*`
//! variables, installs a `tracing-subscriber` stack that writes log lines to
//! stderr and, when an OTLP endpoint is configured, exports spans over
//! OTLP/gRPC through `tracing-opentelemetry`. It is the non-Axum counterpart
//! of `rune-axum-trace`'s `TraceConfig`; installed globally, both share one
//! OpenTelemetry tracer provider.
//!
//! The configuration is plain data ([`TelemetryConfig`]) parsed by a
//! sans-I/O function from any variable lookup, so it is testable without
//! touching the process environment. [`Telemetry`] turns it into a
//! subscriber, either installed globally or returned as a [`tracing::Dispatch`].
//!
//! # Features
//!
//! - `otlp`: OTLP/gRPC span export (OpenTelemetry, tonic). Off by default,
//!   so a library can depend on this crate for its configuration types
//!   without pulling OpenTelemetry in; the application turns it on.
//! - `json`: the `json` log format.
//!
//! # Sane defaults
//!
//! | Setting      | Default                           | Variable                          |
//! | ------------ | --------------------------------- | --------------------------------- |
//! | filter       | `info`                            | `RUST_LOG`                        |
//! | format       | full single-line                  | `RUST_LOG_FORMAT`                 |
//! | colours      | when stderr is a terminal         | `NO_COLOR`                        |
//! | service name | `unknown_service`                 | `OTEL_SERVICE_NAME`               |
//! | span export  | off, on once an endpoint is set   | `OTEL_TRACES_EXPORTER`            |
//! | endpoint     | `http://localhost:4317`           | `OTEL_EXPORTER_OTLP_ENDPOINT`     |
//! | sampler      | `parentbased_always_on`           | `OTEL_TRACES_SAMPLER`             |
//!
//! See [`TelemetryConfig::with_env`] for every variable and its precedence.
//!
//! # Example
//!
//! Build a subscriber from an explicit environment and use it locally:
//!
//! ```
//! use rune_telemetry::{Telemetry, TelemetryConfig};
//!
//! let env = [("RUST_LOG", "debug"), ("NO_COLOR", "1")];
//! let config = TelemetryConfig::default()
//!     .with_service_name("worker")
//!     .with_env(|k| env.iter().find(|(n, _)| *n == k).map(|(_, v)| (*v).to_owned()))?;
//!
//! let (dispatch, guard) = Telemetry::new(config).with_writer(std::io::sink).build()?;
//! tracing::dispatcher::with_default(&dispatch, || {
//!     let span = tracing::info_span!("job", id = 7);
//!     let _entered = span.enter();
//!     tracing::debug!("working");
//! });
//! guard.shutdown()?;
//! # Ok::<(), rune_telemetry::Error>(())
//! ```
//!
//! In an application, one call at the top of `main` (inside the Tokio
//! runtime when OTLP export is on):
//!
//! ```no_run
//! # async fn run() -> Result<(), rune_telemetry::Error> {
//! let guard = rune_telemetry::init()?;
//! tracing::info!("started");
//! // ... run the program ...
//! guard.shutdown()?;
//! # Ok(()) }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod config;
mod error;
mod telemetry;

pub use config::{
    DEFAULT_FILTER, DEFAULT_OTLP_ENDPOINT, DEFAULT_OTLP_TIMEOUT, DEFAULT_SERVICE_NAME, LogFormat,
    OtlpConfig, OtlpProtocol, Sampler, TelemetryConfig, TracesExporter, parse_key_values, vars,
};
pub use error::Error;
pub use telemetry::{Telemetry, TelemetryGuard};

/// Re-export of the `opentelemetry` crate this build links, for callers that
/// add their own spans or propagation with matching versions.
#[cfg(feature = "otlp")]
pub use opentelemetry;
/// Re-export of the `opentelemetry_sdk` crate, for custom span exporters
/// passed to [`Telemetry::with_span_exporter`].
#[cfg(feature = "otlp")]
pub use opentelemetry_sdk;

/// Configures and installs telemetry from the process environment.
///
/// Equivalent to
/// `Telemetry::new(TelemetryConfig::default().with_env(|k| std::env::var(k).ok())?).install()`.
/// This is the crate's only entry point that reads the environment; it is
/// meant for application `main` functions. Libraries and tests should build
/// a [`TelemetryConfig`] and use [`Telemetry`] directly.
///
/// With OTLP export enabled, call it from within a Tokio runtime.
///
/// # Errors
///
/// A malformed variable ([`Error::InvalidVar`], [`Error::InvalidFilter`]),
/// a global subscriber already installed ([`Error::AlreadyInitialized`]), or
/// any error from [`Telemetry::install`].
pub fn init() -> Result<TelemetryGuard, Error> {
    let config = TelemetryConfig::default().with_env(|name| std::env::var(name).ok())?;
    Telemetry::new(config).install()
}
