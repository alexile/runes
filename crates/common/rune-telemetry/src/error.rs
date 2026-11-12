//! The crate's error type.

/// Errors returned while reading configuration or installing telemetry.
///
/// Messages never echo the value of `OTEL_EXPORTER_OTLP_*HEADERS`, which
/// usually carry credentials.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An environment variable holds a value this crate cannot use.
    #[error("invalid value for {name}: {reason}")]
    InvalidVar {
        /// The variable name, for example `OTEL_TRACES_SAMPLER`.
        name: String,
        /// Why the value was rejected.
        reason: String,
    },
    /// The log filter (`RUST_LOG`) does not parse as an `EnvFilter` directive list.
    #[error("invalid log filter: {0}")]
    InvalidFilter(String),
    /// The configuration needs a cargo feature this build does not enable.
    #[error("{what} needs the `{feature}` feature of rune-telemetry")]
    FeatureDisabled {
        /// What the configuration asked for.
        what: &'static str,
        /// The cargo feature that provides it.
        feature: &'static str,
    },
    /// The OTLP transport protocol is not supported by this crate.
    #[error("unsupported OTLP protocol {0:?}; only \"grpc\" is supported")]
    UnsupportedProtocol(String),
    /// An OTLP header name or value is not valid gRPC metadata.
    #[error("invalid OTLP header {name:?}")]
    InvalidHeader {
        /// The offending header name. The value is never included.
        name: String,
    },
    /// The OTLP/gRPC exporter must be built inside a Tokio runtime.
    #[error("the OTLP/gRPC exporter must be installed from within a Tokio runtime")]
    NoTokioRuntime,
    /// Building the span exporter failed.
    #[error("failed to build the OTLP exporter: {0}")]
    Exporter(String),
    /// A global `tracing` subscriber is already installed.
    #[error("a global tracing subscriber is already installed")]
    AlreadyInitialized,
    /// Flushing or shutting down the tracer provider failed.
    #[error("telemetry shutdown failed: {0}")]
    Shutdown(String),
}
