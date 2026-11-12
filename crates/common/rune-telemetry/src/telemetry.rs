//! Building and installing the `tracing` subscriber (and OTLP pipeline).

use std::fmt;
use std::io::IsTerminal;

use tracing::Dispatch;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::{EnvFilter, Registry};

use crate::Error;
use crate::config::{LogFormat, TelemetryConfig, TracesExporter};

/// The subscriber stack below the per-output layers.
type Base = tracing_subscriber::layer::Layered<EnvFilter, Registry>;
type BoxedLayer = Box<dyn Layer<Base> + Send + Sync + 'static>;

/// A telemetry pipeline that is configured but not yet built.
///
/// [`build`](Self::build) returns a [`Dispatch`] to use with
/// `tracing::dispatcher::with_default` (handy in tests);
/// [`install`](Self::install) makes it the process-wide default.
///
/// ```
/// use rune_telemetry::{Telemetry, TelemetryConfig};
///
/// let config = TelemetryConfig::default().with_filter("debug").with_ansi(false);
/// let (dispatch, guard) = Telemetry::new(config).with_writer(std::io::sink).build()?;
/// tracing::dispatcher::with_default(&dispatch, || {
///     tracing::debug!(answer = 42, "written to the sink");
/// });
/// guard.shutdown()?;
/// # Ok::<(), rune_telemetry::Error>(())
/// ```
#[must_use = "a Telemetry does nothing until it is built or installed"]
pub struct Telemetry {
    config: TelemetryConfig,
    writer: Option<BoxMakeWriter>,
    #[cfg(feature = "otlp")]
    processor: Option<opentelemetry_sdk::trace::BatchSpanProcessor>,
}

impl fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Telemetry");
        s.field("config", &self.config)
            .field("custom_writer", &self.writer.is_some());
        #[cfg(feature = "otlp")]
        s.field("custom_exporter", &self.processor.is_some());
        s.finish()
    }
}

impl Telemetry {
    /// Starts a pipeline from `config`. Logs go to stderr by default.
    pub const fn new(config: TelemetryConfig) -> Self {
        Self {
            config,
            writer: None,
            #[cfg(feature = "otlp")]
            processor: None,
        }
    }

    /// Writes log lines to `writer` instead of stderr.
    ///
    /// ANSI colours are off for a custom writer unless the configuration
    /// forces them on.
    pub fn with_writer<W>(mut self, writer: W) -> Self
    where
        W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
    {
        self.writer = Some(BoxMakeWriter::new(writer));
        self
    }

    /// Exports spans through `exporter` (batched) instead of the OTLP/gRPC
    /// exporter built from the configuration.
    ///
    /// Export still only happens when the configuration's `traces_exporter`
    /// is [`TracesExporter::Otlp`], so `OTEL_SDK_DISABLED=true` and
    /// `OTEL_TRACES_EXPORTER=none` keep working.
    #[cfg(feature = "otlp")]
    pub fn with_span_exporter<E>(mut self, exporter: E) -> Self
    where
        E: opentelemetry_sdk::trace::SpanExporter + 'static,
    {
        self.processor =
            Some(opentelemetry_sdk::trace::BatchSpanProcessor::builder(exporter).build());
        self
    }

    /// Builds the subscriber without installing it.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFilter`] for a bad filter, [`Error::FeatureDisabled`]
    /// when the configuration needs a feature this build lacks, and the
    /// OTLP errors listed on [`install`](Self::install).
    pub fn build(self) -> Result<(Dispatch, TelemetryGuard), Error> {
        self.build_parts()
    }

    /// Builds the subscriber and installs it as the global default. With OTLP
    /// export on, also installs the tracer provider and the W3C trace-context
    /// propagator as OpenTelemetry globals, so `opentelemetry::global` users
    /// (such as `rune-axum-trace`'s layer) share the pipeline.
    ///
    /// Keep the returned guard alive for the life of the program; dropping it
    /// flushes and shuts the exporter down.
    ///
    /// # Errors
    ///
    /// Everything [`build`](Self::build) returns, plus
    /// [`Error::AlreadyInitialized`] when a global subscriber exists. With
    /// OTLP: [`Error::UnsupportedProtocol`] for HTTP protocols,
    /// [`Error::InvalidHeader`], [`Error::NoTokioRuntime`] when called outside
    /// a Tokio runtime, and [`Error::Exporter`].
    pub fn install(self) -> Result<TelemetryGuard, Error> {
        let (dispatch, guard) = self.build_parts()?;
        tracing::dispatcher::set_global_default(dispatch).map_err(|_| Error::AlreadyInitialized)?;
        #[cfg(feature = "otlp")]
        if let Some(provider) = &guard.provider {
            opentelemetry::global::set_tracer_provider(provider.clone());
            opentelemetry::global::set_text_map_propagator(
                opentelemetry_sdk::propagation::TraceContextPropagator::new(),
            );
        }
        Ok(guard)
    }

    fn build_parts(self) -> Result<(Dispatch, TelemetryGuard), Error> {
        let config = self.config;
        let filter =
            EnvFilter::try_new(&config.filter).map_err(|e| Error::InvalidFilter(e.to_string()))?;

        let (writer, ansi) = match self.writer {
            Some(writer) => (writer, config.ansi.unwrap_or(false)),
            None => (
                BoxMakeWriter::new(std::io::stderr),
                config
                    .ansi
                    .unwrap_or_else(|| std::io::stderr().is_terminal()),
            ),
        };
        #[cfg_attr(
            not(feature = "otlp"),
            allow(unused_mut, reason = "pushed to with `otlp`")
        )]
        let mut layers: Vec<BoxedLayer> = vec![fmt_layer(config.format, writer, ansi)?];

        #[cfg(feature = "otlp")]
        let provider = match config.traces_exporter {
            TracesExporter::Otlp => {
                let processor = match self.processor {
                    Some(processor) => processor,
                    None => otlp::batch_processor(&config.otlp)?,
                };
                let (layer, provider) = otlp::layer(&config, processor);
                layers.push(layer);
                Some(provider)
            }
            TracesExporter::None => None,
        };
        #[cfg(not(feature = "otlp"))]
        if config.traces_exporter == TracesExporter::Otlp {
            return Err(Error::FeatureDisabled {
                what: "OTLP trace export",
                feature: "otlp",
            });
        }

        let subscriber = tracing_subscriber::registry().with(filter).with(layers);
        let guard = TelemetryGuard {
            #[cfg(feature = "otlp")]
            provider,
        };
        Ok((Dispatch::new(subscriber), guard))
    }
}

#[cfg_attr(
    feature = "json",
    allow(
        clippy::unnecessary_wraps,
        reason = "fails only without the `json` feature"
    )
)]
fn fmt_layer(format: LogFormat, writer: BoxMakeWriter, ansi: bool) -> Result<BoxedLayer, Error> {
    let base = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(ansi);
    Ok(match format {
        LogFormat::Compact => base.compact().boxed(),
        LogFormat::Pretty => base.pretty().boxed(),
        #[cfg(feature = "json")]
        LogFormat::Json => base.json().boxed(),
        #[cfg(not(feature = "json"))]
        LogFormat::Json => {
            return Err(Error::FeatureDisabled {
                what: "the json log format",
                feature: "json",
            });
        }
        // `Full` and any future format default to the full layout.
        _ => base.boxed(),
    })
}

/// Keeps the telemetry pipeline alive; flushes and shuts down span export
/// when dropped.
///
/// Prefer [`shutdown`](Self::shutdown) at the end of `main` to see errors.
/// With OTLP/gRPC export, drop or shut down the guard on a multi-threaded
/// Tokio runtime (or outside one): shutdown blocks the calling thread while
/// the exporter's I/O runs on the runtime.
#[must_use = "dropping the guard shuts telemetry down"]
pub struct TelemetryGuard {
    #[cfg(feature = "otlp")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl fmt::Debug for TelemetryGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("TelemetryGuard");
        #[cfg(feature = "otlp")]
        s.field("exporting", &self.provider.is_some());
        s.finish_non_exhaustive()
    }
}

impl TelemetryGuard {
    /// Whether spans are being exported.
    #[must_use]
    pub const fn is_exporting(&self) -> bool {
        #[cfg(feature = "otlp")]
        {
            self.provider.is_some()
        }
        #[cfg(not(feature = "otlp"))]
        {
            false
        }
    }

    /// Exports every finished span that is still buffered.
    ///
    /// # Errors
    ///
    /// [`Error::Shutdown`] when the exporter fails.
    #[cfg_attr(
        not(feature = "otlp"),
        allow(
            clippy::missing_const_for_fn,
            clippy::unnecessary_wraps,
            reason = "no-op without `otlp`"
        )
    )]
    pub fn force_flush(&self) -> Result<(), Error> {
        #[cfg(feature = "otlp")]
        if let Some(provider) = &self.provider {
            provider
                .force_flush()
                .map_err(|e| Error::Shutdown(e.to_string()))?;
        }
        Ok(())
    }

    /// Flushes buffered spans and shuts the exporter down.
    ///
    /// # Errors
    ///
    /// [`Error::Shutdown`] when flushing or shutting down fails.
    pub fn shutdown(mut self) -> Result<(), Error> {
        self.shutdown_inner()
    }

    #[cfg_attr(
        not(feature = "otlp"),
        allow(
            clippy::unnecessary_wraps,
            clippy::missing_const_for_fn,
            clippy::unused_self,
            clippy::needless_pass_by_ref_mut,
            reason = "no-op without `otlp`"
        )
    )]
    fn shutdown_inner(&mut self) -> Result<(), Error> {
        #[cfg(feature = "otlp")]
        if let Some(provider) = self.provider.take() {
            provider
                .shutdown()
                .map_err(|e| Error::Shutdown(e.to_string()))?;
        }
        Ok(())
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        // Errors cannot be reported from `drop`; `shutdown` surfaces them.
        let _ = self.shutdown_inner();
    }
}

#[cfg(feature = "otlp")]
mod otlp {
    use opentelemetry::KeyValue;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::trace::{BatchSpanProcessor, SdkTracerProvider};
    use tracing_subscriber::filter::filter_fn;
    use tracing_subscriber::layer::Layer;

    use super::BoxedLayer;
    use crate::Error;
    use crate::config::{OtlpConfig, OtlpProtocol, Sampler, TelemetryConfig};

    /// Targets whose events would feed back into the exporter.
    const EXPORT_PATH_TARGETS: &[&str] =
        &["opentelemetry", "tonic", "h2", "hyper", "tower", "reqwest"];

    pub(super) fn batch_processor(config: &OtlpConfig) -> Result<BatchSpanProcessor, Error> {
        if config.protocol != OtlpProtocol::Grpc {
            return Err(Error::UnsupportedProtocol(
                config.protocol.as_str().to_owned(),
            ));
        }
        let mut headers = http::HeaderMap::new();
        for (name, value) in &config.headers {
            let invalid = || Error::InvalidHeader { name: name.clone() };
            let key = http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?;
            let value = http::HeaderValue::from_str(value).map_err(|_| invalid())?;
            headers.append(key, value);
        }
        // tonic's lazy channel spawns onto the current runtime and panics
        // without one; check first so a misconfiguration is an error.
        tokio::runtime::Handle::try_current().map_err(|_| Error::NoTokioRuntime)?;
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(config.endpoint.clone())
            .with_timeout(config.timeout)
            .with_metadata(
                opentelemetry_otlp::tonic_types::metadata::MetadataMap::from_headers(headers),
            )
            .build()
            .map_err(|e| Error::Exporter(e.to_string()))?;
        Ok(BatchSpanProcessor::builder(exporter).build())
    }

    pub(super) fn layer(
        config: &TelemetryConfig,
        processor: BatchSpanProcessor,
    ) -> (BoxedLayer, SdkTracerProvider) {
        let resource = Resource::builder()
            .with_service_name(config.service_name.clone())
            .with_attributes(
                config
                    .resource_attributes
                    .iter()
                    .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
            )
            .build();
        let provider = SdkTracerProvider::builder()
            .with_span_processor(processor)
            .with_sampler(sampler(config.sampler))
            .with_resource(resource)
            .build();
        let tracer = provider.tracer(env!("CARGO_PKG_NAME"));
        let layer = tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_filter(filter_fn(|meta| !is_export_path(meta.target())))
            .boxed();
        (layer, provider)
    }

    fn is_export_path(target: &str) -> bool {
        EXPORT_PATH_TARGETS.iter().any(|prefix| {
            target.strip_prefix(prefix).is_some_and(|rest| {
                rest.is_empty() || rest.starts_with("::") || rest.starts_with('_')
            })
        })
    }

    fn sampler(sampler: Sampler) -> opentelemetry_sdk::trace::Sampler {
        use opentelemetry_sdk::trace::Sampler as S;
        match sampler {
            Sampler::AlwaysOn => S::AlwaysOn,
            Sampler::AlwaysOff => S::AlwaysOff,
            Sampler::TraceIdRatio(ratio) => S::TraceIdRatioBased(ratio),
            Sampler::ParentBasedAlwaysOff => S::ParentBased(Box::new(S::AlwaysOff)),
            Sampler::ParentBasedTraceIdRatio(ratio) => {
                S::ParentBased(Box::new(S::TraceIdRatioBased(ratio)))
            }
            // `ParentBasedAlwaysOn` and any future variant use the spec default.
            _ => S::ParentBased(Box::new(S::AlwaysOn)),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::is_export_path;

        #[test]
        fn export_path_targets() {
            assert!(is_export_path("opentelemetry_sdk"));
            assert!(is_export_path("opentelemetry"));
            assert!(is_export_path("h2::codec"));
            assert!(is_export_path("hyper_util::client"));
            assert!(!is_export_path("hyperion"));
            assert!(!is_export_path("my_app::tonic"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Buffer {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn capture(config: TelemetryConfig, f: impl FnOnce()) -> String {
        let buffer = Buffer::default();
        let sink = buffer.clone();
        let (dispatch, guard) = Telemetry::new(config)
            .with_writer(move || sink.clone())
            .build()
            .unwrap();
        tracing::dispatcher::with_default(&dispatch, f);
        guard.shutdown().unwrap();
        buffer.text()
    }

    #[test]
    fn filter_applies() {
        let out = capture(TelemetryConfig::default().with_filter("warn"), || {
            tracing::info!("hidden");
            tracing::warn!("shown");
        });
        assert!(out.contains("shown"));
        assert!(!out.contains("hidden"));
        assert!(!out.contains('\u{1b}'), "no ANSI for a custom writer");
    }

    #[test]
    fn per_target_directives() {
        let config = TelemetryConfig::default().with_filter("warn,noisy=off,chatty=trace");
        let out = capture(config, || {
            tracing::error!(target: "noisy", "muted");
            tracing::trace!(target: "chatty", "loud");
        });
        assert!(!out.contains("muted"));
        assert!(out.contains("loud"));
    }

    #[test]
    fn formats_render() {
        for format in [LogFormat::Full, LogFormat::Compact, LogFormat::Pretty] {
            let out = capture(TelemetryConfig::default().with_format(format), || {
                tracing::info!(user = "ada", "hello");
            });
            assert!(out.contains("hello"), "{format:?}: {out}");
            assert!(out.contains("ada"), "{format:?}: {out}");
        }
    }

    #[test]
    fn forced_ansi() {
        let out = capture(TelemetryConfig::default().with_ansi(true), || {
            tracing::info!("x");
        });
        assert!(out.contains('\u{1b}'));
    }

    #[cfg(feature = "json")]
    #[test]
    fn json_format() {
        let out = capture(
            TelemetryConfig::default().with_format(LogFormat::Json),
            || {
                tracing::info!(n = 3, "structured");
            },
        );
        let line = out.lines().next().unwrap();
        assert!(line.starts_with('{') && line.contains("\"n\":3"), "{line}");
    }

    #[cfg(not(feature = "json"))]
    #[test]
    fn json_needs_feature() {
        let err = Telemetry::new(TelemetryConfig::default().with_format(LogFormat::Json))
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::FeatureDisabled {
                feature: "json",
                ..
            }
        ));
    }

    #[cfg(not(feature = "otlp"))]
    #[test]
    fn otlp_needs_feature() {
        let config = TelemetryConfig::default().with_otlp_endpoint("http://127.0.0.1:4317");
        let err = Telemetry::new(config).build().unwrap_err();
        assert!(matches!(
            err,
            Error::FeatureDisabled {
                feature: "otlp",
                ..
            }
        ));
    }

    #[test]
    fn invalid_filter_is_an_error() {
        let err = Telemetry::new(TelemetryConfig::default().with_filter("a=notalevel"))
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::InvalidFilter(_)));
    }

    #[test]
    fn guard_without_export() {
        let (_dispatch, guard) = Telemetry::new(TelemetryConfig::default()).build().unwrap();
        assert!(!guard.is_exporting());
        guard.force_flush().unwrap();
        assert!(format!("{guard:?}").starts_with("TelemetryGuard"));
    }
}
