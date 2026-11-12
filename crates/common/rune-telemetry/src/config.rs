//! Sans-I/O telemetry configuration and its environment-variable parser.

use std::fmt;
use std::time::Duration;

use crate::Error;

/// Default `service.name` when neither code nor environment sets one.
pub const DEFAULT_SERVICE_NAME: &str = "unknown_service";
/// Default log filter when `RUST_LOG` is unset.
pub const DEFAULT_FILTER: &str = "info";
/// Default OTLP/gRPC endpoint.
pub const DEFAULT_OTLP_ENDPOINT: &str = "http://localhost:4317";
/// Default OTLP export timeout (the OpenTelemetry specification's 10 s).
pub const DEFAULT_OTLP_TIMEOUT: Duration = Duration::from_secs(10);

/// Environment variables read by [`TelemetryConfig::with_env`].
pub mod vars {
    /// Log filter directives (`tracing_subscriber::EnvFilter` syntax).
    pub const RUST_LOG: &str = "RUST_LOG";
    /// Log line format: `full`, `compact`, `pretty` or `json`.
    pub const RUST_LOG_FORMAT: &str = "RUST_LOG_FORMAT";
    /// Disables ANSI colours when set to any non-empty value.
    pub const NO_COLOR: &str = "NO_COLOR";
    /// `true` disables OpenTelemetry export entirely.
    pub const OTEL_SDK_DISABLED: &str = "OTEL_SDK_DISABLED";
    /// The `service.name` resource attribute.
    pub const OTEL_SERVICE_NAME: &str = "OTEL_SERVICE_NAME";
    /// Extra resource attributes as `key=value,key=value` (percent-encoded).
    pub const OTEL_RESOURCE_ATTRIBUTES: &str = "OTEL_RESOURCE_ATTRIBUTES";
    /// Trace exporter: `otlp` or `none`.
    pub const OTEL_TRACES_EXPORTER: &str = "OTEL_TRACES_EXPORTER";
    /// Sampler name.
    pub const OTEL_TRACES_SAMPLER: &str = "OTEL_TRACES_SAMPLER";
    /// Sampler argument (the ratio for `traceidratio` samplers).
    pub const OTEL_TRACES_SAMPLER_ARG: &str = "OTEL_TRACES_SAMPLER_ARG";
    /// OTLP endpoint for all signals.
    pub const OTEL_EXPORTER_OTLP_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
    /// OTLP endpoint for traces; overrides the generic one.
    pub const OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT";
    /// OTLP protocol for all signals.
    pub const OTEL_EXPORTER_OTLP_PROTOCOL: &str = "OTEL_EXPORTER_OTLP_PROTOCOL";
    /// OTLP protocol for traces; overrides the generic one.
    pub const OTEL_EXPORTER_OTLP_TRACES_PROTOCOL: &str = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL";
    /// OTLP export timeout in milliseconds for all signals.
    pub const OTEL_EXPORTER_OTLP_TIMEOUT: &str = "OTEL_EXPORTER_OTLP_TIMEOUT";
    /// OTLP export timeout in milliseconds for traces.
    pub const OTEL_EXPORTER_OTLP_TRACES_TIMEOUT: &str = "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT";
    /// OTLP request headers for all signals, as `key=value,key=value`.
    pub const OTEL_EXPORTER_OTLP_HEADERS: &str = "OTEL_EXPORTER_OTLP_HEADERS";
    /// OTLP request headers for traces, merged over the generic ones.
    pub const OTEL_EXPORTER_OTLP_TRACES_HEADERS: &str = "OTEL_EXPORTER_OTLP_TRACES_HEADERS";
}

/// How log lines are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum LogFormat {
    /// `tracing_subscriber`'s default single-line format.
    #[default]
    Full,
    /// A terser single-line format.
    Compact,
    /// Multi-line, human-oriented output.
    Pretty,
    /// Newline-delimited JSON (needs the `json` feature).
    Json,
}

impl LogFormat {
    fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "full" | "text" => Some(Self::Full),
            "compact" => Some(Self::Compact),
            "pretty" => Some(Self::Pretty),
            "json" => Some(Self::Json),
            _ => None,
        }
    }
}

/// Where finished spans go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TracesExporter {
    /// No span export; only log lines are written.
    #[default]
    None,
    /// Export spans over OTLP (needs the `otlp` feature).
    Otlp,
}

/// OTLP transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OtlpProtocol {
    /// OTLP over gRPC (the only protocol installed by this crate).
    #[default]
    Grpc,
    /// OTLP over HTTP with protobuf bodies (parsed, not yet supported).
    HttpProtobuf,
    /// OTLP over HTTP with JSON bodies (parsed, not yet supported).
    HttpJson,
}

impl OtlpProtocol {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "grpc" => Some(Self::Grpc),
            "http/protobuf" => Some(Self::HttpProtobuf),
            "http/json" => Some(Self::HttpJson),
            _ => None,
        }
    }

    /// The protocol's name as written in `OTEL_EXPORTER_OTLP_PROTOCOL`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Grpc => "grpc",
            Self::HttpProtobuf => "http/protobuf",
            Self::HttpJson => "http/json",
        }
    }
}

/// Trace sampling strategy, mirroring `OTEL_TRACES_SAMPLER`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[non_exhaustive]
pub enum Sampler {
    /// Record every trace.
    AlwaysOn,
    /// Record no trace.
    AlwaysOff,
    /// Record this fraction (0.0 to 1.0) of traces, by trace id.
    TraceIdRatio(f64),
    /// Follow the parent's decision; sample root spans.
    #[default]
    ParentBasedAlwaysOn,
    /// Follow the parent's decision; drop root spans.
    ParentBasedAlwaysOff,
    /// Follow the parent's decision; sample this fraction of root spans.
    ParentBasedTraceIdRatio(f64),
}

impl Sampler {
    fn parse(name: &str, arg: Option<&str>) -> Result<Self, Error> {
        let ratio = || -> Result<f64, Error> {
            let Some(arg) = arg else { return Ok(1.0) };
            let invalid = || Error::InvalidVar {
                name: vars::OTEL_TRACES_SAMPLER_ARG.to_owned(),
                reason: format!("{arg:?} is not a ratio between 0 and 1"),
            };
            let value: f64 = arg.trim().parse().map_err(|_| invalid())?;
            if (0.0..=1.0).contains(&value) {
                Ok(value)
            } else {
                Err(invalid())
            }
        };
        match name.to_ascii_lowercase().as_str() {
            "always_on" => Ok(Self::AlwaysOn),
            "always_off" => Ok(Self::AlwaysOff),
            "traceidratio" => Ok(Self::TraceIdRatio(ratio()?)),
            "parentbased_always_on" => Ok(Self::ParentBasedAlwaysOn),
            "parentbased_always_off" => Ok(Self::ParentBasedAlwaysOff),
            "parentbased_traceidratio" => Ok(Self::ParentBasedTraceIdRatio(ratio()?)),
            _ => Err(Error::InvalidVar {
                name: vars::OTEL_TRACES_SAMPLER.to_owned(),
                reason: format!("unknown sampler {name:?}"),
            }),
        }
    }
}

/// OTLP exporter settings.
///
/// `Debug` prints header names only: header values usually carry API keys.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OtlpConfig {
    /// Collector endpoint, for example `http://localhost:4317`.
    pub endpoint: String,
    /// Transport protocol.
    pub protocol: OtlpProtocol,
    /// Per-export timeout.
    pub timeout: Duration,
    /// Extra request headers (gRPC metadata), in order.
    pub headers: Vec<(String, String)>,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_OTLP_ENDPOINT.to_owned(),
            protocol: OtlpProtocol::Grpc,
            timeout: DEFAULT_OTLP_TIMEOUT,
            headers: Vec::new(),
        }
    }
}

impl fmt::Debug for OtlpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Redacted<'a>(&'a [(String, String)]);
        impl fmt::Debug for Redacted<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_map()
                    .entries(self.0.iter().map(|(k, _)| (k, "<redacted>")))
                    .finish()
            }
        }
        f.debug_struct("OtlpConfig")
            .field("endpoint", &self.endpoint)
            .field("protocol", &self.protocol)
            .field("timeout", &self.timeout)
            .field("headers", &Redacted(&self.headers))
            .finish()
    }
}

/// Everything [`Telemetry`](crate::Telemetry) needs to set up `tracing`.
///
/// Start from [`Default`], adjust with the `with_*` builder methods, then
/// layer the environment on top with [`with_env`](Self::with_env). The struct
/// is plain data: building it performs no I/O.
///
/// ```
/// use rune_telemetry::{LogFormat, TelemetryConfig, TracesExporter};
///
/// let env = [
///     ("RUST_LOG", "debug,hyper=warn"),
///     ("OTEL_SERVICE_NAME", "checkout"),
///     ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317"),
/// ];
/// let config = TelemetryConfig::default()
///     .with_service_name("fallback-name")
///     .with_format(LogFormat::Compact)
///     .with_env(|k| env.iter().find(|(n, _)| *n == k).map(|(_, v)| (*v).to_owned()))?;
///
/// assert_eq!(config.service_name, "checkout");
/// assert_eq!(config.filter, "debug,hyper=warn");
/// assert_eq!(config.traces_exporter, TracesExporter::Otlp);
/// assert_eq!(config.otlp.endpoint, "http://collector:4317");
/// # Ok::<(), rune_telemetry::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TelemetryConfig {
    /// `EnvFilter` directives, for example `info,my_crate=debug`.
    pub filter: String,
    /// Log line format.
    pub format: LogFormat,
    /// ANSI colours: `Some(on)` forces, `None` detects a terminal on stderr.
    pub ansi: Option<bool>,
    /// The `service.name` resource attribute.
    pub service_name: String,
    /// Further resource attributes (never `service.name`).
    pub resource_attributes: Vec<(String, String)>,
    /// Span exporter.
    pub traces_exporter: TracesExporter,
    /// Sampling strategy for exported traces.
    pub sampler: Sampler,
    /// OTLP exporter settings, used when `traces_exporter` is `Otlp`.
    pub otlp: OtlpConfig,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            filter: DEFAULT_FILTER.to_owned(),
            format: LogFormat::default(),
            ansi: None,
            service_name: DEFAULT_SERVICE_NAME.to_owned(),
            resource_attributes: Vec::new(),
            traces_exporter: TracesExporter::default(),
            sampler: Sampler::default(),
            otlp: OtlpConfig::default(),
        }
    }
}

impl TelemetryConfig {
    /// Sets the log filter directives.
    #[must_use]
    pub fn with_filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = filter.into();
        self
    }

    /// Sets the log line format.
    #[must_use]
    pub const fn with_format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    /// Forces ANSI colours on or off instead of detecting a terminal.
    #[must_use]
    pub const fn with_ansi(mut self, ansi: bool) -> Self {
        self.ansi = Some(ansi);
        self
    }

    /// Sets the `service.name` resource attribute.
    #[must_use]
    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = name.into();
        self
    }

    /// Adds a resource attribute. `service.name` sets the service name instead.
    #[must_use]
    pub fn with_resource_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.push_resource_attribute(key.into(), value.into());
        self
    }

    /// Chooses the span exporter.
    #[must_use]
    pub const fn with_traces_exporter(mut self, exporter: TracesExporter) -> Self {
        self.traces_exporter = exporter;
        self
    }

    /// Sets the sampling strategy.
    #[must_use]
    pub const fn with_sampler(mut self, sampler: Sampler) -> Self {
        self.sampler = sampler;
        self
    }

    /// Sets the OTLP endpoint and enables OTLP export.
    #[must_use]
    pub fn with_otlp_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.otlp.endpoint = endpoint.into();
        self.traces_exporter = TracesExporter::Otlp;
        self
    }

    /// Sets the OTLP export timeout.
    #[must_use]
    pub const fn with_otlp_timeout(mut self, timeout: Duration) -> Self {
        self.otlp.timeout = timeout;
        self
    }

    /// Adds an OTLP request header, replacing one with the same name.
    #[must_use]
    pub fn with_otlp_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        upsert(&mut self.otlp.headers, name.into(), value.into());
        self
    }

    /// Overlays configuration from environment variables.
    ///
    /// `lookup` returns a variable's value; pass `|k| std::env::var(k).ok()`
    /// for the process environment, or a map in tests. Empty values count as
    /// unset, as the OpenTelemetry specification requires. The variables are
    /// listed in [`vars`]. Precedence, highest first:
    ///
    /// - `service.name`: `OTEL_SERVICE_NAME`, then `service.name` inside
    ///   `OTEL_RESOURCE_ATTRIBUTES`, then the value already set.
    /// - Endpoint, protocol, timeout: the `_TRACES_` variable, then the
    ///   generic one, then the value already set.
    /// - Headers: `_TRACES_HEADERS` entries override `OTEL_EXPORTER_OTLP_HEADERS`
    ///   entries of the same name; both add to headers already set.
    /// - Exporter: `OTEL_SDK_DISABLED=true` turns export off. Otherwise
    ///   `OTEL_TRACES_EXPORTER` decides; when it is unset, any OTLP endpoint
    ///   variable turns OTLP export on, so pointing at a collector is enough.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidVar`] for a value that does not parse. The message
    /// never includes header values.
    pub fn with_env<F>(mut self, lookup: F) -> Result<Self, Error>
    where
        F: Fn(&str) -> Option<String>,
    {
        let get = |name: &str| lookup(name).filter(|v| !v.trim().is_empty());

        if let Some(filter) = get(vars::RUST_LOG) {
            self.filter = filter;
        }
        if let Some(format) = get(vars::RUST_LOG_FORMAT) {
            self.format = LogFormat::parse(format.trim()).ok_or_else(|| Error::InvalidVar {
                name: vars::RUST_LOG_FORMAT.to_owned(),
                reason: format!("{format:?} is not one of full, compact, pretty, json"),
            })?;
        }
        if get(vars::NO_COLOR).is_some() {
            self.ansi = Some(false);
        }

        if let Some(attrs) = get(vars::OTEL_RESOURCE_ATTRIBUTES) {
            let parsed = parse_key_values(&attrs).map_err(|reason| Error::InvalidVar {
                name: vars::OTEL_RESOURCE_ATTRIBUTES.to_owned(),
                reason,
            })?;
            for (key, value) in parsed {
                self.push_resource_attribute(key, value);
            }
        }
        if let Some(name) = get(vars::OTEL_SERVICE_NAME) {
            self.service_name = name;
        }

        if let Some(name) = get(vars::OTEL_TRACES_SAMPLER) {
            let arg = get(vars::OTEL_TRACES_SAMPLER_ARG);
            self.sampler = Sampler::parse(name.trim(), arg.as_deref())?;
        }

        let endpoint = get(vars::OTEL_EXPORTER_OTLP_TRACES_ENDPOINT)
            .or_else(|| get(vars::OTEL_EXPORTER_OTLP_ENDPOINT));
        let endpoint_set = endpoint.is_some();
        if let Some(endpoint) = endpoint {
            endpoint.trim().clone_into(&mut self.otlp.endpoint);
        }
        for name in [
            vars::OTEL_EXPORTER_OTLP_TRACES_PROTOCOL,
            vars::OTEL_EXPORTER_OTLP_PROTOCOL,
        ] {
            if let Some(protocol) = get(name) {
                self.otlp.protocol =
                    OtlpProtocol::parse(protocol.trim()).ok_or_else(|| Error::InvalidVar {
                        name: name.to_owned(),
                        reason: format!(
                            "{protocol:?} is not one of grpc, http/protobuf, http/json"
                        ),
                    })?;
                break;
            }
        }
        for name in [
            vars::OTEL_EXPORTER_OTLP_TRACES_TIMEOUT,
            vars::OTEL_EXPORTER_OTLP_TIMEOUT,
        ] {
            if let Some(timeout) = get(name) {
                let millis: u64 = timeout.trim().parse().map_err(|_| Error::InvalidVar {
                    name: name.to_owned(),
                    reason: format!("{timeout:?} is not a whole number of milliseconds"),
                })?;
                self.otlp.timeout = Duration::from_millis(millis);
                break;
            }
        }
        for name in [
            vars::OTEL_EXPORTER_OTLP_HEADERS,
            vars::OTEL_EXPORTER_OTLP_TRACES_HEADERS,
        ] {
            if let Some(headers) = get(name) {
                // The reason never quotes the input: header values are secrets.
                let parsed = parse_key_values(&headers).map_err(|_| Error::InvalidVar {
                    name: name.to_owned(),
                    reason: "expected comma-separated key=value pairs (percent-encoded)".to_owned(),
                })?;
                for (key, value) in parsed {
                    upsert(&mut self.otlp.headers, key, value);
                }
            }
        }

        if let Some(exporter) = get(vars::OTEL_TRACES_EXPORTER) {
            self.traces_exporter = match exporter.trim().to_ascii_lowercase().as_str() {
                "otlp" => TracesExporter::Otlp,
                "none" => TracesExporter::None,
                _ => {
                    return Err(Error::InvalidVar {
                        name: vars::OTEL_TRACES_EXPORTER.to_owned(),
                        reason: format!("{exporter:?} is not one of otlp, none"),
                    });
                }
            };
        } else if endpoint_set {
            self.traces_exporter = TracesExporter::Otlp;
        }
        if get(vars::OTEL_SDK_DISABLED).is_some_and(|v| v.trim().eq_ignore_ascii_case("true")) {
            self.traces_exporter = TracesExporter::None;
        }

        Ok(self)
    }

    fn push_resource_attribute(&mut self, key: String, value: String) {
        if key == "service.name" {
            self.service_name = value;
        } else {
            upsert(&mut self.resource_attributes, key, value);
        }
    }
}

fn upsert(list: &mut Vec<(String, String)>, key: String, value: String) {
    if let Some(slot) = list.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = value;
    } else {
        list.push((key, value));
    }
}

/// Parses the `key=value,key=value` list format shared by
/// `OTEL_RESOURCE_ATTRIBUTES` and `OTEL_EXPORTER_OTLP_HEADERS`.
///
/// Whitespace around keys and values is trimmed, empty list items are
/// skipped, and keys and values are percent-decoded (UTF-8). The reason in
/// the error never quotes the input.
///
/// ```
/// let pairs = rune_telemetry::parse_key_values("team=core, region=eu%2Dwest%201")?;
/// assert_eq!(pairs, [
///     ("team".to_owned(), "core".to_owned()),
///     ("region".to_owned(), "eu-west 1".to_owned()),
/// ]);
/// # Ok::<(), String>(())
/// ```
///
/// # Errors
///
/// A description of the first malformed item: one without `=`, with an
/// empty key, or with a bad percent escape.
pub fn parse_key_values(input: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for (index, item) in input.split(',').enumerate() {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let position = index + 1;
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| format!("item {position} has no '='"))?;
        let key = percent_decode(key.trim())
            .ok_or_else(|| format!("item {position} has an invalid percent escape in its key"))?;
        if key.is_empty() {
            return Err(format!("item {position} has an empty key"));
        }
        let value = percent_decode(value.trim())
            .ok_or_else(|| format!("item {position} has an invalid percent escape in its value"))?;
        out.push((key, value));
    }
    Ok(out)
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = hex_digit(*bytes.get(i + 1)?)?;
            let lo = hex_digit(*bytes.get(i + 2)?)?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| map.get(k).cloned()
    }

    fn from(pairs: &[(&str, &str)]) -> Result<TelemetryConfig, Error> {
        TelemetryConfig::default().with_env(env(pairs))
    }

    #[test]
    fn empty_env_keeps_defaults() {
        assert_eq!(from(&[]).unwrap(), TelemetryConfig::default());
    }

    #[test]
    fn defaults_are_sane() {
        let c = TelemetryConfig::default();
        assert_eq!(c.filter, "info");
        assert_eq!(c.service_name, "unknown_service");
        assert_eq!(c.traces_exporter, TracesExporter::None);
        assert_eq!(c.sampler, Sampler::ParentBasedAlwaysOn);
        assert_eq!(c.otlp.endpoint, "http://localhost:4317");
        assert_eq!(c.otlp.timeout, Duration::from_secs(10));
    }

    #[test]
    fn empty_values_count_as_unset() {
        let c = from(&[("RUST_LOG", ""), ("OTEL_EXPORTER_OTLP_ENDPOINT", "  ")]).unwrap();
        assert_eq!(c, TelemetryConfig::default());
    }

    #[test]
    fn rust_log_and_format() {
        let c = from(&[
            ("RUST_LOG", "warn,app=trace"),
            ("RUST_LOG_FORMAT", "Compact"),
        ])
        .unwrap();
        assert_eq!(c.filter, "warn,app=trace");
        assert_eq!(c.format, LogFormat::Compact);
        let err = from(&[("RUST_LOG_FORMAT", "xml")]).unwrap_err();
        assert!(matches!(err, Error::InvalidVar { ref name, .. } if name == "RUST_LOG_FORMAT"));
    }

    #[test]
    fn no_color_disables_ansi() {
        assert_eq!(from(&[("NO_COLOR", "1")]).unwrap().ansi, Some(false));
        assert_eq!(from(&[]).unwrap().ansi, None);
    }

    #[test]
    fn service_name_precedence() {
        let base = TelemetryConfig::default().with_service_name("code");
        assert_eq!(
            base.clone().with_env(env(&[])).unwrap().service_name,
            "code"
        );
        let attrs = [("OTEL_RESOURCE_ATTRIBUTES", "service.name=attr,team=core")];
        let c = base.clone().with_env(env(&attrs)).unwrap();
        assert_eq!(c.service_name, "attr");
        assert_eq!(
            c.resource_attributes,
            [("team".to_owned(), "core".to_owned())]
        );
        let both = [attrs[0], ("OTEL_SERVICE_NAME", "env")];
        assert_eq!(base.with_env(env(&both)).unwrap().service_name, "env");
    }

    #[test]
    fn endpoint_enables_otlp_and_traces_specific_wins() {
        let c = from(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "http://a:4317")]).unwrap();
        assert_eq!(c.traces_exporter, TracesExporter::Otlp);
        assert_eq!(c.otlp.endpoint, "http://a:4317");
        let c = from(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://a:4317"),
            ("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "http://b:4317"),
        ])
        .unwrap();
        assert_eq!(c.otlp.endpoint, "http://b:4317");
    }

    #[test]
    fn exporter_none_and_sdk_disabled_override_endpoint() {
        let c = from(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://a:4317"),
            ("OTEL_TRACES_EXPORTER", "none"),
        ])
        .unwrap();
        assert_eq!(c.traces_exporter, TracesExporter::None);
        let c = from(&[
            ("OTEL_TRACES_EXPORTER", "otlp"),
            ("OTEL_SDK_DISABLED", "TRUE"),
        ])
        .unwrap();
        assert_eq!(c.traces_exporter, TracesExporter::None);
        let c = from(&[
            ("OTEL_TRACES_EXPORTER", "otlp"),
            ("OTEL_SDK_DISABLED", "no"),
        ])
        .unwrap();
        assert_eq!(c.traces_exporter, TracesExporter::Otlp);
        assert!(from(&[("OTEL_TRACES_EXPORTER", "zipkin")]).is_err());
    }

    #[test]
    fn protocol_and_timeout() {
        let c = from(&[
            ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"),
            ("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "grpc"),
            ("OTEL_EXPORTER_OTLP_TIMEOUT", "2500"),
        ])
        .unwrap();
        assert_eq!(c.otlp.protocol, OtlpProtocol::Grpc);
        assert_eq!(c.otlp.timeout, Duration::from_millis(2500));
        let c = from(&[("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json")]).unwrap();
        assert_eq!(c.otlp.protocol, OtlpProtocol::HttpJson);
        assert!(from(&[("OTEL_EXPORTER_OTLP_PROTOCOL", "udp")]).is_err());
        assert!(from(&[("OTEL_EXPORTER_OTLP_TRACES_TIMEOUT", "-1")]).is_err());
    }

    #[test]
    fn headers_merge_and_never_leak() {
        let c = from(&[
            ("OTEL_EXPORTER_OTLP_HEADERS", "api-key=s3cret,x-tenant=a"),
            ("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "x-tenant=b%20c"),
        ])
        .unwrap();
        assert_eq!(
            c.otlp.headers,
            [
                ("api-key".to_owned(), "s3cret".to_owned()),
                ("x-tenant".to_owned(), "b c".to_owned())
            ]
        );
        assert!(!format!("{c:?}").contains("s3cret"));
        let err =
            from(&[("OTEL_EXPORTER_OTLP_HEADERS", "token-without-equals-s3cret")]).unwrap_err();
        assert!(!err.to_string().contains("s3cret"));
    }

    #[test]
    fn samplers() {
        let s = |name: &str, arg: Option<&str>| {
            let mut pairs = vec![("OTEL_TRACES_SAMPLER", name)];
            if let Some(arg) = arg {
                pairs.push(("OTEL_TRACES_SAMPLER_ARG", arg));
            }
            from(&pairs).map(|c| c.sampler)
        };
        assert_eq!(s("always_on", None).unwrap(), Sampler::AlwaysOn);
        assert_eq!(s("always_off", None).unwrap(), Sampler::AlwaysOff);
        assert_eq!(
            s("traceidratio", Some("0.25")).unwrap(),
            Sampler::TraceIdRatio(0.25)
        );
        assert_eq!(s("traceidratio", None).unwrap(), Sampler::TraceIdRatio(1.0));
        assert_eq!(
            s("parentbased_always_off", None).unwrap(),
            Sampler::ParentBasedAlwaysOff
        );
        assert_eq!(
            s("parentbased_traceidratio", Some("0")).unwrap(),
            Sampler::ParentBasedTraceIdRatio(0.0)
        );
        assert!(s("traceidratio", Some("1.5")).is_err());
        assert!(s("traceidratio", Some("NaN")).is_err());
        assert!(s("jaeger_remote", None).is_err());
    }

    #[test]
    fn key_value_parsing() {
        assert_eq!(parse_key_values("").unwrap(), []);
        assert_eq!(parse_key_values(" , ,").unwrap(), []);
        assert_eq!(
            parse_key_values("a=1, b = x=y ,c=").unwrap(),
            [
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), "x=y".to_owned()),
                ("c".to_owned(), String::new())
            ]
        );
        assert!(parse_key_values("a").is_err());
        assert!(parse_key_values("=v").is_err());
        assert!(parse_key_values("a=%zz").is_err());
        assert!(parse_key_values("a=%4").is_err());
        assert!(parse_key_values("a=%ff").is_err(), "not UTF-8");
        assert_eq!(
            parse_key_values("k%2Cx=%E2%82%AC").unwrap(),
            [("k,x".to_owned(), "€".to_owned())]
        );
    }

    #[test]
    fn builders() {
        let c = TelemetryConfig::default()
            .with_filter("debug")
            .with_ansi(true)
            .with_resource_attribute("service.name", "via-attr")
            .with_resource_attribute("k", "1")
            .with_resource_attribute("k", "2")
            .with_otlp_endpoint("http://x:4317")
            .with_otlp_timeout(Duration::from_secs(1))
            .with_otlp_header("a", "1")
            .with_otlp_header("a", "2")
            .with_sampler(Sampler::AlwaysOff);
        assert_eq!(c.service_name, "via-attr");
        assert_eq!(c.resource_attributes, [("k".to_owned(), "2".to_owned())]);
        assert_eq!(c.otlp.headers, [("a".to_owned(), "2".to_owned())]);
        assert_eq!(c.traces_exporter, TracesExporter::Otlp);
        assert_eq!(c.ansi, Some(true));
        assert_eq!(OtlpProtocol::HttpProtobuf.as_str(), "http/protobuf");
    }
}
