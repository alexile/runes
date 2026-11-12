//! [`LogConfig`]: level filter, output format and redaction, built into a
//! `tracing-subscriber` layer.

use std::fmt;
use std::str::FromStr;

use rune_redact::{RedactingFields, RedactingMakeWriter, Redactor};
use tracing_core::Subscriber;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::format::{Format, Full};
use tracing_subscriber::fmt::{FormatFields, MakeWriter};
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::registry::{LookupSpan, Registry};

use crate::error::Error;
use crate::json::{JsonFields, JsonFormat};

/// A boxed, filtered, redacting layer, as returned by [`LogConfig::layer`].
pub type BoxedLayer<S> = Box<dyn Layer<S> + Send + Sync + 'static>;

/// How each event is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum LogFormat {
    /// Human-readable, one line per event, with span context
    /// (`tracing-subscriber`'s default format). Parsed from `full` or `text`.
    #[default]
    Full,
    /// Like [`Full`](Self::Full) but shorter: span fields are appended after
    /// the event's fields.
    Compact,
    /// One JSON object per line, every value redacted on its own (see
    /// [`JsonFormat`]).
    Json,
}

impl LogFormat {
    /// The canonical name, as accepted by [`FromStr`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Compact => "compact",
            Self::Json => "json",
        }
    }
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LogFormat {
    type Err = Error;

    /// Parses `full`/`text`, `compact` or `json`, ignoring case and
    /// surrounding whitespace.
    fn from_str(s: &str) -> Result<Self, Error> {
        match s.trim().to_ascii_lowercase().as_str() {
            "full" | "text" => Ok(Self::Full),
            "compact" => Ok(Self::Compact),
            "json" => Ok(Self::Json),
            _ => Err(Error::InvalidFormat(s.to_owned())),
        }
    }
}

/// What the redactor sees in the text formats.
///
/// [`LogFormat::Json`] always redacts value by value, whatever the scope, so
/// its output stays valid JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum RedactionScope {
    /// Event and span fields, including the message
    /// ([`RedactingFields`]). Timestamp, level and target are left alone.
    #[default]
    Fields,
    /// The whole formatted line ([`RedactingMakeWriter`]): also catches
    /// secrets in span names or targets, at the cost of scanning every byte.
    Line,
}

impl RedactionScope {
    /// The canonical name, as accepted by [`FromStr`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fields => "fields",
            Self::Line => "line",
        }
    }
}

impl fmt::Display for RedactionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RedactionScope {
    type Err = Error;

    /// Parses `fields` or `line`, ignoring case and surrounding whitespace.
    fn from_str(s: &str) -> Result<Self, Error> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fields" => Ok(Self::Fields),
            "line" => Ok(Self::Line),
            _ => Err(Error::InvalidScope(s.to_owned())),
        }
    }
}

/// The variable names [`LogConfig::with_env`] looks up.
///
/// The library never reads the process environment itself: the caller
/// passes a lookup function, usually `|k| std::env::var(k).ok()`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EnvKeys {
    /// Level filter directives. Default `RUST_LOG`.
    pub filter: String,
    /// [`LogFormat`] name. Default `LOG_FORMAT`.
    pub format: String,
    /// [`RedactionScope`] name. Default `LOG_REDACT`.
    pub scope: String,
}

impl Default for EnvKeys {
    fn default() -> Self {
        Self {
            filter: "RUST_LOG".to_owned(),
            format: "LOG_FORMAT".to_owned(),
            scope: "LOG_REDACT".to_owned(),
        }
    }
}

impl EnvKeys {
    /// Keys with a common prefix: `{prefix}_LOG`, `{prefix}_LOG_FORMAT` and
    /// `{prefix}_LOG_REDACT`.
    ///
    /// ```rust
    /// let keys = rune_log::EnvKeys::with_prefix("MYAPP");
    /// assert_eq!(keys.filter, "MYAPP_LOG");
    /// assert_eq!(keys.format, "MYAPP_LOG_FORMAT");
    /// ```
    #[must_use]
    pub fn with_prefix(prefix: &str) -> Self {
        Self {
            filter: format!("{prefix}_LOG"),
            format: format!("{prefix}_LOG_FORMAT"),
            scope: format!("{prefix}_LOG_REDACT"),
        }
    }
}

/// Logging configuration: level filter, [`LogFormat`], [`Redactor`] and
/// [`RedactionScope`]. Build a layer with [`layer`](Self::layer).
///
/// Defaults: filter `info`, [`LogFormat::Full`], `Redactor::default()`
/// (credentials, tokens and common PII), [`RedactionScope::Fields`],
/// timestamps and targets on. ANSI colours are always off, so escape codes
/// can never split a secret and hide it from the redactor.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LogConfig {
    filter: Targets,
    format: LogFormat,
    redactor: Redactor,
    scope: RedactionScope,
    timestamps: bool,
    target: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            filter: Targets::new().with_default(tracing_core::LevelFilter::INFO),
            format: LogFormat::default(),
            redactor: Redactor::default(),
            scope: RedactionScope::default(),
            timestamps: true,
            target: true,
        }
    }
}

impl LogConfig {
    /// Sets the level filter from directives: a level (`trace` … `error`,
    /// `off`), `target=level` pairs, or both, comma-separated
    /// (`warn,my_crate=debug,my_crate::db=trace`).
    pub fn with_filter(mut self, directives: &str) -> Result<Self, Error> {
        self.filter = parse_filter(directives)?;
        Ok(self)
    }

    /// Sets the level filter from an already-built [`Targets`].
    #[must_use]
    pub fn with_targets(mut self, targets: Targets) -> Self {
        self.filter = targets;
        self
    }

    /// Sets the output format.
    #[must_use]
    pub const fn with_format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    /// Sets the redactor (and so the [`rune_redact::Policy`]).
    #[must_use]
    pub fn with_redactor(mut self, redactor: Redactor) -> Self {
        self.redactor = redactor;
        self
    }

    /// Sets what the redactor sees in the text formats.
    #[must_use]
    pub const fn with_scope(mut self, scope: RedactionScope) -> Self {
        self.scope = scope;
        self
    }

    /// Writes (`true`, the default) or omits timestamps.
    #[must_use]
    pub const fn with_timestamps(mut self, on: bool) -> Self {
        self.timestamps = on;
        self
    }

    /// Writes (`true`, the default) or omits event targets.
    #[must_use]
    pub const fn with_target(mut self, on: bool) -> Self {
        self.target = on;
        self
    }

    /// Overrides filter, format and scope from environment-style values
    /// under the default [`EnvKeys`] (`RUST_LOG`, `LOG_FORMAT`,
    /// `LOG_REDACT`). Unset or blank values keep the current setting.
    ///
    /// ```rust
    /// use rune_log::{LogConfig, LogFormat};
    ///
    /// let env = |k: &str| match k {
    ///     "RUST_LOG" => Some("warn,app=debug".to_owned()),
    ///     "LOG_FORMAT" => Some("json".to_owned()),
    ///     _ => None,
    /// };
    /// let config = LogConfig::default().with_env(env)?;
    /// assert_eq!(config.format(), LogFormat::Json);
    /// // In a binary: LogConfig::default().with_env(|k| std::env::var(k).ok())
    /// # Ok::<(), rune_log::Error>(())
    /// ```
    pub fn with_env<F>(self, lookup: F) -> Result<Self, Error>
    where
        F: Fn(&str) -> Option<String>,
    {
        self.with_env_keys(&EnvKeys::default(), lookup)
    }

    /// Like [`with_env`](Self::with_env) with custom variable names.
    pub fn with_env_keys<F>(mut self, keys: &EnvKeys, lookup: F) -> Result<Self, Error>
    where
        F: Fn(&str) -> Option<String>,
    {
        let get = |key: &str| lookup(key).filter(|v| !v.trim().is_empty());
        if let Some(v) = get(&keys.filter) {
            self.filter = parse_filter(&v)?;
        }
        if let Some(v) = get(&keys.format) {
            self.format = v.parse()?;
        }
        if let Some(v) = get(&keys.scope) {
            self.scope = v.parse()?;
        }
        Ok(self)
    }

    /// The level filter.
    #[must_use]
    pub const fn filter(&self) -> &Targets {
        &self.filter
    }

    /// The output format.
    #[must_use]
    pub const fn format(&self) -> LogFormat {
        self.format
    }

    /// The redactor.
    #[must_use]
    pub const fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    /// The redaction scope for the text formats.
    #[must_use]
    pub const fn scope(&self) -> RedactionScope {
        self.scope
    }

    /// Builds the filtered, redacting fmt layer, writing through
    /// `make_writer` (`std::io::stderr`, a file appender, …).
    ///
    /// Compose it with other layers (metrics, OpenTelemetry) on a
    /// [`Registry`]; the level filter applies to this layer only.
    pub fn layer<S, W>(&self, make_writer: W) -> BoxedLayer<S>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
        W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
    {
        let base = tracing_subscriber::fmt::layer::<S>()
            .with_ansi(false)
            .with_target(self.target);
        match (self.format, self.scope) {
            (LogFormat::Json, _) => {
                let layer = base
                    .fmt_fields(JsonFields::new(self.redactor.clone()))
                    .event_format(
                        JsonFormat::new(self.redactor.clone())
                            .with_timestamps(self.timestamps)
                            .with_target(self.target),
                    )
                    .with_writer(make_writer);
                Box::new(layer.with_filter(self.filter.clone()))
            }
            (_, RedactionScope::Fields) => self.text(
                base.fmt_fields(RedactingFields::new(self.redactor.clone()))
                    .with_writer(make_writer),
            ),
            (_, RedactionScope::Line) => self.text(
                base.with_writer(RedactingMakeWriter::new(make_writer, self.redactor.clone())),
            ),
        }
    }

    /// A [`Registry`] with only this layer, ready for
    /// `tracing::subscriber::with_default` or `set_global_default`.
    pub fn subscriber<W>(&self, make_writer: W) -> impl Subscriber + Send + Sync + 'static
    where
        W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
    {
        Registry::default().with(self.layer(make_writer))
    }

    /// Installs [`subscriber`](Self::subscriber) as the process-wide default.
    ///
    /// This is the one call that touches global state; it is meant for the
    /// top of `main`, never for library code.
    pub fn try_init<W>(&self, make_writer: W) -> Result<(), Error>
    where
        W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
    {
        tracing_core::dispatcher::set_global_default(tracing_core::Dispatch::new(
            self.subscriber(make_writer),
        ))
        .map_err(|_| Error::AlreadyInitialized)
    }

    /// Applies format (full or compact) and timestamps to a text layer, then
    /// the level filter.
    fn text<S, N, W>(
        &self,
        layer: tracing_subscriber::fmt::Layer<S, N, Format<Full>, W>,
    ) -> BoxedLayer<S>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
        N: for<'w> FormatFields<'w> + Send + Sync + 'static,
        W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
    {
        let filter = self.filter.clone();
        match (self.format, self.timestamps) {
            (LogFormat::Compact, true) => Box::new(layer.compact().with_filter(filter)),
            (LogFormat::Compact, false) => {
                Box::new(layer.compact().without_time().with_filter(filter))
            }
            (_, true) => Box::new(layer.with_filter(filter)),
            (_, false) => Box::new(layer.without_time().with_filter(filter)),
        }
    }
}

fn parse_filter(directives: &str) -> Result<Targets, Error> {
    directives
        .trim()
        .parse()
        .map_err(
            |e: tracing_subscriber::filter::ParseError| Error::InvalidFilter {
                value: directives.to_owned(),
                reason: e.to_string(),
            },
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_core::{Level, LevelFilter};

    #[test]
    fn format_parses_aliases_and_case() {
        assert_eq!("JSON".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!(" text ".parse::<LogFormat>().unwrap(), LogFormat::Full);
        assert_eq!("compact".parse::<LogFormat>().unwrap(), LogFormat::Compact);
        assert_eq!(
            "yaml".parse::<LogFormat>(),
            Err(Error::InvalidFormat("yaml".into()))
        );
        for f in [LogFormat::Full, LogFormat::Compact, LogFormat::Json] {
            assert_eq!(f.to_string().parse::<LogFormat>().unwrap(), f);
        }
    }

    #[test]
    fn scope_parses() {
        assert_eq!(
            "Line".parse::<RedactionScope>().unwrap(),
            RedactionScope::Line
        );
        assert!("all".parse::<RedactionScope>().is_err());
    }

    #[test]
    fn default_is_info() {
        let c = LogConfig::default();
        assert!(c.filter().would_enable("any", &Level::INFO));
        assert!(!c.filter().would_enable("any", &Level::DEBUG));
    }

    #[test]
    fn env_overrides_filter_format_and_scope() {
        let env = |k: &str| match k {
            "RUST_LOG" => Some("warn,app::db=trace".to_owned()),
            "LOG_FORMAT" => Some("compact".to_owned()),
            "LOG_REDACT" => Some("line".to_owned()),
            _ => None,
        };
        let c = LogConfig::default().with_env(env).unwrap();
        assert_eq!(c.format(), LogFormat::Compact);
        assert_eq!(c.scope(), RedactionScope::Line);
        assert!(c.filter().would_enable("app::db", &Level::TRACE));
        assert!(!c.filter().would_enable("other", &Level::INFO));
        assert!(c.filter().would_enable("other", &Level::WARN));
    }

    #[test]
    fn blank_or_missing_env_keeps_settings() {
        let c = LogConfig::default()
            .with_format(LogFormat::Json)
            .with_env(|k| (k == "LOG_FORMAT").then(|| "  ".to_owned()))
            .unwrap();
        assert_eq!(c.format(), LogFormat::Json);
    }

    #[test]
    fn prefixed_keys() {
        let keys = EnvKeys::with_prefix("SVC");
        let c = LogConfig::default()
            .with_env_keys(&keys, |k| (k == "SVC_LOG").then(|| "off".to_owned()))
            .unwrap();
        assert_eq!(c.filter().default_level(), Some(LevelFilter::OFF));
    }

    #[test]
    fn invalid_env_values_are_errors() {
        let bad_format =
            LogConfig::default().with_env(|k| (k == "LOG_FORMAT").then(|| "xml".into()));
        assert_eq!(bad_format.unwrap_err(), Error::InvalidFormat("xml".into()));

        let bad_filter =
            LogConfig::default().with_env(|k| (k == "RUST_LOG").then(|| "app=loud".into()));
        assert!(matches!(
            bad_filter.unwrap_err(),
            Error::InvalidFilter { value, .. } if value == "app=loud"
        ));
    }
}
