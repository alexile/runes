//! Text exposition encoders: Prometheus 0.0.4 and `OpenMetrics` 1.0.0.

use std::fmt::Write as _;

use crate::model::{Metric, MetricFamily, MetricType, Value};

/// An exposition format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Format {
    /// The [Prometheus text format] 0.0.4, understood by every scraper.
    ///
    /// [Prometheus text format]: https://prometheus.io/docs/instrumenting/exposition_formats/
    #[default]
    Prometheus,
    /// [OpenMetrics] 1.0.0 text: `# UNIT` lines and a closing `# EOF`.
    ///
    /// [OpenMetrics]: https://github.com/prometheus/OpenMetrics/blob/main/specification/OpenMetrics.md
    OpenMetrics,
}

impl Format {
    /// The `Content-Type` of a response body in this format.
    #[must_use]
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Prometheus => "text/plain; version=0.0.4; charset=utf-8",
            Self::OpenMetrics => "application/openmetrics-text; version=1.0.0; charset=utf-8",
        }
    }

    /// Picks a format from an HTTP `Accept` header value: `OpenMetrics` when
    /// the client accepts `application/openmetrics-text` (with a non-zero
    /// quality), the Prometheus text format otherwise.
    ///
    /// ```
    /// use rune_metrics::Format;
    ///
    /// let prom = "application/openmetrics-text;version=1.0.0,text/plain;version=0.0.4;q=0.5";
    /// assert_eq!(Format::negotiate(prom), Format::OpenMetrics);
    /// assert_eq!(Format::negotiate("text/plain"), Format::Prometheus);
    /// assert_eq!(Format::negotiate("application/openmetrics-text;q=0"), Format::Prometheus);
    /// ```
    #[must_use]
    pub fn negotiate(accept: &str) -> Self {
        let wants_openmetrics = accept.split(',').any(|range| {
            let mut parts = range.split(';').map(str::trim);
            let media = parts.next().unwrap_or_default();
            if !media.eq_ignore_ascii_case("application/openmetrics-text") {
                return false;
            }
            !parts.any(|p| {
                p.split_once('=').is_some_and(|(k, v)| {
                    k.trim().eq_ignore_ascii_case("q")
                        && v.trim().parse::<f64>().is_ok_and(|q| q <= 0.0)
                })
            })
        });
        if wants_openmetrics {
            Self::OpenMetrics
        } else {
            Self::Prometheus
        }
    }
}

/// Encodes metric families as text in `format`.
///
/// Families are written in the order given;
/// [`Registry::gather`](crate::Registry::gather) sorts them by name.
///
/// # Examples
///
/// ```
/// use rune_metrics::{Format, Metric, MetricFamily, MetricType, Value, encode};
///
/// let family = MetricFamily::new("up", "Target is up.", MetricType::Gauge)
///     .with_metric(Metric::new(vec![], Value::Gauge(1.0)));
/// assert_eq!(
///     encode(&[family], Format::Prometheus),
///     "# HELP up Target is up.\n# TYPE up gauge\nup 1\n",
/// );
/// ```
#[must_use]
pub fn encode(families: &[MetricFamily], format: Format) -> String {
    let mut out = String::new();
    for family in families {
        encode_family(&mut out, family, format);
    }
    if format == Format::OpenMetrics {
        out.push_str("# EOF\n");
    }
    out
}

fn encode_family(out: &mut String, family: &MetricFamily, format: Format) {
    let om = format == Format::OpenMetrics;
    // Prometheus 0.0.4 names a counter family after its `_total` sample;
    // OpenMetrics names it without the suffix.
    let header_name = if family.kind == MetricType::Counter && !om {
        format!("{}_total", family.name)
    } else {
        family.name.clone()
    };
    let _ = writeln!(
        out,
        "# HELP {header_name} {}",
        escape_help(&family.help, om)
    );
    let _ = writeln!(out, "# TYPE {header_name} {}", family.kind.as_str());
    if om && let Some(unit) = &family.unit {
        let _ = writeln!(out, "# UNIT {header_name} {unit}");
    }
    for metric in &family.metrics {
        encode_metric(out, &family.name, metric);
    }
}

fn encode_metric(out: &mut String, name: &str, metric: &Metric) {
    match &metric.value {
        Value::Counter(v) => sample(out, name, "_total", &metric.labels, *v),
        Value::Gauge(v) => sample(out, name, "", &metric.labels, *v),
        Value::Histogram(h) => {
            for (bound, count) in &h.buckets {
                let le = format_le(*bound);
                sample_u64(out, name, &metric.labels, &le, *count);
            }
            sample_u64(out, name, &metric.labels, "+Inf", h.count);
            sample(out, name, "_sum", &metric.labels, h.sum);
            let mut line = String::new();
            write_series(&mut line, name, "_count", &metric.labels, None);
            let _ = writeln!(out, "{line} {}", h.count);
        }
    }
}

fn sample_u64(out: &mut String, name: &str, labels: &[(String, String)], le: &str, count: u64) {
    let mut line = String::new();
    write_series(&mut line, name, "_bucket", labels, Some(le));
    let _ = writeln!(out, "{line} {count}");
}

fn sample(out: &mut String, name: &str, suffix: &str, labels: &[(String, String)], value: f64) {
    let mut line = String::new();
    write_series(&mut line, name, suffix, labels, None);
    let _ = writeln!(out, "{line} {}", format_value(value));
}

fn write_series(
    out: &mut String,
    name: &str,
    suffix: &str,
    labels: &[(String, String)],
    le: Option<&str>,
) {
    out.push_str(name);
    out.push_str(suffix);
    if labels.is_empty() && le.is_none() {
        return;
    }
    out.push('{');
    let extra = le.map(|v| ("le", v));
    for (i, (k, v)) in labels
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .chain(extra)
        .enumerate()
    {
        if i > 0 {
            out.push(',');
        }
        out.push_str(k);
        out.push_str("=\"");
        escape_label_value(out, v);
        out.push('"');
    }
    out.push('}');
}

fn escape_label_value(out: &mut String, v: &str) {
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

fn escape_help(help: &str, openmetrics: bool) -> String {
    let mut out = String::with_capacity(help.len());
    for c in help.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '"' if openmetrics => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out
}

/// Formats a sample value: `+Inf`, `-Inf`, `NaN` or the shortest decimal.
fn format_value(v: f64) -> String {
    if v.is_nan() {
        "NaN".to_owned()
    } else if v.is_infinite() {
        if v > 0.0 { "+Inf" } else { "-Inf" }.to_owned()
    } else {
        format!("{v}")
    }
}

/// Formats a bucket bound canonically (`1.0`, `0.25`), as `OpenMetrics` asks.
fn format_le(v: f64) -> String {
    format!("{v:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::HistogramValue;

    fn labels(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn sample_families() -> Vec<MetricFamily> {
        vec![
            MetricFamily::new("requests_total", "Requests served.", MetricType::Counter)
                .with_metric(Metric::new(
                    labels(&[("path", "/a\"b\\c\nd")]),
                    Value::Counter(3.0),
                )),
            MetricFamily::new("latency_seconds", "Latency.", MetricType::Histogram)
                .with_unit("seconds")
                .with_metric(Metric::new(
                    labels(&[("m", "GET")]),
                    Value::Histogram(HistogramValue::new(vec![(0.5, 1), (1.0, 2)], 1.25, 3)),
                )),
        ]
    }

    #[test]
    fn prometheus_text_known_answer() {
        let text = encode(&sample_families(), Format::Prometheus);
        assert_eq!(
            text,
            "# HELP requests_total Requests served.\n\
             # TYPE requests_total counter\n\
             requests_total{path=\"/a\\\"b\\\\c\\nd\"} 3\n\
             # HELP latency_seconds Latency.\n\
             # TYPE latency_seconds histogram\n\
             latency_seconds_bucket{m=\"GET\",le=\"0.5\"} 1\n\
             latency_seconds_bucket{m=\"GET\",le=\"1.0\"} 2\n\
             latency_seconds_bucket{m=\"GET\",le=\"+Inf\"} 3\n\
             latency_seconds_sum{m=\"GET\"} 1.25\n\
             latency_seconds_count{m=\"GET\"} 3\n"
        );
    }

    #[test]
    fn openmetrics_known_answer() {
        let text = encode(&sample_families(), Format::OpenMetrics);
        assert_eq!(
            text,
            "# HELP requests Requests served.\n\
             # TYPE requests counter\n\
             requests_total{path=\"/a\\\"b\\\\c\\nd\"} 3\n\
             # HELP latency_seconds Latency.\n\
             # TYPE latency_seconds histogram\n\
             # UNIT latency_seconds seconds\n\
             latency_seconds_bucket{m=\"GET\",le=\"0.5\"} 1\n\
             latency_seconds_bucket{m=\"GET\",le=\"1.0\"} 2\n\
             latency_seconds_bucket{m=\"GET\",le=\"+Inf\"} 3\n\
             latency_seconds_sum{m=\"GET\"} 1.25\n\
             latency_seconds_count{m=\"GET\"} 3\n\
             # EOF\n"
        );
    }

    #[test]
    fn special_values_and_help_escaping() {
        assert_eq!(format_value(f64::INFINITY), "+Inf");
        assert_eq!(format_value(f64::NEG_INFINITY), "-Inf");
        assert_eq!(format_value(f64::NAN), "NaN");
        assert_eq!(format_value(0.1), "0.1");
        assert_eq!(escape_help("a\\b\n\"c\"", false), "a\\\\b\\n\"c\"");
        assert_eq!(escape_help("\"", true), "\\\"");
    }

    #[test]
    fn empty_openmetrics_is_just_eof() {
        assert_eq!(encode(&[], Format::OpenMetrics), "# EOF\n");
        assert_eq!(encode(&[], Format::Prometheus), "");
    }
}
