//! Metrics for services: counters, gauges and histograms in a [`Registry`],
//! exposed in the [Prometheus text format] or as [OpenMetrics] 1.0.0.
//!
//! - **Instruments** ([`Counter`], [`Gauge`], [`Histogram`]) are lock-free
//!   handles; labelled [`Family`]s hand out one instrument per label set.
//! - **No global state.** Create a [`Registry`], pass clones around, and
//!   serve [`Registry::encode`]. Registration validates names, labels,
//!   units and buckets and returns an [`Error`] instead of panicking.
//! - **Sans-I/O encoder.** [`encode`] turns [`MetricFamily`] snapshots into
//!   text; [`Format::negotiate`] picks the format from an `Accept` header.
//! - **Collectors** ([`Collector`]) produce families at scrape time.
//!   [`ProcessCollector`] provides the standard `process_*` metrics.
//! - **HTTP** (feature `tower`): [`HttpMetricsLayer`] records
//!   `http_server_*` request metrics for any Tower/Axum service, and
//!   [`MetricsEndpoint`] serves the scrape endpoint.
//!
//! [Prometheus text format]: https://prometheus.io/docs/instrumenting/exposition_formats/
//! [OpenMetrics]: https://github.com/prometheus/OpenMetrics/blob/main/specification/OpenMetrics.md
//!
//! # Example
//!
//! ```
//! use rune_metrics::{DEFAULT_BUCKETS, Format, Opts, ProcessCollector, Registry};
//!
//! let registry = Registry::new();
//! registry.register_collector(ProcessCollector::new());
//!
//! let jobs = registry.counter_vec(("jobs_total", "Jobs processed."), &["outcome"])?;
//! let queue = registry.gauge(("queue_depth", "Jobs waiting."))?;
//! let latency = registry.histogram(
//!     Opts::new("job_duration_seconds", "Job run time.").with_unit("seconds"),
//!     DEFAULT_BUCKETS,
//! )?;
//!
//! jobs.with_label_values(&["ok"])?.inc();
//! queue.set(4.0);
//! latency.observe(0.042);
//!
//! let text = registry.encode(Format::Prometheus);
//! assert!(text.contains("# TYPE jobs_total counter\n"));
//! assert!(text.contains("jobs_total{outcome=\"ok\"} 1\n"));
//! assert!(text.contains("queue_depth 4\n"));
//! assert!(text.contains("job_duration_seconds_bucket{le=\"0.05\"} 1\n"));
//!
//! let om = registry.encode(Format::OpenMetrics);
//! assert!(om.contains("# UNIT job_duration_seconds seconds\n"));
//! assert!(om.ends_with("# EOF\n"));
//! # Ok::<(), rune_metrics::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod encode;
mod error;
#[cfg(feature = "tower")]
mod http;
mod metric;
mod model;
mod process;
mod registry;

pub use encode::{Format, encode};
pub use error::Error;
#[cfg(feature = "tower")]
pub use http::{HttpMetricsFuture, HttpMetricsLayer, HttpMetricsService, MetricsEndpoint};
pub use metric::{Counter, DEFAULT_BUCKETS, Gauge, Histogram, Instrument};
pub use model::{HistogramValue, Metric, MetricFamily, MetricType, Value};
pub use process::{ProcFiles, ProcessCollector, ProcessStats};
pub use registry::{
    Collector, CounterVec, Family, GaugeVec, HistogramVec, Opts, Registry, is_valid_label_name,
    is_valid_metric_name,
};
