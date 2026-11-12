//! Point-in-time snapshot data model shared by the registry, collectors and
//! the encoder.

/// The type of a metric family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MetricType {
    /// A monotonically increasing total.
    Counter,
    /// A value that goes up and down.
    Gauge,
    /// Observations counted into cumulative buckets.
    Histogram,
}

impl MetricType {
    /// The type name used on `# TYPE` lines.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// A snapshot of a histogram.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct HistogramValue {
    /// `(upper bound, cumulative count)` for every finite bucket, in
    /// increasing order. The `+Inf` bucket is [`HistogramValue::count`].
    pub buckets: Vec<(f64, u64)>,
    /// Sum of all observations.
    pub sum: f64,
    /// Number of observations.
    pub count: u64,
}

impl HistogramValue {
    /// Creates a histogram snapshot from cumulative finite buckets, the sum
    /// and the total count.
    #[must_use]
    pub const fn new(buckets: Vec<(f64, u64)>, sum: f64, count: u64) -> Self {
        Self {
            buckets,
            sum,
            count,
        }
    }
}

/// The value of one sample set.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Value {
    /// A counter total.
    Counter(f64),
    /// A gauge reading.
    Gauge(f64),
    /// A histogram snapshot.
    Histogram(HistogramValue),
}

/// One labelled member of a [`MetricFamily`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Metric {
    /// `(name, value)` label pairs.
    pub labels: Vec<(String, String)>,
    /// The current value.
    pub value: Value,
}

impl Metric {
    /// Creates a metric from label pairs and a value.
    #[must_use]
    pub const fn new(labels: Vec<(String, String)>, value: Value) -> Self {
        Self { labels, value }
    }
}

/// A snapshot of every member of one named metric.
///
/// For counters, `name` is the family name without the `_total` suffix; the
/// encoder adds it to samples.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct MetricFamily {
    /// Family name.
    pub name: String,
    /// Help text.
    pub help: String,
    /// Unit, if declared (`seconds`, `bytes`, ...).
    pub unit: Option<String>,
    /// Metric type.
    pub kind: MetricType,
    /// Members, one per label value combination.
    pub metrics: Vec<Metric>,
}

impl MetricFamily {
    /// Creates an empty family. `name` ending in `_total` is trimmed for
    /// counters.
    #[must_use]
    pub fn new(name: impl Into<String>, help: impl Into<String>, kind: MetricType) -> Self {
        let mut name = name.into();
        if kind == MetricType::Counter && name.ends_with("_total") {
            name.truncate(name.len() - "_total".len());
        }
        Self {
            name,
            help: help.into(),
            unit: None,
            kind,
            metrics: Vec::new(),
        }
    }

    /// Sets the unit.
    #[must_use]
    pub fn with_unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }

    /// Appends a member.
    #[must_use]
    pub fn with_metric(mut self, metric: Metric) -> Self {
        self.metrics.push(metric);
        self
    }
}
