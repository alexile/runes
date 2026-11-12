//! [`Registry`], labelled [`Family`] instruments and the [`Collector`] trait.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::Error;
use crate::encode::{Format, encode};
use crate::metric::{Counter, Gauge, Histogram, Instrument, validate_buckets};
use crate::model::{Metric, MetricFamily, MetricType};

/// Produces metric families at scrape time.
///
/// Implement it for values that are cheaper to read on demand than to keep
/// updated, such as process statistics or queue depths. Registered metrics
/// ([`Registry::counter`] and friends) are collectors too.
pub trait Collector: Send + Sync {
    /// Returns a snapshot of the families this collector owns.
    fn collect(&self) -> Vec<MetricFamily>;
}

impl<F> Collector for F
where
    F: Fn() -> Vec<MetricFamily> + Send + Sync,
{
    fn collect(&self) -> Vec<MetricFamily> {
        self()
    }
}

/// Name, help text and optional unit of a metric being registered.
///
/// # Examples
///
/// ```
/// use rune_metrics::Opts;
///
/// let opts = Opts::new("job_duration_seconds", "Time spent per job.").with_unit("seconds");
/// assert_eq!(opts.name(), "job_duration_seconds");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Opts {
    name: String,
    help: String,
    unit: Option<String>,
}

impl Opts {
    /// Creates options for a metric named `name` described by `help`.
    #[must_use]
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            unit: None,
        }
    }

    /// Declares the metric's unit. The name must end with `_<unit>` (before
    /// any `_total`), as `OpenMetrics` requires.
    #[must_use]
    pub fn with_unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }

    /// The metric name as given.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl<N: Into<String>, H: Into<String>> From<(N, H)> for Opts {
    fn from((name, help): (N, H)) -> Self {
        Self::new(name, help)
    }
}

/// Returns `true` if `name` is a valid metric name.
#[must_use]
pub fn is_valid_metric_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == ':')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

/// Returns `true` if `name` is a valid, non-reserved label name.
#[must_use]
pub fn is_valid_label_name(name: &str) -> bool {
    let mut chars = name.chars();
    !name.starts_with("__")
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Validated descriptor of a registered family.
#[derive(Debug, Clone)]
struct Desc {
    name: String,
    help: String,
    unit: Option<String>,
    kind: MetricType,
}

impl Desc {
    fn new(opts: Opts, kind: MetricType, labels: &[&str]) -> Result<Self, Error> {
        let Opts { name, help, unit } = opts;
        if !is_valid_metric_name(&name) {
            return Err(Error::InvalidName(name));
        }
        let base = match kind {
            MetricType::Counter => name.strip_suffix("_total").unwrap_or(&name).to_owned(),
            _ => name,
        };
        if base.is_empty() {
            return Err(Error::InvalidName(base));
        }
        if let Some(unit) = &unit
            && (unit.is_empty()
                || !unit.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                || !base.ends_with(&format!("_{unit}")))
        {
            return Err(Error::InvalidUnit {
                name: base,
                unit: unit.clone(),
            });
        }
        let mut seen = HashSet::new();
        for label in labels {
            if !is_valid_label_name(label) || (kind == MetricType::Histogram && *label == "le") {
                return Err(Error::InvalidLabelName((*label).to_owned()));
            }
            if !seen.insert(*label) {
                return Err(Error::DuplicateLabelName((*label).to_owned()));
            }
        }
        Ok(Self {
            name: base,
            help,
            unit,
            kind,
        })
    }

    fn family(&self) -> MetricFamily {
        let mut family = MetricFamily::new(self.name.clone(), self.help.clone(), self.kind);
        family.unit.clone_from(&self.unit);
        family
    }
}

type Make<M> = Arc<dyn Fn() -> M + Send + Sync>;

/// A metric with labels: one instrument per combination of label values.
///
/// Cheap to clone; clones share their members. Get a member with
/// [`Family::with_label_values`] and keep the returned handle for hot paths.
pub struct Family<M> {
    desc: Arc<Desc>,
    label_names: Arc<[String]>,
    members: Arc<Mutex<BTreeMap<Vec<String>, M>>>,
    make: Make<M>,
}

impl<M> Clone for Family<M> {
    fn clone(&self) -> Self {
        Self {
            desc: Arc::clone(&self.desc),
            label_names: Arc::clone(&self.label_names),
            members: Arc::clone(&self.members),
            make: Arc::clone(&self.make),
        }
    }
}

impl<M> fmt::Debug for Family<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Family")
            .field("name", &self.desc.name)
            .field("labels", &self.label_names)
            .finish_non_exhaustive()
    }
}

/// A counter with labels.
pub type CounterVec = Family<Counter>;
/// A gauge with labels.
pub type GaugeVec = Family<Gauge>;
/// A histogram with labels.
pub type HistogramVec = Family<Histogram>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<M: Instrument> Family<M> {
    fn new(desc: Desc, labels: &[&str], make: Make<M>) -> Self {
        Self {
            desc: Arc::new(desc),
            label_names: labels.iter().map(|&l| l.to_owned()).collect(),
            members: Arc::default(),
            make,
        }
    }

    /// Returns the member for `values`, given in label-name order, creating
    /// it on first use.
    ///
    /// # Errors
    ///
    /// [`Error::LabelCount`] if the number of values differs from the
    /// number of label names.
    pub fn with_label_values(&self, values: &[&str]) -> Result<M, Error> {
        if values.len() != self.label_names.len() {
            return Err(Error::LabelCount {
                expected: self.label_names.len(),
                got: values.len(),
            });
        }
        let key: Vec<String> = values.iter().map(|&v| v.to_owned()).collect();
        let mut members = lock(&self.members);
        Ok(members.entry(key).or_insert_with(|| (self.make)()).clone())
    }

    /// Removes the member for `values`. Returns whether it existed.
    #[allow(
        clippy::must_use_candidate,
        reason = "removal is the point; the result is optional"
    )]
    pub fn remove(&self, values: &[&str]) -> bool {
        let key: Vec<String> = values.iter().map(|&v| v.to_owned()).collect();
        lock(&self.members).remove(&key).is_some()
    }

    /// The label names, in order.
    #[must_use]
    pub fn label_names(&self) -> &[String] {
        &self.label_names
    }
}

impl<M: Instrument> Collector for Family<M> {
    fn collect(&self) -> Vec<MetricFamily> {
        let mut family = self.desc.family();
        family.metrics = lock(&self.members)
            .iter()
            .map(|(values, m)| {
                let labels = self
                    .label_names
                    .iter()
                    .cloned()
                    .zip(values.iter().cloned())
                    .collect();
                Metric::new(labels, m.value())
            })
            .collect();
        vec![family]
    }
}

#[derive(Default)]
struct Inner {
    names: HashSet<String>,
    collectors: Vec<Arc<dyn Collector>>,
}

/// A set of metrics and collectors that is encoded as one exposition.
///
/// There is no global registry: create one, pass clones to the code that
/// records metrics, and serve [`Registry::encode`] at `/metrics`. Clones
/// share their contents.
///
/// # Examples
///
/// ```
/// use rune_metrics::{Format, Registry};
///
/// let registry = Registry::new();
/// let jobs = registry.counter_vec(("jobs_total", "Jobs processed."), &["queue"])?;
/// jobs.with_label_values(&["email"])?.inc();
///
/// let text = registry.encode(Format::Prometheus);
/// assert!(text.contains("jobs_total{queue=\"email\"} 1"));
/// # Ok::<(), rune_metrics::Error>(())
/// ```
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<Mutex<Inner>>,
}

impl fmt::Debug for Registry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = lock(&self.inner);
        f.debug_struct("Registry")
            .field("names", &inner.names)
            .field("collectors", &inner.collectors.len())
            .finish()
    }
}

impl Registry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn add<M: Instrument>(&self, family: Family<M>) -> Result<Family<M>, Error> {
        {
            let mut inner = lock(&self.inner);
            if !inner.names.insert(family.desc.name.clone()) {
                return Err(Error::AlreadyRegistered(family.desc.name.clone()));
            }
            inner.collectors.push(Arc::new(family.clone()));
        }
        Ok(family)
    }

    fn register_family<M: Instrument>(
        &self,
        opts: Opts,
        kind: MetricType,
        labels: &[&str],
        make: Make<M>,
    ) -> Result<Family<M>, Error> {
        let desc = Desc::new(opts, kind, labels)?;
        self.add(Family::new(desc, labels, make))
    }

    /// Registers an unlabelled counter. A trailing `_total` in the name is
    /// optional; it is always added on exposition.
    ///
    /// # Errors
    ///
    /// An invalid name or unit, or a name already registered.
    pub fn counter(&self, opts: impl Into<Opts>) -> Result<Counter, Error> {
        self.counter_vec(opts, &[])?.with_label_values(&[])
    }

    /// Registers a counter with labels.
    ///
    /// # Errors
    ///
    /// An invalid name, unit or label name, or a name already registered.
    pub fn counter_vec(&self, opts: impl Into<Opts>, labels: &[&str]) -> Result<CounterVec, Error> {
        self.register_family(
            opts.into(),
            MetricType::Counter,
            labels,
            Arc::new(Counter::default),
        )
    }

    /// Registers an unlabelled gauge.
    ///
    /// # Errors
    ///
    /// An invalid name or unit, or a name already registered.
    pub fn gauge(&self, opts: impl Into<Opts>) -> Result<Gauge, Error> {
        self.gauge_vec(opts, &[])?.with_label_values(&[])
    }

    /// Registers a gauge with labels.
    ///
    /// # Errors
    ///
    /// An invalid name, unit or label name, or a name already registered.
    pub fn gauge_vec(&self, opts: impl Into<Opts>, labels: &[&str]) -> Result<GaugeVec, Error> {
        self.register_family(
            opts.into(),
            MetricType::Gauge,
            labels,
            Arc::new(Gauge::default),
        )
    }

    /// Registers an unlabelled histogram with the given bucket upper bounds
    /// (see [`DEFAULT_BUCKETS`](crate::DEFAULT_BUCKETS)).
    ///
    /// # Errors
    ///
    /// Invalid buckets, an invalid name or unit, or a name already
    /// registered.
    pub fn histogram(&self, opts: impl Into<Opts>, buckets: &[f64]) -> Result<Histogram, Error> {
        self.histogram_vec(opts, &[], buckets)?
            .with_label_values(&[])
    }

    /// Registers a histogram with labels. `le` is reserved.
    ///
    /// # Errors
    ///
    /// Invalid buckets, an invalid name, unit or label name, or a name
    /// already registered.
    pub fn histogram_vec(
        &self,
        opts: impl Into<Opts>,
        labels: &[&str],
        buckets: &[f64],
    ) -> Result<HistogramVec, Error> {
        validate_buckets(buckets)?;
        let bounds: Arc<[f64]> = buckets.into();
        self.register_family(
            opts.into(),
            MetricType::Histogram,
            labels,
            Arc::new(move || Histogram::from_valid_bounds(&bounds)),
        )
    }

    /// Registers a collector that is called on every [`Registry::gather`].
    ///
    /// Family names produced by collectors are not checked against
    /// registered metrics; keep them distinct.
    pub fn register_collector(&self, collector: impl Collector + 'static) {
        lock(&self.inner).collectors.push(Arc::new(collector));
    }

    /// Snapshots every registered metric and collector, sorted by family
    /// name.
    #[must_use]
    pub fn gather(&self) -> Vec<MetricFamily> {
        // Clone the collector list so collectors run without the lock held.
        let collectors = lock(&self.inner).collectors.clone();
        let mut families: Vec<MetricFamily> = collectors.iter().flat_map(|c| c.collect()).collect();
        families.sort_by(|a, b| a.name.cmp(&b.name));
        families
    }

    /// Gathers and encodes every metric in `format`.
    #[must_use]
    pub fn encode(&self, format: Format) -> String {
        encode(&self.gather(), format)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_validated() {
        let r = Registry::new();
        assert_eq!(
            r.counter(("1bad", "x")).unwrap_err(),
            Error::InvalidName("1bad".into())
        );
        assert!(r.counter(("_total", "x")).is_err());
        assert_eq!(
            r.gauge_vec(("ok", "x"), &["__reserved"]).unwrap_err(),
            Error::InvalidLabelName("__reserved".into())
        );
        assert!(r.histogram_vec(("h", "x"), &["le"], &[1.0]).is_err());
        assert_eq!(
            r.gauge_vec(("ok2", "x"), &["a", "a"]).unwrap_err(),
            Error::DuplicateLabelName("a".into())
        );
        assert!(
            r.gauge(Opts::new("size_bytes", "x").with_unit("seconds"))
                .is_err()
        );
        assert!(
            r.gauge(Opts::new("size_bytes", "x").with_unit("bytes"))
                .is_ok()
        );
        assert!(
            r.counter(Opts::new("cpu_seconds_total", "x").with_unit("seconds"))
                .is_ok()
        );
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let r = Registry::new();
        r.counter(("hits", "x")).unwrap();
        assert_eq!(
            r.counter(("hits_total", "x")).unwrap_err(),
            Error::AlreadyRegistered("hits".into())
        );
        assert!(r.gauge(("hits", "x")).is_err());
    }

    #[test]
    fn families_track_members_and_check_arity() {
        let r = Registry::new();
        let fam = r.counter_vec(("req", "x"), &["method", "code"]).unwrap();
        fam.with_label_values(&["GET", "200"]).unwrap().inc();
        fam.with_label_values(&["GET", "200"]).unwrap().inc();
        assert_eq!(
            fam.with_label_values(&["GET"]).unwrap_err(),
            Error::LabelCount {
                expected: 2,
                got: 1
            }
        );
        let gathered = r.gather();
        assert_eq!(gathered.len(), 1);
        assert_eq!(gathered[0].metrics.len(), 1);
        assert_eq!(
            gathered[0].metrics[0].labels,
            vec![
                ("method".to_owned(), "GET".to_owned()),
                ("code".to_owned(), "200".to_owned())
            ]
        );
        assert!(fam.remove(&["GET", "200"]));
        assert_eq!(r.gather()[0].metrics, vec![]);
    }

    #[test]
    fn collectors_are_gathered_sorted() {
        let r = Registry::new();
        r.gauge(("zeta", "z")).unwrap();
        r.register_collector(|| vec![MetricFamily::new("alpha", "a", MetricType::Gauge)]);
        let names: Vec<_> = r.gather().into_iter().map(|f| f.name).collect();
        assert_eq!(names, ["alpha", "zeta"]);
    }
}
