//! Lock-free instruments: [`Counter`], [`Gauge`] and [`Histogram`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::Error;
use crate::model::{HistogramValue, Value};

/// Default histogram buckets, in seconds: the Prometheus client defaults,
/// suited to request latencies from 5 ms to 10 s.
pub const DEFAULT_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// An `f64` stored in an `AtomicU64`.
#[derive(Debug, Default)]
struct AtomicF64(AtomicU64);

impl AtomicF64 {
    fn get(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::Relaxed))
    }

    fn set(&self, v: f64) {
        self.0.store(v.to_bits(), Ordering::Relaxed);
    }

    fn add(&self, v: f64) {
        let mut current = self.0.load(Ordering::Relaxed);
        loop {
            let next = (f64::from_bits(current) + v).to_bits();
            match self
                .0
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }
}

/// A monotonically increasing total. Cheap to clone; clones share the value.
///
/// # Examples
///
/// ```
/// let requests = rune_metrics::Counter::default();
/// requests.inc();
/// requests.inc_by(2.0);
/// assert_eq!(requests.get(), 3.0);
/// ```
#[derive(Debug, Clone, Default)]
pub struct Counter(Arc<AtomicF64>);

impl Counter {
    /// Adds one.
    pub fn inc(&self) {
        self.0.add(1.0);
    }

    /// Adds `v`. Negative, NaN and infinite values are ignored, since a
    /// counter only goes up.
    pub fn inc_by(&self, v: f64) {
        if v.is_finite() && v > 0.0 {
            self.0.add(v);
        }
    }

    /// Returns the current total.
    #[must_use]
    pub fn get(&self) -> f64 {
        self.0.get()
    }
}

/// A value that goes up and down. Cheap to clone; clones share the value.
///
/// # Examples
///
/// ```
/// let in_flight = rune_metrics::Gauge::default();
/// in_flight.inc();
/// in_flight.inc();
/// in_flight.dec();
/// assert_eq!(in_flight.get(), 1.0);
/// in_flight.set(42.5);
/// assert_eq!(in_flight.get(), 42.5);
/// ```
#[derive(Debug, Clone, Default)]
pub struct Gauge(Arc<AtomicF64>);

impl Gauge {
    /// Sets the value.
    pub fn set(&self, v: f64) {
        self.0.set(v);
    }

    /// Adds one.
    pub fn inc(&self) {
        self.0.add(1.0);
    }

    /// Subtracts one.
    pub fn dec(&self) {
        self.0.add(-1.0);
    }

    /// Adds `v` (which may be negative).
    pub fn add(&self, v: f64) {
        self.0.add(v);
    }

    /// Returns the current value.
    #[must_use]
    pub fn get(&self) -> f64 {
        self.0.get()
    }
}

#[derive(Debug)]
struct HistogramInner {
    bounds: Box<[f64]>,
    /// Non-cumulative counts, one per bound plus the `+Inf` bucket.
    counts: Box<[AtomicU64]>,
    sum: AtomicF64,
}

/// Observations counted into buckets. Cheap to clone; clones share state.
///
/// # Examples
///
/// ```
/// let latency = rune_metrics::Histogram::new(&[0.1, 1.0])?;
/// latency.observe(0.05);
/// latency.observe(0.5);
/// latency.observe(3.0);
/// let snapshot = latency.snapshot();
/// assert_eq!(snapshot.buckets, vec![(0.1, 1), (1.0, 2)]);
/// assert_eq!(snapshot.count, 3);
/// # Ok::<(), rune_metrics::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Histogram(Arc<HistogramInner>);

impl Default for Histogram {
    /// A histogram with [`DEFAULT_BUCKETS`].
    fn default() -> Self {
        Self::from_valid_bounds(DEFAULT_BUCKETS)
    }
}

impl Histogram {
    /// Creates a histogram with the given finite bucket upper bounds. The
    /// `+Inf` bucket is implicit.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidBuckets`] unless `bounds` is non-empty, finite and
    /// strictly increasing.
    pub fn new(bounds: &[f64]) -> Result<Self, Error> {
        validate_buckets(bounds)?;
        Ok(Self::from_valid_bounds(bounds))
    }

    /// Builds a histogram from bounds already checked by `validate_buckets`.
    #[must_use]
    pub(crate) fn from_valid_bounds(bounds: &[f64]) -> Self {
        let counts = (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect();
        Self(Arc::new(HistogramInner {
            bounds: bounds.into(),
            counts,
            sum: AtomicF64::default(),
        }))
    }

    /// Records one observation. NaN is ignored.
    pub fn observe(&self, v: f64) {
        if v.is_nan() {
            return;
        }
        let idx = self.0.bounds.partition_point(|&b| b < v);
        if let Some(c) = self.0.counts.get(idx) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        self.0.sum.add(v);
    }

    /// Returns the bucket upper bounds.
    #[must_use]
    pub fn bounds(&self) -> &[f64] {
        &self.0.bounds
    }

    /// Returns a snapshot with cumulative bucket counts.
    #[must_use]
    pub fn snapshot(&self) -> HistogramValue {
        let mut cumulative = 0u64;
        let mut buckets = Vec::with_capacity(self.0.bounds.len());
        for (bound, count) in self.0.bounds.iter().zip(self.0.counts.iter()) {
            cumulative = cumulative.saturating_add(count.load(Ordering::Relaxed));
            buckets.push((*bound, cumulative));
        }
        let inf = self
            .0
            .counts
            .last()
            .map_or(0, |c| c.load(Ordering::Relaxed));
        HistogramValue::new(buckets, self.0.sum.get(), cumulative.saturating_add(inf))
    }
}

/// Checks that bucket bounds are non-empty, finite and strictly increasing.
pub fn validate_buckets(bounds: &[f64]) -> Result<(), Error> {
    if bounds.is_empty()
        || bounds.iter().any(|b| !b.is_finite())
        || bounds.windows(2).any(|w| w[0] >= w[1])
    {
        return Err(Error::InvalidBuckets);
    }
    Ok(())
}

/// An instrument that can be snapshotted into a [`Value`].
pub trait Instrument: Clone + Send + Sync + 'static {
    /// Returns the current value.
    fn value(&self) -> Value;
}

impl Instrument for Counter {
    fn value(&self) -> Value {
        Value::Counter(self.get())
    }
}

impl Instrument for Gauge {
    fn value(&self) -> Value {
        Value::Gauge(self.get())
    }
}

impl Instrument for Histogram {
    fn value(&self) -> Value {
        Value::Histogram(self.snapshot())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_ignores_invalid_increments() {
        let c = Counter::default();
        c.inc_by(-1.0);
        c.inc_by(f64::NAN);
        c.inc_by(f64::INFINITY);
        assert_eq!(c.get(), 0.0);
        c.inc_by(0.5);
        let shared = c.clone();
        shared.inc();
        assert_eq!(c.get(), 1.5);
    }

    #[test]
    fn histogram_buckets_are_inclusive_upper_bounds() {
        let h = Histogram::new(&[1.0, 2.0]).unwrap();
        for v in [0.5, 1.0, 1.5, 2.0, 2.5, f64::NAN] {
            h.observe(v);
        }
        let s = h.snapshot();
        assert_eq!(s.buckets, vec![(1.0, 2), (2.0, 4)]);
        assert_eq!(s.count, 5);
        assert!((s.sum - 7.5).abs() < f64::EPSILON);
    }

    #[test]
    fn invalid_buckets_are_rejected() {
        assert_eq!(Histogram::new(&[]).unwrap_err(), Error::InvalidBuckets);
        assert!(Histogram::new(&[1.0, 1.0]).is_err());
        assert!(Histogram::new(&[2.0, 1.0]).is_err());
        assert!(Histogram::new(&[1.0, f64::INFINITY]).is_err());
        assert!(Histogram::new(&[f64::NAN]).is_err());
        assert_eq!(Histogram::default().bounds(), DEFAULT_BUCKETS);
    }

    #[test]
    fn gauge_moves_both_ways() {
        let g = Gauge::default();
        g.add(5.0);
        g.dec();
        g.add(-1.5);
        assert_eq!(g.get(), 2.5);
    }
}
