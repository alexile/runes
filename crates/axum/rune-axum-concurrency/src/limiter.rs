//! Sans-I/O admission core: a lock-free in-flight counter with metrics.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Shared counters behind a [`Limiter`].
#[derive(Debug)]
struct State {
    max: usize,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
    admitted: AtomicU64,
    shed: AtomicU64,
}

/// A bounded counter of in-flight work that never waits.
///
/// [`try_acquire`](Self::try_acquire) either admits the caller, returning a
/// [`Permit`] that frees its slot when dropped, or refuses at once when the
/// limit is reached (load shedding). There is no queue, no runtime and no
/// lock: admission is a single compare-and-swap.
///
/// Cloning a `Limiter` is cheap and every clone shares the same budget and
/// counters.
///
/// # Examples
///
/// ```rust
/// use rune_axum_concurrency::Limiter;
///
/// let limiter = Limiter::new(1);
/// let first = limiter.try_acquire();
/// assert!(first.is_some());
/// assert!(limiter.try_acquire().is_none()); // shed
///
/// drop(first);
/// assert!(limiter.try_acquire().is_some()); // slot freed
///
/// let m = limiter.metrics();
/// assert_eq!((m.admitted, m.shed, m.in_flight), (2, 1, 0));
/// ```
#[derive(Clone)]
pub struct Limiter {
    state: Arc<State>,
}

impl fmt::Debug for Limiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Limiter")
            .field("metrics", &self.metrics())
            .finish()
    }
}

impl Limiter {
    /// Creates a limiter that admits at most `max_in_flight` concurrent
    /// holders. A limit of zero sheds everything.
    #[must_use]
    pub fn new(max_in_flight: usize) -> Self {
        Self {
            state: Arc::new(State {
                max: max_in_flight,
                in_flight: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                admitted: AtomicU64::new(0),
                shed: AtomicU64::new(0),
            }),
        }
    }

    /// Tries to take a slot without waiting.
    ///
    /// Returns a [`Permit`] that holds the slot until it is dropped, or
    /// `None` when the limit is already reached. Every call counts as either
    /// admitted or shed in [`metrics`](Self::metrics).
    #[must_use = "dropping the permit frees the slot immediately"]
    pub fn try_acquire(&self) -> Option<Permit> {
        let state = &self.state;
        // A compare-and-swap loop rather than `fetch_update`/`try_update`,
        // which are deprecated or unavailable across the supported toolchains.
        let mut current = state.in_flight.load(Ordering::Acquire);
        loop {
            if current >= state.max {
                state.shed.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            match state.in_flight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        state.peak.fetch_max(current + 1, Ordering::Relaxed);
        state.admitted.fetch_add(1, Ordering::Relaxed);
        Some(Permit {
            state: Arc::clone(state),
        })
    }

    /// Returns the configured maximum number of in-flight holders.
    #[must_use]
    pub fn max_in_flight(&self) -> usize {
        self.state.max
    }

    /// Returns a point-in-time snapshot of the counters.
    ///
    /// The fields are read one after another, so under concurrent load they
    /// are individually exact but not a single atomic snapshot.
    #[must_use]
    pub fn metrics(&self) -> Metrics {
        let s = &self.state;
        Metrics {
            limit: s.max,
            in_flight: s.in_flight.load(Ordering::Acquire),
            peak: s.peak.load(Ordering::Relaxed),
            admitted: s.admitted.load(Ordering::Relaxed),
            shed: s.shed.load(Ordering::Relaxed),
        }
    }
}

/// A held slot of a [`Limiter`]. Dropping it frees the slot.
#[must_use = "dropping the permit frees the slot immediately"]
pub struct Permit {
    state: Arc<State>,
}

impl fmt::Debug for Permit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Permit").finish_non_exhaustive()
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.state.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A snapshot of a [`Limiter`]'s counters, for metrics export.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Metrics {
    /// Configured maximum number of in-flight requests.
    pub limit: usize,
    /// Requests currently holding a slot.
    pub in_flight: usize,
    /// Highest `in_flight` value observed since the limiter was created.
    pub peak: usize,
    /// Total requests admitted.
    pub admitted: u64,
    /// Total requests shed because the limit was reached.
    pub shed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_up_to_limit_then_sheds() {
        let l = Limiter::new(3);
        let permits: Vec<_> = (0..3).map(|_| l.try_acquire()).collect();
        assert!(permits.iter().all(Option::is_some));
        assert!(l.try_acquire().is_none());
        let m = l.metrics();
        assert_eq!(m.in_flight, 3);
        assert_eq!(m.peak, 3);
        assert_eq!(m.admitted, 3);
        assert_eq!(m.shed, 1);
        assert_eq!(m.limit, 3);
        drop(permits);
        assert_eq!(l.metrics().in_flight, 0);
        assert_eq!(l.metrics().peak, 3);
    }

    #[test]
    fn zero_limit_sheds_everything() {
        let l = Limiter::new(0);
        assert!(l.try_acquire().is_none());
        assert_eq!(l.metrics().shed, 1);
        assert_eq!(l.metrics().admitted, 0);
    }

    #[test]
    fn clones_share_budget() {
        let a = Limiter::new(1);
        let b = a.clone();
        let _p = a.try_acquire();
        assert!(b.try_acquire().is_none());
        assert_eq!(b.max_in_flight(), 1);
    }

    #[test]
    fn concurrent_threads_never_exceed_limit() {
        let l = Limiter::new(4);
        std::thread::scope(|s| {
            for _ in 0..8 {
                let l = l.clone();
                s.spawn(move || {
                    for _ in 0..10_000 {
                        if let Some(p) = l.try_acquire() {
                            assert!(l.metrics().in_flight <= 4);
                            drop(p);
                        }
                    }
                });
            }
        });
        let m = l.metrics();
        assert_eq!(m.in_flight, 0);
        assert!(m.peak <= 4);
        assert_eq!(m.admitted + m.shed, 80_000);
    }
}
