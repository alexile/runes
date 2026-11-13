//! The processing-time deduplicator: exact or approximate, with a TTL window.

use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::marker::PhantomData;
use std::time::{Duration, Instant};

use crate::bloom::{ApproxConfig, Generation, Generations};
use crate::error::{ConfigError, RestoreError};
use crate::hash::HashKey;
use crate::metrics::{EvictionReason, MetricEvent, Recorder, Stats};
use crate::store::ExactStore;
use crate::time::Timestamp;

pub const SNAPSHOT_VERSION: u32 = 1;

/// How a [`Dedupe`] remembers keys.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[non_exhaustive]
pub enum Mode {
    /// Stores every key. Never wrong while memory allows; bounded by the window
    /// and, optionally, [`DedupeBuilder::max_keys`].
    #[default]
    Exact,
    /// Stores no keys, only rotating Bloom filters of fixed size. Never misses a
    /// duplicate within the window, but reports a small, configurable fraction
    /// of new keys as duplicates. See [`ApproxConfig`].
    Approximate(ApproxConfig),
}

#[derive(Debug, Clone)]
enum Engine<K, T> {
    Exact(ExactStore<K, T>),
    Approx(Generations<T>, ApproxConfig),
}

/// A deduplicator that drops keys seen within a trailing `window`.
///
/// Time is passed in explicitly, never read from a clock, so decisions are
/// deterministic. `T` is any [`Timestamp`]: [`Instant`] (the default),
/// [`SystemTime`](std::time::SystemTime), or `i64`/`u64` milliseconds. Use a
/// serializable type if you want to persist [snapshots](Self::snapshot).
///
/// # Semantics
///
/// A key is fresh if it has no *accepted* occurrence in the last `window`
/// (inclusive). Duplicates do not extend the window. A timestamp earlier than
/// the recorded one (clock skew) counts as inside the window.
///
/// # Memory and eviction
///
/// - Entries older than the window are dropped as later checks pass them,
///   oldest first, in `O(log n)` per entry.
/// - With [`max_keys`](DedupeBuilder::max_keys), inserting a new key at the cap
///   first evicts the oldest-accepted key (the one closest to expiring anyway).
///   That key may then be accepted again within its window; each such eviction
///   is counted in [`Stats::evicted_capacity`]. Without a cap, memory grows
///   with the number of distinct keys per window. Set one for untrusted input.
/// - [`Mode::Approximate`] uses fixed memory instead.
///
/// # Example
///
/// ```rust
/// use rune_dedupe::Dedupe;
/// use std::time::{Duration, Instant};
///
/// let start = Instant::now();
/// let mut dedupe = Dedupe::new(Duration::from_secs(60));
///
/// assert!(dedupe.check("msg-1", start), "first time seeing this key");
/// assert!(!dedupe.check("msg-1", start + Duration::from_secs(1)), "duplicate");
/// assert!(dedupe.check("msg-1", start + Duration::from_secs(61)), "window elapsed");
/// ```
pub struct Dedupe<K, T = Instant> {
    window: Duration,
    max_keys: Option<usize>,
    hash_key: HashKey,
    engine: Engine<K, T>,
    metrics: Recorder,
}

impl<K: Eq + Hash + Clone, T: Timestamp> Dedupe<K, T> {
    /// An exact, unbounded deduplicator with a random [`HashKey`].
    #[must_use]
    pub fn new(window: Duration) -> Self {
        let hash_key = HashKey::random();
        Self {
            window,
            max_keys: None,
            hash_key,
            engine: Engine::Exact(ExactStore::new(hash_key)),
            metrics: Recorder::default(),
        }
    }

    /// Starts configuring a deduplicator.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_dedupe::{ApproxConfig, Dedupe};
    /// use std::time::Duration;
    ///
    /// let exact: Dedupe<String, u64> = Dedupe::builder(Duration::from_secs(300))
    ///     .max_keys(100_000)
    ///     .build()?;
    /// let approx: Dedupe<String, u64> = Dedupe::builder(Duration::from_secs(300))
    ///     .approximate(ApproxConfig::new(1_000_000, 0.001))
    ///     .build()?;
    /// # Ok::<(), rune_dedupe::ConfigError>(())
    /// ```
    #[must_use]
    pub fn builder(window: Duration) -> DedupeBuilder<K, T> {
        DedupeBuilder {
            window,
            max_keys: None,
            mode: Mode::Exact,
            hash_key: None,
            hook: None,
            _types: PhantomData,
        }
    }

    /// Checks `key` at time `at`. Returns `true` and records the key if it has
    /// not been accepted within the window, or `false` if it is a duplicate.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_dedupe::Dedupe;
    /// use std::time::{Duration, Instant};
    ///
    /// let start = Instant::now();
    /// let mut dedupe = Dedupe::new(Duration::from_secs(10));
    /// assert!(dedupe.check("a", start));
    /// assert!(!dedupe.check("a", start + Duration::from_secs(5)));
    /// ```
    pub fn check(&mut self, key: K, at: T) -> bool {
        let window = self.window;
        let (fresh, expired, capacity) = match &mut self.engine {
            Engine::Exact(store) => {
                let expired = store.pop_while(|t| at.saturating_since(t) > window);
                if store.contains_key(&key) {
                    (false, expired, 0)
                } else {
                    let capacity = store.make_room(self.max_keys);
                    store.insert(key, at);
                    (true, expired, capacity)
                }
            }
            Engine::Approx(gens, _) => {
                let out = gens.check(self.hash_key.hash_one(&key), at, window);
                (!out.duplicate, out.expired, out.capacity)
            }
        };
        self.metrics.evicted(EvictionReason::Expired, expired);
        self.metrics.evicted(EvictionReason::Capacity, capacity);
        self.metrics.record(if fresh {
            MetricEvent::Fresh
        } else {
            MetricEvent::Duplicate
        });
        fresh
    }

    /// Whether [`check`](Self::check) would call `key` a duplicate at `at`,
    /// without recording anything or dropping expired state.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_dedupe::Dedupe;
    /// use std::time::Duration;
    ///
    /// let mut d = Dedupe::new(Duration::from_secs(1));
    /// d.check("a", 0_u64);
    /// assert!(d.contains(&"a", 1_000));
    /// assert!(!d.contains(&"a", 1_001));
    /// assert!(!d.contains(&"b", 0));
    /// ```
    #[must_use]
    pub fn contains(&self, key: &K, at: T) -> bool {
        match &self.engine {
            Engine::Exact(store) => store
                .times(key)
                .any(|t| at.saturating_since(t) <= self.window),
            Engine::Approx(gens, _) => gens.contains(self.hash_key.hash_one(key), at, self.window),
        }
    }

    /// Keys currently remembered, as of the last [`check`](Self::check). In
    /// approximate mode this counts keys recorded in live generations.
    #[must_use]
    pub fn len(&self) -> usize {
        match &self.engine {
            Engine::Exact(store) => store.keys(),
            Engine::Approx(gens, _) => gens.len(),
        }
    }

    /// Whether no keys are remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The dedupe window.
    #[must_use]
    pub const fn window(&self) -> Duration {
        self.window
    }

    /// The mode this deduplicator runs in.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        match &self.engine {
            Engine::Exact(_) => Mode::Exact,
            Engine::Approx(_, cfg) => Mode::Approximate(*cfg),
        }
    }

    /// Running counters. See [`Stats`].
    #[must_use]
    pub const fn stats(&self) -> Stats {
        self.metrics.stats
    }

    /// Installs (or with `None`, removes) a callback that receives every
    /// [`MetricEvent`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_dedupe::{Dedupe, MetricEvent};
    /// use std::sync::atomic::{AtomicU64, Ordering};
    /// use std::sync::Arc;
    ///
    /// let dupes = Arc::new(AtomicU64::new(0));
    /// let counter = Arc::clone(&dupes);
    /// let mut d = Dedupe::new(std::time::Duration::from_secs(1));
    /// d.set_metrics(Some(Box::new(move |e| {
    ///     if e == MetricEvent::Duplicate {
    ///         counter.fetch_add(1, Ordering::Relaxed);
    ///     }
    /// })));
    /// d.check(1, 0_i64);
    /// d.check(1, 0_i64);
    /// assert_eq!(dupes.load(Ordering::Relaxed), 1);
    /// ```
    pub fn set_metrics(&mut self, hook: Option<Box<dyn FnMut(MetricEvent) + Send + Sync>>) {
        self.metrics.set_hook(hook);
    }

    /// Captures the full state: settings, hash key, counters and every
    /// remembered key or filter. [`restore`](Self::restore) rebuilds a
    /// deduplicator that makes exactly the same decisions from here on. The
    /// metrics callback is not captured.
    ///
    /// With the `serde` feature the snapshot is serializable whenever `K` and
    /// `T` are; see the crate docs for committing it together with a stream
    /// offset.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<K, T> {
        let state = match &self.engine {
            Engine::Exact(store) => SnapshotState::Exact {
                entries: store.to_vec(),
            },
            Engine::Approx(gens, cfg) => SnapshotState::Approximate {
                config: *cfg,
                generations: gens.to_vec(),
            },
        };
        Snapshot {
            version: SNAPSHOT_VERSION,
            window: self.window,
            max_keys: self.max_keys,
            hash_key: self.hash_key,
            stats: self.metrics.stats,
            state,
        }
    }

    /// Rebuilds a deduplicator from a [`snapshot`](Self::snapshot).
    ///
    /// # Errors
    ///
    /// [`RestoreError`] if the snapshot is from an unknown version or its state
    /// does not match its settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_dedupe::Dedupe;
    /// use std::time::Duration;
    ///
    /// let mut d = Dedupe::new(Duration::from_secs(10));
    /// d.check("a", 1_000_u64);
    /// let mut restored = Dedupe::restore(d.snapshot())?;
    /// assert!(!restored.check("a", 2_000));
    /// # Ok::<(), rune_dedupe::RestoreError>(())
    /// ```
    pub fn restore(snapshot: Snapshot<K, T>) -> Result<Self, RestoreError> {
        let Snapshot {
            version,
            window,
            max_keys,
            hash_key,
            stats,
            state,
        } = snapshot;
        if version != SNAPSHOT_VERSION {
            return Err(RestoreError::UnsupportedVersion(version));
        }
        if max_keys == Some(0) {
            return Err(ConfigError::ZeroMaxKeys.into());
        }
        let engine = match state {
            SnapshotState::Exact { entries } => {
                if max_keys.is_some_and(|cap| entries.len() > cap) {
                    return Err(RestoreError::Inconsistent("more entries than max_keys"));
                }
                let mut store = ExactStore::new(hash_key);
                for (key, t) in entries {
                    if store.contains_key(&key) {
                        return Err(RestoreError::Inconsistent("key recorded twice"));
                    }
                    store.insert(key, t);
                }
                Engine::Exact(store)
            }
            SnapshotState::Approximate {
                config,
                generations,
            } => {
                if max_keys.is_some() {
                    return Err(ConfigError::MaxKeysWithApproximate.into());
                }
                let gens = Generations::from_vec(config.params()?, window, generations).ok_or(
                    RestoreError::Inconsistent("filter size does not match config"),
                )?;
                Engine::Approx(gens, config)
            }
        };
        Ok(Self {
            window,
            max_keys,
            hash_key,
            engine,
            metrics: Recorder::new(stats, None),
        })
    }
}

impl<K, T> fmt::Debug for Dedupe<K, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mode = match &self.engine {
            Engine::Exact(_) => "exact",
            Engine::Approx(..) => "approximate",
        };
        f.debug_struct("Dedupe")
            .field("window", &self.window)
            .field("max_keys", &self.max_keys)
            .field("mode", &mode)
            .field("stats", &self.metrics.stats)
            .finish_non_exhaustive()
    }
}

/// Settings for a [`Dedupe`], from [`Dedupe::builder`].
pub struct DedupeBuilder<K, T = Instant> {
    window: Duration,
    max_keys: Option<usize>,
    mode: Mode,
    hash_key: Option<HashKey>,
    hook: Option<Box<dyn FnMut(MetricEvent) + Send + Sync>>,
    _types: PhantomData<fn() -> (K, T)>,
}

impl<K: Eq + Hash + Clone, T: Timestamp> DedupeBuilder<K, T> {
    /// Caps exact mode at `max_keys` remembered keys, evicting the oldest
    /// accepted key when full. Must be at least 1.
    #[must_use]
    pub const fn max_keys(mut self, max_keys: usize) -> Self {
        self.max_keys = Some(max_keys);
        self
    }

    /// Picks [`Mode::Exact`] or [`Mode::Approximate`]. Exact is the default.
    #[must_use]
    pub const fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Shorthand for `mode(Mode::Approximate(config))`.
    #[must_use]
    pub const fn approximate(self, config: ApproxConfig) -> Self {
        self.mode(Mode::Approximate(config))
    }

    /// Uses a fixed hash key instead of a random one. Only do this for trusted
    /// keys or in tests.
    #[must_use]
    pub const fn hash_key(mut self, key: HashKey) -> Self {
        self.hash_key = Some(key);
        self
    }

    /// Installs a metrics callback. See [`Dedupe::set_metrics`].
    #[must_use]
    pub fn metrics(mut self, hook: impl FnMut(MetricEvent) + Send + Sync + 'static) -> Self {
        self.hook = Some(Box::new(hook));
        self
    }

    /// Builds the deduplicator.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for a zero `max_keys`, `max_keys` combined with
    /// approximate mode, or an invalid [`ApproxConfig`].
    pub fn build(self) -> Result<Dedupe<K, T>, ConfigError> {
        let hash_key = self.hash_key.unwrap_or_else(HashKey::random);
        let engine = match self.mode {
            Mode::Exact => {
                if self.max_keys == Some(0) {
                    return Err(ConfigError::ZeroMaxKeys);
                }
                Engine::Exact(ExactStore::new(hash_key))
            }
            Mode::Approximate(cfg) => {
                if self.max_keys.is_some() {
                    return Err(ConfigError::MaxKeysWithApproximate);
                }
                Engine::Approx(Generations::new(cfg.params()?, self.window), cfg)
            }
        };
        Ok(Dedupe {
            window: self.window,
            max_keys: self.max_keys,
            hash_key,
            engine,
            metrics: Recorder::new(Stats::default(), self.hook),
        })
    }
}

impl<K, T> fmt::Debug for DedupeBuilder<K, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DedupeBuilder")
            .field("window", &self.window)
            .field("max_keys", &self.max_keys)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

/// The saved state of a [`Dedupe`], from [`Dedupe::snapshot`].
///
/// Opaque on purpose: build one with `snapshot`, persist it (with the `serde`
/// feature), and hand it to [`Dedupe::restore`]. It contains the secret
/// [`HashKey`], so store it as you would any other secret-bearing state.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Snapshot<K, T> {
    version: u32,
    window: Duration,
    max_keys: Option<usize>,
    hash_key: HashKey,
    stats: Stats,
    state: SnapshotState<K, T>,
}

impl<K, T> Snapshot<K, T> {
    /// The counters at the time of the snapshot.
    #[must_use]
    pub const fn stats(&self) -> Stats {
        self.stats
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
enum SnapshotState<K, T> {
    Exact {
        entries: Vec<(K, T)>,
    },
    Approximate {
        config: ApproxConfig,
        generations: Vec<Generation<T>>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    #[test]
    fn first_occurrence_is_not_a_duplicate() {
        let mut dedupe = Dedupe::new(secs(10));
        assert!(dedupe.check("a", Instant::now()));
    }

    #[test]
    fn immediate_repeat_is_a_duplicate() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(secs(10));
        assert!(dedupe.check("a", start));
        assert!(!dedupe.check("a", start + Duration::from_millis(1)));
    }

    #[test]
    fn repeat_after_window_elapsed_is_not_a_duplicate() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(secs(10));
        assert!(dedupe.check("a", start));
        assert!(dedupe.check("a", start + secs(11)));
    }

    #[test]
    fn repeat_exactly_at_window_boundary_is_still_a_duplicate() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(secs(10));
        assert!(dedupe.check("a", start));
        assert!(!dedupe.check("a", start + secs(10)));
        assert!(dedupe.check("a", start + secs(10) + Duration::from_nanos(1)));
    }

    #[test]
    fn duplicate_check_does_not_reset_expiry() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(secs(10));
        assert!(dedupe.check("a", start));
        assert!(!dedupe.check("a", start + secs(5)));
        assert!(dedupe.check("a", start + secs(11)));
    }

    #[test]
    fn purge_keeps_memory_bounded() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(secs(10));
        for i in 0..1000 {
            dedupe.check(i, start);
        }
        assert_eq!(dedupe.len(), 1000);
        assert!(dedupe.check(999_999, start + secs(1000)));
        assert_eq!(dedupe.len(), 1);
        assert_eq!(dedupe.stats().evicted_expired, 1000);
    }

    #[test]
    fn empty_dedupe_reports_empty() {
        let dedupe: Dedupe<&str> = Dedupe::new(secs(10));
        assert!(dedupe.is_empty());
        assert_eq!(dedupe.mode(), Mode::Exact);
    }

    #[test]
    fn zero_window_only_dedupes_same_instant() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(Duration::ZERO);
        assert!(dedupe.check("a", start));
        assert!(!dedupe.check("a", start));
        assert!(dedupe.check("a", start + Duration::from_nanos(1)));
    }

    #[test]
    fn earlier_timestamp_is_treated_as_duplicate() {
        let earlier = Instant::now();
        let later = earlier + secs(50);
        let mut dedupe = Dedupe::new(secs(1));
        assert!(dedupe.check("a", later));
        assert!(!dedupe.check("a", earlier));
    }

    #[test]
    fn purge_is_per_key() {
        let mut dedupe = Dedupe::new(secs(10));
        dedupe.check("old", 0_u64);
        dedupe.check("new", 8_000);
        assert!(dedupe.check("other", 12_000));
        assert_eq!(dedupe.len(), 2);
        assert!(!dedupe.check("new", 12_000));
    }

    #[test]
    fn cap_evicts_oldest_accepted_key() {
        let mut d: Dedupe<&str, u64> = Dedupe::builder(secs(100)).max_keys(2).build().unwrap();
        assert!(d.check("a", 0));
        assert!(d.check("b", 1));
        assert!(!d.check("a", 2), "duplicates do not refresh position");
        assert!(d.check("c", 3), "evicts a");
        assert_eq!(d.len(), 2);
        assert!(d.check("a", 4), "a was evicted, so it is accepted again");
        assert!(!d.check("c", 5));
        assert_eq!(d.stats().evicted_capacity, 2);
    }

    #[test]
    fn builder_rejects_bad_settings() {
        let b = || Dedupe::<u8, u64>::builder(secs(1));
        assert_eq!(
            b().max_keys(0).build().err(),
            Some(ConfigError::ZeroMaxKeys)
        );
        assert_eq!(
            b().max_keys(5)
                .approximate(ApproxConfig::new(10, 0.01))
                .build()
                .err(),
            Some(ConfigError::MaxKeysWithApproximate)
        );
        assert_eq!(
            b().approximate(ApproxConfig::new(10, 2.0)).build().err(),
            Some(ConfigError::InvalidFalsePositiveRate)
        );
    }

    #[test]
    fn approximate_mode_dedupes_within_window() {
        let mut d: Dedupe<&str, u64> = Dedupe::builder(secs(10))
            .approximate(ApproxConfig::new(100, 0.001))
            .hash_key(HashKey::new(1, 2))
            .build()
            .unwrap();
        assert!(d.check("a", 0));
        assert!(!d.check("a", 10_000));
        assert!(d.check("b", 10_000));
        assert!(d.check("a", 30_000), "long gone");
        assert!(matches!(d.mode(), Mode::Approximate(_)));
    }

    #[test]
    fn metrics_hook_sees_everything() {
        use std::sync::{Arc, Mutex};
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let mut d: Dedupe<u8, u64> = Dedupe::builder(secs(1))
            .max_keys(1)
            .metrics(move |e| sink.lock().unwrap().push(e))
            .build()
            .unwrap();
        d.check(1, 0);
        d.check(1, 0);
        d.check(2, 0);
        d.check(3, 5_000);
        let got = log.lock().unwrap().clone();
        assert_eq!(
            got,
            vec![
                MetricEvent::Fresh,
                MetricEvent::Duplicate,
                MetricEvent::Evicted {
                    reason: EvictionReason::Capacity,
                    count: 1
                },
                MetricEvent::Fresh,
                MetricEvent::Evicted {
                    reason: EvictionReason::Expired,
                    count: 1
                },
                MetricEvent::Fresh,
            ]
        );
        let s = d.stats();
        assert_eq!((s.seen, s.fresh, s.duplicates), (4, 3, 1));
    }

    #[test]
    fn restore_rejects_bad_snapshots() {
        let mut d: Dedupe<u8, u64> = Dedupe::new(secs(1));
        d.check(1, 0);
        let mut snap = d.snapshot();
        snap.version = 99;
        assert_eq!(
            Dedupe::restore(snap).err(),
            Some(RestoreError::UnsupportedVersion(99))
        );
        let mut snap = d.snapshot();
        snap.state = SnapshotState::Exact {
            entries: vec![(1, 0), (1, 1)],
        };
        assert!(matches!(
            Dedupe::restore(snap),
            Err(RestoreError::Inconsistent(_))
        ));
        let mut snap = d.snapshot();
        snap.max_keys = Some(0);
        assert_eq!(
            Dedupe::restore(snap).err(),
            Some(RestoreError::Config(ConfigError::ZeroMaxKeys))
        );
    }
}
