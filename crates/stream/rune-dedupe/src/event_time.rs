//! Event-time deduplication with watermark-driven eviction.

use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;
use std::time::Duration;

use crate::dedupe::SNAPSHOT_VERSION;
use crate::error::{ConfigError, RestoreError};
use crate::hash::HashKey;
use crate::metrics::{EvictionReason, MetricEvent, Recorder, Stats};
use crate::store::ExactStore;
use crate::time::Timestamp;

/// The outcome of an [`EventTimeDedupe::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// No accepted occurrence of the key lies within the window of this event.
    /// The event is recorded.
    Fresh,
    /// An accepted occurrence of the key lies within the window of this event.
    Duplicate,
    /// The event is behind the watermark and no matching occurrence is still
    /// held. A match may already have been evicted, so the event can't be
    /// called fresh safely; it is not recorded. Drop it, or route it to a side
    /// output, as your pipeline prefers.
    Late,
}

/// Exact deduplication keyed on *event* time rather than arrival time.
///
/// Two occurrences of a key are duplicates when their event times are at most
/// `window` apart, in either direction, so out-of-order arrivals are handled.
/// State is dropped only when the watermark (a promise that no event older than
/// it is still coming) has moved more than `window` past it, via
/// [`advance_watermark`](Self::advance_watermark). That makes the result exact
/// for every event at or ahead of the watermark; events behind it get
/// [`Verdict::Late`] unless a match is still held.
///
/// `T` defaults to `i64` milliseconds, the representation `rune-watermark`
/// uses, so a `WatermarkTracker`'s `watermark()` can be passed straight in.
///
/// A [`max_keys`](EventTimeBuilder::max_keys) cap bounds memory by evicting the
/// entry with the oldest event time first (counted as a capacity eviction).
/// The cap counts entries: a key accepted twice, far apart, holds two.
///
/// # Example
///
/// ```rust
/// use rune_dedupe::{EventTimeDedupe, Verdict};
/// use std::time::Duration;
///
/// let mut d: EventTimeDedupe<&str> = EventTimeDedupe::new(Duration::from_millis(100));
/// assert_eq!(d.check("order-7", 1_000), Verdict::Fresh);
/// assert_eq!(d.check("order-7", 950), Verdict::Duplicate, "out of order, still caught");
/// assert_eq!(d.check("order-7", 1_200), Verdict::Fresh, "200 ms later is a new event");
///
/// // The watermark passes 1_000 + window: that entry can go.
/// d.advance_watermark(1_150);
/// assert_eq!(d.check("order-7", 1_050), Verdict::Late);
/// ```
pub struct EventTimeDedupe<K, T = i64> {
    window: Duration,
    max_keys: Option<usize>,
    hash_key: HashKey,
    store: ExactStore<K, T>,
    watermark: Option<T>,
    metrics: Recorder,
}

impl<K: Eq + Hash + Clone, T: Timestamp> EventTimeDedupe<K, T> {
    /// An unbounded deduplicator with a random [`HashKey`].
    #[must_use]
    pub fn new(window: Duration) -> Self {
        let hash_key = HashKey::random();
        Self {
            window,
            max_keys: None,
            hash_key,
            store: ExactStore::new(hash_key),
            watermark: None,
            metrics: Recorder::default(),
        }
    }

    /// Starts configuring a deduplicator.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_dedupe::EventTimeDedupe;
    /// use std::time::Duration;
    ///
    /// let d: EventTimeDedupe<u64> = EventTimeDedupe::builder(Duration::from_secs(60))
    ///     .max_keys(50_000)
    ///     .build()?;
    /// # Ok::<(), rune_dedupe::ConfigError>(())
    /// ```
    #[must_use]
    pub fn builder(window: Duration) -> EventTimeBuilder<K, T> {
        EventTimeBuilder {
            window,
            max_keys: None,
            hash_key: None,
            hook: None,
            _types: PhantomData,
        }
    }

    /// Checks `key` with event time `event_time`.
    pub fn check(&mut self, key: K, event_time: T) -> Verdict {
        let window = self.window;
        let verdict = if self.store.any_within(&key, event_time, window) {
            Verdict::Duplicate
        } else if self.watermark.is_some_and(|wm| event_time < wm) {
            Verdict::Late
        } else {
            let evicted = self.store.make_room(self.max_keys);
            self.metrics.evicted(EvictionReason::Capacity, evicted);
            self.store.insert(key, event_time);
            Verdict::Fresh
        };
        self.metrics.record(match verdict {
            Verdict::Fresh => MetricEvent::Fresh,
            Verdict::Duplicate => MetricEvent::Duplicate,
            Verdict::Late => MetricEvent::Late,
        });
        verdict
    }

    /// Moves the watermark forward and drops every entry more than `window`
    /// behind it. A watermark lower than the current one is ignored. Returns
    /// how many entries were dropped.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_dedupe::EventTimeDedupe;
    /// use std::time::Duration;
    ///
    /// let mut d = EventTimeDedupe::new(Duration::from_millis(10));
    /// d.check("a", 100_i64);
    /// assert_eq!(d.advance_watermark(110), 0, "100 is still within reach");
    /// assert_eq!(d.advance_watermark(111), 1);
    /// assert!(d.is_empty());
    /// ```
    pub fn advance_watermark(&mut self, watermark: T) -> usize {
        if self.watermark.is_some_and(|wm| watermark <= wm) {
            return 0;
        }
        self.watermark = Some(watermark);
        let window = self.window;
        let n = self
            .store
            .pop_while(|t| watermark.saturating_since(t) > window);
        self.metrics.evicted(EvictionReason::Expired, n);
        usize::try_from(n).unwrap_or(usize::MAX)
    }

    /// The current watermark, if one has been set.
    #[must_use]
    pub const fn watermark(&self) -> Option<T> {
        self.watermark
    }

    /// Entries held (one per accepted occurrence).
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.entries()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The dedupe window.
    #[must_use]
    pub const fn window(&self) -> Duration {
        self.window
    }

    /// Running counters. See [`Stats`].
    #[must_use]
    pub const fn stats(&self) -> Stats {
        self.metrics.stats
    }

    /// Installs (or with `None`, removes) a metrics callback.
    pub fn set_metrics(&mut self, hook: Option<Box<dyn FnMut(MetricEvent) + Send + Sync>>) {
        self.metrics.set_hook(hook);
    }

    /// Captures the full state, including the watermark. See
    /// [`Dedupe::snapshot`](crate::Dedupe::snapshot).
    #[must_use]
    pub fn snapshot(&self) -> EventTimeSnapshot<K, T> {
        EventTimeSnapshot {
            version: SNAPSHOT_VERSION,
            window: self.window,
            max_keys: self.max_keys,
            hash_key: self.hash_key,
            stats: self.metrics.stats,
            watermark: self.watermark,
            entries: self.store.to_vec(),
        }
    }

    /// Rebuilds a deduplicator from a [`snapshot`](Self::snapshot).
    ///
    /// # Errors
    ///
    /// [`RestoreError`] for an unknown version or state that breaks the stored
    /// `max_keys`.
    pub fn restore(snapshot: EventTimeSnapshot<K, T>) -> Result<Self, RestoreError> {
        let EventTimeSnapshot {
            version,
            window,
            max_keys,
            hash_key,
            stats,
            watermark,
            entries,
        } = snapshot;
        if version != SNAPSHOT_VERSION {
            return Err(RestoreError::UnsupportedVersion(version));
        }
        if max_keys == Some(0) {
            return Err(ConfigError::ZeroMaxKeys.into());
        }
        if max_keys.is_some_and(|cap| entries.len() > cap) {
            return Err(RestoreError::Inconsistent("more entries than max_keys"));
        }
        let mut store = ExactStore::new(hash_key);
        for (key, t) in entries {
            store.insert(key, t);
        }
        Ok(Self {
            window,
            max_keys,
            hash_key,
            store,
            watermark,
            metrics: Recorder::new(stats, None),
        })
    }
}

impl<K, T: fmt::Debug> fmt::Debug for EventTimeDedupe<K, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventTimeDedupe")
            .field("window", &self.window)
            .field("max_keys", &self.max_keys)
            .field("watermark", &self.watermark)
            .field("stats", &self.metrics.stats)
            .finish_non_exhaustive()
    }
}

/// Settings for an [`EventTimeDedupe`], from [`EventTimeDedupe::builder`].
pub struct EventTimeBuilder<K, T = i64> {
    window: Duration,
    max_keys: Option<usize>,
    hash_key: Option<HashKey>,
    hook: Option<Box<dyn FnMut(MetricEvent) + Send + Sync>>,
    _types: PhantomData<fn() -> (K, T)>,
}

impl<K: Eq + Hash + Clone, T: Timestamp> EventTimeBuilder<K, T> {
    /// Caps the number of held entries, evicting the oldest event time first.
    #[must_use]
    pub const fn max_keys(mut self, max_keys: usize) -> Self {
        self.max_keys = Some(max_keys);
        self
    }

    /// Uses a fixed hash key instead of a random one.
    #[must_use]
    pub const fn hash_key(mut self, key: HashKey) -> Self {
        self.hash_key = Some(key);
        self
    }

    /// Installs a metrics callback.
    #[must_use]
    pub fn metrics(mut self, hook: impl FnMut(MetricEvent) + Send + Sync + 'static) -> Self {
        self.hook = Some(Box::new(hook));
        self
    }

    /// Builds the deduplicator.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ZeroMaxKeys`] if `max_keys` is zero.
    pub fn build(self) -> Result<EventTimeDedupe<K, T>, ConfigError> {
        if self.max_keys == Some(0) {
            return Err(ConfigError::ZeroMaxKeys);
        }
        let hash_key = self.hash_key.unwrap_or_else(HashKey::random);
        Ok(EventTimeDedupe {
            window: self.window,
            max_keys: self.max_keys,
            hash_key,
            store: ExactStore::new(hash_key),
            watermark: None,
            metrics: Recorder::new(Stats::default(), self.hook),
        })
    }
}

impl<K, T> fmt::Debug for EventTimeBuilder<K, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventTimeBuilder")
            .field("window", &self.window)
            .field("max_keys", &self.max_keys)
            .finish_non_exhaustive()
    }
}

/// The saved state of an [`EventTimeDedupe`]. Opaque; see
/// [`Snapshot`](crate::Snapshot).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EventTimeSnapshot<K, T> {
    version: u32,
    window: Duration,
    max_keys: Option<usize>,
    hash_key: HashKey,
    stats: Stats,
    watermark: Option<T>,
    entries: Vec<(K, T)>,
}

impl<K, T: Copy> EventTimeSnapshot<K, T> {
    /// The watermark at the time of the snapshot.
    #[must_use]
    pub const fn watermark(&self) -> Option<T> {
        self.watermark
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn out_of_order_duplicates_are_caught_both_ways() {
        let mut d = EventTimeDedupe::new(ms(10));
        assert_eq!(d.check("k", 100_i64), Verdict::Fresh);
        assert_eq!(d.check("k", 110), Verdict::Duplicate);
        assert_eq!(d.check("k", 90), Verdict::Duplicate);
        assert_eq!(d.check("k", 89), Verdict::Fresh);
        assert_eq!(d.check("k", 80), Verdict::Duplicate, "matches 89");
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn late_events_use_remaining_state() {
        let mut d = EventTimeDedupe::new(ms(10));
        d.check("a", 100_i64);
        d.check("b", 120);
        d.advance_watermark(125);
        assert_eq!(d.len(), 1, "a at 100 is >10 behind 125");
        assert_eq!(d.check("b", 115), Verdict::Duplicate, "late but held");
        assert_eq!(d.check("a", 100), Verdict::Late);
        assert_eq!(d.check("c", 130), Verdict::Fresh);
        assert_eq!(d.stats().late, 1);
        assert_eq!(d.stats().evicted_expired, 1);
    }

    #[test]
    fn watermark_never_moves_back() {
        let mut d: EventTimeDedupe<u8> = EventTimeDedupe::new(ms(1));
        d.advance_watermark(50);
        assert_eq!(d.advance_watermark(10), 0);
        assert_eq!(d.watermark(), Some(50));
    }

    #[test]
    fn cap_evicts_oldest_event_time() {
        let mut d: EventTimeDedupe<&str> = EventTimeDedupe::builder(ms(1_000))
            .max_keys(2)
            .build()
            .unwrap();
        d.check("new", 500);
        d.check("old", 100);
        d.check("third", 300);
        assert_eq!(d.check("old", 100), Verdict::Fresh, "old was evicted");
        assert_eq!(d.check("new", 500), Verdict::Duplicate, "newest survives");
        assert_eq!(d.check("third", 300), Verdict::Fresh, "evicted by old");
        assert_eq!(d.stats().evicted_capacity, 3);
    }

    #[test]
    fn builder_rejects_zero_cap() {
        let r = EventTimeDedupe::<u8>::builder(ms(1)).max_keys(0).build();
        assert_eq!(r.err(), Some(ConfigError::ZeroMaxKeys));
    }
}
