//! Counters and an optional callback for wiring dedupe into a metrics system.

use std::fmt;

/// Why tracked state was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvictionReason {
    /// The entry aged out of the window (TTL or watermark). This is normal and
    /// never causes a missed duplicate.
    Expired,
    /// The memory cap was hit and the oldest entry was pushed out early. A later
    /// repeat of that key inside its window will be accepted again, so a steady
    /// rate of these means the cap is too small.
    Capacity,
}

/// One observation passed to a metrics callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetricEvent {
    /// A check accepted a key as new.
    Fresh,
    /// A check rejected a key as a duplicate.
    Duplicate,
    /// An event-time check arrived behind the watermark and could not be
    /// decided (see [`Verdict::Late`](crate::Verdict::Late)).
    Late,
    /// State was dropped. `count` is the number of entries; for an approximate
    /// filter it is the number of keys recorded in the dropped generation.
    Evicted {
        /// Why the state was dropped.
        reason: EvictionReason,
        /// How many entries went.
        count: u64,
    },
}

/// Running totals kept by every deduplicator, readable at any time and
/// carried across [`snapshot`](crate::Dedupe::snapshot)/restore.
///
/// # Example
///
/// ```rust
/// use rune_dedupe::Dedupe;
///
/// let mut d = Dedupe::new(std::time::Duration::from_secs(5));
/// d.check("a", 0_u64);
/// d.check("a", 1_u64);
/// let s = d.stats();
/// assert_eq!((s.seen, s.fresh, s.duplicates), (2, 1, 1));
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Stats {
    /// Every key checked.
    pub seen: u64,
    /// Checks that accepted the key.
    pub fresh: u64,
    /// Checks that rejected the key as a duplicate.
    pub duplicates: u64,
    /// Event-time checks that arrived behind the watermark undecided.
    pub late: u64,
    /// Entries that aged out normally.
    pub evicted_expired: u64,
    /// Entries pushed out by the memory cap.
    pub evicted_capacity: u64,
}

pub type Hook = Box<dyn FnMut(MetricEvent) + Send + Sync>;

/// Keeps [`Stats`] and forwards each event to the user's callback, if any.
#[derive(Default)]
pub struct Recorder {
    pub stats: Stats,
    hook: Option<Hook>,
}

impl Recorder {
    pub fn new(stats: Stats, hook: Option<Hook>) -> Self {
        Self { stats, hook }
    }

    pub fn set_hook(&mut self, hook: Option<Hook>) {
        self.hook = hook;
    }

    pub fn record(&mut self, event: MetricEvent) {
        let s = &mut self.stats;
        match event {
            MetricEvent::Fresh => {
                s.seen = s.seen.saturating_add(1);
                s.fresh = s.fresh.saturating_add(1);
            }
            MetricEvent::Duplicate => {
                s.seen = s.seen.saturating_add(1);
                s.duplicates = s.duplicates.saturating_add(1);
            }
            MetricEvent::Late => {
                s.seen = s.seen.saturating_add(1);
                s.late = s.late.saturating_add(1);
            }
            MetricEvent::Evicted { count: 0, .. } => return,
            MetricEvent::Evicted {
                reason: EvictionReason::Expired,
                count,
            } => s.evicted_expired = s.evicted_expired.saturating_add(count),
            MetricEvent::Evicted {
                reason: EvictionReason::Capacity,
                count,
            } => s.evicted_capacity = s.evicted_capacity.saturating_add(count),
        }
        if let Some(hook) = self.hook.as_mut() {
            hook(event);
        }
    }

    pub fn evicted(&mut self, reason: EvictionReason, count: u64) {
        self.record(MetricEvent::Evicted { reason, count });
    }
}

impl fmt::Debug for Recorder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recorder")
            .field("stats", &self.stats)
            .field("hook", &self.hook.is_some())
            .finish()
    }
}
