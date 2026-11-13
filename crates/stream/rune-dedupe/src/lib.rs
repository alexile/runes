//! Idempotency/dedup filter over a keyed, windowed stream.
//!
//! Turns at-least-once delivery (retried webhooks, redelivered queue messages,
//! flaky uplinks) into at-most-once processing by remembering which keys were
//! accepted recently, with bounded memory and state that can be checkpointed.
//!
//! # Pick a deduplicator
//!
//! | Need | Use |
//! | --- | --- |
//! | Drop repeats within a TTL of arrival time | [`Dedupe`] in [`Mode::Exact`] |
//! | Same, with fixed memory and a small false-positive rate | [`Dedupe`] in [`Mode::Approximate`] |
//! | Drop repeats by *event* time, with watermarks | [`EventTimeDedupe`] |
//!
//! All of them take time as an argument instead of reading a clock, so runs are
//! deterministic. Time can be an [`Instant`](std::time::Instant), a
//! [`SystemTime`](std::time::SystemTime), or `i64`/`u64` milliseconds (see
//! [`Timestamp`]).
//!
//! ```rust
//! use rune_dedupe::Dedupe;
//! use std::time::{Duration, Instant};
//!
//! let start = Instant::now();
//! let mut dedupe = Dedupe::new(Duration::from_secs(60));
//!
//! assert!(dedupe.check("msg-1", start), "first time seeing this key");
//! assert!(!dedupe.check("msg-1", start + Duration::from_secs(1)), "duplicate within window");
//! assert!(dedupe.check("msg-1", start + Duration::from_secs(61)), "window elapsed");
//! ```
//!
//! # Bounding memory
//!
//! Exact mode drops entries once they leave the window. On its own that bounds
//! memory by the number of distinct keys per window, which an untrusted sender
//! controls, so set a hard cap too. At the cap the **oldest accepted** key is
//! evicted first: it is the one closest to expiring anyway. Capacity evictions
//! are the only way exact mode can miss a duplicate, and each one is counted.
//!
//! Approximate mode stores no keys at all: the window is covered by a few
//! rotating Bloom filters whose total size is fixed up front by
//! [`ApproxConfig`]. It never misses a duplicate within the window (while sized
//! correctly), and reports at most the configured fraction of new keys as
//! duplicates.
//!
//! ```rust
//! use rune_dedupe::{ApproxConfig, Dedupe};
//! use std::time::Duration;
//!
//! let window = Duration::from_secs(600);
//! let capped: Dedupe<String, u64> = Dedupe::builder(window).max_keys(250_000).build()?;
//! let approx: Dedupe<String, u64> = Dedupe::builder(window)
//!     .approximate(ApproxConfig::new(5_000_000, 0.0001))
//!     .build()?;
//! # Ok::<(), rune_dedupe::ConfigError>(())
//! ```
//!
//! # Event time and watermarks
//!
//! [`EventTimeDedupe`] treats two occurrences as duplicates when their event
//! times are within the window of each other, in either order, and only forgets
//! an entry once the watermark has moved a full window past it. Events behind
//! the watermark come back as [`Verdict::Late`] when they can't be decided.
//! Timestamps default to `i64` milliseconds, matching `rune-watermark`, so its
//! tracker plugs in directly:
//!
//! ```rust
//! use rune_dedupe::{EventTimeDedupe, Verdict};
//! use std::time::Duration;
//!
//! let mut dedupe: EventTimeDedupe<&str> = EventTimeDedupe::new(Duration::from_secs(5));
//! for (key, ts) in [("a", 10_000), ("a", 7_000), ("b", 9_000)] {
//!     // With rune-watermark: `tracker.observe(ts); if let Some(wm) = tracker.watermark() { .. }`
//!     dedupe.advance_watermark(ts - 2_000);
//!     let _ = dedupe.check(key, ts);
//! }
//! assert_eq!(dedupe.check("a", 12_000), Verdict::Duplicate);
//! ```
//!
//! # Exactly-once with checkpoints
//!
//! A consumer that crashes after processing an event but before recording its
//! progress will see the event again. To make that safe, commit the dedupe
//! state and the input offset **together, atomically**, after the outputs for
//! everything up to that offset are durable (or in the same transaction as
//! them):
//!
//! 1. Read events from `offset`, call `check`, emit only fresh ones.
//! 2. Periodically build a [`Checkpoint`] from the next offset and
//!    [`Dedupe::snapshot`], serialize it (with the `serde` feature) and write it
//!    in one atomic step: write a temp file and rename it over the old one, or
//!    put it in the same database transaction as the outputs.
//! 3. On start, load the checkpoint, [`Dedupe::restore`] the state and seek to
//!    its offset. Replayed events hit the restored seen-set and are dropped.
//!
//! A restored deduplicator makes exactly the same decisions as the original
//! (approximate mode included: the snapshot carries the hash key and filters).
//! `rune-checkpoint` persists offsets only, as a `source -> u64` map, so it
//! can't hold the seen-set; storing the two separately would let them drift
//! apart on a crash. Keep the offset inside the [`Checkpoint`] and treat that
//! as the source of truth.
//!
//! ```rust
//! use rune_dedupe::{Checkpoint, Dedupe};
//! use std::time::Duration;
//!
//! let mut dedupe: Dedupe<String, u64> = Dedupe::new(Duration::from_secs(60));
//! let input = ["a", "b", "a", "c"];
//! for key in &input[..2] {
//!     dedupe.check((*key).to_owned(), 0);
//! }
//! let saved = Checkpoint { offset: 2, state: dedupe.snapshot() };
//! // With the `serde` feature: serde_json::to_vec(&saved), write + rename.
//!
//! // ...crash, restart...
//! let mut dedupe = Dedupe::restore(saved.state)?;
//! let replayed: Vec<_> = input[saved.offset as usize..]
//!     .iter()
//!     .filter(|k| dedupe.check((**k).to_owned(), 1))
//!     .collect();
//! assert_eq!(replayed, [&"c"]);
//! # Ok::<(), rune_dedupe::RestoreError>(())
//! ```
//!
//! # Untrusted keys
//!
//! Keys are hashed with SipHash-2-4 under a secret random [`HashKey`], so
//! nobody can craft keys that collide in the hash table (`HashDoS`) or that a
//! Bloom filter would mistake for duplicates. Only pin a fixed key for
//! reproducible tests.
//!
//! # Metrics
//!
//! Every deduplicator keeps [`Stats`] (seen, fresh, duplicates, late,
//! evictions by reason) and can forward each [`MetricEvent`] to a callback.
//!
//! # CLI
//!
//! ```bash
//! rune-dedupe --window-secs 60 keys.txt
//! cat keys.txt | rune-dedupe --window-secs 60 --max-keys 100000 -
//! ```

mod bloom;
mod dedupe;
mod error;
mod event_time;
mod hash;
mod metrics;
mod store;
mod time;

pub use bloom::ApproxConfig;
pub use dedupe::{Dedupe, DedupeBuilder, Mode, Snapshot};
pub use error::{ConfigError, RestoreError};
pub use event_time::{EventTimeBuilder, EventTimeDedupe, EventTimeSnapshot, Verdict};
pub use hash::{HashKey, SipHasher24};
pub use metrics::{EvictionReason, MetricEvent, Stats};
pub use time::Timestamp;

/// Dedupe state paired with the input offset it covers, to be committed in
/// one atomic write. See the crate docs for the full pattern.
///
/// `S` is usually a [`Snapshot`] or [`EventTimeSnapshot`].
///
/// # Example
///
/// ```rust
/// use rune_dedupe::{Checkpoint, EventTimeDedupe};
///
/// let d: EventTimeDedupe<u32> = EventTimeDedupe::new(std::time::Duration::from_secs(1));
/// let cp = Checkpoint { offset: 42, state: d.snapshot() };
/// assert_eq!(cp.offset, 42);
/// ```
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Checkpoint<S> {
    /// The next input position to read after restoring.
    pub offset: u64,
    /// The dedupe state as of just before `offset`.
    pub state: S,
}
