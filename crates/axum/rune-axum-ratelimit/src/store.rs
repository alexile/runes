//! Rate-limit algorithms and the pluggable storage backend.
//!
//! The algorithms are sans-I/O: [`fixed_window`] and [`gcra`] take the stored state and the
//! current time as plain values and return the [`Decision`] plus the state to write back.
//! [`InMemoryStore`] wraps them in a bounded, mutex-protected map; a distributed backend
//! (Redis, a database) implements [`RateLimitStore`] and must apply the same update
//! atomically, e.g. in a Lua script or a transaction, using the server's clock.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;
use tokio::time::Instant;

/// A boxed, `Send` future, as returned by [`RateLimitStore::check`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The counting algorithm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Algorithm {
    /// Fixed window: up to `limit` requests per window, the counter resets when the window
    /// that began with a client's first request ends. Cheap, but allows up to `2 × limit`
    /// requests across a window boundary.
    #[default]
    FixedWindow,
    /// Generic Cell Rate Algorithm (a leaky bucket stored as one timestamp). Requests are
    /// spaced `window / limit` apart with a burst of `burst` (default `limit`), so there is
    /// no boundary spike and capacity refills continuously.
    Gcra,
}

/// The limit applied to each key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    /// Requests allowed per window.
    pub limit: u64,
    /// The window length.
    pub window: Duration,
    /// GCRA burst size: requests that may arrive back to back. Ignored by
    /// [`Algorithm::FixedWindow`]. Usually equal to `limit`.
    pub burst: u64,
    /// The counting algorithm.
    pub algorithm: Algorithm,
}

impl Quota {
    /// Creates a quota of `limit` requests per `window`, with `burst = limit`.
    #[must_use]
    pub const fn new(limit: u64, window: Duration, algorithm: Algorithm) -> Self {
        Self {
            limit,
            window,
            burst: limit,
            algorithm,
        }
    }
}

/// The outcome of one rate-limit check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// Whether the request may proceed.
    pub allowed: bool,
    /// The quota limit, reported as `q` in `RateLimit-Policy`.
    pub limit: u64,
    /// Requests still available right now, reported as `r` in `RateLimit`.
    pub remaining: u64,
    /// Time until the quota is fully restored, reported as `t` in `RateLimit`.
    pub reset: Duration,
    /// For a denied request, how long to wait before retrying (`Retry-After`).
    pub retry_after: Option<Duration>,
}

/// An error from a [`RateLimitStore`] backend.
#[derive(Debug)]
pub struct StoreError(Box<dyn std::error::Error + Send + Sync>);

impl StoreError {
    /// Wraps a backend error.
    pub fn new(err: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self(err.into())
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rate-limit store error: {}", self.0)
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// A storage backend for rate-limit state.
///
/// One call to [`check`](Self::check) must atomically read the key's state, apply the
/// quota's algorithm, persist the new state and return the decision. [`InMemoryStore`] is
/// the bundled implementation, and the `redis` feature adds `redis::RedisStore`. For another
/// shared backend, implement this trait mirroring [`fixed_window`] or [`gcra`] in a server-side
/// script so concurrent instances cannot race, and let keys expire after
/// [`Decision::reset`] so storage stays bounded.
///
/// Errors are handled according to `RateLimitConfig::on_store_error`.
///
/// # Examples
///
/// ```rust
/// use rune_axum_ratelimit::store::{BoxFuture, Decision, Quota, RateLimitStore, StoreError};
///
/// /// A store that never limits (for illustration only).
/// struct Unlimited;
///
/// impl RateLimitStore for Unlimited {
///     fn check<'a>(
///         &'a self,
///         _key: &'a str,
///         quota: &'a Quota,
///     ) -> BoxFuture<'a, Result<Decision, StoreError>> {
///         Box::pin(async move {
///             Ok(Decision {
///                 allowed: true,
///                 limit: quota.limit,
///                 remaining: quota.limit,
///                 reset: std::time::Duration::ZERO,
///                 retry_after: None,
///             })
///         })
///     }
/// }
/// ```
pub trait RateLimitStore: Send + Sync + 'static {
    /// Counts one request for `key` under `quota` and returns the decision.
    fn check<'a>(
        &'a self,
        key: &'a str,
        quota: &'a Quota,
    ) -> BoxFuture<'a, Result<Decision, StoreError>>;
}

/// Fixed-window state: when the current window began and how many requests it has seen.
///
/// Times are offsets from an arbitrary epoch chosen by the store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowState {
    /// Start of the current window.
    pub start: Duration,
    /// Requests counted in the current window.
    pub count: u64,
}

/// Applies the fixed-window algorithm. `state` is `None` for a key never seen (or expired).
///
/// Returns the decision and the state to store; the state may be dropped once `reset`
/// has elapsed.
#[must_use]
pub fn fixed_window(
    state: Option<WindowState>,
    now: Duration,
    quota: &Quota,
) -> (Decision, WindowState) {
    let mut st = match state {
        Some(s) if now.saturating_sub(s.start) < quota.window => s,
        _ => WindowState {
            start: now,
            count: 0,
        },
    };
    let reset = (st.start + quota.window).saturating_sub(now);
    if st.count >= quota.limit {
        let retry = if quota.limit == 0 {
            quota.window
        } else {
            reset
        };
        let decision = Decision {
            allowed: false,
            limit: quota.limit,
            remaining: 0,
            reset: retry,
            retry_after: Some(retry),
        };
        return (decision, st);
    }
    st.count += 1;
    let decision = Decision {
        allowed: true,
        limit: quota.limit,
        remaining: quota.limit - st.count,
        reset,
        retry_after: None,
    };
    (decision, st)
}

/// Applies GCRA. `tat` is the stored theoretical arrival time (`None` for a new or expired
/// key), as an offset from the store's epoch.
///
/// Returns the decision and the new TAT. The key is fully replenished, and may be dropped,
/// once `now >= tat`.
#[must_use]
pub fn gcra(tat: Option<Duration>, now: Duration, quota: &Quota) -> (Decision, Duration) {
    let now_ns = now.as_nanos();
    let tat_ns = tat.map_or(now_ns, |t| t.as_nanos()).max(now_ns);
    if quota.limit == 0 || quota.burst == 0 {
        let decision = Decision {
            allowed: false,
            limit: quota.limit,
            remaining: 0,
            reset: quota.window,
            retry_after: Some(quota.window),
        };
        return (decision, nanos(tat_ns));
    }
    let interval = quota.window.as_nanos() / u128::from(quota.limit);
    let capacity = interval.saturating_mul(u128::from(quota.burst));
    let new_tat = tat_ns.saturating_add(interval);
    let ahead = new_tat - now_ns;
    if ahead > capacity {
        let decision = Decision {
            allowed: false,
            limit: quota.limit,
            remaining: 0,
            reset: nanos(tat_ns - now_ns),
            retry_after: Some(nanos(ahead - capacity)),
        };
        return (decision, nanos(tat_ns));
    }
    let remaining = (capacity - ahead)
        .checked_div(interval)
        .map_or(quota.burst, |r| {
            u64::try_from(r).unwrap_or(u64::MAX).min(quota.burst)
        });
    let decision = Decision {
        allowed: true,
        limit: quota.limit,
        remaining,
        reset: nanos(ahead),
        retry_after: None,
    };
    (decision, nanos(new_tat))
}

fn nanos(ns: u128) -> Duration {
    let secs = u64::try_from(ns / 1_000_000_000).unwrap_or(u64::MAX);
    // The remainder is below 1e9 and always fits in u32.
    let sub = u32::try_from(ns % 1_000_000_000).unwrap_or(0);
    Duration::new(secs, sub)
}

#[derive(Debug)]
struct Slot {
    window: WindowState,
    tat: Duration,
    /// When the slot is back to its initial state and can be dropped.
    expires: Duration,
}

#[derive(Debug, Default)]
struct Inner {
    map: HashMap<String, Slot>,
    ops: u64,
}

/// The default upper bound on tracked keys for [`InMemoryStore`].
pub const DEFAULT_MAX_KEYS: usize = 100_000;

/// How often (in checks) the in-memory store sweeps expired keys even when not full.
const SWEEP_EVERY: u64 = 4_096;

/// A bounded in-process [`RateLimitStore`].
///
/// Keys whose quota is fully restored are swept periodically and whenever the map is full.
/// If the map is still at [`max_keys`](Self::with_max_keys) after a sweep, the keys closest
/// to being restored are evicted in a batch (1/16 of capacity), so memory stays bounded
/// even under a flood of distinct keys. Uses [`tokio::time::Instant`], so tests can drive it
/// with `tokio::time::pause`.
///
/// > [!NOTE]
/// > Share one store only between layers with the same quota: state is keyed by the client
/// > key alone.
#[derive(Debug)]
pub struct InMemoryStore {
    inner: Mutex<Inner>,
    epoch: Instant,
    max_keys: usize,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    /// Creates a store bounded to [`DEFAULT_MAX_KEYS`] keys.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_keys(DEFAULT_MAX_KEYS)
    }

    /// Creates a store bounded to `max_keys` keys (at least 1).
    #[must_use]
    pub fn with_max_keys(max_keys: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            epoch: Instant::now(),
            max_keys: max_keys.max(1),
        }
    }

    /// Returns the number of keys currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    /// Returns `true` when no key is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves the counters usable; keep going.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs one check synchronously.
    #[must_use]
    pub fn check_now(&self, key: &str, quota: &Quota) -> Decision {
        let now = Instant::now().saturating_duration_since(self.epoch);
        let mut inner = self.lock();
        inner.ops = inner.ops.wrapping_add(1);
        if inner.ops.is_multiple_of(SWEEP_EVERY) {
            inner.map.retain(|_, slot| slot.expires > now);
        }
        if !inner.map.contains_key(key) && inner.map.len() >= self.max_keys {
            self.make_room(&mut inner.map, now);
        }
        let existing = inner.map.get(key).filter(|slot| slot.expires > now);
        let (decision, slot) = match quota.algorithm {
            Algorithm::FixedWindow => {
                let (decision, window) = fixed_window(existing.map(|s| s.window), now, quota);
                let expires = window.start + quota.window;
                (
                    decision,
                    Slot {
                        window,
                        tat: Duration::ZERO,
                        expires,
                    },
                )
            }
            Algorithm::Gcra => {
                let (decision, tat) = gcra(existing.map(|s| s.tat), now, quota);
                let slot = Slot {
                    window: WindowState::default(),
                    tat,
                    expires: tat,
                };
                (decision, slot)
            }
        };
        if slot.expires > now {
            inner.map.insert(key.to_owned(), slot);
        } else {
            inner.map.remove(key);
        }
        drop(inner);
        decision
    }

    fn make_room(&self, map: &mut HashMap<String, Slot>, now: Duration) {
        map.retain(|_, slot| slot.expires > now);
        if map.len() < self.max_keys {
            return;
        }
        let batch = (self.max_keys / 16).max(1).min(map.len());
        let mut by_expiry: Vec<(Duration, String)> = map
            .iter()
            .map(|(key, slot)| (slot.expires, key.clone()))
            .collect();
        by_expiry.select_nth_unstable_by_key(batch - 1, |(expires, _)| *expires);
        for (_, key) in by_expiry.into_iter().take(batch) {
            map.remove(&key);
        }
    }
}

impl RateLimitStore for InMemoryStore {
    fn check<'a>(
        &'a self,
        key: &'a str,
        quota: &'a Quota,
    ) -> BoxFuture<'a, Result<Decision, StoreError>> {
        let decision = self.check_now(key, quota);
        Box::pin(std::future::ready(Ok(decision)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    #[test]
    fn fixed_window_counts_and_resets() {
        let q = Quota::new(2, 10 * SEC, Algorithm::FixedWindow);
        let (d, s) = fixed_window(None, SEC, &q);
        assert!(d.allowed);
        assert_eq!(d.remaining, 1);
        assert_eq!(d.reset, 10 * SEC);
        let (d, s) = fixed_window(Some(s), 2 * SEC, &q);
        assert!(d.allowed);
        assert_eq!(d.remaining, 0);
        let (d, s) = fixed_window(Some(s), 3 * SEC, &q);
        assert!(!d.allowed);
        assert_eq!(d.retry_after, Some(8 * SEC));
        let (d, _) = fixed_window(Some(s), 11 * SEC, &q);
        assert!(d.allowed);
        assert_eq!(d.remaining, 1);
    }

    #[test]
    fn gcra_spaces_requests() {
        // 4 per 4 s: one token per second, burst 4.
        let q = Quota::new(4, 4 * SEC, Algorithm::Gcra);
        let mut tat = None;
        for expected in [3, 2, 1, 0] {
            let (d, t) = gcra(tat, Duration::ZERO, &q);
            assert!(d.allowed);
            assert_eq!(d.remaining, expected);
            tat = Some(t);
        }
        let (d, _) = gcra(tat, Duration::ZERO, &q);
        assert!(!d.allowed);
        assert_eq!(d.retry_after, Some(SEC));
        assert_eq!(d.reset, 4 * SEC);
        // Half a second later: still denied, retry in 0.5 s.
        let (d, _) = gcra(tat, SEC / 2, &q);
        assert_eq!(d.retry_after, Some(SEC / 2));
        // One second later: exactly one token.
        let (d, t) = gcra(tat, SEC, &q);
        assert!(d.allowed);
        assert_eq!(d.remaining, 0);
        let (d, _) = gcra(Some(t), SEC, &q);
        assert!(!d.allowed);
    }

    #[test]
    fn gcra_burst_smaller_than_limit() {
        let q = Quota {
            burst: 1,
            ..Quota::new(10, 10 * SEC, Algorithm::Gcra)
        };
        let (d, t) = gcra(None, Duration::ZERO, &q);
        assert!(d.allowed);
        let (d, _) = gcra(Some(t), Duration::ZERO, &q);
        assert!(!d.allowed);
        assert_eq!(d.retry_after, Some(SEC));
    }

    #[test]
    fn zero_limit_always_denies() {
        for alg in [Algorithm::FixedWindow, Algorithm::Gcra] {
            let store = InMemoryStore::new();
            let q = Quota::new(0, 5 * SEC, alg);
            let d = store.check_now("k", &q);
            assert!(!d.allowed);
            assert_eq!(d.retry_after, Some(5 * SEC));
        }
    }

    #[test]
    fn zero_window_never_panics() {
        for alg in [Algorithm::FixedWindow, Algorithm::Gcra] {
            let store = InMemoryStore::new();
            let q = Quota::new(3, Duration::ZERO, alg);
            for _ in 0..10 {
                let _ = store.check_now("k", &q);
            }
        }
    }

    #[test]
    fn map_is_bounded() {
        let store = InMemoryStore::with_max_keys(64);
        let q = Quota::new(5, 3600 * SEC, Algorithm::FixedWindow);
        for i in 0..10_000 {
            let _ = store.check_now(&format!("key-{i}"), &q);
            assert!(store.len() <= 64);
        }
        // The most recent key is tracked.
        let d = store.check_now("key-9999", &q);
        assert_eq!(d.remaining, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn expired_keys_are_swept() {
        let store = InMemoryStore::with_max_keys(8);
        let q = Quota::new(1, SEC, Algorithm::Gcra);
        for i in 0..8 {
            let _ = store.check_now(&format!("old-{i}"), &q);
        }
        assert_eq!(store.len(), 8);
        tokio::time::advance(2 * SEC).await;
        let _ = store.check_now("new", &q);
        assert_eq!(store.len(), 1);
    }
}
