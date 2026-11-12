//! [`CachedProvider`]: keeps resolved secrets for a time-to-live.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use rune_secret_ref::{SecretRef, SecretValue};

use crate::{ProviderError, SecretProvider};

/// A monotonic time source, so cache expiry can be tested without
/// sleeping.
pub trait Clock {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// A cached secret and when it expires (`None`: the TTL is too large to
/// represent, so never).
type Entry = (Option<Instant>, SecretValue);

/// The real clock: [`Instant::now`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Wraps a provider and remembers each resolved secret for `ttl`.
///
/// Only successes are cached: a failed lookup is retried on the next call.
/// Expired entries are replaced on access; [`purge_expired`] drops them
/// eagerly and [`invalidate`] / [`clear`] forget secrets on demand (after
/// a rotation, say). Cached values stay [`SecretValue`]s, and the cache's
/// `Debug` output lists only how many entries it holds.
///
/// Concurrent misses for the same reference may each call the inner
/// provider; the lock is not held while it runs.
///
/// ```
/// use std::sync::atomic::{AtomicUsize, Ordering};
/// use std::time::Duration;
/// use rune_secret_vault::{CachedProvider, EnvProvider, SecretProvider};
///
/// let lookups = AtomicUsize::new(0);
/// let env = EnvProvider::new(|_| {
///     lookups.fetch_add(1, Ordering::Relaxed);
///     Some("v".to_owned())
/// });
/// let cached = CachedProvider::new(env, Duration::from_secs(300));
/// let reference = "env:TOKEN".parse()?;
/// cached.resolve(&reference)?;
/// cached.resolve(&reference)?;
/// assert_eq!(lookups.load(Ordering::Relaxed), 1);
/// # Ok::<(), rune_secret_vault::ProviderError>(())
/// ```
///
/// [`purge_expired`]: Self::purge_expired
/// [`invalidate`]: Self::invalidate
/// [`clear`]: Self::clear
pub struct CachedProvider<P, C = SystemClock> {
    inner: P,
    ttl: Duration,
    clock: C,
    entries: Mutex<HashMap<SecretRef, Entry>>,
}

impl<P> CachedProvider<P> {
    /// Caches `inner`'s secrets for `ttl` on the system clock.
    pub fn new(inner: P, ttl: Duration) -> Self {
        Self::with_clock(inner, ttl, SystemClock)
    }
}

impl<P, C> CachedProvider<P, C> {
    /// Caches `inner`'s secrets for `ttl`, measuring time with `clock`.
    pub fn with_clock(inner: P, ttl: Duration, clock: C) -> Self {
        Self {
            inner,
            ttl,
            clock,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The wrapped provider.
    pub const fn inner(&self) -> &P {
        &self.inner
    }

    /// The time-to-live of a cached secret.
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Forgets one reference's cached secret. Returns whether it was
    /// cached.
    pub fn invalidate(&self, reference: &SecretRef) -> bool {
        self.lock().remove(reference).is_some()
    }

    /// Forgets every cached secret.
    pub fn clear(&self) {
        self.lock().clear();
    }

    /// The number of cached entries, expired ones included.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// A poisoned lock only means another thread panicked mid-update of a
    /// plain map; its contents are still consistent.
    fn lock(&self) -> MutexGuard<'_, HashMap<SecretRef, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<P, C: Clock> CachedProvider<P, C> {
    /// Drops expired entries now instead of on their next access.
    pub fn purge_expired(&self) {
        let now = self.clock.now();
        self.lock()
            .retain(|_, (expires, _)| expires.is_none_or(|expires| now < expires));
    }
}

impl<P: SecretProvider, C: Clock> SecretProvider for CachedProvider<P, C> {
    fn handles(&self, scheme: &str) -> bool {
        self.inner.handles(scheme)
    }

    fn resolve(&self, reference: &SecretRef) -> Result<SecretValue, ProviderError> {
        let now = self.clock.now();
        if let Some((expires, value)) = self.lock().get(reference)
            && expires.is_none_or(|expires| now < expires)
        {
            return Ok(value.clone());
        }
        let value = self.inner.resolve(reference)?;
        let expires = now.checked_add(self.ttl);
        self.lock()
            .insert(reference.clone(), (expires, value.clone()));
        Ok(value)
    }
}

impl<P: fmt::Debug, C> fmt::Debug for CachedProvider<P, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedProvider")
            .field("inner", &self.inner)
            .field("ttl", &self.ttl)
            .field("entries", &self.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::EnvProvider;

    /// A clock that only moves when told to.
    struct ManualClock {
        start: Instant,
        offset: Cell<Duration>,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                start: Instant::now(),
                offset: Cell::new(Duration::ZERO),
            }
        }

        fn advance(&self, by: Duration) {
            self.offset.set(self.offset.get() + by);
        }
    }

    impl Clock for &ManualClock {
        fn now(&self) -> Instant {
            self.start + self.offset.get()
        }
    }

    fn reference(text: &str) -> SecretRef {
        text.parse().unwrap()
    }

    #[test]
    fn caches_until_ttl_then_refreshes() {
        let calls = AtomicUsize::new(0);
        let env = EnvProvider::new(|name| {
            let n = calls.fetch_add(1, Ordering::Relaxed);
            Some(format!("{name}-{n}"))
        });
        let clock = ManualClock::new();
        let cache = CachedProvider::with_clock(env, Duration::from_secs(60), &clock);
        let r = reference("env:A");

        assert_eq!(cache.resolve(&r).unwrap().expose(), "A-0");
        clock.advance(Duration::from_secs(59));
        assert_eq!(cache.resolve(&r).unwrap().expose(), "A-0");
        clock.advance(Duration::from_secs(1));
        assert_eq!(cache.resolve(&r).unwrap().expose(), "A-1");
        assert_eq!(calls.load(Ordering::Relaxed), 2);

        assert_eq!(cache.resolve(&reference("env:B")).unwrap().expose(), "B-2");
        assert_eq!(cache.len(), 2);
        clock.advance(Duration::from_secs(60));
        cache.purge_expired();
        assert!(cache.is_empty());
    }

    #[test]
    fn errors_are_not_cached_and_invalidate_works() {
        let present = Cell::new(false);
        let env = EnvProvider::new(|_| present.get().then(|| "v".to_owned()));
        let cache = CachedProvider::new(env, Duration::from_secs(60));
        let r = reference("env:A");

        assert!(cache.resolve(&r).is_err());
        assert!(cache.is_empty());
        present.set(true);
        assert_eq!(cache.resolve(&r).unwrap().expose(), "v");
        assert!(cache.invalidate(&r));
        assert!(!cache.invalidate(&r));
        cache.resolve(&r).unwrap();
        cache.clear();
        assert!(cache.is_empty());
        assert!(cache.handles("env"));
        assert_eq!(cache.ttl(), Duration::from_secs(60));
        assert!(cache.inner().handles("env"));
    }

    #[test]
    fn debug_does_not_show_values() {
        let cache = CachedProvider::new(
            EnvProvider::new(|_| Some("hunter2-secret".to_owned())),
            Duration::MAX,
        );
        cache.resolve(&reference("env:A")).unwrap();
        let debug = format!("{cache:?}");
        assert!(!debug.contains("hunter2-secret"), "{debug}");
        assert!(debug.contains("entries: 1"), "{debug}");
        // Duration::MAX does not overflow and the entry stays fresh.
        assert_eq!(
            cache.resolve(&reference("env:A")).unwrap().expose(),
            "hunter2-secret"
        );
    }
}
