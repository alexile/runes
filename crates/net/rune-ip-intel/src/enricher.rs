//! [`Enricher`]: several providers behind one call, with a verdict cache
//! and per-provider pacing.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::http::Transport;
use crate::{Error, ReputationProvider, Summary, Verdict};

/// Settings for an [`Enricher`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// How long a verdict is reused before the provider is asked again.
    pub cache_ttl: Duration,
    /// Most cached verdicts; the ones closest to expiry go first.
    pub max_cache_entries: usize,
    /// Pause after a provider answers 429 without `Retry-After`.
    pub default_backoff: Duration,
    /// Send non-global addresses (private, loopback, documentation...) to
    /// the providers. Off by default: they have no reputation, and asking
    /// leaks internal addressing to a third party.
    pub allow_non_global: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            cache_ttl: Duration::from_secs(6 * 3600),
            max_cache_entries: 10_000,
            default_backoff: Duration::from_secs(60),
            allow_non_global: false,
        }
    }
}

impl Options {
    /// Sets [`cache_ttl`](Self::cache_ttl).
    #[must_use]
    pub const fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Sets [`max_cache_entries`](Self::max_cache_entries).
    #[must_use]
    pub const fn with_max_cache_entries(mut self, max: usize) -> Self {
        self.max_cache_entries = max;
        self
    }

    /// Sets [`default_backoff`](Self::default_backoff).
    #[must_use]
    pub const fn with_default_backoff(mut self, backoff: Duration) -> Self {
        self.default_backoff = backoff;
        self
    }

    /// Sets [`allow_non_global`](Self::allow_non_global).
    #[must_use]
    pub const fn with_allow_non_global(mut self, allow: bool) -> Self {
        self.allow_non_global = allow;
        self
    }
}

struct Slot {
    provider: Box<dyn ReputationProvider>,
    min_interval: Duration,
    next_allowed: Option<Instant>,
}

/// Queries several [`ReputationProvider`]s about an address and merges
/// their verdicts into a [`Summary`].
///
/// - **Cache.** Verdicts (including "unknown") are kept for
///   [`Options::cache_ttl`]; errors are not cached.
/// - **Pacing.** Each provider gets a minimum interval between requests.
///   A request that would come too early is not sent: the provider reports
///   [`Error::RateLimited`] in the summary with the time left. A 429 from
///   the provider pauses it for its `Retry-After` (or
///   [`Options::default_backoff`]).
/// - **Privacy.** Non-global addresses are refused unless
///   [`Options::allow_non_global`]; IPv4-mapped IPv6 is unwrapped first.
///
/// The enricher never sleeps or reads the clock: pass `now` in.
pub struct Enricher {
    slots: Vec<Slot>,
    cache: HashMap<(&'static str, IpAddr), (Instant, Verdict)>,
    options: Options,
}

impl std::fmt::Debug for Enricher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enricher")
            .field(
                "providers",
                &self
                    .slots
                    .iter()
                    .map(|s| s.provider.name())
                    .collect::<Vec<_>>(),
            )
            .field("cached", &self.cache.len())
            .field("options", &self.options)
            .finish()
    }
}

impl Default for Enricher {
    fn default() -> Self {
        Self::new(Options::default())
    }
}

impl Enricher {
    /// An enricher with no providers.
    #[must_use]
    pub fn new(options: Options) -> Self {
        Self {
            slots: Vec::new(),
            cache: HashMap::new(),
            options,
        }
    }

    /// Adds a provider, asked at most once per `min_interval` (zero for no
    /// pacing). Providers are asked in the order they were added.
    #[must_use]
    pub fn with_provider(
        mut self,
        provider: impl ReputationProvider + 'static,
        min_interval: Duration,
    ) -> Self {
        self.slots.push(Slot {
            provider: Box::new(provider),
            min_interval,
            next_allowed: None,
        });
        self
    }

    /// Names of the providers, in order.
    #[must_use]
    pub fn providers(&self) -> Vec<&'static str> {
        self.slots.iter().map(|s| s.provider.name()).collect()
    }

    /// Number of cached verdicts (expired ones included until evicted).
    #[must_use]
    pub fn cached(&self) -> usize {
        self.cache.len()
    }

    /// Drops every cached verdict.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Asks every provider about `ip` (or reuses a cached verdict) at time
    /// `now`, and merges the answers. Provider failures are collected in
    /// [`Summary::errors`]; they do not fail the call.
    ///
    /// # Errors
    ///
    /// [`Error::NonGlobalAddress`] when `ip` is not globally routable and
    /// [`Options::allow_non_global`] is off.
    pub fn enrich(
        &mut self,
        ip: IpAddr,
        transport: &dyn Transport,
        now: Instant,
    ) -> Result<Summary, Error> {
        let ip = rune_ip::canonical(ip);
        if !self.options.allow_non_global && !rune_ip::is_global(ip) {
            return Err(Error::NonGlobalAddress(ip));
        }
        let mut verdicts = Vec::new();
        let mut errors = Vec::new();
        for index in 0..self.slots.len() {
            let name = self.slots[index].provider.name();
            if let Some((expires, verdict)) = self.cache.get(&(name, ip))
                && now < *expires
            {
                verdicts.push(verdict.clone());
                continue;
            }
            match self.ask(index, ip, transport, now) {
                Ok(verdict) => {
                    self.store(name, ip, verdict.clone(), now);
                    verdicts.push(verdict);
                }
                Err(error) => errors.push((name, error)),
            }
        }
        Ok(Summary::new(ip, verdicts, errors))
    }

    fn ask(
        &mut self,
        index: usize,
        ip: IpAddr,
        transport: &dyn Transport,
        now: Instant,
    ) -> Result<Verdict, Error> {
        let slot = &mut self.slots[index];
        let name = slot.provider.name();
        if let Some(next) = slot.next_allowed
            && now < next
        {
            return Err(Error::RateLimited {
                provider: name,
                retry_after: Some(next - now),
            });
        }
        slot.next_allowed = Some(now + slot.min_interval);
        let result = slot.provider.check(ip, transport);
        if let Err(Error::RateLimited { retry_after, .. }) = &result {
            let pause = retry_after
                .unwrap_or(self.options.default_backoff)
                .max(slot.min_interval);
            slot.next_allowed = Some(now + pause);
        }
        result
    }

    fn store(&mut self, name: &'static str, ip: IpAddr, verdict: Verdict, now: Instant) {
        if self.options.max_cache_entries == 0 || self.options.cache_ttl.is_zero() {
            return;
        }
        if self.cache.len() >= self.options.max_cache_entries {
            self.cache.retain(|_, (expires, _)| now < *expires);
        }
        while self.cache.len() >= self.options.max_cache_entries {
            let Some(oldest) = self
                .cache
                .iter()
                .min_by_key(|(_, (expires, _))| *expires)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.cache.remove(&oldest);
        }
        self.cache
            .insert((name, ip), (now + self.options.cache_ttl, verdict));
    }
}
