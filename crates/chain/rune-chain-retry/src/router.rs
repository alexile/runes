//! [`Router`]: one [`Llm`] in front of several providers.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use rune_chain_core::{
    EventStream, FunctionDefinition, GenerateResult, Llm, LlmError, LlmErrorKind, Message, Pricing,
    ResponseFormat, ToolChoice,
};
use tokio::time::Instant;

use crate::event::{BreakerState, Event, Observer, Observers, SkipReason};
use crate::exec::{self, Classifier, Ctx, LlmStream, Output, Request};
use crate::policy::{RetryPolicy, Rng};
use crate::{ErrorClass, classify, estimate_tokens, retry_after};

/// How a [`Router`] orders its providers for each request.
///
/// Whatever the order, the router walks it as a fallback chain: a provider
/// that fails with an error that [`should_fallback`](ErrorClass::should_fallback)
/// hands the request to the next one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Strategy {
    /// The order the providers were added in (primary, then fallbacks).
    #[default]
    Ordered,
    /// A random order, each pick weighted by [`Provider::weight`].
    /// Zero-weight providers only serve as last-resort fallbacks.
    WeightedRandom,
    /// Rotate the starting provider on every request.
    RoundRobin,
    /// Fastest first, by an exponentially weighted moving average of each
    /// provider's successful latency (time to first chunk for streams).
    /// Providers without a sample yet go first, so each gets measured.
    LowestLatency,
    /// Cheapest first, by the [`Pricing`] of the estimated prompt plus
    /// [`Router::expected_output_tokens`]. Providers without pricing go last.
    CheapestFirst,
}

/// Circuit-breaker and cooldown settings, applied to each provider.
///
/// After [`failure_threshold`](Self::failure_threshold) consecutive failures
/// that [`trip the breaker`](ErrorClass::trips_breaker), a provider is
/// skipped for [`open_for`](Self::open_for). Then one probe request is let
/// through (half-open): success closes the breaker, failure re-opens it.
/// A rate-limited provider is skipped for the provider's retry-after hint,
/// or [`rate_limit_cooldown`](Self::rate_limit_cooldown) without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BreakerConfig {
    /// Consecutive failures that open the breaker (default 5; 0 disables
    /// the breaker).
    pub failure_threshold: u32,
    /// How long an open breaker stays open (default 30 s).
    pub open_for: Duration,
    /// Cooldown after a rate limit without a retry-after hint (default 5 s;
    /// zero disables cooldowns).
    pub rate_limit_cooldown: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_for: Duration::from_secs(30),
            rate_limit_cooldown: Duration::from_secs(5),
        }
    }
}

impl BreakerConfig {
    /// Set [`failure_threshold`](Self::failure_threshold).
    #[must_use]
    pub const fn with_failure_threshold(mut self, n: u32) -> Self {
        self.failure_threshold = n;
        self
    }

    /// Set [`open_for`](Self::open_for).
    #[must_use]
    pub const fn with_open_for(mut self, d: Duration) -> Self {
        self.open_for = d;
        self
    }

    /// Set [`rate_limit_cooldown`](Self::rate_limit_cooldown).
    #[must_use]
    pub const fn with_rate_limit_cooldown(mut self, d: Duration) -> Self {
        self.rate_limit_cooldown = d;
        self
    }
}

/// One provider behind a [`Router`]: a named [`Llm`] plus routing metadata.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::{GenerateResult, Llm, LlmError, Message, Pricing};
/// use rune_chain_retry::Provider;
/// # struct MyLlm;
/// # #[async_trait::async_trait]
/// # impl Llm for MyLlm {
/// #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
/// #         Ok(GenerateResult::from_text("ok"))
/// #     }
/// # }
///
/// let p = Provider::new("small", MyLlm)
///     .weight(3)
///     .pricing(Pricing::per_mtok(150_000, 600_000))
///     .max_context_tokens(128_000);
/// assert_eq!(p.name(), "small");
/// ```
#[derive(Clone)]
pub struct Provider {
    name: Arc<str>,
    llm: Arc<dyn Llm>,
    weight: u32,
    pricing: Option<Pricing>,
    max_context_tokens: Option<usize>,
    retry: Option<RetryPolicy>,
}

impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provider")
            .field("name", &self.name)
            .field("weight", &self.weight)
            .field("pricing", &self.pricing)
            .field("max_context_tokens", &self.max_context_tokens)
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

impl Provider {
    /// A provider named `name` (used in [`Event`]s) serving `llm`, with
    /// weight 1, no pricing and no context limit.
    pub fn new(name: impl Into<Arc<str>>, llm: impl Llm + 'static) -> Self {
        Self::from_arc(name, Arc::new(llm))
    }

    /// Like [`new`](Self::new), for an already shared model.
    pub fn from_arc(name: impl Into<Arc<str>>, llm: Arc<dyn Llm>) -> Self {
        Self {
            name: name.into(),
            llm,
            weight: 1,
            pricing: None,
            max_context_tokens: None,
            retry: None,
        }
    }

    /// The provider's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Weight for [`Strategy::WeightedRandom`] (default 1).
    #[must_use]
    pub const fn weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Token prices, used by [`Strategy::CheapestFirst`].
    #[must_use]
    pub const fn pricing(mut self, pricing: Pricing) -> Self {
        self.pricing = Some(pricing);
        self
    }

    /// The model's context window in tokens. When set, the router skips
    /// this provider for prompts whose estimate (plus
    /// [`Router::reserve_output_tokens`]) does not fit.
    #[must_use]
    pub const fn max_context_tokens(mut self, tokens: usize) -> Self {
        self.max_context_tokens = Some(tokens);
        self
    }

    /// A retry policy for this provider, overriding
    /// [`Router::retry_policy`].
    #[must_use]
    pub const fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry = Some(policy);
        self
    }
}

/// Per-provider mutable health.
#[derive(Debug)]
struct Health {
    state: BreakerState,
    failures: u32,
    opened_at: Option<Instant>,
    probe_in_flight: bool,
    cooldown_until: Option<Instant>,
    ewma_ms: Option<f64>,
}

impl Health {
    const fn new() -> Self {
        Self {
            state: BreakerState::Closed,
            failures: 0,
            opened_at: None,
            probe_in_flight: false,
            cooldown_until: None,
            ewma_ms: None,
        }
    }
}

struct Slot {
    provider: Provider,
    health: Mutex<Health>,
}

impl Slot {
    fn health(&self) -> MutexGuard<'_, Health> {
        self.health.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Releases a half-open probe slot if the request is dropped mid-flight.
struct ProbeGuard<'a> {
    slot: &'a Slot,
    armed: bool,
}

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.slot.health().probe_in_flight = false;
        }
    }
}

/// Longest cooldown actually scheduled; longer ones are clamped to it.
const FAR_FUTURE: Duration = Duration::from_secs(86_400 * 365 * 30);

type Estimator = Arc<dyn Fn(&[Message]) -> usize + Send + Sync>;

/// An [`Llm`] that routes each request across several providers, with
/// per-provider retries, circuit breakers, rate-limit cooldowns and
/// context-window filtering.
///
/// For each request the router orders its providers by [`Strategy`], skips
/// those whose breaker is open, that are cooling down after a rate limit or
/// whose [`max_context_tokens`](Provider::max_context_tokens) is too small,
/// and tries the rest in turn until one succeeds. Errors that are not
/// worth sending elsewhere ([`ErrorClass::InvalidRequest`]) are returned
/// immediately; otherwise the last provider's error is returned.
///
/// **Streaming** ([`stream`](Llm::stream) and
/// [`stream_events`](Llm::stream_events)) falls back only before the first
/// chunk: a provider whose stream fails to open, or yields an error as its
/// first item, is replaced
/// by the next one; once a chunk has been delivered, later errors are passed
/// through and the outputs of two providers are never spliced together.
///
/// By default each provider gets a single attempt
/// ([`RetryPolicy::no_retry`]), as fallback is the router's main tool; set
/// [`retry_policy`](Self::retry_policy) to retry each provider in place.
///
/// # Example
///
/// ```rust
/// use std::sync::{Arc, Mutex};
/// use async_trait::async_trait;
/// use rune_chain_core::{GenerateResult, Llm, LlmError, Message};
/// use rune_chain_retry::{Event, Provider, Router, Strategy};
///
/// struct Down;
/// #[async_trait]
/// impl Llm for Down {
///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
///         Err(LlmError::provider("Overloaded"))
///     }
/// }
/// struct Up;
/// #[async_trait]
/// impl Llm for Up {
///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
///         Ok(GenerateResult::from_text("hi"))
///     }
/// }
///
/// let fallbacks = Arc::new(Mutex::new(0));
/// let seen = Arc::clone(&fallbacks);
/// let router = Router::new(Strategy::Ordered)
///     .provider(Provider::new("primary", Down))
///     .provider(Provider::new("backup", Up))
///     .on_event(move |e| {
///         if matches!(e, Event::Fallback { .. }) {
///             *seen.lock().unwrap() += 1;
///         }
///     });
///
/// # tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(async {
/// let out = router.generate(&[Message::human("hello")]).await.unwrap();
/// assert_eq!(out.generation, "hi");
/// assert_eq!(*fallbacks.lock().unwrap(), 1);
/// # });
/// ```
pub struct Router {
    slots: Vec<Slot>,
    strategy: Strategy,
    policy: RetryPolicy,
    breaker: BreakerConfig,
    estimator: Estimator,
    reserve_output_tokens: usize,
    expected_output_tokens: u64,
    ewma_alpha: f64,
    classifier: Classifier,
    observers: Observers,
    rng: Rng,
    next: AtomicUsize,
}

impl fmt::Debug for Router {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Router")
            .field(
                "providers",
                &self.slots.iter().map(|s| &s.provider).collect::<Vec<_>>(),
            )
            .field("strategy", &self.strategy)
            .field("policy", &self.policy)
            .field("breaker", &self.breaker)
            .field("observers", &self.observers)
            .finish_non_exhaustive()
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new(Strategy::default())
    }
}

impl Router {
    /// An empty router using `strategy`. Add providers with
    /// [`provider`](Self::provider); a router without providers fails every
    /// request with [`LlmError::other`].
    #[must_use]
    pub fn new(strategy: Strategy) -> Self {
        Self {
            slots: Vec::new(),
            strategy,
            policy: RetryPolicy::no_retry(),
            breaker: BreakerConfig::default(),
            estimator: Arc::new(estimate_tokens),
            reserve_output_tokens: 0,
            expected_output_tokens: 256,
            ewma_alpha: 0.3,
            classifier: classify,
            observers: Observers::new(),
            rng: Rng::new(),
            next: AtomicUsize::new(0),
        }
    }

    /// Add a provider (after those already added).
    #[must_use]
    pub fn provider(mut self, provider: Provider) -> Self {
        self.slots.push(Slot {
            provider,
            health: Mutex::new(Health::new()),
        });
        self
    }

    /// Default retry policy for every provider (default:
    /// [`RetryPolicy::no_retry`]). [`Provider::retry_policy`] overrides it.
    #[must_use]
    pub const fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Circuit-breaker and cooldown settings.
    #[must_use]
    pub const fn breaker(mut self, config: BreakerConfig) -> Self {
        self.breaker = config;
        self
    }

    /// Replace the prompt-size estimator used for context-window filtering
    /// and [`Strategy::CheapestFirst`] (default: [`estimate_tokens`]). Plug
    /// in a real tokenizer here for exact counts.
    #[must_use]
    pub fn token_estimator(
        mut self,
        estimator: impl Fn(&[Message]) -> usize + Send + Sync + 'static,
    ) -> Self {
        self.estimator = Arc::new(estimator);
        self
    }

    /// Tokens to keep free for the answer when checking a provider's
    /// context window (default 0).
    #[must_use]
    pub const fn reserve_output_tokens(mut self, tokens: usize) -> Self {
        self.reserve_output_tokens = tokens;
        self
    }

    /// Completion length assumed when comparing prices for
    /// [`Strategy::CheapestFirst`] (default 256).
    #[must_use]
    pub const fn expected_output_tokens(mut self, tokens: u64) -> Self {
        self.expected_output_tokens = tokens;
        self
    }

    /// Smoothing factor in `(0, 1]` for the latency average used by
    /// [`Strategy::LowestLatency`] (default 0.3; higher reacts faster).
    /// Out-of-range values are clamped.
    #[must_use]
    pub const fn ewma_alpha(mut self, alpha: f64) -> Self {
        self.ewma_alpha = if alpha.is_nan() {
            0.3
        } else {
            alpha.clamp(0.01, 1.0)
        };
        self
    }

    /// Replace the error classifier (default: [`classify`]).
    #[must_use]
    pub const fn classifier(mut self, classifier: fn(&LlmError) -> ErrorClass) -> Self {
        self.classifier = classifier;
        self
    }

    /// Register an observer for [`Event`]s. Can be called more than once.
    #[must_use]
    pub fn on_event(mut self, observer: impl Fn(&Event) + Send + Sync + 'static) -> Self {
        let observer: Observer = Arc::new(observer);
        self.observers.push(observer);
        self
    }

    /// Seed the random source used for jitter and [`Strategy::WeightedRandom`],
    /// for reproducible tests. Unseeded routers draw a random seed.
    #[must_use]
    pub fn seed(mut self, seed: u64) -> Self {
        self.rng = Rng::seeded(seed);
        self
    }

    /// Names of the providers, in the order they were added.
    pub fn provider_names(&self) -> impl Iterator<Item = &str> {
        self.slots.iter().map(|s| s.provider.name())
    }

    /// Current breaker state of the named provider. An open breaker whose
    /// open period has ended is reported as half-open.
    #[must_use]
    pub fn breaker_state(&self, provider: &str) -> Option<BreakerState> {
        let slot = self.slot(provider)?;
        let h = slot.health();
        Some(match (h.state, h.opened_at) {
            (BreakerState::Open, Some(at)) if at.elapsed() >= self.breaker.open_for => {
                BreakerState::HalfOpen
            }
            (state, _) => state,
        })
    }

    /// Smoothed successful latency of the named provider, if measured.
    #[must_use]
    pub fn latency(&self, provider: &str) -> Option<Duration> {
        let ms = self.slot(provider)?.health().ewma_ms?;
        Duration::try_from_secs_f64(ms / 1000.0).ok()
    }

    fn slot(&self, name: &str) -> Option<&Slot> {
        self.slots.iter().find(|s| &*s.provider.name == name)
    }

    /// Provider indices in strategy order.
    fn order(&self, est_tokens: usize) -> Vec<usize> {
        let n = self.slots.len();
        let mut order: Vec<usize> = (0..n).collect();
        match self.strategy {
            Strategy::Ordered => {}
            Strategy::RoundRobin => {
                let start = self.next.fetch_add(1, Ordering::Relaxed) % n;
                order.rotate_left(start);
            }
            Strategy::WeightedRandom => {
                let mut pool: Vec<usize> = order
                    .iter()
                    .copied()
                    .filter(|&i| self.slots[i].provider.weight > 0)
                    .collect();
                let mut picked = Vec::with_capacity(n);
                while !pool.is_empty() {
                    let total: u64 = pool
                        .iter()
                        .map(|&i| u64::from(self.slots[i].provider.weight))
                        .sum();
                    let mut r = self.rng.next_u64() % total;
                    let mut at = pool.len() - 1;
                    for (k, &i) in pool.iter().enumerate() {
                        let w = u64::from(self.slots[i].provider.weight);
                        if r < w {
                            at = k;
                            break;
                        }
                        r -= w;
                    }
                    picked.push(pool.remove(at));
                }
                picked.extend(
                    order
                        .iter()
                        .filter(|&&i| self.slots[i].provider.weight == 0),
                );
                order = picked;
            }
            Strategy::LowestLatency => {
                let keys: Vec<f64> = self
                    .slots
                    .iter()
                    .map(|s| s.health().ewma_ms.unwrap_or(0.0))
                    .collect();
                order.sort_by(|&a, &b| keys[a].total_cmp(&keys[b]));
            }
            Strategy::CheapestFirst => {
                let input = est_tokens as u64;
                let out = self.expected_output_tokens;
                order.sort_by_key(|&i| {
                    self.slots[i]
                        .provider
                        .pricing
                        .map_or((1, 0), |p| (0, p.cost_of(input, out).picodollars()))
                });
            }
        }
        order
    }

    /// Decide whether `slot` may take a request now.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the guard is dropped at the end of the block, before events are emitted"
    )]
    fn admit<'a>(&self, slot: &'a Slot) -> Result<ProbeGuard<'a>, SkipReason> {
        let now = Instant::now();
        let mut changed = None;
        let verdict = {
            let mut h = slot.health();
            if h.cooldown_until.is_some_and(|until| now < until) {
                Err(SkipReason::CoolingDown)
            } else {
                h.cooldown_until = None;
                if h.state == BreakerState::Open
                    && h.opened_at
                        .is_none_or(|at| now.duration_since(at) >= self.breaker.open_for)
                {
                    h.state = BreakerState::HalfOpen;
                    changed = Some((BreakerState::Open, BreakerState::HalfOpen));
                }
                match h.state {
                    BreakerState::Closed => Ok(false),
                    BreakerState::HalfOpen if !h.probe_in_flight => {
                        h.probe_in_flight = true;
                        Ok(true)
                    }
                    _ => Err(SkipReason::BreakerOpen),
                }
            }
        };
        self.breaker_changed(slot, changed);
        verdict.map(|armed| ProbeGuard { slot, armed })
    }

    fn breaker_changed(&self, slot: &Slot, change: Option<(BreakerState, BreakerState)>) {
        if let Some((from, to)) = change {
            self.observers.emit(|| Event::BreakerStateChanged {
                provider: Arc::clone(&slot.provider.name),
                from,
                to,
            });
        }
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "the guard is dropped at the end of the block, before events are emitted"
    )]
    fn record_success(&self, mut guard: ProbeGuard<'_>, latency: Duration) {
        guard.armed = false;
        let slot = guard.slot;
        let changed = {
            let mut h = slot.health();
            h.failures = 0;
            h.probe_in_flight = false;
            let sample = latency.as_secs_f64() * 1000.0;
            h.ewma_ms = Some(
                h.ewma_ms
                    .map_or(sample, |prev| self.ewma_alpha.mul_add(sample - prev, prev)),
            );
            let from = h.state;
            h.state = BreakerState::Closed;
            h.opened_at = None;
            (from != BreakerState::Closed).then_some((from, BreakerState::Closed))
        };
        self.breaker_changed(slot, changed);
    }

    fn record_failure(&self, mut guard: ProbeGuard<'_>, class: ErrorClass, error: &LlmError) {
        guard.armed = false;
        let slot = guard.slot;
        let now = Instant::now();
        let mut cooldown = None;
        let changed = {
            let mut h = slot.health();
            h.probe_in_flight = false;
            if class == ErrorClass::RateLimited {
                let d = retry_after(error).unwrap_or(self.breaker.rate_limit_cooldown);
                if !d.is_zero() {
                    // Clamp so a configured `Duration::MAX` cannot overflow
                    // the clock; 30 years is "never" for a cooldown.
                    h.cooldown_until = now.checked_add(d.min(FAR_FUTURE));
                    cooldown = Some(d);
                }
            }
            let from = h.state;
            if class.trips_breaker() && self.breaker.failure_threshold > 0 {
                h.failures = h.failures.saturating_add(1);
                if from == BreakerState::HalfOpen
                    || (from == BreakerState::Closed
                        && h.failures >= self.breaker.failure_threshold)
                {
                    h.state = BreakerState::Open;
                    h.opened_at = Some(now);
                }
            }
            (from != h.state).then_some((from, h.state))
        };
        if let Some(duration) = cooldown {
            self.observers.emit(|| Event::CooldownStarted {
                provider: Arc::clone(&slot.provider.name),
                duration,
            });
        }
        self.breaker_changed(slot, changed);
    }

    async fn route(&self, req: Request<'_>) -> Result<Output, LlmError> {
        if self.slots.is_empty() {
            return Err(LlmError::other("router has no providers"));
        }
        let est = (self.estimator)(req.messages());
        let needed = est.saturating_add(self.reserve_output_tokens);
        let mut last: Option<(LlmError, ErrorClass, Arc<str>)> = None;
        let mut too_small = 0usize;
        for i in self.order(est) {
            let slot = &self.slots[i];
            let p = &slot.provider;
            let skip = |reason| {
                self.observers.emit(|| Event::ProviderSkipped {
                    provider: Arc::clone(&p.name),
                    reason,
                });
            };
            if p.max_context_tokens.is_some_and(|max| needed > max) {
                too_small += 1;
                skip(SkipReason::ContextTooSmall);
                continue;
            }
            let guard = match self.admit(slot) {
                Ok(g) => g,
                Err(reason) => {
                    skip(reason);
                    continue;
                }
            };
            if let Some((_, class, from)) = &last {
                self.observers.emit(|| Event::Fallback {
                    from: Arc::clone(from),
                    to: Arc::clone(&p.name),
                    class: *class,
                });
            }
            let ctx = Ctx {
                name: &p.name,
                policy: p.retry.as_ref().unwrap_or(&self.policy),
                rng: &self.rng,
                observers: &self.observers,
                classifier: self.classifier,
            };
            match exec::run(&ctx, &*p.llm, req).await {
                Ok(s) => {
                    self.record_success(guard, s.latency);
                    return Ok(s.output);
                }
                Err(f) => {
                    self.record_failure(guard, f.class, &f.error);
                    if !f.class.should_fallback() {
                        return Err(f.error);
                    }
                    last = Some((f.error, f.class, Arc::clone(&p.name)));
                }
            }
        }
        Err(match last {
            Some((error, ..)) => error,
            None if too_small == self.slots.len() => LlmError::new(
                LlmErrorKind::ContextLengthExceeded,
                format!("prompt (~{est} tokens) exceeds the context window of every provider"),
            ),
            None => LlmError::new(
                LlmErrorKind::Overloaded,
                "all providers are temporarily unavailable (circuit open or cooling down)",
            ),
        })
    }
}

#[async_trait]
impl Llm for Router {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        self.route(Request::Generate(messages)).await?.into_result()
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        self.route(Request::Tools(messages, tools, &tool_choice))
            .await?
            .into_result()
    }

    async fn stream(&self, messages: &[Message]) -> Result<LlmStream, LlmError> {
        self.route(Request::Stream(messages)).await?.into_stream()
    }

    async fn stream_events(
        &self,
        messages: &[Message],
        tools: Option<&[FunctionDefinition]>,
        tool_choice: Option<ToolChoice>,
    ) -> Result<EventStream, LlmError> {
        self.route(Request::Events(messages, tools, &tool_choice))
            .await?
            .into_events()
    }

    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        self.route(Request::Structured(messages, format))
            .await?
            .into_result()
    }
}
