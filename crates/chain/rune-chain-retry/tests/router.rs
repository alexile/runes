//! `Router` strategies, breaker, cooldown, context filtering, streaming
//! fallback and events — all with scripted mock models and paused time.

#![allow(
    clippy::unwrap_used,
    clippy::significant_drop_tightening,
    clippy::items_after_statements,
    reason = "test assertions"
)]

use rune_chain_core::LlmErrorKind;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::{Stream, StreamExt, stream};
use rune_chain_core::testing::check_llm;
use rune_chain_core::{GenerateResult, Llm, LlmError, Message, Pricing, StreamData};
use rune_chain_retry::{
    BreakerConfig, BreakerState, ErrorClass, Event, Provider, RetryPolicy, Router, SkipReason,
    Strategy,
};

type BoxStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;

/// A model that answers with its name, after `delay`, unless a scripted
/// error is queued.
struct Mock {
    name: &'static str,
    delay: Duration,
    calls: Arc<AtomicU32>,
    script: Mutex<VecDeque<LlmError>>,
    always: Option<LlmError>,
}

impl Mock {
    fn ok(name: &'static str) -> (Self, Arc<AtomicU32>) {
        let calls = Arc::new(AtomicU32::new(0));
        (
            Self {
                name,
                delay: Duration::ZERO,
                calls: Arc::clone(&calls),
                script: Mutex::new(VecDeque::new()),
                always: None,
            },
            calls,
        )
    }

    fn failing(name: &'static str, e: LlmError) -> (Self, Arc<AtomicU32>) {
        let (mut m, c) = Self::ok(name);
        m.always = Some(e);
        (m, c)
    }

    const fn delay(mut self, d: Duration) -> Self {
        self.delay = d;
        self
    }

    fn then_fail(self, e: LlmError) -> Self {
        self.script.lock().unwrap().push_back(e);
        self
    }

    fn step(&self) -> Result<(), LlmError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(e) = &self.always {
            return Err(e.clone());
        }
        self.script.lock().unwrap().pop_front().map_or(Ok(()), Err)
    }
}

#[async_trait]
impl Llm for Mock {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        tokio::time::sleep(self.delay).await;
        self.step()?;
        Ok(GenerateResult::from_text(self.name))
    }

    async fn stream(&self, _: &[Message]) -> Result<BoxStream, LlmError> {
        tokio::time::sleep(self.delay).await;
        let first = self.step();
        let name = self.name;
        Ok(Box::pin(stream::iter(match first {
            Err(e) => vec![Err(e)],
            Ok(()) => vec![
                Ok(StreamData::chunk(name)),
                Err(LlmError::provider("Overloaded")),
            ],
        })))
    }
}

fn overloaded() -> LlmError {
    LlmError::provider("Overloaded")
}

fn recorder() -> (
    Arc<Mutex<Vec<Event>>>,
    impl Fn(&Event) + Send + Sync + 'static,
) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    (events, move |e: &Event| {
        sink.lock().unwrap().push(e.clone());
    })
}

async fn ask(r: &Router) -> Result<String, LlmError> {
    r.generate(&[Message::human("hi")])
        .await
        .map(|g| g.generation)
}

#[tokio::test]
async fn healthy_router_meets_the_llm_contract() {
    let router = Router::default().provider(Provider::new("a", Mock::ok("a").0));
    check_llm(&router).await.unwrap();
}

#[tokio::test]
async fn empty_router_errors() {
    assert!(matches!(
        ask(&Router::default()).await,
        Err(e) if e.kind() == LlmErrorKind::Other
    ));
}

#[tokio::test]
async fn ordered_falls_back_and_emits_events() {
    let (events, obs) = recorder();
    let (a, a_calls) = Mock::failing("a", overloaded());
    let router = Router::new(Strategy::Ordered)
        .provider(Provider::new("a", a))
        .provider(Provider::new("b", Mock::ok("b").0))
        .on_event(obs);
    assert_eq!(ask(&router).await.unwrap(), "b");
    assert_eq!(a_calls.load(Ordering::SeqCst), 1, "no retry by default");
    let events = events.lock().unwrap();
    assert!(events.iter().any(|e| matches!(
        e,
        Event::Fallback { from, to, class: ErrorClass::Overloaded } if &**from == "a" && &**to == "b"
    )));
}

#[tokio::test]
async fn invalid_requests_do_not_fall_back() {
    let (a, _) = Mock::failing("a", LlmError::provider("invalid_request_error"));
    let (b, b_calls) = Mock::ok("b");
    let router = Router::default()
        .provider(Provider::new("a", a))
        .provider(Provider::new("b", b));
    assert!(ask(&router).await.is_err());
    assert_eq!(b_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn all_failing_returns_last_error() {
    let router = Router::default()
        .provider(Provider::new("a", Mock::failing("a", overloaded()).0))
        .provider(Provider::new(
            "b",
            Mock::failing("b", LlmError::request_failed("connection reset")).0,
        ));
    assert!(matches!(
        ask(&router).await,
        Err(e) if e.kind() == LlmErrorKind::Network
    ));
}

#[tokio::test(start_paused = true)]
async fn per_provider_retry_policy_applies_before_fallback() {
    let (a, a_calls) = Mock::ok("a");
    let a = a.then_fail(overloaded());
    let router = Router::default()
        .provider(Provider::new("a", a).retry_policy(RetryPolicy::default().with_max_retries(1)))
        .provider(Provider::new("b", Mock::ok("b").0));
    assert_eq!(ask(&router).await.unwrap(), "a");
    assert_eq!(a_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn round_robin_rotates() {
    let router = Router::new(Strategy::RoundRobin)
        .provider(Provider::new("a", Mock::ok("a").0))
        .provider(Provider::new("b", Mock::ok("b").0))
        .provider(Provider::new("c", Mock::ok("c").0));
    let mut got = Vec::new();
    for _ in 0..6 {
        got.push(ask(&router).await.unwrap());
    }
    assert_eq!(got, ["a", "b", "c", "a", "b", "c"]);
}

#[tokio::test]
async fn weighted_random_follows_weights_and_is_seedable() {
    let build = || {
        Router::new(Strategy::WeightedRandom)
            .provider(Provider::new("heavy", Mock::ok("heavy").0).weight(9))
            .provider(Provider::new("light", Mock::ok("light").0).weight(1))
            .provider(Provider::new("never", Mock::ok("never").0).weight(0))
            .seed(7)
    };
    let (r1, r2) = (build(), build());
    let mut heavy = 0;
    for _ in 0..1000 {
        let a = ask(&r1).await.unwrap();
        assert_eq!(a, ask(&r2).await.unwrap(), "same seed, same picks");
        assert_ne!(a, "never");
        heavy += usize::from(a == "heavy");
    }
    assert!((850..=950).contains(&heavy), "heavy picked {heavy}/1000");
}

#[tokio::test]
async fn zero_weight_provider_is_last_resort() {
    let router = Router::new(Strategy::WeightedRandom)
        .provider(Provider::new("down", Mock::failing("down", overloaded()).0))
        .provider(Provider::new("spare", Mock::ok("spare").0).weight(0));
    assert_eq!(ask(&router).await.unwrap(), "spare");
}

#[tokio::test(start_paused = true)]
async fn lowest_latency_learns_the_fastest() {
    let router = Router::new(Strategy::LowestLatency)
        .provider(Provider::new(
            "slow",
            Mock::ok("slow").0.delay(Duration::from_millis(900)),
        ))
        .provider(Provider::new(
            "fast",
            Mock::ok("fast").0.delay(Duration::from_millis(100)),
        ));
    // Unmeasured providers go first, in declared order.
    assert_eq!(ask(&router).await.unwrap(), "slow");
    assert_eq!(ask(&router).await.unwrap(), "fast");
    for _ in 0..5 {
        assert_eq!(ask(&router).await.unwrap(), "fast");
    }
    assert_eq!(router.latency("fast"), Some(Duration::from_millis(100)));
    assert_eq!(router.latency("slow"), Some(Duration::from_millis(900)));
}

#[tokio::test]
async fn cheapest_first_uses_pricing() {
    let router = Router::new(Strategy::CheapestFirst)
        .provider(Provider::new("unpriced", Mock::ok("unpriced").0))
        .provider(
            Provider::new("pricey", Mock::ok("pricey").0)
                .pricing(Pricing::per_mtok(15_000_000, 75_000_000)),
        )
        .provider(
            Provider::new("cheap", Mock::ok("cheap").0)
                .pricing(Pricing::per_mtok(150_000, 600_000)),
        );
    assert_eq!(ask(&router).await.unwrap(), "cheap");
}

#[tokio::test]
async fn context_filter_skips_small_windows() {
    let (events, obs) = recorder();
    let (small, small_calls) = Mock::ok("small");
    let router = Router::default()
        .provider(Provider::new("small", small).max_context_tokens(50))
        .provider(Provider::new("big", Mock::ok("big").0).max_context_tokens(10_000))
        .on_event(obs);
    let long = [Message::human("x".repeat(400))];
    assert_eq!(router.generate(&long).await.unwrap().generation, "big");
    assert_eq!(small_calls.load(Ordering::SeqCst), 0);
    assert!(events.lock().unwrap().iter().any(|e| matches!(
        e,
        Event::ProviderSkipped {
            reason: SkipReason::ContextTooSmall,
            ..
        }
    )));
    // Short prompts still use the first provider.
    assert_eq!(ask(&router).await.unwrap(), "small");

    let tiny = Router::default()
        .provider(Provider::new("t", Mock::ok("t").0).max_context_tokens(10))
        .reserve_output_tokens(5);
    let e = tiny.generate(&long).await.unwrap_err();
    assert_eq!(rune_chain_retry::classify(&e), ErrorClass::ContextLength);
}

#[tokio::test]
async fn custom_token_estimator_is_used() {
    let router = Router::default()
        .provider(Provider::new("a", Mock::ok("a").0).max_context_tokens(100))
        .provider(Provider::new("b", Mock::ok("b").0))
        .token_estimator(|_| 1_000);
    assert_eq!(ask(&router).await.unwrap(), "b");
}

#[tokio::test(start_paused = true)]
async fn breaker_opens_half_opens_and_closes() {
    let (events, obs) = recorder();
    let (a, a_calls) = Mock::ok("a");
    let a = a
        .then_fail(overloaded())
        .then_fail(overloaded())
        .then_fail(overloaded());
    let router = Router::default()
        .provider(Provider::new("a", a))
        .provider(Provider::new("b", Mock::ok("b").0))
        .breaker(
            BreakerConfig::default()
                .with_failure_threshold(2)
                .with_open_for(Duration::from_secs(10)),
        )
        .on_event(obs);

    assert_eq!(ask(&router).await.unwrap(), "b");
    assert_eq!(router.breaker_state("a"), Some(BreakerState::Closed));
    assert_eq!(ask(&router).await.unwrap(), "b");
    assert_eq!(router.breaker_state("a"), Some(BreakerState::Open));

    // While open, "a" is not called at all.
    assert_eq!(ask(&router).await.unwrap(), "b");
    assert_eq!(a_calls.load(Ordering::SeqCst), 2);

    // After the open period one probe goes through; it fails → open again.
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(router.breaker_state("a"), Some(BreakerState::HalfOpen));
    assert_eq!(ask(&router).await.unwrap(), "b");
    assert_eq!(a_calls.load(Ordering::SeqCst), 3);
    assert_eq!(router.breaker_state("a"), Some(BreakerState::Open));

    // Next probe succeeds → closed.
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(ask(&router).await.unwrap(), "a");
    assert_eq!(router.breaker_state("a"), Some(BreakerState::Closed));

    let transitions: Vec<_> = events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            Event::BreakerStateChanged { from, to, .. } => Some((*from, *to)),
            _ => None,
        })
        .collect();
    use BreakerState::{Closed, HalfOpen, Open};
    assert_eq!(
        transitions,
        [
            (Closed, Open),
            (Open, HalfOpen),
            (HalfOpen, Open),
            (Open, HalfOpen),
            (HalfOpen, Closed)
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn auth_failures_trip_the_breaker() {
    let router = Router::default()
        .provider(Provider::new(
            "a",
            Mock::failing("a", LlmError::provider("invalid x-api-key")).0,
        ))
        .provider(Provider::new("b", Mock::ok("b").0))
        .breaker(BreakerConfig::default().with_failure_threshold(1));
    assert_eq!(ask(&router).await.unwrap(), "b");
    assert_eq!(router.breaker_state("a"), Some(BreakerState::Open));
}

#[tokio::test(start_paused = true)]
async fn rate_limit_starts_a_cooldown_from_the_hint() {
    let (events, obs) = recorder();
    let (a, a_calls) = Mock::ok("a");
    let a = a.then_fail(LlmError::provider(
        "Rate limit reached. Please try again in 20s.",
    ));
    let router = Router::default()
        .provider(Provider::new("a", a))
        .provider(Provider::new("b", Mock::ok("b").0))
        .on_event(obs);
    assert_eq!(ask(&router).await.unwrap(), "b");
    assert_eq!(ask(&router).await.unwrap(), "b");
    assert_eq!(a_calls.load(Ordering::SeqCst), 1);
    // Rate limits do not count against the breaker.
    assert_eq!(router.breaker_state("a"), Some(BreakerState::Closed));
    tokio::time::advance(Duration::from_secs(20)).await;
    assert_eq!(ask(&router).await.unwrap(), "a");
    let events = events.lock().unwrap();
    assert!(events.iter().any(|e| matches!(
        e,
        Event::CooldownStarted { duration, .. } if *duration == Duration::from_secs(20)
    )));
    assert!(events.iter().any(|e| matches!(
        e,
        Event::ProviderSkipped {
            reason: SkipReason::CoolingDown,
            ..
        }
    )));
}

#[tokio::test(start_paused = true)]
async fn everything_unavailable_is_a_retryable_error() {
    let router = Router::default().provider(Provider::new(
        "a",
        Mock::failing("a", LlmError::provider("429 Too Many Requests")).0,
    ));
    assert!(ask(&router).await.is_err());
    let e = ask(&router).await.unwrap_err();
    assert!(rune_chain_retry::classify(&e).is_retryable(), "{e}");
}

#[tokio::test]
async fn stream_falls_back_only_before_the_first_chunk() {
    let router = Router::default()
        .provider(Provider::new("a", Mock::failing("a", overloaded()).0))
        .provider(Provider::new("b", Mock::ok("b").0))
        .provider(Provider::new("c", Mock::ok("c").0));
    let items: Vec<_> = router.stream(&[]).await.unwrap().collect().await;
    // "b" won; its mid-stream error is passed through, "c" is never spliced in.
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].as_ref().unwrap().content, "b");
    assert!(items[1].is_err());
}

#[tokio::test(start_paused = true)]
async fn attempt_timeout_triggers_fallback() {
    let router = Router::default()
        .provider(Provider::new(
            "slow",
            Mock::ok("slow").0.delay(Duration::from_secs(120)),
        ))
        .provider(Provider::new("b", Mock::ok("b").0))
        .retry_policy(RetryPolicy::no_retry().with_attempt_timeout(Duration::from_secs(5)));
    let start = tokio::time::Instant::now();
    assert_eq!(ask(&router).await.unwrap(), "b");
    assert_eq!(start.elapsed(), Duration::from_secs(5));
}

#[tokio::test]
async fn routers_compose_with_shared_models() {
    let shared: Arc<dyn Llm> = Arc::new(Mock::ok("shared").0);
    let inner = Router::default().provider(Provider::from_arc("s", Arc::clone(&shared)));
    let outer = Router::default()
        .provider(Provider::new("inner", inner))
        .provider(Provider::from_arc("s2", shared));
    assert_eq!(ask(&outer).await.unwrap(), "shared");
    assert_eq!(outer.provider_names().collect::<Vec<_>>(), ["inner", "s2"]);
}

#[tokio::test]
async fn huge_cooldown_does_not_panic() {
    // A "never come back" cooldown must not overflow the clock.
    let (a, _) = Mock::failing("a", LlmError::from_status(429, "slow down"));
    let router = Router::new(Strategy::Ordered)
        .breaker(BreakerConfig::default().with_rate_limit_cooldown(Duration::MAX))
        .provider(Provider::new("a", a))
        .provider(Provider::new("b", Mock::ok("b").0));
    assert_eq!(ask(&router).await.unwrap(), "b");
    // `a` stays benched.
    assert_eq!(ask(&router).await.unwrap(), "b");
}
