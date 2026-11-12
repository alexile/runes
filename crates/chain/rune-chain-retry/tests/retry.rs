//! `RetryLlm` behaviour across every `Llm` entry point, plus the shared
//! `rune_chain_core` LLM contract.

#![allow(
    clippy::unwrap_used,
    clippy::significant_drop_tightening,
    clippy::items_after_statements,
    reason = "test assertions"
)]

use rune_chain_core::LlmErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use futures::{Stream, StreamExt, stream};
use rune_chain_core::testing::check_llm;
use rune_chain_core::{
    FunctionDefinition, GenerateResult, Llm, LlmError, Message, StreamData, ToolChoice,
};
use rune_chain_retry::{Event, Jitter, RetryLlm};

type BoxStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;

/// Fails the first `failures` calls (on every entry point) with `error`.
struct Flaky {
    calls: Arc<AtomicU32>,
    failures: u32,
    error: LlmError,
}

impl Flaky {
    fn new(failures: u32, error: LlmError) -> (Self, Arc<AtomicU32>) {
        let calls = Arc::new(AtomicU32::new(0));
        let llm = Self {
            calls: Arc::clone(&calls),
            failures,
            error,
        };
        (llm, calls)
    }

    fn attempt(&self) -> Result<(), LlmError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n < self.failures {
            Err(self.error.clone())
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl Llm for Flaky {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        self.attempt()?;
        Ok(GenerateResult::from_text("ok"))
    }

    async fn generate_with_tools(
        &self,
        _: &[Message],
        _: &[FunctionDefinition],
        _: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        self.attempt()?;
        Ok(GenerateResult::from_text("tools ok"))
    }

    async fn stream(&self, _: &[Message]) -> Result<BoxStream, LlmError> {
        self.attempt()?;
        Ok(Box::pin(stream::iter([
            Ok(StreamData::chunk("o")),
            Ok(StreamData::chunk("k")),
            Ok(StreamData::done()),
        ])))
    }
}

const fn retry(llm: Flaky, max: u32) -> RetryLlm<Flaky> {
    RetryLlm::new(llm).max_retries(max).initial_delay_ms(0)
}

#[tokio::test]
async fn healthy_llm_meets_the_llm_contract() {
    let (llm, _) = Flaky::new(0, LlmError::other(String::new()));
    check_llm(&retry(llm, 3)).await.unwrap();
}

#[tokio::test]
async fn flaky_llm_meets_the_llm_contract_once_retried() {
    let (llm, _) = Flaky::new(2, LlmError::request_failed("reset"));
    check_llm(&retry(llm, 3)).await.unwrap();
}

#[tokio::test]
async fn makes_exactly_max_retries_plus_one_attempts() {
    for max in [0, 1, 4] {
        let (llm, calls) = Flaky::new(u32::MAX, LlmError::provider("529"));
        let err = retry(llm, max).generate(&[]).await.unwrap_err();
        assert!(matches!(err, e if e.kind() == LlmErrorKind::Provider));
        assert_eq!(calls.load(Ordering::SeqCst), max + 1, "max_retries={max}");
    }
}

#[tokio::test]
async fn provider_errors_are_retried() {
    let (llm, calls) = Flaky::new(1, LlmError::provider("overloaded"));
    assert_eq!(retry(llm, 1).generate(&[]).await.unwrap().generation, "ok");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn non_transient_errors_fail_immediately() {
    for error in [
        LlmError::invalid_response("bad"),
        LlmError::unsupported("no"),
        LlmError::other("budget"),
    ] {
        let (llm, calls) = Flaky::new(1, error);
        assert!(retry(llm, 5).generate(&[]).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn generate_with_tools_is_retried() {
    let (llm, calls) = Flaky::new(2, LlmError::request_failed("timeout"));
    let tools = [FunctionDefinition::single_input("echo", "Echo.")];
    let r = retry(llm, 2)
        .generate_with_tools(&[], &tools, Some(ToolChoice::Auto))
        .await
        .unwrap();
    assert_eq!(r.generation, "tools ok");
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn opening_a_stream_is_retried() {
    let (llm, calls) = Flaky::new(1, LlmError::request_failed("reset"));
    let s = retry(llm, 1).stream(&[]).await.unwrap();
    let text: String = s
        .map(|c| c.unwrap().content)
        .collect::<Vec<_>>()
        .await
        .concat();
    assert_eq!(text, "ok");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let (llm, calls) = Flaky::new(5, LlmError::request_failed("reset"));
    assert!(retry(llm, 1).stream(&[]).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn backs_off_exponentially() {
    let (llm, _) = Flaky::new(3, LlmError::request_failed("timeout"));
    let llm = RetryLlm::new(llm)
        .max_retries(3)
        .initial_delay_ms(100)
        .multiplier(2.0)
        .jitter(Jitter::None);
    let start = tokio::time::Instant::now();
    llm.generate(&[]).await.unwrap();
    // 100 + 200 + 400 ms of virtual time.
    assert_eq!(start.elapsed(), Duration::from_millis(700));
}

#[tokio::test(start_paused = true)]
async fn absurd_backoff_settings_do_not_panic() {
    for multiplier in [f64::NAN, -3.0, f64::INFINITY, 1e300] {
        let (llm, _) = Flaky::new(1, LlmError::request_failed("x"));
        let llm = RetryLlm::new(llm)
            .max_retries(1)
            .initial_delay_ms(1)
            .multiplier(multiplier);
        // Paused time auto-advances, so even a huge delay completes instantly.
        assert_eq!(llm.generate(&[]).await.unwrap().generation, "ok");
    }
}

#[tokio::test]
async fn auth_and_invalid_request_are_never_retried() {
    for msg in [
        "invalid x-api-key",
        "HTTP 401 Unauthorized",
        "invalid_request_error: bad",
    ] {
        let (llm, calls) = Flaky::new(1, LlmError::provider(msg));
        assert!(retry(llm, 5).generate(&[]).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{msg}");
    }
}

#[tokio::test(start_paused = true)]
async fn full_jitter_stays_within_the_exponential_bound() {
    let (llm, _) = Flaky::new(3, LlmError::provider("Overloaded"));
    let llm = RetryLlm::new(llm)
        .max_retries(3)
        .initial_delay_ms(100)
        .seed(42);
    let start = tokio::time::Instant::now();
    llm.generate(&[]).await.unwrap();
    assert!(start.elapsed() <= Duration::from_millis(700));
}

#[tokio::test(start_paused = true)]
async fn retry_after_hint_is_honoured() {
    let (llm, calls) = Flaky::new(
        1,
        LlmError::provider("Rate limit reached. Please try again in 7s."),
    );
    let llm = RetryLlm::new(llm).max_retries(1).initial_delay_ms(10);
    let start = tokio::time::Instant::now();
    llm.generate(&[]).await.unwrap();
    assert!(start.elapsed() >= Duration::from_secs(7));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn max_elapsed_stops_retrying() {
    let (llm, calls) = Flaky::new(u32::MAX, LlmError::provider("503"));
    let llm = RetryLlm::new(llm)
        .max_retries(100)
        .initial_delay_ms(1_000)
        .jitter(Jitter::None)
        .max_elapsed(Duration::from_millis(3_500));
    assert!(llm.generate(&[]).await.is_err());
    // Waits 1 s + 2 s; the next 4 s wait would overrun the 3.5 s budget.
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

/// Never answers.
struct Hang(Arc<AtomicU32>);

#[async_trait]
impl Llm for Hang {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            std::future::pending::<()>().await;
        }
        Ok(GenerateResult::from_text("late ok"))
    }
}

#[tokio::test(start_paused = true)]
async fn attempt_timeout_fails_the_attempt_and_retries() {
    let calls = Arc::new(AtomicU32::new(0));
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let llm = RetryLlm::new(Hang(Arc::clone(&calls)))
        .max_retries(1)
        .initial_delay_ms(0)
        .attempt_timeout(Duration::from_secs(5))
        .name("hang")
        .on_event(move |e| sink.lock().unwrap().push(e.clone()));
    assert_eq!(llm.generate(&[]).await.unwrap().generation, "late ok");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let events = events.lock().unwrap();
    assert!(events.iter().any(|e| matches!(
        e,
        Event::AttemptFailed { class: rune_chain_retry::ErrorClass::Timeout, provider, .. } if &**provider == "hang"
    )));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::RetryScheduled { attempt: 2, .. }))
    );
}

/// Stream whose first item is an error for the first `failures` opens.
struct FlakyStream {
    calls: Arc<AtomicU32>,
    failures: u32,
}

#[async_trait]
impl Llm for FlakyStream {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text("x"))
    }

    async fn stream(&self, _: &[Message]) -> Result<BoxStream, LlmError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) < self.failures {
            return Ok(Box::pin(stream::iter([Err(LlmError::provider(
                "Overloaded",
            ))])));
        }
        Ok(Box::pin(stream::iter([
            Ok(StreamData::chunk("a")),
            Err(LlmError::provider("Overloaded")),
        ])))
    }
}

#[tokio::test]
async fn stream_retries_before_first_chunk_but_not_after() {
    let calls = Arc::new(AtomicU32::new(0));
    let llm = RetryLlm::new(FlakyStream {
        calls: Arc::clone(&calls),
        failures: 1,
    })
    .max_retries(3)
    .initial_delay_ms(0);
    let items: Vec<_> = llm.stream(&[]).await.unwrap().collect().await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].as_ref().unwrap().content, "a");
    assert!(items[1].is_err(), "mid-stream errors pass through");
}
