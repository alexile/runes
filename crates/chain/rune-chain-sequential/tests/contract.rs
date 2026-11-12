//! `SequentialChain` against the shared `Chain` contract, plus pipeline
//! behaviour: wiring checks, key mapping, timeouts, retries, early exit,
//! events, streaming and summed usage. Everything runs on mock chains with
//! a paused clock, so timings are exact.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::{Stream, StreamExt, stream};
use rune_chain_core::testing::{check_chain, check_chain_rejects};
use rune_chain_core::{
    Chain, ChainError, FinishReason, GenerateResult, LlmError, LlmErrorKind, PromptArgs,
    StreamData, TokenUsage, prompt_args,
};
use rune_chain_sequential::{BuildError, RetryPolicy, SequentialChain, Step, StepEvent};
use serde_json::{Value, json};

/// Reads `from`, applies `f`, reports one prompt and one completion token.
/// Can be told to sleep, or to fail its first `failures` calls.
struct Map {
    from: &'static str,
    f: fn(&str) -> String,
    calls: Arc<AtomicUsize>,
    delay: Duration,
    failures: usize,
    failure: fn() -> ChainError,
}

impl Map {
    fn new(from: &'static str, f: fn(&str) -> String) -> Self {
        Self {
            from,
            f,
            calls: Arc::default(),
            delay: Duration::ZERO,
            failures: 0,
            failure: || LlmError::from_status(503, "overloaded").into(),
        }
    }

    const fn slow(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    const fn flaky(mut self, failures: usize, failure: fn() -> ChainError) -> Self {
        self.failures = failures;
        self.failure = failure;
        self
    }
}

#[async_trait]
impl Chain for Map {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        if n < self.failures {
            return Err((self.failure)());
        }
        let text = input
            .get(self.from)
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable(self.from.into()))?;
        Ok(GenerateResult::from_text((self.f)(text))
            .with_tokens(TokenUsage::new(1, 1).with_reasoning_tokens(1))
            .with_finish_reason(FinishReason::Stop))
    }

    async fn stream(
        &self,
        input: PromptArgs,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, ChainError>> + Send>>, ChainError>
    {
        let text = self.call(input).await?.generation;
        let chunks: Vec<_> = text
            .chars()
            .map(|c| Ok(StreamData::chunk(c.to_string())))
            .chain([Ok(StreamData::done())])
            .collect();
        Ok(Box::pin(stream::iter(chunks)))
    }

    fn input_keys(&self) -> Vec<String> {
        vec![self.from.into()]
    }
}

/// A two-output chain: `title` and `body`, the body being its answer.
struct Split;

#[async_trait]
impl Chain for Split {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let text = input["doc"].as_str().unwrap_or_default();
        Ok(GenerateResult::from_text(text.to_lowercase()))
    }

    async fn execute(&self, input: PromptArgs) -> Result<HashMap<String, Value>, ChainError> {
        let text = input["doc"].as_str().unwrap_or_default().to_string();
        let result = self.call(input).await?;
        Ok(HashMap::from([
            ("title".to_string(), json!(text.to_uppercase())),
            ("body".to_string(), json!(result.generation)),
            ("generate_result".to_string(), json!(result)),
        ]))
    }

    fn input_keys(&self) -> Vec<String> {
        vec!["doc".into()]
    }

    fn output_keys(&self) -> Vec<String> {
        vec!["title".into(), "body".into(), "generate_result".into()]
    }
}

fn exclaim(s: &str) -> String {
    format!("{s}!")
}

fn upper(s: &str) -> String {
    s.to_uppercase()
}

fn three_steps() -> SequentialChain {
    SequentialChain::builder()
        .chain(Map::new("input", upper), "upper")
        .chain(Map::new("upper", exclaim), "loud")
        // Earlier outputs and the original input stay visible downstream.
        .chain(Map::new("input", exclaim), "quiet")
        .build()
        .unwrap()
}

#[tokio::test]
async fn pipelines_meet_the_chain_contract() {
    let one = SequentialChain::builder()
        .chain(Map::new("input", upper), "upper")
        .build()
        .unwrap();
    check_chain(&one, &prompt_args! { "input" => "hi" })
        .await
        .unwrap();
    let seq = three_steps();
    assert_eq!(seq.primary_output_key(), "quiet");
    check_chain(&seq, &prompt_args! { "input" => "hi" })
        .await
        .unwrap();
    let empty = SequentialChain::builder().build().unwrap();
    check_chain(&empty, &prompt_args! {}).await.unwrap();
    assert_eq!(empty.execute(prompt_args! {}).await.unwrap()["output"], "");
}

#[tokio::test]
async fn missing_inputs_are_rejected_before_any_step_runs() {
    let first = Map::new("input", upper);
    let calls = Arc::clone(&first.calls);
    let seq = SequentialChain::builder()
        .chain(first, "upper")
        .chain(Map::new("upper", exclaim), "loud")
        .build()
        .unwrap();
    assert_eq!(seq.input_keys(), ["input"]);
    check_chain_rejects(&seq, &prompt_args! { "wrong" => "x" })
        .await
        .unwrap();
    assert!(seq.stream(prompt_args! {}).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn outputs_feed_later_steps_and_usage_is_summed() {
    let seq = three_steps();
    let out = seq.execute(prompt_args! { "input" => "hi" }).await.unwrap();
    assert_eq!(out["upper"], "HI");
    assert_eq!(out["loud"], "HI!");
    assert_eq!(out["quiet"], "hi!");

    let r = seq.call(prompt_args! { "input" => "hi" }).await.unwrap();
    assert_eq!(r.generation, "hi!", "call returns the last step's output");
    let usage = r.tokens.unwrap();
    assert_eq!((usage.total_tokens, usage.reasoning_tokens), (6, 3));
    assert_eq!(r.finish_reason, Some(FinishReason::Stop));

    let run = seq.run(prompt_args! { "input" => "hi" }).await.unwrap();
    let names: Vec<&str> = run.steps.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["upper", "loud", "quiet"]);
    assert!(run.steps.iter().all(|s| s.attempts == 1));
    assert_eq!(run.usage().unwrap().total_tokens, 6);
    assert_eq!(run.exited_after, None);
}

#[tokio::test]
async fn build_catches_wiring_mistakes() {
    let err = SequentialChain::builder()
        .inputs(["input"])
        .chain(Map::new("input", upper), "upper")
        .chain(Map::new("uper", exclaim), "loud")
        .build()
        .unwrap_err();
    assert_eq!(
        err,
        BuildError::MissingInput {
            step: "loud".into(),
            key: "uper".into()
        }
    );

    let err = SequentialChain::builder()
        .chain(Map::new("input", upper), "x")
        .chain(Map::new("x", exclaim), "x")
        .build()
        .unwrap_err();
    assert!(matches!(err, BuildError::DuplicateKey { ref key, .. } if key == "x"));

    // An output may not shadow a pipeline input either.
    let err = SequentialChain::builder()
        .chain(Map::new("input", upper), "input")
        .build()
        .unwrap_err();
    assert!(matches!(err, BuildError::DuplicateKey { .. }));

    let err = SequentialChain::builder()
        .chain(Map::new("input", upper), "generate_result")
        .build()
        .unwrap_err();
    assert!(matches!(err, BuildError::ReservedKey { .. }));

    let err = SequentialChain::builder()
        .chain(Map::new("input", upper), "")
        .build()
        .unwrap_err();
    assert_eq!(err, BuildError::EmptyOutputKey { index: 0 });

    let err = SequentialChain::builder()
        .step(Step::new(Split, "lower").map_output("summary", "s"))
        .build()
        .unwrap_err();
    assert!(matches!(err, BuildError::UnknownOutput { ref key, .. } if key == "summary"));

    let err = SequentialChain::builder()
        .inputs(["text"])
        .step(Step::new(Map::new("input", upper), "u").map_input("input", "txt"))
        .build()
        .unwrap_err();
    assert!(matches!(err, BuildError::MissingInput { ref key, .. } if key == "txt"));
    assert!(ChainError::from(err).to_string().contains("txt"));
}

#[tokio::test]
async fn keys_can_be_mapped_in_and_out() {
    let seq = SequentialChain::builder()
        .inputs(["article"])
        .step(
            Step::new(Split, "lower")
                .name("split")
                .map_input("doc", "article")
                .map_output("title", "headline"),
        )
        .step(Step::new(Map::new("text", exclaim), "final").map_input("text", "headline"))
        .build()
        .unwrap();
    assert_eq!(seq.input_keys(), ["article"]);
    assert_eq!(
        seq.output_keys(),
        ["headline", "lower", "final", "generate_result"]
    );
    assert_eq!(seq.step_names(), ["split", "final"]);
    let out = seq
        .execute(prompt_args! { "article" => "Big News" })
        .await
        .unwrap();
    assert_eq!(out["headline"], "BIG NEWS");
    assert_eq!(out["lower"], "big news");
    assert_eq!(out["final"], "BIG NEWS!");
    check_chain(&seq, &prompt_args! { "article" => "Big News" })
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_step_timeout_fails_the_pipeline() {
    let last = Map::new("upper", exclaim);
    let last_calls = Arc::clone(&last.calls);
    let seq = SequentialChain::builder()
        .step(
            Step::new(
                Map::new("input", upper).slow(Duration::from_secs(5)),
                "upper",
            )
            .timeout(Duration::from_secs(1)),
        )
        .chain(last, "loud")
        .build()
        .unwrap();
    let started = tokio::time::Instant::now();
    let err = seq
        .call(prompt_args! { "input" => "hi" })
        .await
        .unwrap_err();
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    match err {
        ChainError::LlmError(e) => {
            assert_eq!(e.kind(), LlmErrorKind::Timeout);
            assert!(e.message().contains("`upper`"));
        }
        other => panic!("unexpected error: {other}"),
    }
    assert_eq!(last_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn the_default_step_timeout_applies_to_steps_without_their_own() {
    let seq = SequentialChain::builder()
        .step_timeout(Duration::from_millis(100))
        .chain(
            Map::new("input", upper).slow(Duration::from_millis(50)),
            "fast",
        )
        .step(
            Step::new(
                Map::new("input", upper).slow(Duration::from_millis(300)),
                "slow_ok",
            )
            .timeout(Duration::from_secs(1)),
        )
        .chain(
            Map::new("input", upper).slow(Duration::from_millis(200)),
            "slow",
        )
        .build()
        .unwrap();
    let err = seq.call(prompt_args! { "input" => "a" }).await.unwrap_err();
    assert!(err.to_string().contains("`slow`"), "{err}");
}

#[tokio::test(start_paused = true)]
async fn transient_failures_are_retried_with_backoff_and_reported() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    let flaky = Map::new("input", upper).flaky(2, || {
        LlmError::from_status(429, "slow down")
            .with_retry_after(Duration::from_millis(500))
            .into()
    });
    let calls = Arc::clone(&flaky.calls);
    let seq =
        SequentialChain::builder()
            .step(Step::new(flaky, "upper").retry(
                RetryPolicy::new(3).backoff(Duration::from_millis(100), Duration::from_secs(2)),
            ))
            .on_event(move |e| {
                let line = match e {
                    StepEvent::Started { name, .. } => format!("start {name}"),
                    StepEvent::Retrying { attempt, delay, .. } => {
                        format!("retry {attempt} after {}ms", delay.as_millis())
                    }
                    StepEvent::Finished {
                        attempts, elapsed, ..
                    } => {
                        format!("done in {attempts} attempts, {}ms", elapsed.as_millis())
                    }
                    other => format!("{other:?}"),
                };
                sink.lock().unwrap().push(line);
            })
            .build()
            .unwrap();
    let run = seq.run(prompt_args! { "input" => "hi" }).await.unwrap();
    assert_eq!(run.result.generation, "HI");
    assert_eq!(run.steps[0].attempts, 3);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    // The provider's retry-after (500 ms) beats the 100/200 ms backoff.
    assert_eq!(
        *events.lock().unwrap(),
        [
            "start upper",
            "retry 1 after 500ms",
            "retry 2 after 500ms",
            "done in 3 attempts, 1000ms"
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn retries_stop_at_the_limit_and_skip_permanent_errors() {
    let failed = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&failed);
    let always = Map::new("input", upper).flaky(10, || LlmError::request_failed("reset").into());
    let calls = Arc::clone(&always.calls);
    let seq = SequentialChain::builder()
        .step(Step::new(always, "u").retry(RetryPolicy::new(2)))
        .on_event(move |e| {
            if let StepEvent::Failed { attempts, .. } = e {
                *sink.lock().unwrap() = Some(*attempts);
            }
        })
        .build()
        .unwrap();
    assert!(seq.call(prompt_args! { "input" => "x" }).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(*failed.lock().unwrap(), Some(2));

    let auth = Map::new("input", upper).flaky(10, || LlmError::from_status(401, "bad key").into());
    let calls = Arc::clone(&auth.calls);
    let seq = SequentialChain::builder()
        .step(Step::new(auth, "u").retry(RetryPolicy::new(5)))
        .build()
        .unwrap();
    assert!(seq.call(prompt_args! { "input" => "x" }).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn timeouts_count_as_transient_for_retries() {
    // First attempt sleeps past the limit, the retry is fast enough.
    struct SlowOnce(AtomicUsize);
    #[async_trait]
    impl Chain for SlowOnce {
        async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            Ok(GenerateResult::from_text("ok"))
        }
    }
    let seq = SequentialChain::builder()
        .step(
            Step::new(SlowOnce(AtomicUsize::new(0)), "out")
                .timeout(Duration::from_secs(1))
                .retry(RetryPolicy::new(2).backoff(Duration::ZERO, Duration::ZERO)),
        )
        .build()
        .unwrap();
    let run = seq.run(prompt_args! {}).await.unwrap();
    assert_eq!(
        (run.result.generation.as_str(), run.steps[0].attempts),
        ("ok", 2)
    );
}

#[tokio::test]
async fn custom_retry_hooks_decide_what_to_retry() {
    let parse = Map::new("input", upper).flaky(1, || ChainError::ParseError("bad".into()));
    let seq = SequentialChain::builder()
        .step(
            Step::new(parse, "u").retry(
                RetryPolicy::new(2)
                    .backoff(Duration::ZERO, Duration::ZERO)
                    .retry_if(|e, attempt| attempt == 1 && matches!(e, ChainError::ParseError(_))),
            ),
        )
        .build()
        .unwrap();
    assert_eq!(
        seq.invoke(prompt_args! { "input" => "a" }).await.unwrap(),
        "A"
    );
}

#[tokio::test]
async fn early_exit_skips_the_remaining_steps() {
    let skipped = Map::new("checked", exclaim);
    let skipped_calls = Arc::clone(&skipped.calls);
    let exited = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&exited);
    let seq = SequentialChain::builder()
        .step(Step::new(Map::new("input", upper), "checked").exit_if(|r| r.generation == "STOP"))
        .chain(skipped, "final")
        .on_event(move |e| {
            if let StepEvent::Exited { name, .. } = e {
                *sink.lock().unwrap() = Some(name.to_string());
            }
        })
        .build()
        .unwrap();

    let run = seq.run(prompt_args! { "input" => "stop" }).await.unwrap();
    assert_eq!(run.result.generation, "STOP");
    assert_eq!(run.exited_after.as_deref(), Some("checked"));
    assert_eq!(run.steps.len(), 1);
    assert_eq!(
        run.outputs["final"], "STOP",
        "the last key holds the answer"
    );
    assert_eq!(skipped_calls.load(Ordering::SeqCst), 0);
    assert_eq!(exited.lock().unwrap().as_deref(), Some("checked"));
    check_chain(&seq, &prompt_args! { "input" => "stop" })
        .await
        .unwrap();

    let streamed: String = seq
        .stream(prompt_args! { "input" => "stop" })
        .await
        .unwrap()
        .map(|c| c.unwrap().content)
        .collect::<Vec<_>>()
        .await
        .concat();
    assert_eq!(streamed, "STOP");

    // When the condition does not fire, everything runs.
    let run = seq.run(prompt_args! { "input" => "go" }).await.unwrap();
    assert_eq!(run.result.generation, "GO!");
    assert_eq!(skipped_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn skipped_intermediate_keys_are_null_after_an_early_exit() {
    let seq = SequentialChain::builder()
        .step(Step::new(Map::new("input", upper), "a").exit_if(|_| true))
        .chain(Map::new("a", exclaim), "b")
        .chain(Map::new("b", exclaim), "c")
        .build()
        .unwrap();
    let out = seq.execute(prompt_args! { "input" => "x" }).await.unwrap();
    assert_eq!(
        (out["a"].clone(), out["b"].clone(), out["c"].clone()),
        (json!("X"), Value::Null, json!("X"))
    );
}

#[tokio::test]
async fn a_failing_step_stops_the_pipeline_and_is_reported() {
    let last = Map::new("upper", exclaim);
    let last_calls = Arc::clone(&last.calls);
    let failed = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&failed);
    let seq = SequentialChain::builder()
        .chain(
            Map::new("input", upper).flaky(1, || ChainError::Other("boom".into())),
            "upper",
        )
        .chain(last, "loud")
        .on_event(move |e| {
            if let StepEvent::Failed { name, error, .. } = e {
                sink.lock().unwrap().push(format!("{name}: {error}"));
            }
        })
        .build()
        .unwrap();
    let err = seq
        .call(prompt_args! { "input" => "hi" })
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "boom");
    assert_eq!(last_calls.load(Ordering::SeqCst), 0);
    assert_eq!(*failed.lock().unwrap(), ["upper: boom"]);
}

#[tokio::test]
async fn streams_run_earlier_steps_then_stream_the_last() {
    let seq = SequentialChain::builder()
        .chain(Map::new("input", upper), "upper")
        .chain(Map::new("upper", exclaim), "loud")
        .build()
        .unwrap();
    let chunks: Vec<StreamData> = seq
        .stream(prompt_args! { "input" => "hi" })
        .await
        .unwrap()
        .map(Result::unwrap)
        .collect()
        .await;
    let text: String = chunks.iter().map(|c| c.content.as_str()).collect();
    assert_eq!(text, "HI!");
    assert_eq!(chunks.len(), 4, "the last step streams char by char");
    assert!(chunks.last().unwrap().is_finished);
}

#[tokio::test(start_paused = true)]
async fn the_streamed_step_honours_its_timeout() {
    let seq = SequentialChain::builder()
        .step(
            Step::new(Map::new("input", upper).slow(Duration::from_secs(3)), "u")
                .timeout(Duration::from_secs(1)),
        )
        .build()
        .unwrap();
    match seq.stream(prompt_args! { "input" => "a" }).await {
        Err(ChainError::LlmError(e)) => assert_eq!(e.kind(), LlmErrorKind::Timeout),
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("expected a timeout"),
    }
}

#[tokio::test]
async fn shared_chains_and_debug_output() {
    let shared: Arc<dyn Chain> = Arc::new(Map::new("input", upper));
    let seq = SequentialChain::builder()
        .step(Step::from_arc(Arc::clone(&shared), "a"))
        .build()
        .unwrap();
    assert_eq!(
        seq.invoke(prompt_args! { "input" => "q" }).await.unwrap(),
        "Q"
    );
    assert!(format!("{seq:?}").contains("SequentialChain"));
    let builder =
        SequentialChain::builder().step(Step::from_arc(shared, "b").retry(RetryPolicy::new(2)));
    assert!(format!("{builder:?}").contains("RetryPolicy"));
}
