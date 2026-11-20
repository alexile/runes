//! The runner: concurrency, timeouts, retries, usage, cost and errors.

#![allow(
    clippy::unwrap_used,
    clippy::unnecessary_literal_bound,
    clippy::float_cmp,
    reason = "test helpers fail loudly"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use rune_chain_core::testing::{FakeLlm, FakeReply};
use rune_chain_core::{
    Chain, ChainError, Cost, GenerateResult, Llm, LlmError, Message, Pricing, PromptArgs,
    TokenUsage,
};
use rune_chain_eval::{
    Dataset, EvalError, Evaluation, Evaluator, ExactMatch, Example, MetricOutcome, Score,
    TargetOutput, chain_target, target_fn,
};
use rune_chain_usage::UsageMeter;

/// A minimal chain: send the question to the model.
struct Ask(Arc<FakeLlm>);

#[async_trait]
impl Chain for Ask {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let q = input["question"].as_str().unwrap_or_default();
        Ok(self.0.generate(&[Message::human(q)]).await?)
    }
}

fn dataset(n: usize) -> Dataset {
    Dataset::new(
        (0..n)
            .map(|i| {
                Example::from_question(i.to_string(), format!("q{i}"))
                    .with_reference(format!("Q{i}"))
            })
            .collect(),
    )
    .unwrap()
}

#[tokio::test]
async fn chain_target_with_bounded_concurrency_usage_and_cost() {
    let llm = Arc::new(
        FakeLlm::from_fn(|req| {
            let mut r = GenerateResult::from_text(req.prompt().unwrap_or_default().to_uppercase());
            r.tokens = Some(TokenUsage::new(1000, 500));
            Ok(r)
        })
        .with_latency(Duration::from_millis(20)),
    );
    let meter = UsageMeter::unlimited();
    let run = Evaluation::new("upper")
        .evaluator(ExactMatch::new())
        .concurrency(3)
        .pricing(Pricing::per_mtok(3_000_000, 15_000_000))
        .meter(meter.clone(), "fake", "fake-1")
        .run(&dataset(10), &chain_target(Ask(llm.clone())))
        .await
        .unwrap();
    assert_eq!(llm.call_count(), 10);
    assert_eq!(llm.max_in_flight(), 3);
    let s = &run.summary;
    assert_eq!(s.examples, 10);
    assert_eq!(s.target_errors, 0);
    assert_eq!(s.usage.as_ref().unwrap().total_tokens, 15_000);
    // 1000 * $3/MTok + 500 * $15/MTok = $0.0105 per example.
    assert_eq!(run.examples[0].cost, Some(Cost::from_micros(10_500)));
    assert_eq!(s.cost, Some(Cost::from_micros(105_000)));
    assert_eq!(meter.totals().calls, 10);
    assert_eq!(meter.by_tag()[0].0, "upper");
    assert!(s.latency.p50_ms >= 15.0, "{:?}", s.latency);
    assert!(s.latency.p95_ms >= s.latency.p50_ms);
    let m = run.metric("exact_match").unwrap();
    assert_eq!((m.passed, m.errors, m.pass_rate), (10, 0, 1.0));
    // Dataset order is kept.
    let ids: Vec<&str> = run.examples.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(ids, ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]);
}

#[tokio::test]
async fn timeouts_are_retried() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let target = target_fn(move |_ex| {
        let n = c.fetch_add(1, Ordering::SeqCst);
        async move {
            if n == 0 {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            Ok::<_, ChainError>(TargetOutput::text("Q0"))
        }
    });
    let run = Evaluation::new("t")
        .evaluator(ExactMatch::new())
        .timeout(Duration::from_millis(50))
        .retries(1)
        .retry_backoff(Duration::ZERO)
        .run(&dataset(1), &target)
        .await
        .unwrap();
    let e = &run.examples[0];
    assert_eq!(e.attempts, 2);
    assert_eq!(e.output.as_deref(), Some("Q0"));
    assert!(e.scores["exact_match"].passed());
}

#[tokio::test]
async fn timeout_without_retry_is_a_target_error() {
    let target = target_fn(|_ex| async {
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok::<_, ChainError>(TargetOutput::text("late"))
    });
    let run = Evaluation::new("t")
        .evaluator(ExactMatch::new())
        .timeout(Duration::from_millis(20))
        .run(&dataset(2), &target)
        .await
        .unwrap();
    assert_eq!(run.summary.target_errors, 2);
    let e = &run.examples[0];
    assert!(e.error.as_deref().unwrap().contains("timed out"));
    assert!(matches!(
        e.scores["exact_match"],
        MetricOutcome::Error { .. }
    ));
    let m = run.metric("exact_match").unwrap();
    assert_eq!((m.errors, m.passed, m.pass_rate, m.mean), (2, 0, 0.0, None));
}

#[tokio::test]
async fn only_retryable_errors_are_retried() {
    let llm = Arc::new(FakeLlm::with_replies([
        FakeReply::rate_limited(),
        FakeReply::text("Q0"),
        FakeReply::provider_error("bad request"),
    ]));
    let ev = Evaluation::new("r")
        .evaluator(ExactMatch::new())
        .retries(3)
        .retry_backoff(Duration::ZERO)
        .concurrency(1);
    let run = ev
        .run(&dataset(1), &chain_target(Ask(llm.clone())))
        .await
        .unwrap();
    assert_eq!(run.examples[0].attempts, 2);
    assert!(run.examples[0].error.is_none());
    let run = ev
        .run(&dataset(1), &chain_target(Ask(llm.clone())))
        .await
        .unwrap();
    assert_eq!(run.examples[0].attempts, 1);
    assert!(run.examples[0].error.is_some());
}

#[tokio::test]
async fn outputs_are_capped() {
    let target =
        target_fn(|_ex| async { Ok::<_, ChainError>(TargetOutput::text("é".repeat(100))) });
    let run = Evaluation::new("cap")
        .max_output_bytes(9)
        .run(&dataset(1), &target)
        .await
        .unwrap();
    let e = &run.examples[0];
    assert!(e.output_truncated);
    assert_eq!(e.output.as_deref(), Some("éééé"));
}

struct Nan;

#[async_trait]
impl Evaluator for Nan {
    fn name(&self) -> &str {
        "nan"
    }
    async fn evaluate(&self, _: &Example, _: &TargetOutput) -> Result<Score, EvalError> {
        Ok(Score::new(f64::NAN, true))
    }
}

struct Slow;

#[async_trait]
impl Evaluator for Slow {
    fn name(&self) -> &str {
        "slow"
    }
    async fn evaluate(&self, _: &Example, _: &TargetOutput) -> Result<Score, EvalError> {
        tokio::time::sleep(Duration::from_secs(60)).await;
        Ok(Score::binary(true))
    }
}

#[tokio::test]
async fn bad_evaluators_become_errors_not_passes() {
    let target = target_fn(|_ex| async { Ok::<_, ChainError>(TargetOutput::text("x")) });
    let run = Evaluation::new("e")
        .evaluator(Nan)
        .evaluator(Slow)
        .evaluator_timeout(Duration::from_millis(20))
        .run(&dataset(2), &target)
        .await
        .unwrap();
    for name in ["nan", "slow"] {
        let m = run.metric(name).unwrap();
        assert_eq!((m.errors, m.passed, m.pass_rate), (2, 0, 0.0), "{name}");
    }
    assert!(!run.examples[0].passed_all());
}

#[tokio::test]
async fn duplicate_metric_names_are_rejected() {
    let target = target_fn(|_ex| async { Ok::<_, ChainError>(TargetOutput::text("x")) });
    let err = Evaluation::new("d")
        .evaluator(ExactMatch::new())
        .evaluator(ExactMatch::new().strict())
        .run(&dataset(1), &target)
        .await
        .unwrap_err();
    assert!(matches!(err, EvalError::Config(_)));
    let ok = Evaluation::new("d")
        .evaluator(ExactMatch::new())
        .evaluator(ExactMatch::new().strict().with_name("exact_strict"))
        .run(&dataset(1), &target)
        .await;
    assert!(ok.is_ok());
}

#[tokio::test]
async fn score_outputs_rescores_stored_answers() {
    let pairs = vec![
        (
            Example::from_question("a", "q").with_reference("yes"),
            TargetOutput::text("yes"),
        ),
        (
            Example::from_question("b", "q").with_reference("yes"),
            TargetOutput::text("no"),
        ),
    ];
    let run = Evaluation::new("stored")
        .evaluator(ExactMatch::new())
        .score_outputs(&pairs)
        .await
        .unwrap();
    assert_eq!(run.metric("exact_match").unwrap().pass_rate, 0.5);
}

#[tokio::test]
async fn errors_from_the_model_are_kept_short() {
    let long = "z".repeat(5000);
    let target = target_fn(move |_ex| {
        let long = long.clone();
        async move { Err::<TargetOutput, _>(ChainError::LlmError(LlmError::provider(long))) }
    });
    let run = Evaluation::new("e")
        .run(&dataset(1), &target)
        .await
        .unwrap();
    assert!(run.examples[0].error.as_ref().unwrap().chars().count() <= 501);
}
