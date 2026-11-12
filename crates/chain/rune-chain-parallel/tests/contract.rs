//! `ParallelChain` against the shared `Chain` contract, plus fan-out
//! behaviour: bounded concurrency, timeouts, fail-fast cancellation,
//! collect-all errors, ordering and summed usage. Branches are mock chains
//! and the clock is paused, so timings are exact.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use rune_chain_core::testing::{check_chain, check_chain_rejects};
use rune_chain_core::{
    Chain, ChainError, FinishReason, GenerateResult, LlmErrorKind, PromptArgs, TokenUsage,
    prompt_args,
};
use rune_chain_parallel::{Branch, ErrorMode, ParallelChain, Semaphore};
use tokio::time::Instant;

/// Tracks how many branches run at once and the highest count seen.
#[derive(Default)]
struct Gauge {
    now: AtomicUsize,
    peak: AtomicUsize,
}

/// Transforms `input` with `f` after `delay`, reports `tokens` usage,
/// counts calls, and records whether it was dropped before finishing.
struct Map {
    f: fn(&str) -> String,
    tokens: u32,
    delay: Duration,
    fail: bool,
    calls: Arc<AtomicUsize>,
    cancelled: Arc<AtomicBool>,
    gauge: Option<Arc<Gauge>>,
}

impl Map {
    fn new(f: fn(&str) -> String, tokens: u32) -> Self {
        Self {
            f,
            tokens,
            delay: Duration::ZERO,
            fail: false,
            calls: Arc::default(),
            cancelled: Arc::default(),
            gauge: None,
        }
    }

    const fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    const fn failing(mut self) -> Self {
        self.fail = true;
        self
    }

    fn gauged(mut self, gauge: &Arc<Gauge>) -> Self {
        self.gauge = Some(Arc::clone(gauge));
        self
    }
}

/// Sets the flag when dropped unless disarmed.
struct DropFlag(Arc<AtomicBool>, bool);

impl Drop for DropFlag {
    fn drop(&mut self) {
        if self.1 {
            self.0.store(true, Ordering::SeqCst);
        }
    }
}

#[async_trait]
impl Chain for Map {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut flag = DropFlag(Arc::clone(&self.cancelled), true);
        if let Some(g) = &self.gauge {
            let now = g.now.fetch_add(1, Ordering::SeqCst) + 1;
            g.peak.fetch_max(now, Ordering::SeqCst);
        }
        tokio::time::sleep(self.delay).await;
        if let Some(g) = &self.gauge {
            g.now.fetch_sub(1, Ordering::SeqCst);
        }
        flag.1 = false;
        if self.fail {
            return Err(ChainError::Other("branch failed".into()));
        }
        let text = input
            .get("input")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable("input".into()))?;
        Ok(GenerateResult::from_text((self.f)(text))
            .with_tokens(TokenUsage::new(self.tokens, self.tokens).with_cache_read_tokens(1))
            .with_finish_reason(FinishReason::Stop))
    }

    fn input_keys(&self) -> Vec<String> {
        vec!["input".into()]
    }
}

fn upper(s: &str) -> String {
    s.to_uppercase()
}

fn lower(s: &str) -> String {
    s.to_lowercase()
}

#[tokio::test]
async fn fan_outs_meet_the_chain_contract() {
    let one = ParallelChain::new().branch(Map::new(upper, 1), "upper");
    check_chain(&one, &prompt_args! { "input" => "hello" })
        .await
        .unwrap();
    let two = ParallelChain::new()
        .branch(Map::new(upper, 1), "upper")
        .branch(Map::new(lower, 2), "lower")
        .max_concurrency(1);
    assert_eq!(two.primary_output_key(), "lower");
    check_chain(&two, &prompt_args! { "input" => "MiXeD" })
        .await
        .unwrap();
    check_chain(&ParallelChain::new(), &prompt_args! {})
        .await
        .unwrap();
}

#[tokio::test]
async fn rejects_input_a_branch_rejects() {
    let par = ParallelChain::new()
        .branch(Map::new(upper, 1), "upper")
        .branch(Map::new(lower, 1), "lower");
    check_chain_rejects(&par, &prompt_args! { "other" => "x" })
        .await
        .unwrap();
}

#[tokio::test]
async fn every_branch_runs_once_and_usage_is_summed() {
    let a = Map::new(upper, 3);
    let b = Map::new(lower, 5);
    let (ca, cb) = (Arc::clone(&a.calls), Arc::clone(&b.calls));
    let par = ParallelChain::new().branch(a, "upper").branch(b, "lower");

    let out = par
        .execute(prompt_args! { "input" => "MiXeD" })
        .await
        .unwrap();
    assert_eq!(out["upper"], "MIXED");
    assert_eq!(out["lower"], "mixed");
    let result: GenerateResult = serde_json::from_value(out["generate_result"].clone()).unwrap();
    let usage = result.tokens.unwrap();
    assert_eq!(
        (
            usage.prompt_tokens,
            usage.total_tokens,
            usage.cache_read_tokens
        ),
        (8, 16, 2)
    );
    assert_eq!(
        (ca.load(Ordering::SeqCst), cb.load(Ordering::SeqCst)),
        (1, 1)
    );

    // `call` returns the last branch's result with the summed usage.
    let r = par.call(prompt_args! { "input" => "MiXeD" }).await.unwrap();
    assert_eq!(r.generation, "mixed");
    assert_eq!(r.tokens.unwrap().completion_tokens, 8);
    assert_eq!(r.finish_reason, Some(FinishReason::Stop));
}

#[tokio::test(start_paused = true)]
async fn outputs_follow_declaration_order_not_finish_order() {
    let par = ParallelChain::new()
        .branch(Map::new(upper, 1).after(Duration::from_millis(30)), "first")
        .branch(
            Map::new(lower, 1).after(Duration::from_millis(20)),
            "second",
        )
        .branch(Map::new(upper, 1).after(Duration::from_millis(10)), "third");
    let run = par.run(prompt_args! { "input" => "Ab" }).await.unwrap();
    let keys: Vec<&str> = run.branches.iter().map(|b| b.output_key.as_str()).collect();
    assert_eq!(keys, ["first", "second", "third"]);
    let elapsed: Vec<u128> = run.branches.iter().map(|b| b.elapsed.as_millis()).collect();
    assert_eq!(elapsed, [30, 20, 10]);
    assert_eq!(
        par.invoke(prompt_args! { "input" => "Ab" }).await.unwrap(),
        "AB",
        "the last declared branch is the answer even though it finished first"
    );
}

#[tokio::test(start_paused = true)]
async fn concurrency_is_bounded() {
    let gauge = Arc::new(Gauge::default());
    let mut par = ParallelChain::new().max_concurrency(2);
    for i in 0..6 {
        par = par.branch(
            Map::new(upper, 1)
                .after(Duration::from_millis(100))
                .gauged(&gauge),
            format!("b{i}"),
        );
    }
    let started = Instant::now();
    let run = par.run(prompt_args! { "input" => "x" }).await.unwrap();
    assert!(run.is_success());
    assert_eq!(gauge.peak.load(Ordering::SeqCst), 2);
    assert_eq!(started.elapsed(), Duration::from_millis(300));
    // Waiting for a slot does not count towards a branch's time.
    assert!(
        run.branches
            .iter()
            .all(|b| b.elapsed == Duration::from_millis(100))
    );
}

#[tokio::test(start_paused = true)]
async fn a_shared_semaphore_bounds_several_chains() {
    let gauge = Arc::new(Gauge::default());
    let permits = Arc::new(Semaphore::new(1));
    let make = || {
        ParallelChain::new()
            .with_semaphore(Arc::clone(&permits))
            .branch(
                Map::new(upper, 1)
                    .after(Duration::from_millis(10))
                    .gauged(&gauge),
                "a",
            )
            .branch(
                Map::new(upper, 1)
                    .after(Duration::from_millis(10))
                    .gauged(&gauge),
                "b",
            )
    };
    let (x, y) = (make(), make());
    let (rx, ry) = tokio::join!(
        x.call(prompt_args! { "input" => "q" }),
        y.call(prompt_args! { "input" => "q" })
    );
    assert!(rx.is_ok() && ry.is_ok());
    assert_eq!(gauge.peak.load(Ordering::SeqCst), 1);

    permits.close();
    let err = make()
        .call(prompt_args! { "input" => "q" })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("closed"));
}

#[tokio::test(start_paused = true)]
async fn fail_fast_cancels_the_branches_still_running() {
    let slow = Map::new(upper, 1).after(Duration::from_secs(10));
    let cancelled = Arc::clone(&slow.cancelled);
    let par = ParallelChain::new().branch(slow, "slow").branch(
        Map::new(upper, 1)
            .after(Duration::from_millis(10))
            .failing(),
        "boom",
    );
    let started = Instant::now();
    let err = par
        .execute(prompt_args! { "input" => "x" })
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "branch failed");
    assert_eq!(started.elapsed(), Duration::from_millis(10));
    assert!(
        cancelled.load(Ordering::SeqCst),
        "the slow branch was not cancelled"
    );
}

#[tokio::test(start_paused = true)]
async fn collect_all_lets_every_branch_finish() {
    let slow = Map::new(upper, 2).after(Duration::from_secs(1));
    let cancelled = Arc::clone(&slow.cancelled);
    let par = ParallelChain::new()
        .branch(slow, "slow")
        .branch(Map::new(upper, 1).failing(), "boom")
        .error_mode(ErrorMode::CollectAll);
    let run = par.run(prompt_args! { "input" => "x" }).await.unwrap();
    assert!(!cancelled.load(Ordering::SeqCst));
    assert!(!run.is_success());
    assert_eq!(run.outputs()["slow"], "X");
    assert_eq!(run.usage().unwrap().total_tokens, 4);
    let errors: Vec<(&str, String)> = run.errors().map(|(k, e)| (k, e.to_string())).collect();
    assert_eq!(errors, [("boom", "branch failed".to_string())]);

    // Through the `Chain` trait a single failure comes back unchanged...
    let err = par.call(prompt_args! { "input" => "x" }).await.unwrap_err();
    assert_eq!(err.to_string(), "branch failed");

    // ...and several are summarised.
    let par = ParallelChain::new()
        .branch(Map::new(upper, 1).failing(), "a")
        .branch(Map::new(upper, 1), "ok")
        .branch(Map::new(upper, 1).failing(), "c")
        .error_mode(ErrorMode::CollectAll);
    let err = par.call(prompt_args! { "input" => "x" }).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "2 of 3 branches failed: `a`: branch failed; `c`: branch failed"
    );
}

#[tokio::test(start_paused = true)]
async fn branch_timeouts() {
    let par = ParallelChain::new()
        .branch_timeout(Duration::from_millis(50))
        .branch(Map::new(upper, 1).after(Duration::from_millis(10)), "fast")
        .with_branch(
            Branch::new(
                Map::new(upper, 1).after(Duration::from_millis(200)),
                "patient",
            )
            .timeout(Duration::from_secs(1)),
        )
        .branch(Map::new(upper, 1).after(Duration::from_millis(100)), "slow")
        .error_mode(ErrorMode::CollectAll);
    let run = par.run(prompt_args! { "input" => "x" }).await.unwrap();
    let ok: Vec<bool> = run.branches.iter().map(|b| b.result.is_ok()).collect();
    assert_eq!(ok, [true, true, false]);
    match &run.branches[2].result {
        Err(ChainError::LlmError(e)) => {
            assert_eq!(e.kind(), LlmErrorKind::Timeout);
            assert!(e.message().contains("`slow`"));
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
    assert_eq!(run.branches[2].elapsed, Duration::from_millis(50));
}

#[tokio::test]
async fn duplicate_or_reserved_keys_are_rejected() {
    let dup = ParallelChain::new()
        .branch(Map::new(upper, 1), "a")
        .branch(Map::new(lower, 1), "a");
    assert!(dup.validate().is_err());
    assert!(dup.call(prompt_args! { "input" => "x" }).await.is_err());
    let reserved = ParallelChain::new().branch(Map::new(upper, 1), "generate_result");
    assert!(reserved.validate().is_err());
    let empty = ParallelChain::new().branch(Map::new(upper, 1), "");
    assert!(empty.validate().is_err());
}

#[tokio::test]
async fn input_keys_are_the_union_of_all_branches() {
    struct Reads(&'static str);
    #[async_trait]
    impl Chain for Reads {
        async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
            Ok(GenerateResult::from_text(self.0))
        }
        fn input_keys(&self) -> Vec<String> {
            vec![self.0.into(), "shared".into()]
        }
    }
    let par = ParallelChain::new()
        .branch(Reads("a"), "x")
        .branch(Reads("b"), "y");
    assert_eq!(par.input_keys(), ["a", "shared", "b"]);
    assert_eq!(ParallelChain::default().input_keys(), Vec::<String>::new());
    assert!(format!("{par:?}").contains("ParallelChain"));
}

#[tokio::test]
async fn usage_is_absent_when_no_branch_reports_it() {
    struct Plain;
    #[async_trait]
    impl Chain for Plain {
        async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
            Ok(GenerateResult::from_text("p"))
        }
    }
    let par = ParallelChain::new().branch(Plain, "a").branch(Plain, "b");
    assert!(par.call(prompt_args! {}).await.unwrap().tokens.is_none());
}
