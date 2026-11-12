//! `SequentialChain` against the shared `Chain` contract, plus pipeline
//! behaviour: outputs feed later steps, a failing step stops the run, and
//! token usage is summed.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use rune_chain_core::testing::{check_chain, check_chain_rejects};
use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, TokenUsage, prompt_args};
use rune_chain_sequential::SequentialChain;

/// Reads `from`, applies `f`, reports one prompt and one completion token.
struct Step {
    from: &'static str,
    f: fn(&str) -> String,
    calls: Arc<AtomicUsize>,
}

impl Step {
    fn new(from: &'static str, f: fn(&str) -> String) -> Self {
        Self {
            from,
            f,
            calls: Arc::default(),
        }
    }
}

#[async_trait]
impl Chain for Step {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let text = input
            .get(self.from)
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable(self.from.into()))?;
        let mut r = GenerateResult::from_text((self.f)(text));
        r.tokens = Some(TokenUsage::new(1, 1).with_total_tokens(2));
        Ok(r)
    }

    fn input_keys(&self) -> Vec<String> {
        vec![self.from.into()]
    }
}

fn exclaim(s: &str) -> String {
    format!("{s}!")
}

#[tokio::test]
async fn single_step_meets_the_chain_contract() {
    let seq = SequentialChain::new().chain(Step::new("input", str::to_uppercase), "upper");
    check_chain(&seq, &prompt_args! { "input" => "hi" })
        .await
        .unwrap();
}

#[tokio::test]
async fn rejects_input_the_first_step_rejects() {
    let seq = SequentialChain::new()
        .chain(Step::new("input", str::to_uppercase), "upper")
        .chain(Step::new("upper", exclaim), "loud");
    check_chain_rejects(&seq, &prompt_args! { "wrong" => "x" })
        .await
        .unwrap();
}

#[tokio::test]
async fn outputs_feed_later_steps_and_usage_is_summed() {
    let seq = SequentialChain::new()
        .chain(Step::new("input", str::to_uppercase), "upper")
        .chain(Step::new("upper", exclaim), "loud")
        // Earlier outputs and the original input stay visible downstream.
        .chain(Step::new("input", exclaim), "quiet");
    let out = seq.execute(prompt_args! { "input" => "hi" }).await.unwrap();
    assert_eq!(out["upper"], "HI");
    assert_eq!(out["loud"], "HI!");
    assert_eq!(out["quiet"], "hi!");

    let r = seq.call(prompt_args! { "input" => "hi" }).await.unwrap();
    assert_eq!(r.generation, "hi!", "call returns the last step's output");
    assert_eq!(r.tokens.unwrap().total_tokens, 6);
    assert_eq!(
        seq.invoke(prompt_args! { "input" => "hi" }).await.unwrap(),
        "hi!"
    );
}

#[tokio::test]
async fn a_failing_step_stops_the_pipeline() {
    let last = Step::new("upper", exclaim);
    let last_calls = Arc::clone(&last.calls);
    let seq = SequentialChain::new()
        .chain(Step::new("missing", str::to_uppercase), "upper")
        .chain(last, "loud");
    let err = seq
        .call(prompt_args! { "input" => "hi" })
        .await
        .unwrap_err();
    assert!(matches!(err, ChainError::MissingVariable(ref v) if v == "missing"));
    assert_eq!(last_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn input_keys_come_from_the_first_step() {
    let seq = SequentialChain::new()
        .chain(Step::new("question", str::to_uppercase), "a")
        .chain(Step::new("a", exclaim), "b");
    assert_eq!(seq.input_keys(), ["question"]);
    assert_eq!(
        SequentialChain::default().input_keys(),
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn multi_step_pipelines_meet_the_chain_contract() {
    // Regression: `check_chain` used to look for the answer under the *first*
    // output key, which a multi-step pipeline stores an intermediate under.
    let seq = SequentialChain::new()
        .chain(Step::new("input", str::to_uppercase), "upper")
        .chain(Step::new("upper", exclaim), "loud");
    assert_eq!(seq.primary_output_key(), "loud");
    check_chain(&seq, &prompt_args! { "input" => "hi" })
        .await
        .unwrap();
    let three = SequentialChain::new()
        .chain(Step::new("input", str::to_uppercase), "upper")
        .chain(Step::new("upper", exclaim), "loud")
        .chain(Step::new("input", exclaim), "quiet");
    check_chain(&three, &prompt_args! { "input" => "hi" })
        .await
        .unwrap();
}

#[tokio::test]
async fn empty_pipeline_meets_the_chain_contract() {
    let seq = SequentialChain::new();
    check_chain(&seq, &prompt_args! {}).await.unwrap();
    assert_eq!(seq.execute(prompt_args! {}).await.unwrap()["output"], "");
}
