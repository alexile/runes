//! `ParallelChain` against the shared `Chain` contract, plus fan-out
//! behaviour: every branch sees the same input, errors propagate, and token
//! usage is summed.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use rune_chain_core::testing::{check_chain, check_chain_rejects};
use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, TokenUsage, prompt_args};
use rune_chain_parallel::ParallelChain;

/// Transforms `input` with `f`, reports `tokens` usage, and counts calls.
struct Map {
    f: fn(&str) -> String,
    tokens: u32,
    calls: Arc<AtomicUsize>,
}

impl Map {
    fn new(f: fn(&str) -> String, tokens: u32) -> Self {
        Self {
            f,
            tokens,
            calls: Arc::default(),
        }
    }
}

#[async_trait]
impl Chain for Map {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let text = input
            .get("input")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable("input".into()))?;
        let mut r = GenerateResult::from_text((self.f)(text));
        r.tokens =
            Some(TokenUsage::new(self.tokens, self.tokens).with_total_tokens(self.tokens * 2));
        Ok(r)
    }

    fn input_keys(&self) -> Vec<String> {
        vec!["input".into()]
    }
}

struct Fail;

#[async_trait]
impl Chain for Fail {
    async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
        Err(ChainError::Other("branch failed".into()))
    }
}

#[tokio::test]
async fn single_branch_meets_the_chain_contract() {
    let par = ParallelChain::new().branch(Map::new(str::to_uppercase, 1), "upper");
    check_chain(&par, &prompt_args! { "input" => "hello" })
        .await
        .unwrap();
}

#[tokio::test]
async fn rejects_input_a_branch_rejects() {
    let par = ParallelChain::new()
        .branch(Map::new(str::to_uppercase, 1), "upper")
        .branch(Map::new(str::to_lowercase, 1), "lower");
    check_chain_rejects(&par, &prompt_args! { "other" => "x" })
        .await
        .unwrap();
}

#[tokio::test]
async fn one_failing_branch_fails_the_whole_chain() {
    let par = ParallelChain::new()
        .branch(Map::new(str::to_uppercase, 1), "upper")
        .branch(Fail, "boom");
    let err = par
        .execute(prompt_args! { "input" => "x" })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("branch failed"));
}

#[tokio::test]
async fn every_branch_runs_once_and_usage_is_summed() {
    let a = Map::new(str::to_uppercase, 3);
    let b = Map::new(str::to_lowercase, 5);
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
    assert_eq!((usage.prompt_tokens, usage.total_tokens), (8, 16));
    assert_eq!(
        (ca.load(Ordering::SeqCst), cb.load(Ordering::SeqCst)),
        (1, 1)
    );

    // `call` returns the last branch's generation and the summed usage.
    let r = par.call(prompt_args! { "input" => "MiXeD" }).await.unwrap();
    assert_eq!(r.generation, "mixed");
    assert_eq!(r.tokens.unwrap().completion_tokens, 8);
}

#[tokio::test]
async fn input_keys_come_from_the_first_branch() {
    let par = ParallelChain::new().branch(Map::new(str::to_uppercase, 1), "u");
    assert_eq!(par.input_keys(), ["input"]);
    assert_eq!(ParallelChain::default().input_keys(), Vec::<String>::new());
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

#[tokio::test]
async fn multi_branch_fan_out_meets_the_chain_contract() {
    // Regression: `check_chain` used to look for the answer under the *first*
    // branch key, while `call` returns the last branch's generation.
    let par = ParallelChain::new()
        .branch(Map::new(str::to_uppercase, 1), "upper")
        .branch(Map::new(str::to_lowercase, 2), "lower");
    assert_eq!(par.primary_output_key(), "lower");
    check_chain(&par, &prompt_args! { "input" => "MiXeD" })
        .await
        .unwrap();
}

#[tokio::test]
async fn empty_fan_out_meets_the_chain_contract() {
    check_chain(&ParallelChain::new(), &prompt_args! {})
        .await
        .unwrap();
}
