//! `AutonomousAgent` against the shared `Chain` contract, driven by an LLM
//! that answers by role (planner, worker, evaluator) so every run agrees.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::sync::Arc;

use async_trait::async_trait;
use rune_chain_autonomous::{AutonomousAgent, RunStatus};
use rune_chain_core::testing::{check_chain, check_chain_rejects};
use rune_chain_core::{Chain, GenerateResult, Llm, LlmError, Message, Role, prompt_args};

struct RoleLlm;

#[async_trait]
impl Llm for RoleLlm {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        let system = messages
            .iter()
            .find(|m| m.role == Role::System)
            .map(|m| m.content.text_content())
            .unwrap_or_default();
        let reply = if system.contains("planning") {
            "1. Gather facts\n2. Write summary"
        } else if system.contains("evaluator") {
            "STATUS: DONE\nANSWER: Summary written."
        } else {
            "step finished"
        };
        Ok(GenerateResult::from_text(reply))
    }
}

struct Down;

#[async_trait]
impl Llm for Down {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Err(LlmError::provider("overloaded"))
    }
}

#[tokio::test]
async fn meets_the_chain_contract() {
    let agent = AutonomousAgent::new(Arc::new(RoleLlm)).max_steps(5);
    check_chain(&agent, &prompt_args! { "input" => "Summarise the report" })
        .await
        .unwrap();
    assert_eq!(
        agent
            .invoke(prompt_args! { "input" => "goal" })
            .await
            .unwrap(),
        "Summary written."
    );
}

#[tokio::test]
async fn rejects_missing_goal_and_llm_failure() {
    let agent = AutonomousAgent::new(Arc::new(RoleLlm));
    check_chain_rejects(&agent, &prompt_args! { "goal" => "x" })
        .await
        .unwrap();

    check_chain_rejects(
        &AutonomousAgent::new(Arc::new(Down)),
        &prompt_args! { "input" => "x" },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn step_budget_bounds_the_run() {
    let agent = AutonomousAgent::new(Arc::new(RoleLlm)).max_steps(1);
    let result = agent.run("goal").await.unwrap();
    assert_ne!(result.status, RunStatus::Completed);
    assert_eq!(result.history.len(), 1);
}

/// `RoleLlm` that reports 2 prompt + 1 completion tokens per call.
struct MeteredRoleLlm;

#[async_trait]
impl Llm for MeteredRoleLlm {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        let mut r = RoleLlm.generate(messages).await?;
        r.tokens = Some(rune_chain_core::TokenUsage::new(2, 1));
        Ok(r)
    }
}

#[tokio::test]
async fn reports_usage_summed_over_plan_execute_and_reflect() {
    // Regression: `call` used to drop usage via `GenerateResult::from_text`.
    // One plan + two tasks + one reflection = four LLM calls.
    let agent = AutonomousAgent::new(Arc::new(MeteredRoleLlm)).max_steps(5);
    let run = agent.run("goal").await.unwrap();
    assert_eq!(run.status, RunStatus::Completed);
    assert_eq!(run.tokens.as_ref().unwrap().total_tokens, 12);
    let r = agent
        .call(prompt_args! { "input" => "goal" })
        .await
        .unwrap();
    let usage = r.tokens.unwrap();
    assert_eq!(
        (
            usage.prompt_tokens,
            usage.completion_tokens,
            usage.total_tokens
        ),
        (8, 4, 12)
    );
    check_chain(&agent, &prompt_args! { "input" => "goal" })
        .await
        .unwrap();
    let plain = AutonomousAgent::new(Arc::new(RoleLlm)).max_steps(5);
    assert!(plain.run("goal").await.unwrap().tokens.is_none());
}
