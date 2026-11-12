//! Both agents against the shared `Chain` contract, driven by deterministic
//! scripted LLMs that call one tool and then answer.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::sync::Arc;

use async_trait::async_trait;
use rune_chain_agent::{AgentExecutor, FunctionCallingAgent};
use rune_chain_core::testing::{check_chain, check_chain_rejects, check_tool};
use rune_chain_core::{
    Chain, FunctionDefinition, GenerateResult, Llm, LlmError, Message, Role, Tool, ToolCall,
    ToolChoice, ToolError, prompt_args,
};

struct Upper;

#[async_trait]
impl Tool for Upper {
    fn name(&self) -> &'static str {
        "upper"
    }
    fn description(&self) -> &'static str {
        "Upper-cases its input."
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        Ok(input.to_uppercase())
    }
}

/// `ReAct` script: act once, then answer with the last observation. The
/// reply depends only on the conversation, so repeated runs agree.
struct ReactLlm;

#[async_trait]
impl Llm for ReactLlm {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        let observation = messages
            .iter()
            .filter(|m| m.role == Role::Ai)
            .find_map(|m| {
                // The fenced tool output sits on the line after `Observation:`.
                let text = m.content.text_content();
                let mut lines = text.lines().skip_while(|l| !l.starts_with("Observation: "));
                lines.next()?;
                lines.next().map(str::to_owned)
            });
        let reply = observation.map_or_else(
            || "Thought: shout it\nAction: upper\nAction Input: hello".to_owned(),
            |o| format!("Thought: done\nFinal Answer: {o}"),
        );
        Ok(GenerateResult::from_text(reply))
    }
}

/// Native tool-calling script: call `upper` once, then answer with its result.
struct ToolLlm;

#[async_trait]
impl Llm for ToolLlm {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text("no tools"))
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        _: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        assert_eq!(tools.len(), 1);
        if let Some(result) = messages.iter().find(|m| m.role == Role::Tool) {
            let fenced = result.content.text_content();
            let inner = fenced.lines().nth(1).unwrap_or_default().to_owned();
            return Ok(GenerateResult::from_text(inner));
        }
        Ok(
            GenerateResult::from_text(String::new()).with_tool_calls(vec![ToolCall::new(
                "call_1",
                "upper",
                r#"{"input":"hello"}"#,
            )]),
        )
    }
}

struct Down;

#[async_trait]
impl Llm for Down {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Err(LlmError::request_failed("down"))
    }
}

#[tokio::test]
async fn react_agent_meets_the_chain_contract() {
    let agent = AgentExecutor::new(Arc::new(ReactLlm)).tool(Upper);
    check_chain(&agent, &prompt_args! { "input" => "shout hello" })
        .await
        .unwrap();
    assert_eq!(
        agent.invoke(prompt_args! { "input" => "x" }).await.unwrap(),
        "HELLO"
    );
    check_chain_rejects(&agent, &prompt_args! { "question" => "x" })
        .await
        .unwrap();
}

#[tokio::test]
async fn function_calling_agent_meets_the_chain_contract() {
    let agent = FunctionCallingAgent::new(Arc::new(ToolLlm)).tool(Upper);
    check_chain(&agent, &prompt_args! { "input" => "shout hello" })
        .await
        .unwrap();
    assert_eq!(
        agent.invoke(prompt_args! { "input" => "x" }).await.unwrap(),
        // `upper` receives the raw JSON arguments.
        r#"{"INPUT":"HELLO"}"#
    );
    check_chain_rejects(&agent, &prompt_args! {}).await.unwrap();
}

#[tokio::test]
async fn agents_surface_llm_failures() {
    let react = AgentExecutor::new(Arc::new(Down));
    check_chain_rejects(&react, &prompt_args! { "input" => "x" })
        .await
        .unwrap();
    // `Down` keeps the default `generate_with_tools`, which is unsupported.
    let fc = FunctionCallingAgent::new(Arc::new(Down)).tool(Upper);
    check_chain_rejects(&fc, &prompt_args! { "input" => "x" })
        .await
        .unwrap();
}

#[tokio::test]
async fn test_tool_meets_the_tool_contract() {
    check_tool(&Upper, "hi").await.unwrap();
}

/// Wraps a scripted LLM and reports 2 prompt + 1 completion tokens per call.
struct Metered<L>(L);

const fn unit_usage() -> rune_chain_core::TokenUsage {
    rune_chain_core::TokenUsage::new(2, 1)
}

#[async_trait]
impl<L: Llm> Llm for Metered<L> {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        let mut r = self.0.generate(messages).await?;
        r.tokens = Some(unit_usage());
        Ok(r)
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        let mut r = self.0.generate_with_tools(messages, tools, choice).await?;
        r.tokens = Some(unit_usage());
        Ok(r)
    }
}

#[tokio::test]
async fn react_agent_reports_usage_summed_over_llm_calls() {
    // Regression: `call` used to drop usage via `GenerateResult::from_text`.
    let agent = AgentExecutor::new(Arc::new(Metered(ReactLlm))).tool(Upper);
    let run = agent.run("shout hello").await.unwrap();
    assert_eq!(
        run.tokens.as_ref().unwrap().total_tokens,
        6,
        "two LLM calls"
    );
    let r = agent.call(prompt_args! { "input" => "x" }).await.unwrap();
    let usage = r.tokens.unwrap();
    assert_eq!(
        (
            usage.prompt_tokens,
            usage.completion_tokens,
            usage.total_tokens
        ),
        (4, 2, 6)
    );
    check_chain(&agent, &prompt_args! { "input" => "x" })
        .await
        .unwrap();
    // No reported usage stays `None`, not zero.
    let plain = AgentExecutor::new(Arc::new(ReactLlm)).tool(Upper);
    assert!(
        plain
            .call(prompt_args! { "input" => "x" })
            .await
            .unwrap()
            .tokens
            .is_none()
    );
}

#[tokio::test]
async fn function_calling_agent_reports_usage_summed_over_llm_calls() {
    let agent = FunctionCallingAgent::new(Arc::new(Metered(ToolLlm))).tool(Upper);
    let run = agent.run("shout hello").await.unwrap();
    assert_eq!(
        run.tokens.as_ref().unwrap().total_tokens,
        6,
        "two LLM calls"
    );
    let r = agent.call(prompt_args! { "input" => "x" }).await.unwrap();
    assert_eq!(r.tokens.unwrap().prompt_tokens, 4);
    let plain = FunctionCallingAgent::new(Arc::new(ToolLlm)).tool(Upper);
    assert!(
        plain
            .call(prompt_args! { "input" => "x" })
            .await
            .unwrap()
            .tokens
            .is_none()
    );
}
