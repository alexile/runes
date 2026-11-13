use std::sync::Arc;

use async_trait::async_trait;
use rune_chain_core::{
    Chain, ChainError, GenerateResult, Llm, LlmError, Message, PromptArgs, TokenUsage, ToolCall,
    ToolChoice,
};
use tokio::time::Instant;

use crate::builder::toolbox_builder;
use crate::event::{AgentEvent, StopReason};
use crate::runner::{CallStyle, ToolInvocation, Toolbox};

const DEFAULT_SYSTEM_PROMPT: &str =
    "You are a helpful assistant. Use the provided tools when needed to answer questions.";

/// The outcome of a function-calling agent run.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FunctionAgentResult {
    /// The model's final text answer (or its last text when the run stopped
    /// early; see [`stop_reason`](Self::stop_reason)).
    pub output: String,
    /// Number of tool-call rounds completed.
    pub iterations: usize,
    /// Every tool call of the run, in order, with its status and the output
    /// the model saw.
    pub tool_invocations: Vec<ToolInvocation>,
    /// Token usage summed over every LLM call of the run, or `None` when the
    /// LLM never reported usage.
    pub tokens: Option<TokenUsage>,
    /// Why the run ended.
    pub stop_reason: StopReason,
}

/// A structured function-calling agent that uses native LLM tool-calling APIs.
///
/// Unlike [`AgentExecutor`](crate::AgentExecutor) which relies on text-based
/// `ReAct` parsing, `FunctionCallingAgent` uses
/// [`Llm::generate_with_tools`] and
/// the provider's JSON function-calling protocol. This is more reliable,
/// especially with weaker models, because the LLM returns structured JSON tool
/// calls rather than freeform text.
///
/// # How it works
///
/// 1. Converts registered tools into [`FunctionDefinition`](rune_chain_core::FunctionDefinition)s via
///    [`Tool::function_definition`](rune_chain_core::Tool::function_definition).
/// 2. Calls `llm.generate_with_tools(messages, &defs, tool_choice)`.
/// 3. If the result has `tool_calls`, checks each one (known tool, arguments
///    valid against the tool's schema via [`ToolCall::validate`](rune_chain_core::ToolCall::validate), approval
///    where required), runs up to [`AgentLimits::max_concurrency`](crate::AgentLimits::max_concurrency) of them at
///    once with a per-call timeout, and appends the AI turn plus one fenced,
///    size-capped `Tool` result turn per call, in call order. Then repeats.
/// 4. Once the model returns a text answer with no tool calls, returns it.
///
/// Problems with a call (unknown tool, invalid arguments, tool error, timeout,
/// panic, denial) are reported to the model as that call's result rather
/// than ending the run, unless [`ToolErrorMode::Abort`](crate::ToolErrorMode::Abort) is set.
///
/// # Example
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use rune_chain_core::{Llm, Tool, ToolError};
/// use rune_chain_agent::FunctionCallingAgent;
/// use async_trait::async_trait;
///
/// struct UpperCase;
///
/// #[async_trait]
/// impl Tool for UpperCase {
///     fn name(&self) -> &str { "upper_case" }
///     fn description(&self) -> &str { "Converts text to upper case." }
///     async fn run(&self, input: &str) -> Result<String, ToolError> {
///         // input comes as JSON: {"input": "..."}
///         let v: serde_json::Value = serde_json::from_str(input)
///             .unwrap_or(serde_json::json!({"input": input}));
///         let text = v["input"].as_str().unwrap_or(input);
///         Ok(text.to_uppercase())
///     }
/// }
///
/// # async fn run() -> Result<(), rune_chain_core::ChainError> {
/// # let llm: Arc<dyn Llm> = unimplemented!();
/// let agent = FunctionCallingAgent::new(llm).tool(UpperCase);
/// let result = agent.run("Convert 'hello' to upper case.").await?;
/// println!("{}", result.output);
/// # Ok(())
/// # }
/// ```
pub struct FunctionCallingAgent {
    llm: Arc<dyn Llm>,
    toolbox: Toolbox,
    system_prompt: Option<String>,
    tool_choice: Option<ToolChoice>,
}

impl FunctionCallingAgent {
    /// Create a new agent backed by the given LLM, with default
    /// [`AgentLimits`](crate::AgentLimits).
    pub fn new(llm: Arc<dyn Llm>) -> Self {
        Self {
            llm,
            toolbox: Toolbox::default(),
            system_prompt: None,
            tool_choice: None,
        }
    }

    toolbox_builder!();

    /// Override the system prompt. The untrusted-output notice is still
    /// appended while [`fence_tool_outputs`](Self::fence_tool_outputs) is on.
    #[must_use]
    pub fn system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }

    /// Set the tool choice strategy (default: provider default, usually `Auto`).
    #[must_use]
    pub fn tool_choice(mut self, choice: ToolChoice) -> Self {
        self.tool_choice = Some(choice);
        self
    }

    /// Run the function-calling loop and return a [`FunctionAgentResult`].
    ///
    /// # Errors
    ///
    /// LLM failures (including a reply with neither text nor tool calls), an
    /// invalid tool set (bad or duplicate names), and tool failures under
    /// [`ToolErrorMode::Abort`](crate::ToolErrorMode::Abort). Hitting a limit is not an
    /// error: it shows up in [`FunctionAgentResult::stop_reason`].
    pub async fn run(&self, input: &str) -> Result<FunctionAgentResult, ChainError> {
        let tb = &self.toolbox;
        tb.check()?;
        let tool_defs = tb.definitions();
        let system = tb.system_prompt(
            self.system_prompt
                .clone()
                .unwrap_or_else(|| DEFAULT_SYSTEM_PROMPT.to_owned()),
        );
        let deadline = tb.deadline();

        let mut messages = vec![Message::system(system), Message::human(input)];
        let mut out = FunctionAgentResult {
            output: String::new(),
            iterations: 0,
            tool_invocations: Vec::new(),
            tokens: None,
            stop_reason: StopReason::FinalAnswer,
        };

        loop {
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(self.stop(out, StopReason::WallTime));
            }
            tb.emit(&AgentEvent::StepStarted {
                iteration: out.iterations,
            });
            let call =
                self.llm
                    .generate_with_tools(&messages, &tool_defs, self.tool_choice.clone());
            let result = match deadline {
                Some(d) => match tokio::time::timeout_at(d, call).await {
                    Ok(r) => r?,
                    Err(_) => return Ok(self.stop(out, StopReason::WallTime)),
                },
                None => call.await?,
            };
            TokenUsage::accumulate(&mut out.tokens, result.tokens.as_ref());
            out.output.clone_from(&result.generation);

            if !result.wants_tool_calls() {
                if result.generation.trim().is_empty() {
                    return Err(ChainError::LlmError(LlmError::invalid_response(
                        "the model returned an empty reply and no tool calls",
                    )));
                }
                tb.emit(&AgentEvent::FinalAnswer {
                    output: out.output.clone(),
                });
                return Ok(out);
            }

            if out.iterations >= tb.limits.max_iterations {
                return Ok(self.stop(out, StopReason::MaxIterations));
            }
            out.iterations += 1;

            let calls: Vec<ToolCall> = result.tool_calls;
            messages.push(Message::ai_with_tool_calls(
                &result.generation,
                calls.clone(),
            ));
            let invocations = tb
                .execute(&calls, CallStyle::Json, out.iterations, deadline)
                .await?;
            for inv in &invocations {
                messages.push(Message::tool_result(&inv.call_id, tb.render(inv)));
            }
            out.tool_invocations.extend(invocations);
        }
    }

    fn stop(&self, mut out: FunctionAgentResult, reason: StopReason) -> FunctionAgentResult {
        self.toolbox.emit(&AgentEvent::Stopped { reason });
        out.stop_reason = reason;
        out
    }
}

#[async_trait]
impl Chain for FunctionCallingAgent {
    /// Runs the agent on the `"input"` key. Unlike [`run`](FunctionCallingAgent::run),
    /// a run that stops on a limit is an error here, so a chain never passes
    /// on a half-finished answer.
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError> {
        let input = input_variables
            .get("input")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable("input".to_string()))?;

        let result = self.run(input).await?;
        if result.stop_reason != StopReason::FinalAnswer {
            return Err(ChainError::Other(format!(
                "agent stopped without a final answer: {}",
                result.stop_reason
            )));
        }
        Ok(GenerateResult::from_text(result.output).with_tokens(result.tokens))
    }

    fn input_keys(&self) -> Vec<String> {
        vec!["input".to_string()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_chain_core::{FunctionDefinition, LlmError, Tool, ToolCall, ToolError};
    use std::sync::Mutex;

    struct EchoTool;

    #[async_trait]
    impl Tool for EchoTool {
        fn name(&self) -> &'static str {
            "echo"
        }
        fn description(&self) -> &'static str {
            "Returns its input."
        }
        async fn run(&self, input: &str) -> Result<String, ToolError> {
            Ok(input.to_string())
        }
    }

    struct ToolCallLlm {
        call_count: Mutex<usize>,
    }

    #[async_trait]
    impl Llm for ToolCallLlm {
        async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
            Ok(GenerateResult::from_text(""))
        }

        async fn generate_with_tools(
            &self,
            _messages: &[Message],
            _tools: &[FunctionDefinition],
            _tool_choice: Option<ToolChoice>,
        ) -> Result<GenerateResult, LlmError> {
            let mut count = self.call_count.lock().unwrap();
            *count += 1;
            if *count == 1 {
                Ok(
                    GenerateResult::from_text(String::new()).with_tool_calls(vec![ToolCall::new(
                        "call_1",
                        "echo",
                        r#"{"input": "hello"}"#,
                    )]),
                )
            } else {
                Ok(GenerateResult::from_text("The echo returned: hello"))
            }
        }
    }

    #[tokio::test]
    async fn function_agent_calls_tool_and_returns_answer() {
        let llm = Arc::new(ToolCallLlm {
            call_count: Mutex::new(0),
        });
        let agent = FunctionCallingAgent::new(llm).tool(EchoTool);
        let result = agent.run("Echo 'hello'.").await.unwrap();

        assert_eq!(result.output, "The echo returned: hello");
        assert_eq!(result.iterations, 1);
        assert_eq!(result.tool_invocations.len(), 1);
        assert_eq!(result.tool_invocations[0].name, "echo");
    }

    #[tokio::test]
    async fn function_agent_handles_missing_input_key() {
        use rune_chain_core::prompt_args;

        let llm = Arc::new(ToolCallLlm {
            call_count: Mutex::new(0),
        });
        let agent = FunctionCallingAgent::new(llm);
        let err = agent.call(prompt_args! {}).await.unwrap_err();
        assert!(matches!(err, ChainError::MissingVariable(_)));
    }
}
