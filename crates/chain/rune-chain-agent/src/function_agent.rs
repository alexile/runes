use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use rune_chain_core::{
    Chain, ChainError, FunctionDefinition, GenerateResult, Llm, LlmError, Message, PromptArgs,
    StreamAccumulator, StreamEvent, TokenUsage, ToolCall, ToolChoice,
};
use tokio::time::Instant;

use crate::builder::toolbox_builder;
use crate::event::{AgentEvent, AgentStreamEvent, StopReason};
use crate::runner::{CallStyle, ToolInvocation, Toolbox};
use crate::sanitize::sanitize_name;

/// The stream returned by [`FunctionCallingAgent::run_stream`].
pub type AgentStream<'a> =
    Pin<Box<dyn Stream<Item = Result<AgentStreamEvent, ChainError>> + Send + 'a>>;

/// Opening history, tool definitions and the run's deadline.
type Setup = (Vec<Message>, Vec<FunctionDefinition>, Option<Instant>);

/// What one model reply means for the loop.
enum Turn {
    /// The model answered; the run is over.
    Final,
    /// The model wants tools but the iteration limit is reached.
    Limit,
    /// Run these calls (the AI turn is already in the history).
    Calls(Vec<ToolCall>),
}

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
        self.run_messages(vec![Message::human(input)]).await
    }

    /// Run the loop on a whole conversation instead of a single input.
    ///
    /// `conversation` holds the turns that follow the system prompt: earlier
    /// human and AI turns, then the new human turn. The agent puts its own
    /// system prompt in front, so leave system messages out. Use it for
    /// multi-turn chat or to add per-request context to the last turn.
    ///
    /// ```rust,no_run
    /// # use std::sync::Arc;
    /// # use rune_chain_core::{Llm, Message};
    /// # use rune_chain_agent::FunctionCallingAgent;
    /// # async fn run(llm: Arc<dyn Llm>) -> Result<(), rune_chain_core::ChainError> {
    /// let agent = FunctionCallingAgent::new(llm);
    /// let result = agent
    ///     .run_messages(vec![
    ///         Message::human("My name is Ada."),
    ///         Message::ai("Nice to meet you, Ada."),
    ///         Message::human("What is my name?"),
    ///     ])
    ///     .await?;
    /// println!("{}", result.output);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// As for [`run`](Self::run), plus an empty `conversation`.
    pub async fn run_messages(
        &self,
        conversation: Vec<Message>,
    ) -> Result<FunctionAgentResult, ChainError> {
        let (mut messages, tool_defs, deadline) = self.prepare(conversation)?;
        let tb = &self.toolbox;
        let mut out = new_result();

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
            let calls = match self.take_reply(&mut out, &mut messages, result)? {
                Turn::Final => return Ok(out),
                Turn::Limit => return Ok(self.stop(out, StopReason::MaxIterations)),
                Turn::Calls(calls) => calls,
            };
            let invocations = tb
                .execute(&calls, CallStyle::Json, out.iterations, deadline)
                .await?;
            for inv in &invocations {
                messages.push(Message::tool_result(&inv.call_id, tb.render(inv)));
            }
            out.tool_invocations.extend(invocations);
        }
    }

    /// Run the loop with streaming: like [`run_messages`](Self::run_messages),
    /// but every model call goes through
    /// [`Llm::stream_events`], and the run is reported as it happens.
    ///
    /// The stream yields text and reasoning deltas from every round,
    /// [`ToolCallStarted`](AgentStreamEvent::ToolCallStarted) as the model
    /// begins each call, [`ToolResult`](AgentStreamEvent::ToolResult) once a
    /// round's tools have run, and finally
    /// [`Done`](AgentStreamEvent::Done) with the same
    /// [`FunctionAgentResult`] `run_messages` returns. Tool calls are checked,
    /// approved and run exactly as there, under the same
    /// [`AgentLimits`](crate::AgentLimits); the wall-time budget also bounds
    /// reading each streamed reply. Observers get the usual
    /// [`AgentEvent`]s.
    ///
    /// Providers without native streaming tool calls still work: the
    /// default `stream_events` replays each reply whole.
    ///
    /// # Errors
    ///
    /// As for [`run_messages`](Self::run_messages), as the stream's last
    /// item; a stream error ends the run.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::sync::Arc;
    ///
    /// use futures::StreamExt;
    /// use rune_chain_agent::{AgentStreamEvent, FunctionCallingAgent};
    /// use rune_chain_core::testing::{FakeLlm, FakeReply};
    /// use rune_chain_core::{Message, Tool, ToolCall, ToolError};
    ///
    /// struct Clock;
    ///
    /// #[async_trait::async_trait]
    /// impl Tool for Clock {
    ///     fn name(&self) -> &str { "clock" }
    ///     fn description(&self) -> &str { "The time." }
    ///     async fn run(&self, _: &str) -> Result<String, ToolError> {
    ///         Ok("noon".into())
    ///     }
    /// }
    ///
    /// # tokio_test::block_on(async {
    /// let llm = FakeLlm::with_replies([
    ///     FakeReply::tool_calls([ToolCall::new("c1", "clock", r#"{"input":"now"}"#)]),
    ///     FakeReply::text("It is noon."),
    /// ]);
    /// let agent = FunctionCallingAgent::new(Arc::new(llm)).tool(Clock);
    /// let mut stream = agent.run_stream(vec![Message::human("Time?")]);
    /// let mut text = String::new();
    /// while let Some(event) = stream.next().await {
    ///     match event.unwrap() {
    ///         AgentStreamEvent::TextDelta(t) => text.push_str(&t),
    ///         AgentStreamEvent::Done(result) => assert_eq!(result.output, "It is noon."),
    ///         _ => {}
    ///     }
    /// }
    /// assert_eq!(text, "It is noon.");
    /// # });
    /// ```
    pub fn run_stream(&self, conversation: Vec<Message>) -> AgentStream<'_> {
        Box::pin(async_stream::stream! {
            let (mut messages, tool_defs, deadline) = match self.prepare(conversation) {
                Ok(setup) => setup,
                Err(e) => {
                    yield Err(e);
                    return;
                }
            };
            let tb = &self.toolbox;
            let mut out = new_result();
            loop {
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    yield Ok(AgentStreamEvent::Done(self.stop(out, StopReason::WallTime)));
                    return;
                }
                tb.emit(&AgentEvent::StepStarted {
                    iteration: out.iterations,
                });
                let open = self.llm.stream_events(
                    &messages,
                    Some(&tool_defs),
                    self.tool_choice.clone(),
                );
                let opened = match deadline {
                    Some(d) => tokio::time::timeout_at(d, open).await.ok(),
                    None => Some(open.await),
                };
                let mut events = match opened {
                    Some(Ok(events)) => events,
                    Some(Err(e)) => {
                        yield Err(e.into());
                        return;
                    }
                    None => {
                        yield Ok(AgentStreamEvent::Done(self.stop(out, StopReason::WallTime)));
                        return;
                    }
                };
                let round = out.iterations + 1;
                let mut acc = StreamAccumulator::new();
                loop {
                    let next = match deadline {
                        Some(d) => tokio::time::timeout_at(d, events.next()).await.ok(),
                        None => Some(events.next().await),
                    };
                    let Some(next) = next else {
                        yield Ok(AgentStreamEvent::Done(self.stop(out, StopReason::WallTime)));
                        return;
                    };
                    let event = match next {
                        None => break,
                        Some(Ok(event)) => event,
                        Some(Err(e)) => {
                            yield Err(e.into());
                            return;
                        }
                    };
                    if let Err(e) = acc.push(&event) {
                        yield Err(e.into());
                        return;
                    }
                    if let Some(item) = forward(event, round) {
                        yield Ok(item);
                    }
                }
                let calls = match self.take_reply(&mut out, &mut messages, acc.finish()) {
                    Ok(Turn::Final) => {
                        yield Ok(AgentStreamEvent::Done(out));
                        return;
                    }
                    Ok(Turn::Limit) => {
                        yield Ok(AgentStreamEvent::Done(
                            self.stop(out, StopReason::MaxIterations),
                        ));
                        return;
                    }
                    Ok(Turn::Calls(calls)) => calls,
                    Err(e) => {
                        yield Err(e);
                        return;
                    }
                };
                let invocations = match tb
                    .execute(&calls, CallStyle::Json, out.iterations, deadline)
                    .await
                {
                    Ok(invocations) => invocations,
                    Err(e) => {
                        yield Err(e);
                        return;
                    }
                };
                for inv in &invocations {
                    messages.push(Message::tool_result(&inv.call_id, tb.render(inv)));
                    yield Ok(AgentStreamEvent::ToolResult {
                        iteration: out.iterations,
                        invocation: inv.clone(),
                    });
                }
                out.tool_invocations.extend(invocations);
            }
        })
    }

    /// Check the tool set and build the opening history.
    fn prepare(&self, conversation: Vec<Message>) -> Result<Setup, ChainError> {
        if conversation.is_empty() {
            return Err(ChainError::Other("the conversation is empty".into()));
        }
        let tb = &self.toolbox;
        tb.check()?;
        let system = tb.system_prompt(
            self.system_prompt
                .clone()
                .unwrap_or_else(|| DEFAULT_SYSTEM_PROMPT.to_owned()),
        );
        let mut messages = Vec::with_capacity(conversation.len() + 1);
        messages.push(Message::system(system));
        messages.extend(conversation);
        Ok((messages, tb.definitions(), tb.deadline()))
    }

    /// Fold one model reply into the run.
    fn take_reply(
        &self,
        out: &mut FunctionAgentResult,
        messages: &mut Vec<Message>,
        result: GenerateResult,
    ) -> Result<Turn, ChainError> {
        let tb = &self.toolbox;
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
            return Ok(Turn::Final);
        }

        if out.iterations >= tb.limits.max_iterations {
            return Ok(Turn::Limit);
        }
        out.iterations += 1;
        messages.push(Message::ai_with_tool_calls(
            &result.generation,
            result.tool_calls.clone(),
        ));
        Ok(Turn::Calls(result.tool_calls))
    }

    fn stop(&self, mut out: FunctionAgentResult, reason: StopReason) -> FunctionAgentResult {
        self.toolbox.emit(&AgentEvent::Stopped { reason });
        out.stop_reason = reason;
        out
    }
}

const fn new_result() -> FunctionAgentResult {
    FunctionAgentResult {
        output: String::new(),
        iterations: 0,
        tool_invocations: Vec::new(),
        tokens: None,
        stop_reason: StopReason::FinalAnswer,
    }
}

/// The agent event for a model stream event, if the caller should see it.
fn forward(event: StreamEvent, round: usize) -> Option<AgentStreamEvent> {
    match event {
        StreamEvent::TextDelta(t) if !t.is_empty() => Some(AgentStreamEvent::TextDelta(t)),
        StreamEvent::ReasoningDelta { text, .. } if !text.is_empty() => {
            Some(AgentStreamEvent::ReasoningDelta(text))
        }
        StreamEvent::ToolCallStart { id, name, .. } => Some(AgentStreamEvent::ToolCallStarted {
            iteration: round,
            call_id: id,
            name: sanitize_name(&name),
        }),
        _ => None,
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
    use rune_chain_core::{FunctionDefinition, LlmError, Role, Tool, ToolCall, ToolError};
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

    struct Recorder(Mutex<Vec<Message>>);

    #[async_trait]
    impl Llm for Recorder {
        async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
            Ok(GenerateResult::from_text(""))
        }

        async fn generate_with_tools(
            &self,
            messages: &[Message],
            _tools: &[FunctionDefinition],
            _tool_choice: Option<ToolChoice>,
        ) -> Result<GenerateResult, LlmError> {
            *self.0.lock().unwrap() = messages.to_vec();
            Ok(GenerateResult::from_text("Ada"))
        }
    }

    #[tokio::test]
    async fn run_messages_keeps_history_after_the_system_prompt() {
        let llm = Arc::new(Recorder(Mutex::new(Vec::new())));
        let agent = FunctionCallingAgent::new(llm.clone())
            .system_prompt("Be brief.")
            .tool(EchoTool);
        let result = agent
            .run_messages(vec![
                Message::human("My name is Ada."),
                Message::ai("Hi Ada."),
                Message::human("What is my name?"),
            ])
            .await
            .unwrap();
        assert_eq!(result.output, "Ada");

        let seen = llm.0.lock().unwrap().clone();
        let roles: Vec<_> = seen.iter().map(|m| m.role.clone()).collect();
        assert_eq!(
            roles,
            [Role::System, Role::Human, Role::Ai, Role::Human],
            "system prompt first, then the conversation in order"
        );
        assert!(seen[0].text().starts_with("Be brief."));
        assert_eq!(seen[3].text(), "What is my name?");
    }

    #[tokio::test]
    async fn run_messages_rejects_an_empty_conversation() {
        let llm = Arc::new(Recorder(Mutex::new(Vec::new())));
        let agent = FunctionCallingAgent::new(llm.clone());
        assert!(agent.run_messages(Vec::new()).await.is_err());
        assert!(llm.0.lock().unwrap().is_empty(), "no model call");
    }
}
