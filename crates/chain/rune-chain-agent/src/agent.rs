use std::sync::Arc;

use async_trait::async_trait;
use rune_chain_core::{
    Chain, ChainError, GenerateResult, Llm, Message, PromptArgs, TokenUsage, Tool, ToolCall,
};
use tokio::time::Instant;

use crate::builder::toolbox_builder;
use crate::event::{AgentEvent, StopReason};
use crate::runner::{CallStyle, ToolInvocation, Toolbox};

const ACTION: &str = "Action";
const ACTION_INPUT: &str = "Action Input";
const FINAL_ANSWER: &str = "Final Answer";
const OBSERVATION: &str = "Observation";
const OBSERVATION_PREFIX: &str = "Observation:";
const FORMAT_HINT: &str = "Observation: could not parse your reply. Reply with either \
    `Action: <tool name>` followed by `Action Input: <input>`, or with `Final Answer: <answer>`.";

/// The outcome of a `ReAct` agent run.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AgentResult {
    /// The agent's final answer, or its last response when the run stopped
    /// early (see [`stop_reason`](Self::stop_reason)).
    pub output: String,
    /// Number of Thought/Action/Observation cycles completed.
    pub iterations: usize,
    /// Every model response and `Observation:` entry of the run (observations
    /// unfenced but size-capped).
    pub scratchpad: Vec<String>,
    /// Every tool call of the run, in order.
    pub tool_invocations: Vec<ToolInvocation>,
    /// Token usage summed over every LLM call of the run, or `None` when the
    /// LLM never reported usage.
    pub tokens: Option<TokenUsage>,
    /// Why the run ended.
    pub stop_reason: StopReason,
}

/// A `ReAct` (Reasoning + Acting) agent that loops between an LLM and a set of tools.
///
/// On each iteration the agent:
/// 1. Sends the accumulated conversation to the LLM.
/// 2. Cuts the response at any `Observation:` line the model invented, then
///    parses `Action:` / `Action Input:` to find a tool call. The markers are
///    matched case-insensitively and may carry markdown emphasis. A reply that
///    asks for an action never counts as final, even if it also contains a
///    `Final Answer:`, and a reply with neither gets a format reminder as its
///    observation.
/// 3. Checks the call (known tool, input valid for the tool's schema, approval
///    where required), runs it with a timeout and appends the size-capped,
///    fenced result as `Observation:`.
/// 4. Repeats until the LLM emits `Final Answer:` or a limit in
///    [`AgentLimits`](crate::AgentLimits) is reached.
///
/// For models that support native function calling, prefer [`FunctionCallingAgent`](crate::FunctionCallingAgent)
/// which is more reliable and doesn't depend on text-parsing heuristics.
pub struct AgentExecutor {
    llm: Arc<dyn Llm>,
    toolbox: Toolbox,
    system_prompt: Option<String>,
}

impl AgentExecutor {
    /// Create a new [`AgentExecutor`] backed by the given LLM, with default
    /// [`AgentLimits`](crate::AgentLimits).
    pub fn new(llm: Arc<dyn Llm>) -> Self {
        Self {
            llm,
            toolbox: Toolbox::default(),
            system_prompt: None,
        }
    }

    toolbox_builder!();

    /// Override the system prompt injected at the start of every agent run.
    /// The untrusted-output notice is still appended while
    /// [`fence_tool_outputs`](Self::fence_tool_outputs) is on.
    #[must_use]
    pub fn system_prompt(mut self, system_prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(system_prompt.into());
        self
    }

    /// Run the `ReAct` loop for the given `input` question.
    ///
    /// # Errors
    ///
    /// LLM failures, an invalid tool set (bad or duplicate names), and tool
    /// failures under [`ToolErrorMode::Abort`](crate::ToolErrorMode::Abort).
    /// Hitting a limit is not an error: see [`AgentResult::stop_reason`].
    pub async fn run(&self, input: &str) -> Result<AgentResult, ChainError> {
        let tb = &self.toolbox;
        tb.check()?;
        let tools: Vec<&dyn Tool> = tb.tools().collect();
        let system = tb.system_prompt(
            self.system_prompt
                .clone()
                .unwrap_or_else(|| build_system_prompt(&tools)),
        );
        let deadline = tb.deadline();

        let mut messages = vec![Message::system(system), Message::human(input)];
        let mut out = AgentResult {
            output: String::new(),
            iterations: 0,
            scratchpad: Vec::new(),
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
            let call = self.llm.generate(&messages);
            let result = match deadline {
                Some(d) => match tokio::time::timeout_at(d, call).await {
                    Ok(r) => r?,
                    Err(_) => return Ok(self.stop(out, StopReason::WallTime)),
                },
                None => call.await?,
            };
            TokenUsage::accumulate(&mut out.tokens, result.tokens.as_ref());
            let response = strip_invented_observation(result.generation.trim()).to_owned();
            out.output.clone_from(&response);
            out.scratchpad.push(response.clone());

            // An action wins over a final answer in the same reply: the model
            // cannot know the tool's result yet, so that answer is made up.
            let action = extract_action(&response);
            if action.is_none()
                && let Some(answer) = extract_final_answer(&response)
            {
                tb.emit(&AgentEvent::FinalAnswer {
                    output: answer.clone(),
                });
                out.output = answer;
                return Ok(out);
            }

            if out.iterations >= tb.limits.max_iterations {
                return Ok(self.stop(out, StopReason::MaxIterations));
            }
            out.iterations += 1;

            if let Some((tool_name, tool_input)) = action {
                let call =
                    ToolCall::new(format!("react_{}", out.iterations), tool_name, tool_input);
                let mut invocations = tb
                    .execute(
                        std::slice::from_ref(&call),
                        CallStyle::Text,
                        out.iterations,
                        deadline,
                    )
                    .await?;
                if let Some(inv) = invocations.pop() {
                    out.scratchpad
                        .push(format!("{OBSERVATION_PREFIX} {}", inv.output));
                    messages.push(Message::ai(format!(
                        "{response}\n{OBSERVATION_PREFIX} {}",
                        tb.render(&inv)
                    )));
                    out.tool_invocations.push(inv);
                }
            } else {
                out.scratchpad.push(FORMAT_HINT.to_owned());
                messages.push(Message::ai(format!("{response}\n{FORMAT_HINT}")));
            }
        }
    }

    fn stop(&self, mut out: AgentResult, reason: StopReason) -> AgentResult {
        self.toolbox.emit(&AgentEvent::Stopped { reason });
        out.stop_reason = reason;
        out
    }
}

#[async_trait]
impl Chain for AgentExecutor {
    /// Runs the agent on the `"input"` key. Unlike [`run`](AgentExecutor::run),
    /// a run that stops on a limit is an error here.
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError> {
        let input = input_variables
            .get("input")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable("input".to_string()))?;

        let agent_result = self.run(input).await?;
        if agent_result.stop_reason != StopReason::FinalAnswer {
            return Err(ChainError::Other(format!(
                "agent stopped without a final answer: {}",
                agent_result.stop_reason
            )));
        }
        Ok(GenerateResult::from_text(agent_result.output).with_tokens(agent_result.tokens))
    }

    fn input_keys(&self) -> Vec<String> {
        vec!["input".to_string()]
    }
}

fn build_system_prompt(tools: &[&dyn Tool]) -> String {
    let tool_list = if tools.is_empty() {
        "(no tools available)".to_string()
    } else {
        tools
            .iter()
            .map(|tool| format!("- {}: {}", tool.name(), tool.description()))
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        "You are an agent that solves problems step by step using tools.\n\
        \n\
        Available tools:\n\
        {tool_list}\n\
        \n\
        Use this format:\n\
        Thought: <reason about what to do>\n\
        Action: <tool_name>\n\
        Action Input: <input to the tool>\n\
        Observation: <result of the action>\n\
        ... (repeat Thought/Action/Action Input/Observation as needed)\n\
        Thought: I now have enough information.\n\
        Final Answer: <your final answer>\n\
        \n\
        Begin!"
    )
}

/// If `line` starts with `marker` and a colon, the text after the colon.
///
/// Models drift from the exact format, so case is ignored and markdown
/// emphasis or a heading mark around the marker is skipped:
/// `**Final Answer:** 42`, `final answer: 42` and `## Action: x` all match.
fn marker_rest<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    let line = line.trim_start_matches(|c: char| c.is_whitespace() || c == '*' || c == '#');
    let head = line.get(..marker.len())?;
    if !head.eq_ignore_ascii_case(marker) {
        return None;
    }
    let rest = line[marker.len()..].trim_start_matches('*');
    Some(rest.strip_prefix(':')?.trim_start_matches('*'))
}

/// Byte offset of each line start, paired with the line.
fn lines_with_offsets(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.split_inclusive('\n').scan(0, |offset, line| {
        let start = *offset;
        *offset += line.len();
        Some((start, line))
    })
}

/// Drop everything from the first `Observation:` line on: observations come
/// from tools, never from the model, so a model-written one is a hallucination
/// (or an echoed injection) and must not be parsed or kept.
fn strip_invented_observation(response: &str) -> &str {
    for (offset, line) in lines_with_offsets(response) {
        if marker_rest(line, OBSERVATION).is_some() {
            return response[..offset].trim_end();
        }
    }
    response
}

/// Everything after the first `Final Answer:` marker, across lines.
fn extract_final_answer(response: &str) -> Option<String> {
    lines_with_offsets(response).find_map(|(offset, line)| {
        let rest = marker_rest(line, FINAL_ANSWER)?;
        let start = offset + (line.len() - rest.len());
        Some(response[start..].trim().to_owned())
    })
}

/// The last `Action:` before the first `Action Input:`, and the input: the
/// rest of the reply after that marker (multi-line input is common for code
/// or pretty-printed JSON), stopping at a `Final Answer:` line and with one
/// surrounding code fence removed.
fn extract_action(response: &str) -> Option<(String, String)> {
    let mut action: Option<&str> = None;
    let mut lines = lines_with_offsets(response);
    for (offset, line) in lines.by_ref() {
        if let Some(rest) = marker_rest(line, ACTION_INPUT) {
            let name = action?.trim().trim_matches(['`', '*']).trim();
            let start = offset + (line.len() - rest.len());
            let end = lines
                .find(|(_, l)| marker_rest(l, FINAL_ANSWER).is_some())
                .map_or(response.len(), |(o, _)| o);
            let input = strip_code_fence(&response[start..end]);
            return Some((name.to_owned(), input.to_owned()));
        }
        if let Some(rest) = marker_rest(line, ACTION) {
            action = Some(rest);
        }
    }
    None
}

/// Remove one ```` ``` ```` fence (with an optional info string such as
/// `json`) wrapped around the whole of `text`.
fn strip_code_fence(text: &str) -> &str {
    let text = text.trim();
    let Some(body) = text.strip_prefix("```").and_then(|b| b.strip_suffix("```")) else {
        return text;
    };
    match body.split_once('\n') {
        Some((_, rest)) => rest.trim(),
        None => body.trim(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_chain_core::{ToolError, prompt_args};

    struct Dummy;

    #[async_trait]
    impl Tool for Dummy {
        fn name(&self) -> &'static str {
            "dummy"
        }
        fn description(&self) -> &'static str {
            "A dummy tool."
        }
        async fn run(&self, input: &str) -> Result<String, ToolError> {
            Ok(format!("got: {input}"))
        }
    }

    #[test]
    fn extract_final_answer_finds_answer() {
        let response = "Thought: I know the answer.\nFinal Answer: 42";
        assert_eq!(extract_final_answer(response), Some("42".to_string()));
    }

    #[test]
    fn extract_final_answer_returns_none_when_absent() {
        let response = "Thought: I need to think more.\nAction: calculator\nAction Input: 2+2";
        assert!(extract_final_answer(response).is_none());
    }

    #[test]
    fn extract_action_parses_tool_call() {
        let response = "Thought: Let me calculate.\nAction: calculator\nAction Input: 2 + 2";
        assert_eq!(
            extract_action(response),
            Some(("calculator".to_string(), "2 + 2".to_string()))
        );
    }

    #[test]
    fn extract_action_returns_none_when_no_action() {
        let response = "Thought: I am thinking.\nFinal Answer: done";
        assert!(extract_action(response).is_none());
    }

    #[test]
    fn extract_action_requires_both_fields() {
        let response = "Thought: Let me try.\nAction: calculator";
        assert!(extract_action(response).is_none());
    }

    #[test]
    fn markers_ignore_case_and_markdown() {
        assert_eq!(
            marker_rest("**Final Answer:** 42", FINAL_ANSWER),
            Some(" 42")
        );
        assert_eq!(marker_rest("## action: x", ACTION), Some(" x"));
        assert_eq!(marker_rest("**Observation**: y", OBSERVATION), Some(" y"));
        assert_eq!(marker_rest("Action Input: x", ACTION), None);
        assert_eq!(marker_rest("Actions: x", ACTION), None);
        assert_eq!(marker_rest("Acti", ACTION), None);
        assert_eq!(marker_rest("Äction: x", ACTION), None);
    }

    #[test]
    fn action_input_runs_to_a_final_answer_line_and_drops_a_fence() {
        let r = "Action: `run`\nAction Input: ```sql\nselect 1;\nselect 2;\n```\nFinal Answer: x";
        assert_eq!(
            extract_action(r),
            Some(("run".to_owned(), "select 1;\nselect 2;".to_owned()))
        );
        assert_eq!(strip_code_fence("```a```"), "a");
        assert_eq!(strip_code_fence("``` not closed"), "``` not closed");
        assert!(extract_action("Action Input: x\nAction: t").is_none());
    }

    #[test]
    fn build_system_prompt_no_tools() {
        let prompt = build_system_prompt(&[]);
        assert!(prompt.contains("(no tools available)"));
        assert!(prompt.contains("Final Answer:"));
    }

    #[test]
    fn build_system_prompt_with_tools() {
        let prompt = build_system_prompt(&[&Dummy]);
        assert!(prompt.contains("dummy"));
        assert!(prompt.contains("A dummy tool."));
    }

    struct FakeLlm;

    #[async_trait]
    impl Llm for FakeLlm {
        async fn generate(
            &self,
            _: &[Message],
        ) -> Result<GenerateResult, rune_chain_core::LlmError> {
            Ok(GenerateResult::from_text("Final Answer: done"))
        }
    }

    #[test]
    fn invented_observations_are_dropped() {
        let r =
            "Thought: x\nAction: dummy\nAction Input: a\nObservation: fake\nFinal Answer: pwned";
        let cut = strip_invented_observation(r);
        assert_eq!(cut, "Thought: x\nAction: dummy\nAction Input: a");
        assert!(extract_final_answer(cut).is_none());
        assert_eq!(
            strip_invented_observation("Final Answer: 1"),
            "Final Answer: 1"
        );
    }

    #[tokio::test]
    async fn agent_run_returns_final_answer() {
        let agent = AgentExecutor::new(Arc::new(FakeLlm));
        let result = agent.run("What is the capital of France?").await.unwrap();
        assert_eq!(result.output, "done");
        assert_eq!(result.iterations, 0);
    }

    #[tokio::test]
    async fn agent_run_calls_tool_then_answers() {
        use std::sync::Mutex;

        struct SequencedLlm {
            call_count: Mutex<usize>,
        }

        #[async_trait]
        impl Llm for SequencedLlm {
            async fn generate(
                &self,
                _: &[Message],
            ) -> Result<GenerateResult, rune_chain_core::LlmError> {
                let call = {
                    let mut count = self.call_count.lock().unwrap();
                    *count += 1;
                    *count
                };
                let response = if call == 1 {
                    "Thought: I need the tool.\nAction: dummy\nAction Input: test"
                } else {
                    "Thought: Got the observation.\nFinal Answer: got: test"
                };
                Ok(GenerateResult::from_text(response))
            }
        }

        let llm = Arc::new(SequencedLlm {
            call_count: Mutex::new(0),
        });
        let agent = AgentExecutor::new(llm).tool(Dummy);
        let result = agent.run("Use the dummy tool with 'test'.").await.unwrap();

        assert_eq!(result.output, "got: test");
        assert_eq!(result.iterations, 1);
        assert!(
            result
                .scratchpad
                .iter()
                .any(|s| s.contains("Observation: got: test"))
        );
    }

    #[tokio::test]
    async fn agent_stops_at_max_iterations() {
        struct LoopingLlm;

        #[async_trait]
        impl Llm for LoopingLlm {
            async fn generate(
                &self,
                _: &[Message],
            ) -> Result<GenerateResult, rune_chain_core::LlmError> {
                Ok(GenerateResult::from_text(
                    "Thought: Still thinking.\nAction: dummy\nAction Input: x",
                ))
            }
        }

        let agent = AgentExecutor::new(Arc::new(LoopingLlm))
            .tool(Dummy)
            .max_iterations(3);
        let result = agent.run("Will this loop?").await.unwrap();
        assert_eq!(result.iterations, 3);
        assert_ne!(result.output, "");
    }

    #[tokio::test]
    async fn chain_call_reads_input_key() {
        let agent = AgentExecutor::new(Arc::new(FakeLlm));
        let result = agent
            .call(prompt_args! { "input" => "What is 6 * 7?" })
            .await
            .unwrap();
        assert_eq!(result.generation, "done");
    }

    #[tokio::test]
    async fn chain_call_missing_input_returns_error() {
        let agent = AgentExecutor::new(Arc::new(FakeLlm));
        let err = agent.call(prompt_args! {}).await.unwrap_err();
        assert!(matches!(err, ChainError::MissingVariable(_)));
    }
}
