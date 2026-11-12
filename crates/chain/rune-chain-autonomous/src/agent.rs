use std::sync::Arc;

use async_trait::async_trait;
use rune_chain_core::{
    Chain, ChainError, FunctionDefinition, GenerateResult, Llm, Message, PromptArgs, TokenUsage,
    Tool,
};

const DEFAULT_MAX_STEPS: usize = 25;
const DEFAULT_MAX_REPLANS: usize = 3;
const DEFAULT_MAX_TOOL_ITERATIONS: usize = 5;

/// One completed task and the text it produced.
#[derive(Debug, Clone)]
pub struct StepRecord {
    /// The task description, as emitted by the planner.
    pub task: String,
    /// The output produced while completing the task.
    pub output: String,
}

/// How an [`AutonomousAgent::run`] call ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStatus {
    /// Reflection judged the goal fully achieved.
    Completed,
    /// The replanning limit was reached without the goal being achieved.
    Blocked(String),
    /// The total step budget ([`AutonomousAgent::max_steps`]) was exhausted.
    StepBudgetExhausted,
}

/// The outcome of a completed (or halted) autonomous run.
#[derive(Debug, Clone)]
pub struct AutonomousResult {
    /// The original goal passed to [`AutonomousAgent::run`].
    pub goal: String,
    /// The final answer (on [`RunStatus::Completed`]) or the last known progress.
    pub output: String,
    /// How the run ended.
    pub status: RunStatus,
    /// Every plan produced, in order — index 0 is the initial plan, each
    /// subsequent entry is a replan triggered by reflection.
    pub plans: Vec<Vec<String>>,
    /// Every task executed across all plans, in execution order.
    pub history: Vec<StepRecord>,
    /// Token usage summed over every LLM call of the run (planning, task
    /// execution and reflection), or `None` when the LLM never reported usage.
    pub tokens: Option<TokenUsage>,
}

/// The LLM's verdict after a plan has been fully executed.
enum Reflection {
    Done(String),
    Continue(Vec<String>),
}

/// A goal-driven agent that plans, executes, and re-plans without human input.
///
/// Give it a goal instead of a question. It decomposes the goal into tasks,
/// works through them with the registered [`Tool`]s, then asks the LLM to judge
/// whether the goal is met. If not, it re-plans the remaining work and keeps
/// going — up to [`max_replans`](Self::max_replans) revisions and
/// [`max_steps`](Self::max_steps) total tasks — rather than stopping after a
/// single bounded reasoning loop.
pub struct AutonomousAgent {
    llm: Arc<dyn Llm>,
    tools: Vec<Box<dyn Tool>>,
    max_steps: usize,
    max_replans: usize,
    max_tool_iterations: usize,
    system_prompt: Option<String>,
}

impl AutonomousAgent {
    /// Create a new agent backed by the given LLM.
    pub fn new(llm: Arc<dyn Llm>) -> Self {
        Self {
            llm,
            tools: Vec::new(),
            max_steps: DEFAULT_MAX_STEPS,
            max_replans: DEFAULT_MAX_REPLANS,
            max_tool_iterations: DEFAULT_MAX_TOOL_ITERATIONS,
            system_prompt: None,
        }
    }

    /// Register a tool the agent may call while executing tasks.
    #[must_use]
    pub fn tool(mut self, tool: impl Tool + 'static) -> Self {
        self.tools.push(Box::new(tool));
        self
    }

    /// Cap the total number of tasks executed across every plan (default: 25).
    #[must_use]
    pub const fn max_steps(mut self, max_steps: usize) -> Self {
        self.max_steps = max_steps;
        self
    }

    /// Cap how many times reflection may revise the plan (default: 3).
    #[must_use]
    pub const fn max_replans(mut self, max_replans: usize) -> Self {
        self.max_replans = max_replans;
        self
    }

    /// Cap tool-call rounds spent completing a single task (default: 5).
    #[must_use]
    pub const fn max_tool_iterations(mut self, max_tool_iterations: usize) -> Self {
        self.max_tool_iterations = max_tool_iterations;
        self
    }

    /// Override the system prompt used while executing individual tasks.
    #[must_use]
    pub fn system_prompt(mut self, system_prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(system_prompt.into());
        self
    }

    /// Drive the agent toward `goal`, planning, executing, and re-planning
    /// without further input until it is done, blocked, or out of budget.
    pub async fn run(&self, goal: &str) -> Result<AutonomousResult, ChainError> {
        let mut history: Vec<StepRecord> = Vec::new();
        let mut plans: Vec<Vec<String>> = Vec::new();
        let mut steps_used = 0usize;
        let mut replans = 0usize;
        let mut tokens = None;

        let mut current_plan = self.plan(goal, &history, &mut tokens).await?;
        plans.push(current_plan.clone());

        loop {
            for task in current_plan.clone() {
                if steps_used >= self.max_steps {
                    return Ok(AutonomousResult {
                        goal: goal.to_string(),
                        output: last_progress(&history),
                        status: RunStatus::StepBudgetExhausted,
                        plans,
                        history,
                        tokens,
                    });
                }

                let output = self
                    .execute_task(goal, &task, &history, &mut tokens)
                    .await?;
                steps_used += 1;
                history.push(StepRecord { task, output });
            }

            match self.reflect(goal, &history, &mut tokens).await? {
                Reflection::Done(answer) => {
                    return Ok(AutonomousResult {
                        goal: goal.to_string(),
                        output: answer,
                        status: RunStatus::Completed,
                        plans,
                        history,
                        tokens,
                    });
                }
                Reflection::Continue(next_tasks) => {
                    replans += 1;
                    if next_tasks.is_empty() || replans > self.max_replans {
                        return Ok(AutonomousResult {
                            goal: goal.to_string(),
                            output: last_progress(&history),
                            status: RunStatus::Blocked(
                                "reached the replanning limit without completing the goal"
                                    .to_string(),
                            ),
                            plans,
                            history,
                            tokens,
                        });
                    }
                    current_plan = next_tasks;
                    plans.push(current_plan.clone());
                }
            }
        }
    }

    /// Ask the LLM to break `goal` into an ordered list of concrete tasks.
    async fn plan(
        &self,
        goal: &str,
        history: &[StepRecord],
        tokens: &mut Option<TokenUsage>,
    ) -> Result<Vec<String>, ChainError> {
        let prompt = format!(
            "You are an autonomous planning agent. Break the following goal into a \
             short, ordered list of concrete, independently-executable tasks needed \
             to fully achieve it.\n\n\
             Goal: {goal}\n\n\
             Work completed so far:\n{}\n\n\
             Respond with ONLY a numbered list, one task per line, and nothing else. \
             Keep the list as short as possible while still being sufficient.",
            history_block(history)
        );

        let messages = vec![
            Message::system("You are a meticulous planning assistant."),
            Message::human(prompt),
        ];
        let result = self.llm.generate(&messages).await?;
        TokenUsage::accumulate(tokens, result.tokens.as_ref());
        let tasks = parse_numbered_list(&result.generation);

        if tasks.is_empty() {
            Ok(vec![goal.to_string()])
        } else {
            Ok(tasks)
        }
    }

    /// Complete a single task, using tools if any are registered.
    async fn execute_task(
        &self,
        goal: &str,
        task: &str,
        history: &[StepRecord],
        tokens: &mut Option<TokenUsage>,
    ) -> Result<String, ChainError> {
        let mut messages = self.task_messages(goal, task, history);

        if self.tools.is_empty() {
            let result = self.llm.generate(&messages).await?;
            TokenUsage::accumulate(tokens, result.tokens.as_ref());
            return Ok(result.generation);
        }

        let tool_defs: Vec<FunctionDefinition> =
            self.tools.iter().map(|t| t.function_definition()).collect();
        let mut rounds = 0usize;

        loop {
            let result = self
                .llm
                .generate_with_tools(&messages, &tool_defs, None)
                .await?;
            TokenUsage::accumulate(tokens, result.tokens.as_ref());

            if !result.wants_tool_calls() {
                return Ok(result.generation);
            }

            rounds += 1;
            if rounds > self.max_tool_iterations {
                return Ok(result.generation);
            }

            messages.push(Message::ai_with_tool_calls(
                &result.generation,
                result.tool_calls.clone(),
            ));

            for call in &result.tool_calls {
                let output = match self.tools.iter().find(|t| t.name() == call.name) {
                    None => format!("Error: unknown tool '{}'", call.name),
                    Some(tool) => tool
                        .run(&call.arguments)
                        .await
                        .unwrap_or_else(|e| format!("Tool error: {e}")),
                };
                messages.push(Message::tool_result(&call.id, output));
            }
        }
    }

    fn task_messages(&self, goal: &str, task: &str, history: &[StepRecord]) -> Vec<Message> {
        let system = self.system_prompt.clone().unwrap_or_else(|| {
            "You are an autonomous agent working through a task list toward a larger goal. \
             Use the provided tools when needed to complete the current task."
                .to_string()
        });

        let human = format!(
            "Overall goal: {goal}\n\n\
             Work completed so far:\n{}\n\n\
             Your current task: {task}\n\n\
             Complete this task now.",
            history_block(history)
        );

        vec![Message::system(system), Message::human(human)]
    }

    /// Ask the LLM whether the goal is fully achieved given the work so far.
    async fn reflect(
        &self,
        goal: &str,
        history: &[StepRecord],
        tokens: &mut Option<TokenUsage>,
    ) -> Result<Reflection, ChainError> {
        let prompt = format!(
            "Goal: {goal}\n\n\
             Work completed so far:\n{}\n\n\
             Decide whether the goal has been fully achieved.\n\n\
             If it has, respond in EXACTLY this format:\n\
             STATUS: DONE\n\
             ANSWER: <final answer synthesized from the work above>\n\n\
             If more work is needed, respond in EXACTLY this format:\n\
             STATUS: CONTINUE\n\
             NEXT_TASKS:\n\
             1. <task>\n\
             2. <task>",
            history_block(history)
        );

        let messages = vec![
            Message::system("You are a critical evaluator judging whether a goal is complete."),
            Message::human(prompt),
        ];
        let result = self.llm.generate(&messages).await?;
        TokenUsage::accumulate(tokens, result.tokens.as_ref());
        Ok(parse_reflection(&result.generation))
    }
}

#[async_trait]
impl Chain for AutonomousAgent {
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError> {
        let goal = input_variables
            .get("input")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable("input".to_string()))?;

        let result = self.run(goal).await?;
        Ok(GenerateResult::from_text(result.output).with_tokens(result.tokens))
    }

    fn input_keys(&self) -> Vec<String> {
        vec!["input".to_string()]
    }
}

fn history_block(history: &[StepRecord]) -> String {
    if history.is_empty() {
        return "(no work has been done yet)".to_string();
    }
    history
        .iter()
        .enumerate()
        .map(|(i, record)| format!("{}. {} -> {}", i + 1, record.task, record.output))
        .collect::<Vec<_>>()
        .join("\n")
}

fn last_progress(history: &[StepRecord]) -> String {
    history.last().map_or_else(
        || "(no work completed)".to_string(),
        |record| record.output.clone(),
    )
}

/// Parse lines like `"1. Do the thing"` or `"2) Do another thing"` into a task list.
fn parse_numbered_list(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let after_digits = trimmed.trim_start_matches(|c: char| c.is_ascii_digit());
            if after_digits.len() == trimmed.len() {
                return None;
            }
            let rest = after_digits.trim_start_matches(['.', ')']).trim();
            if rest.is_empty() {
                None
            } else {
                Some(rest.to_string())
            }
        })
        .collect()
}

fn parse_reflection(text: &str) -> Reflection {
    let status = text.lines().find_map(|line| {
        let trimmed = line.trim_start();
        let upper = trimmed.to_uppercase();
        upper
            .starts_with("STATUS:")
            .then(|| upper["STATUS:".len()..].trim().to_string())
    });

    match status.as_deref() {
        Some("DONE") => Reflection::Done(
            extract_after_prefix(text, "ANSWER:").unwrap_or_else(|| text.trim().to_string()),
        ),
        Some("CONTINUE") => Reflection::Continue(parse_numbered_list(text)),
        _ => {
            // No explicit STATUS line — fall back to a lenient heuristic rather
            // than failing the run outright on a slightly malformed response.
            if text.to_uppercase().contains("DONE") {
                Reflection::Done(text.trim().to_string())
            } else {
                let tasks = parse_numbered_list(text);
                if tasks.is_empty() {
                    Reflection::Continue(vec![text.trim().to_string()])
                } else {
                    Reflection::Continue(tasks)
                }
            }
        }
    }
}

fn extract_after_prefix(text: &str, prefix: &str) -> Option<String> {
    let upper = text.to_uppercase();
    let idx = upper.find(prefix)?;
    Some(text[idx + prefix.len()..].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_chain_core::{
        FunctionDefinition as FnDef, LlmError, ToolCall, ToolChoice, ToolError, prompt_args,
    };
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

    #[test]
    fn parse_numbered_list_extracts_tasks() {
        let text = "1. Research the topic\n2) Write a draft\n3. Publish it";
        assert_eq!(
            parse_numbered_list(text),
            vec!["Research the topic", "Write a draft", "Publish it"]
        );
    }

    #[test]
    fn parse_numbered_list_ignores_non_list_lines() {
        let text = "Here is the plan:\n1. Do the thing\nThat's it.";
        assert_eq!(parse_numbered_list(text), vec!["Do the thing"]);
    }

    #[test]
    fn parse_reflection_done_extracts_answer() {
        let text = "STATUS: DONE\nANSWER: The report is complete.";
        match parse_reflection(text) {
            Reflection::Done(answer) => assert_eq!(answer, "The report is complete."),
            Reflection::Continue(_) => panic!("expected Done"),
        }
    }

    #[test]
    fn parse_reflection_continue_extracts_next_tasks() {
        let text = "STATUS: CONTINUE\nNEXT_TASKS:\n1. Gather more data\n2. Re-check figures";
        match parse_reflection(text) {
            Reflection::Continue(tasks) => {
                assert_eq!(tasks, vec!["Gather more data", "Re-check figures"]);
            }
            Reflection::Done(_) => panic!("expected Continue"),
        }
    }

    #[test]
    fn parse_reflection_falls_back_when_status_missing() {
        match parse_reflection("Looks fully DONE to me.") {
            Reflection::Done(_) => {}
            Reflection::Continue(_) => panic!("expected Done fallback"),
        }

        match parse_reflection("Not finished yet, needs more research.") {
            Reflection::Continue(tasks) => assert_eq!(tasks.len(), 1),
            Reflection::Done(_) => panic!("expected Continue fallback"),
        }
    }

    struct FakeLlm(&'static str);

    #[async_trait]
    impl Llm for FakeLlm {
        async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
            Ok(GenerateResult::from_text(self.0))
        }
    }

    #[tokio::test]
    async fn execute_task_without_tools_uses_plain_generate() {
        let agent = AutonomousAgent::new(Arc::new(FakeLlm("done with task")));
        let output = agent
            .execute_task("goal", "task", &[], &mut None)
            .await
            .unwrap();
        assert_eq!(output, "done with task");
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
            _tools: &[FnDef],
            _tool_choice: Option<ToolChoice>,
        ) -> Result<GenerateResult, LlmError> {
            let mut count = self.call_count.lock().unwrap();
            *count += 1;
            if *count == 1 {
                Ok(
                    GenerateResult::from_text(String::new()).with_tool_calls(vec![ToolCall::new(
                        "call_1",
                        "echo",
                        r#"{"input": "hi"}"#,
                    )]),
                )
            } else {
                Ok(GenerateResult::from_text("task complete: hi"))
            }
        }
    }

    #[tokio::test]
    async fn execute_task_with_tools_loops_through_tool_call() {
        let agent = AutonomousAgent::new(Arc::new(ToolCallLlm {
            call_count: Mutex::new(0),
        }))
        .tool(EchoTool);
        let output = agent
            .execute_task("goal", "echo hi", &[], &mut None)
            .await
            .unwrap();
        assert_eq!(output, "task complete: hi");
    }

    /// Scripts: plan -> two tasks; execute task 1; execute task 2; reflect -> DONE.
    struct ScriptedLlm {
        call_count: Mutex<usize>,
    }

    #[async_trait]
    impl Llm for ScriptedLlm {
        #[allow(
            clippy::significant_drop_tightening,
            reason = "the guard must outlive the values borrowed from it"
        )]
        async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
            let mut count = self.call_count.lock().unwrap();
            *count += 1;
            let response = match *count {
                1 => "1. Do X\n2. Do Y",
                2 => "X is done.",
                3 => "Y is done.",
                _ => "STATUS: DONE\nANSWER: Goal fully achieved.",
            };
            Ok(GenerateResult::from_text(response))
        }
    }

    #[tokio::test]
    async fn run_completes_after_executing_the_plan() {
        let agent = AutonomousAgent::new(Arc::new(ScriptedLlm {
            call_count: Mutex::new(0),
        }));
        let result = agent.run("Ship the feature").await.unwrap();

        assert_eq!(result.status, RunStatus::Completed);
        assert_eq!(result.output, "Goal fully achieved.");
        assert_eq!(
            result.plans,
            vec![vec!["Do X".to_string(), "Do Y".to_string()]]
        );
        assert_eq!(result.history.len(), 2);
        assert_eq!(result.history[0].output, "X is done.");
        assert_eq!(result.history[1].output, "Y is done.");
    }

    /// Scripts one replan: plan -> [task1]; execute; reflect -> CONTINUE [task2];
    /// execute; reflect -> DONE.
    struct ReplanningLlm {
        call_count: Mutex<usize>,
    }

    #[async_trait]
    impl Llm for ReplanningLlm {
        #[allow(
            clippy::significant_drop_tightening,
            reason = "the guard must outlive the values borrowed from it"
        )]
        async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
            let mut count = self.call_count.lock().unwrap();
            *count += 1;
            let response = match *count {
                1 => "1. Draft the outline",
                2 => "Outline drafted.",
                3 => "STATUS: CONTINUE\nNEXT_TASKS:\n1. Fill in the details",
                4 => "Details filled in.",
                _ => "STATUS: DONE\nANSWER: Document finished.",
            };
            Ok(GenerateResult::from_text(response))
        }
    }

    #[tokio::test]
    async fn run_replans_when_reflection_says_continue() {
        let agent = AutonomousAgent::new(Arc::new(ReplanningLlm {
            call_count: Mutex::new(0),
        }));
        let result = agent.run("Write a document").await.unwrap();

        assert_eq!(result.status, RunStatus::Completed);
        assert_eq!(result.output, "Document finished.");
        assert_eq!(result.plans.len(), 2);
        assert_eq!(result.history.len(), 2);
    }

    struct AlwaysContinueLlm {
        call_count: Mutex<usize>,
    }

    #[async_trait]
    impl Llm for AlwaysContinueLlm {
        #[allow(
            clippy::significant_drop_tightening,
            reason = "the guard must outlive the values borrowed from it"
        )]
        async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
            let mut count = self.call_count.lock().unwrap();
            *count += 1;
            if *count == 1 {
                return Ok(GenerateResult::from_text("1. Try something"));
            }
            Ok(GenerateResult::from_text(
                "STATUS: CONTINUE\nNEXT_TASKS:\n1. Try something else",
            ))
        }
    }

    #[tokio::test]
    async fn run_stops_when_replan_limit_reached() {
        let agent = AutonomousAgent::new(Arc::new(AlwaysContinueLlm {
            call_count: Mutex::new(0),
        }))
        .max_replans(2);
        let result = agent.run("An impossible goal").await.unwrap();

        match result.status {
            RunStatus::Blocked(_) => {}
            other => panic!("expected Blocked, got {other:?}"),
        }
        // Initial plan + 2 replans = 3 plans total.
        assert_eq!(result.plans.len(), 3);
    }

    struct LoopingLlm;

    #[async_trait]
    impl Llm for LoopingLlm {
        async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
            Ok(GenerateResult::from_text("1. Task A\n2. Task B\n3. Task C"))
        }
    }

    #[tokio::test]
    async fn run_stops_at_step_budget() {
        let agent = AutonomousAgent::new(Arc::new(LoopingLlm)).max_steps(1);
        let result = agent.run("A goal with a long plan").await.unwrap();

        assert_eq!(result.status, RunStatus::StepBudgetExhausted);
        assert_eq!(result.history.len(), 1);
    }

    #[tokio::test]
    async fn chain_call_reads_input_key() {
        let agent = AutonomousAgent::new(Arc::new(ScriptedLlm {
            call_count: Mutex::new(0),
        }));
        let result = agent
            .call(prompt_args! { "input" => "Ship the feature" })
            .await
            .unwrap();
        assert_eq!(result.generation, "Goal fully achieved.");
    }

    #[tokio::test]
    async fn chain_call_missing_input_returns_error() {
        let agent = AutonomousAgent::new(Arc::new(FakeLlm("x")));
        let err = agent.call(prompt_args! {}).await.unwrap_err();
        assert!(matches!(err, ChainError::MissingVariable(_)));
    }
}
