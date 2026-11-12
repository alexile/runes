use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rune_chain_agent::sanitize::{redact_secrets, truncate_with_marker};
use rune_chain_agent::{
    AgentEvent, AgentLimits, Approval, ApprovalRequest, Approver, FunctionCallingAgent,
    ToolErrorMode,
};
use rune_chain_core::{
    Chain, ChainError, GenerateResult, Llm, Message, Pricing, PromptArgs, TokenUsage, Tool,
};
use tokio::time::Instant;

use crate::event::{AutonomousEvent, AutonomousObserver, DropReason};
use crate::governor::{GovernedLlm, Governor, GuardedTool};
use crate::planner::{LlmPlanner, PlanContext, Review, TaskPlanner, render_history};
use crate::untrusted::{UNTRUSTED_NOTICE, clean_task, fence, task_key};
use crate::{
    AgentState, BudgetKind, CHECKPOINT_VERSION, Limits, LoopKind, RunOutcome, StopCause,
    StopHandle, Task, TaskRecord,
};

const DEFAULT_SYSTEM_PROMPT: &str = "You are an autonomous agent working through a task \
list toward a larger goal. Do only the current task, using the provided tools when needed, \
and reply with its result.";

/// Error messages kept in [`RunOutcome::Error`].
const MAX_ERROR_BYTES: usize = 1024;

type StateFn = dyn Fn(&AgentState) + Send + Sync;
type StatePredicate = dyn Fn(&AgentState) -> bool + Send + Sync;

/// The result of a run: how it ended plus the full state, which doubles as a
/// checkpoint for [`AutonomousAgent::resume`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AutonomousRun {
    /// How the run ended.
    pub outcome: RunOutcome,
    /// Queue, bounded history and spent budget at the end of the run.
    pub state: AgentState,
}

impl AutonomousRun {
    /// The final answer of a completed run, otherwise the latest task
    /// result (empty if no task ran).
    #[must_use]
    pub fn output(&self) -> &str {
        self.outcome
            .answer()
            .or_else(|| self.state.last_result())
            .unwrap_or_default()
    }

    /// Whether the goal was reported done.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        self.outcome.is_completed()
    }

    /// Token usage over the run, if the LLM reported any.
    #[must_use]
    pub const fn usage(&self) -> Option<&TokenUsage> {
        self.state.usage.as_ref()
    }
}

/// A goal-driven agent that plans tasks, runs them with tools and reviews
/// its progress, inside hard limits.
///
/// Each run:
///
/// 1. asks the [`TaskPlanner`] for an initial task list;
/// 2. runs queued tasks one at a time. With tools registered, a task runs in
///    a [`FunctionCallingAgent`] (schema-validated tool calls, approval,
///    fenced output, per-task [`AgentLimits`]); without tools it is a single
///    LLM call;
/// 3. when the queue is empty, asks the planner to review. `Done` ends the
///    run, `Continue` queues more tasks.
///
/// It stops with a [`RunOutcome`] as soon as the goal is done, a limit in
/// [`Limits`] is hit, a loop is detected, the caller stops it, or an LLM call
/// fails. See the crate docs for the security model.
pub struct AutonomousAgent {
    llm: Arc<dyn Llm>,
    planner: Arc<dyn TaskPlanner>,
    tools: Vec<(Arc<dyn Tool>, bool)>,
    approver: Option<Arc<dyn Approver>>,
    observer: Option<Arc<dyn AutonomousObserver>>,
    on_checkpoint: Option<Arc<StateFn>>,
    stop_when: Option<Arc<StatePredicate>>,
    limits: Limits,
    task_limits: AgentLimits,
    tool_error_mode: ToolErrorMode,
    pricing: Option<Pricing>,
    system_prompt: Option<String>,
    stop: StopHandle,
}

impl AutonomousAgent {
    /// An agent with the [`LlmPlanner`], no tools and default [`Limits`].
    /// Each task gets [`AgentLimits::default`] with at most 5 tool rounds.
    pub fn new(llm: Arc<dyn Llm>) -> Self {
        Self {
            llm,
            planner: Arc::new(LlmPlanner::new()),
            tools: Vec::new(),
            approver: None,
            observer: None,
            on_checkpoint: None,
            stop_when: None,
            limits: Limits::default(),
            task_limits: AgentLimits::default().max_iterations(5),
            tool_error_mode: ToolErrorMode::ReturnToModel,
            pricing: None,
            system_prompt: None,
            stop: StopHandle::new(),
        }
    }

    /// Use another planner / prioritiser.
    #[must_use]
    pub fn planner(mut self, planner: impl TaskPlanner + 'static) -> Self {
        self.planner = Arc::new(planner);
        self
    }

    /// Register a tool tasks may call.
    #[must_use]
    pub fn tool(mut self, tool: impl Tool + 'static) -> Self {
        self.tools.push((Arc::new(tool), false));
        self
    }

    /// Register a tool that only runs after the [`approver`](Self::approver)
    /// allows the call. Without an approver every call to it is denied.
    #[must_use]
    pub fn tool_requiring_approval(mut self, tool: impl Tool + 'static) -> Self {
        self.tools.push((Arc::new(tool), true));
        self
    }

    /// Register already-boxed tools.
    #[must_use]
    pub fn tools(mut self, tools: impl IntoIterator<Item = Box<dyn Tool>>) -> Self {
        self.tools
            .extend(tools.into_iter().map(|t| (Arc::from(t), false)));
        self
    }

    /// Set the approver for tools registered with
    /// [`tool_requiring_approval`](Self::tool_requiring_approval).
    #[must_use]
    pub fn approver(mut self, approver: impl Approver + 'static) -> Self {
        self.approver = Some(Arc::new(approver));
        self
    }

    /// Receive an [`AutonomousEvent`] for every step of the run.
    #[must_use]
    pub fn on_event(mut self, observer: impl AutonomousObserver + 'static) -> Self {
        self.observer = Some(Arc::new(observer));
        self
    }

    /// Called with the current state after every task and at the end of the
    /// run, e.g. to persist a checkpoint.
    #[must_use]
    pub fn on_checkpoint(mut self, f: impl Fn(&AgentState) + Send + Sync + 'static) -> Self {
        self.on_checkpoint = Some(Arc::new(f));
        self
    }

    /// Stop the run (with [`StopCause::Condition`]) once `predicate` returns
    /// `true`. Checked before every task and planning step.
    #[must_use]
    pub fn stop_when(
        mut self,
        predicate: impl Fn(&AgentState) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.stop_when = Some(Arc::new(predicate));
        self
    }

    /// Replace the run limits.
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Shorthand for [`Limits::max_tasks`].
    #[must_use]
    pub const fn max_tasks(mut self, n: usize) -> Self {
        self.limits.max_tasks = n;
        self
    }

    /// Shorthand for [`Limits::max_cycles`].
    #[must_use]
    pub const fn max_cycles(mut self, n: usize) -> Self {
        self.limits.max_cycles = n;
        self
    }

    /// Shorthand for [`Limits::max_wall_time`].
    #[must_use]
    pub const fn max_wall_time(mut self, budget: Option<Duration>) -> Self {
        self.limits.max_wall_time = budget;
        self
    }

    /// Shorthand for [`Limits::max_total_tokens`].
    #[must_use]
    pub const fn max_total_tokens(mut self, budget: Option<u64>) -> Self {
        self.limits.max_total_tokens = budget;
        self
    }

    /// Limits for the tool loop inside each task. Its wall time is further
    /// capped by what is left of the run's.
    #[must_use]
    pub const fn task_limits(mut self, limits: AgentLimits) -> Self {
        self.task_limits = limits;
        self
    }

    /// What a failing tool call does (default: reported to the model).
    #[must_use]
    pub const fn tool_error_mode(mut self, mode: ToolErrorMode) -> Self {
        self.tool_error_mode = mode;
        self
    }

    /// Prices for the model, enabling [`Limits::max_cost`] and
    /// [`AgentState::cost`].
    #[must_use]
    pub const fn pricing(mut self, pricing: Pricing) -> Self {
        self.pricing = Some(pricing);
        self
    }

    /// Replace the system prompt used to run tasks. The untrusted-data
    /// notice is always appended.
    #[must_use]
    pub fn system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }

    /// The limits in force.
    #[must_use]
    pub const fn current_limits(&self) -> &Limits {
        &self.limits
    }

    /// A handle that stops this agent's runs from anywhere.
    #[must_use]
    pub fn stop_handle(&self) -> StopHandle {
        self.stop.clone()
    }

    /// Start a run toward `goal`.
    ///
    /// # Errors
    ///
    /// Only for an invalid configuration: tool names that are invalid or
    /// registered twice. Everything that can happen during the run, LLM
    /// failures included, is reported in [`AutonomousRun::outcome`].
    pub async fn run(&self, goal: &str) -> Result<AutonomousRun, ChainError> {
        self.drive(AgentState::new(goal), false).await
    }

    /// Continue from a checkpoint (an [`AgentState`] from an earlier run or
    /// the checkpoint callback). Spent budget carries over; size bounds are
    /// re-applied to the state.
    ///
    /// # Errors
    ///
    /// As for [`run`](Self::run), plus a state written by an incompatible
    /// version of this crate.
    pub async fn resume(&self, state: AgentState) -> Result<AutonomousRun, ChainError> {
        if state.version != CHECKPOINT_VERSION {
            return Err(ChainError::Other(format!(
                "checkpoint version {} is not supported (expected {CHECKPOINT_VERSION})",
                state.version
            )));
        }
        self.drive(state, true).await
    }

    fn check_tools(&self) -> Result<(), ChainError> {
        let mut seen = HashSet::new();
        for (tool, _) in &self.tools {
            let def = tool.function_definition();
            if !def.has_valid_name() {
                return Err(ChainError::Other(format!(
                    "tool name `{}` is invalid: use 1-64 ASCII letters, digits, `_` or `-`",
                    rune_chain_agent::sanitize::sanitize_name(&def.name)
                )));
            }
            if !seen.insert(def.name.clone()) {
                return Err(ChainError::Other(format!(
                    "tool `{}` is registered twice",
                    def.name
                )));
            }
        }
        Ok(())
    }

    async fn drive(
        &self,
        mut state: AgentState,
        resumed: bool,
    ) -> Result<AutonomousRun, ChainError> {
        self.check_tools()?;
        state.enforce_bounds(&self.limits);

        let started = Instant::now();
        let base_elapsed = state.elapsed;
        let deadline = self
            .limits
            .max_wall_time
            .map(|max| started + max.saturating_sub(base_elapsed));
        let governor = Arc::new(Governor::new(
            self.limits,
            self.pricing,
            deadline,
            self.stop.clone(),
            self.observer.clone(),
            &state,
        ));
        let llm = GovernedLlm {
            inner: Arc::clone(&self.llm),
            governor: Arc::clone(&governor),
        };
        let run = Run {
            agent: self,
            governor: &governor,
            llm: Arc::new(llm),
            started,
            base_elapsed,
        };
        governor.emit(&AutonomousEvent::RunStarted {
            goal: state.goal.clone(),
            resumed,
        });

        let outcome = match state.answer.clone() {
            Some(answer) => RunOutcome::Completed { answer },
            None => run.steps(&mut state).await,
        };
        run.sync(&mut state);
        governor.emit(&AutonomousEvent::Finished {
            outcome: outcome.clone(),
        });
        if let Some(f) = &self.on_checkpoint {
            f(&state);
        }
        Ok(AutonomousRun { outcome, state })
    }
}

/// One run in progress.
struct Run<'a> {
    agent: &'a AutonomousAgent,
    governor: &'a Arc<Governor>,
    llm: Arc<GovernedLlm>,
    started: Instant,
    base_elapsed: Duration,
}

/// Tasks accepted from one planner reply.
struct Enqueued {
    added: Vec<Task>,
    repeated: Option<String>,
}

impl Run<'_> {
    fn sync(&self, state: &mut AgentState) {
        self.governor.sync(state);
        state.elapsed = self.base_elapsed + self.started.elapsed();
    }

    fn ctx<'s>(&self, state: &'s AgentState) -> PlanContext<'s> {
        let mut ctx = PlanContext::new(&state.goal, &state.history, &state.queue);
        ctx.cycle = state.cycle;
        ctx.max_context_bytes = self.agent.limits.max_context_bytes;
        ctx
    }

    /// Map an error to the outcome: a halt the governor latched (limit, loop,
    /// stop) wins over the error it caused.
    fn failure(&self, err: &ChainError) -> RunOutcome {
        self.governor.halted().unwrap_or_else(|| {
            let (message, _) =
                truncate_with_marker(&redact_secrets(&err.to_string()), MAX_ERROR_BYTES);
            RunOutcome::Error { message }
        })
    }

    fn halt_check(&self, state: &mut AgentState) -> Option<RunOutcome> {
        if let Some(outcome) = self.governor.check() {
            return Some(outcome);
        }
        if let Some(pred) = &self.agent.stop_when {
            self.sync(state);
            if pred(state) {
                let outcome = RunOutcome::Stopped(StopCause::Condition);
                self.governor.halt(outcome.clone());
                return Some(outcome);
            }
        }
        None
    }

    async fn steps(&self, state: &mut AgentState) -> RunOutcome {
        let limits = &self.agent.limits;
        let planner = &self.agent.planner;
        loop {
            if let Some(outcome) = self.halt_check(state) {
                return outcome;
            }

            if state.queue.is_empty() {
                let proposed = if state.cycle == 0 {
                    match planner.plan(self.llm.as_ref(), &self.ctx(state)).await {
                        Ok(tasks) => tasks,
                        Err(e) => return self.failure(&e),
                    }
                } else {
                    match planner.review(self.llm.as_ref(), &self.ctx(state)).await {
                        Ok(Review::Done { answer }) => {
                            self.governor
                                .emit(&AutonomousEvent::Reviewed { done: true });
                            state.answer = Some(answer.clone());
                            return RunOutcome::Completed { answer };
                        }
                        Ok(Review::Continue { tasks }) => {
                            self.governor
                                .emit(&AutonomousEvent::Reviewed { done: false });
                            if state.cycle >= limits.max_cycles {
                                return RunOutcome::BudgetExceeded(BudgetKind::Cycles);
                            }
                            tasks
                        }
                        Err(e) => return self.failure(&e),
                    }
                };
                state.cycle += 1;
                let enqueued = match self.enqueue(state, proposed) {
                    Ok(e) => e,
                    Err(outcome) => return outcome,
                };
                if enqueued.added.is_empty() {
                    return RunOutcome::LoopDetected(
                        enqueued
                            .repeated
                            .map_or(LoopKind::NoProgress, |task| LoopKind::RepeatedTask { task }),
                    );
                }
                self.prioritize(state);
                self.governor.emit(&AutonomousEvent::Planned {
                    cycle: state.cycle,
                    tasks: enqueued.added,
                });
                continue;
            }

            if state.tasks_executed >= limits.max_tasks {
                return RunOutcome::BudgetExceeded(BudgetKind::Tasks);
            }
            let Some(task) = state.queue.pop_front() else {
                continue;
            };
            let count = state
                .task_counts
                .entry(task_key(&task.description))
                .or_insert(0);
            *count = count.saturating_add(1);
            state.tasks_executed += 1;
            self.governor
                .emit(&AutonomousEvent::TaskStarted { task: task.clone() });

            let executed = self.execute(state, &task).await;
            let (result, tool_calls) = match executed {
                Ok(r) => r,
                Err(e) => {
                    // Put the task back so a resumed run retries it.
                    state.queue.push_front(task);
                    return self.failure(&e);
                }
            };
            let (result, truncated) = truncate_with_marker(&result, limits.max_result_bytes);
            self.governor.emit(&AutonomousEvent::TaskFinished {
                task_id: task.id,
                result: result.clone(),
                truncated,
            });
            let record = TaskRecord {
                task,
                result,
                truncated,
                tool_calls,
            };
            state.push_record(record.clone(), limits.max_history);
            self.checkpoint(state);

            if let Some(outcome) = self.governor.halted() {
                return outcome;
            }
            let follow_up = match planner
                .after_task(self.llm.as_ref(), &self.ctx(state), &record)
                .await
            {
                Ok(tasks) => tasks,
                Err(e) => return self.failure(&e),
            };
            if !follow_up.is_empty() {
                match self.enqueue(state, follow_up) {
                    Ok(e) if !e.added.is_empty() => {
                        self.prioritize(state);
                        self.governor.emit(&AutonomousEvent::Planned {
                            cycle: state.cycle,
                            tasks: e.added,
                        });
                    }
                    Ok(_) => {}
                    Err(outcome) => return outcome,
                }
            }
        }
    }

    fn prioritize(&self, state: &mut AgentState) {
        let mut queue = std::mem::take(&mut state.queue);
        self.agent.planner.prioritize(&self.ctx(state), &mut queue);
        // A planner may reorder, but not grow the queue past its bound.
        queue.truncate(self.agent.limits.max_queue_len);
        state.queue = queue;
    }

    fn checkpoint(&self, state: &mut AgentState) {
        if let Some(f) = &self.agent.on_checkpoint {
            self.sync(state);
            f(state);
        }
    }

    /// Clean, de-duplicate and cap proposed tasks, then queue them.
    fn enqueue(
        &self,
        state: &mut AgentState,
        proposed: Vec<String>,
    ) -> Result<Enqueued, RunOutcome> {
        let limits = &self.agent.limits;
        let mut out = Enqueued {
            added: Vec::new(),
            repeated: None,
        };
        let mut drops = [0usize; 5];
        let reasons = [
            DropReason::Empty,
            DropReason::Duplicate,
            DropReason::Repeated,
            DropReason::PerStepLimit,
            DropReason::QueueFull,
        ];
        let mut queued: HashSet<String> = state
            .queue
            .iter()
            .map(|t| task_key(&t.description))
            .collect();
        for raw in proposed {
            if out.added.len() >= limits.max_new_tasks_per_step {
                drops[3] += 1;
                continue;
            }
            let Some(description) = clean_task(&raw, limits.max_task_bytes) else {
                drops[0] += 1;
                continue;
            };
            let key = task_key(&description);
            if key.is_empty() {
                drops[0] += 1;
                continue;
            }
            if queued.contains(&key) {
                drops[1] += 1;
                continue;
            }
            if state.task_counts.get(&key).copied().unwrap_or(0) >= limits.max_task_repeats {
                drops[2] += 1;
                out.repeated.get_or_insert(description);
                continue;
            }
            if state.queue.len() >= limits.max_queue_len {
                drops[4] += 1;
                continue;
            }
            if state.tasks_generated >= limits.max_generated_tasks {
                return Err(RunOutcome::BudgetExceeded(BudgetKind::GeneratedTasks));
            }
            state.tasks_generated += 1;
            let task = Task::new(state.next_task_id, description);
            state.next_task_id += 1;
            queued.insert(key);
            state.queue.push_back(task.clone());
            out.added.push(task);
        }
        for (count, reason) in drops.into_iter().zip(reasons) {
            if count > 0 {
                self.governor
                    .emit(&AutonomousEvent::TasksDropped { count, reason });
            }
        }
        Ok(out)
    }

    fn task_prompt(&self, state: &AgentState, task: &Task) -> String {
        format!(
            "Overall goal (from the user): {}\n\n\
             Results of earlier tasks:\n{}\n\n\
             Current task:\n{}\n\n\
             Complete the current task now and reply with its result.",
            state.goal,
            render_history(&state.history, self.agent.limits.max_context_bytes),
            fence("task", &format!("id=\"{}\"", task.id), &task.description),
        )
    }

    fn system_prompt(&self) -> String {
        let base = self
            .agent
            .system_prompt
            .as_deref()
            .unwrap_or(DEFAULT_SYSTEM_PROMPT);
        format!("{base}\n\n{UNTRUSTED_NOTICE}")
    }

    /// Run one task; returns its output and the number of tool calls.
    async fn execute(
        &self,
        state: &AgentState,
        task: &Task,
    ) -> Result<(String, usize), ChainError> {
        let input = self.task_prompt(state, task);
        let agent = self.agent;
        if agent.tools.is_empty() {
            let messages = [Message::system(self.system_prompt()), Message::human(input)];
            let result = self.llm.generate(&messages).await?;
            return Ok((result.generation, 0));
        }

        let remaining = self
            .governor
            .deadline()
            .map(|d| d.saturating_duration_since(Instant::now()));
        let wall = match (agent.task_limits.max_wall_time, remaining) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let llm: Arc<dyn Llm> = self.llm.clone();
        let mut fca = FunctionCallingAgent::new(llm)
            .limits(agent.task_limits.max_wall_time(wall))
            .tool_error_mode(agent.tool_error_mode)
            .fence_tool_outputs(true)
            .system_prompt(self.system_prompt());
        for (tool, needs_approval) in &agent.tools {
            let guarded = GuardedTool {
                inner: Arc::clone(tool),
                governor: Arc::clone(self.governor),
            };
            fca = if *needs_approval {
                fca.tool_requiring_approval(guarded)
            } else {
                fca.tool(guarded)
            };
        }
        if let Some(approver) = &agent.approver {
            fca = fca.approver(SharedApprover(Arc::clone(approver)));
        }
        if let Some(observer) = &agent.observer {
            let observer = Arc::clone(observer);
            let task_id = task.id;
            fca = fca.on_event(move |event: &AgentEvent| {
                observer.on_event(&AutonomousEvent::Agent {
                    task_id,
                    event: event.clone(),
                });
            });
        }
        let result = fca.run(&input).await?;
        Ok((result.output, result.tool_invocations.len()))
    }
}

struct SharedApprover(Arc<dyn Approver>);

#[async_trait]
impl Approver for SharedApprover {
    async fn approve(&self, request: ApprovalRequest) -> Approval {
        self.0.approve(request).await
    }
}

#[async_trait]
impl Chain for AutonomousAgent {
    /// Runs toward the `"input"` goal. A completed run returns the answer
    /// with the run's token usage; any other outcome is an error naming it.
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError> {
        let goal = input_variables
            .get("input")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable("input".to_owned()))?;
        let run = self.run(goal).await?;
        match run.outcome {
            RunOutcome::Completed { answer } => {
                Ok(GenerateResult::from_text(answer).with_tokens(run.state.usage))
            }
            other => Err(ChainError::Other(format!(
                "autonomous run did not complete: {other}"
            ))),
        }
    }

    fn input_keys(&self) -> Vec<String> {
        vec!["input".to_owned()]
    }
}
