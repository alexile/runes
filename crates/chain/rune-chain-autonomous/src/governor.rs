//! The run governor: every LLM call and tool call of a run goes through it,
//! so the hard limits hold no matter which component (planner, task loop,
//! tool) makes the call.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use rune_chain_core::{
    Cost, FunctionDefinition, GenerateResult, Llm, LlmError, Message, Pricing, TokenUsage, Tool,
    ToolChoice, ToolError,
};
use tokio::time::Instant;

use crate::event::{AutonomousEvent, AutonomousObserver};
use crate::untrusted::tool_call_key;
use crate::{AgentState, BudgetKind, Limits, LoopKind, RunOutcome, StopCause, StopHandle};

#[derive(Default)]
struct Counters {
    calls: usize,
    usage: Option<TokenUsage>,
    cost: Cost,
    tool_calls: BTreeMap<String, u32>,
    halted: Option<RunOutcome>,
}

pub struct Governor {
    limits: Limits,
    pricing: Option<Pricing>,
    deadline: Option<Instant>,
    stop: StopHandle,
    observer: Option<Arc<dyn AutonomousObserver>>,
    counters: Mutex<Counters>,
}

impl Governor {
    pub fn new(
        limits: Limits,
        pricing: Option<Pricing>,
        deadline: Option<Instant>,
        stop: StopHandle,
        observer: Option<Arc<dyn AutonomousObserver>>,
        state: &AgentState,
    ) -> Self {
        Self {
            limits,
            pricing,
            deadline,
            stop,
            observer,
            counters: Mutex::new(Counters {
                calls: state.llm_calls,
                usage: state.usage.clone(),
                cost: state.cost,
                tool_calls: state.tool_call_counts.clone(),
                halted: None,
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Counters> {
        // The counters stay consistent even if a holder panicked.
        self.counters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// The outcome the run must end with, if any limit is hit or a stop was
    /// requested. Latches: once halted, always halted.
    pub fn check(&self) -> Option<RunOutcome> {
        let mut c = self.lock();
        if c.halted.is_none() {
            c.halted = self.evaluate(&c);
        }
        c.halted.clone()
    }

    fn evaluate(&self, c: &Counters) -> Option<RunOutcome> {
        let l = &self.limits;
        if self.stop.is_stopped() {
            return Some(RunOutcome::Stopped(StopCause::Requested));
        }
        let budget = if self.deadline.is_some_and(|d| Instant::now() >= d) {
            Some(BudgetKind::WallTime)
        } else if c.calls >= l.max_llm_calls {
            Some(BudgetKind::LlmCalls)
        } else if l
            .max_total_tokens
            .is_some_and(|max| c.usage.as_ref().map_or(0, |u| u64::from(u.total_tokens)) >= max)
        {
            Some(BudgetKind::Tokens)
        } else if self.pricing.is_some() && l.max_cost.is_some_and(|max| c.cost >= max) {
            Some(BudgetKind::Cost)
        } else {
            None
        };
        budget.map(RunOutcome::BudgetExceeded)
    }

    pub fn halt(&self, outcome: RunOutcome) {
        let mut c = self.lock();
        if c.halted.is_none() {
            c.halted = Some(outcome);
        }
    }

    /// The outcome latched by an earlier [`check`](Self::check) or
    /// [`halt`](Self::halt), without evaluating limits again.
    pub fn halted(&self) -> Option<RunOutcome> {
        self.lock().halted.clone()
    }

    /// Copy the spend counters into `state`.
    pub fn sync(&self, state: &mut AgentState) {
        let c = self.lock();
        state.llm_calls = c.calls;
        state.usage.clone_from(&c.usage);
        state.cost = c.cost;
        state.tool_call_counts.clone_from(&c.tool_calls);
    }

    fn before_call(&self) -> Result<(), LlmError> {
        let halted = {
            let mut c = self.lock();
            if c.halted.is_none() {
                c.halted = self.evaluate(&c);
            }
            if c.halted.is_none() {
                c.calls += 1;
            }
            c.halted.clone()
        };
        halted.map_or(Ok(()), |outcome| {
            Err(LlmError::other(format!("autonomous run halted: {outcome}")))
        })
    }

    fn after_call(&self, usage: Option<&TokenUsage>) {
        let event = {
            let mut c = self.lock();
            TokenUsage::accumulate(&mut c.usage, usage);
            if let (Some(p), Some(u)) = (&self.pricing, usage) {
                c.cost += p.cost(u);
            }
            AutonomousEvent::LlmCall {
                calls: c.calls,
                usage: c.usage.clone(),
                cost: c.cost,
            }
        };
        self.emit(&event);
    }

    pub fn emit(&self, event: &AutonomousEvent) {
        if let Some(o) = &self.observer {
            o.on_event(event);
        }
    }

    /// Count a tool call; `Err` once the identical call exceeds the limit.
    fn count_tool_call(&self, tool: &str, arguments: &str) -> Result<(), ToolError> {
        if let Some(outcome) = self.check() {
            return Err(ToolError::ExecutionFailed(format!(
                "not run: autonomous run halted ({outcome})"
            )));
        }
        let max = self.limits.max_identical_tool_calls;
        let key = tool_call_key(tool, arguments);
        let mut c = self.lock();
        let n = c.tool_calls.entry(key).or_insert(0);
        *n = n.saturating_add(1);
        let repeated = *n > max;
        drop(c);
        if repeated {
            self.halt(RunOutcome::LoopDetected(LoopKind::RepeatedToolCall {
                tool: tool.to_owned(),
            }));
            return Err(ToolError::ExecutionFailed(format!(
                "not run: this exact call was already made {max} times"
            )));
        }
        Ok(())
    }

    async fn guarded<F>(&self, call: F) -> Result<GenerateResult, LlmError>
    where
        F: Future<Output = Result<GenerateResult, LlmError>> + Send,
    {
        self.before_call()?;
        let result = match self.deadline {
            Some(d) => {
                if let Ok(r) = tokio::time::timeout_at(d, call).await {
                    r
                } else {
                    self.halt(RunOutcome::BudgetExceeded(BudgetKind::WallTime));
                    return Err(LlmError::timeout(
                        "autonomous run halted: wall-time limit reached",
                    ));
                }
            }
            None => call.await,
        }?;
        self.after_call(result.tokens.as_ref());
        Ok(result)
    }
}

/// The LLM as seen by every component of a run.
pub struct GovernedLlm {
    pub inner: Arc<dyn Llm>,
    pub governor: Arc<Governor>,
}

#[async_trait]
impl Llm for GovernedLlm {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        self.governor.guarded(self.inner.generate(messages)).await
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        self.governor
            .guarded(self.inner.generate_with_tools(messages, tools, tool_choice))
            .await
    }
}

/// A registered tool wrapped so identical calls are counted across the run.
pub struct GuardedTool {
    pub inner: Arc<dyn Tool>,
    pub governor: Arc<Governor>,
}

#[async_trait]
impl Tool for GuardedTool {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn description(&self) -> &str {
        self.inner.description()
    }

    fn schema(&self) -> serde_json::Value {
        self.inner.schema()
    }

    fn function_definition(&self) -> FunctionDefinition {
        self.inner.function_definition()
    }

    async fn run(&self, input: &str) -> Result<String, ToolError> {
        self.governor.count_tool_call(self.inner.name(), input)?;
        self.inner.run(input).await
    }
}
