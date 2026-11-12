# rune-chain-autonomous

> Budgeted autonomous agent for rune-chain: plans and runs tasks toward a goal
> under hard limits, with loop detection, approval-gated tools, checkpoints
> and events.

[![crates.io](https://img.shields.io/crates/v/rune-chain-autonomous)](https://crates.io/crates/rune-chain-autonomous)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-autonomous)](https://docs.rs/rune-chain-autonomous)
[![license](https://img.shields.io/crates/l/rune-chain-autonomous)](LICENSE)

## What it does

`rune-chain-agent`'s agents answer one input in one bounded tool loop.
`AutonomousAgent` sits a level above, in the style of AutoGPT and BabyAGI:
give it a **goal** and it works toward it on its own.

1. **Plan.** A `TaskPlanner` turns the goal into a queue of tasks.
2. **Execute.** Tasks run one at a time. With tools registered, each task runs
   in `rune-chain-agent`'s `FunctionCallingAgent` (schema validation, approval,
   fenced output, per-task limits). Without tools a task is one LLM call.
3. **Review.** When the queue is empty, the planner either declares the goal
   done or queues more work.

Every run ends with a `RunOutcome`:

| Outcome | Meaning |
|---|---|
| `Completed { answer }` | The review declared the goal done |
| `BudgetExceeded(kind)` | A limit was hit: tasks, cycles, LLM calls, wall time, tokens, cost, generated tasks |
| `LoopDetected(kind)` | The same task or the same tool call kept coming back, or a review proposed nothing new |
| `Stopped(cause)` | The caller's `StopHandle` or `stop_when` predicate stopped it |
| `Error { message }` | An LLM call failed (message truncated and redacted) |

The outcome comes with an `AgentState` that serializes with serde and can be
resumed.

## Installation

```toml
[dependencies]
rune-chain-autonomous = "0.2"
rune-chain-core       = "0.2"
```

## Usage

```rust,no_run
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rune_chain_autonomous::{
    Approval, ApprovalRequest, AutonomousAgent, AutonomousEvent, Limits, RunOutcome,
};
use rune_chain_core::{Cost, Llm, Pricing, Tool, ToolError};

struct WebSearch;

#[async_trait]
impl Tool for WebSearch {
    fn name(&self) -> &str { "web_search" }
    fn description(&self) -> &str { "Searches the web and returns a summary of results." }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        Ok(format!("search results for: {input}"))
    }
}

struct SendEmail;

#[async_trait]
impl Tool for SendEmail {
    fn name(&self) -> &str { "send_email" }
    fn description(&self) -> &str { "Sends an email." }
    async fn run(&self, _input: &str) -> Result<String, ToolError> { Ok("sent".into()) }
}

# async fn run() -> Result<(), rune_chain_core::ChainError> {
# let llm: Arc<dyn Llm> = unimplemented!();
let agent = AutonomousAgent::new(llm)
    .tool(WebSearch)
    .tool_requiring_approval(SendEmail)
    .approver(|req: ApprovalRequest| async move {
        // Ask a human, check a policy, ...
        Approval::Deny(format!("{} needs sign-off", req.tool))
    })
    .pricing(Pricing::per_mtok(3_000_000, 15_000_000))
    .limits(
        Limits::default()
            .max_tasks(15)
            .max_wall_time(Some(Duration::from_secs(300)))
            .max_cost(Some(Cost::from_cents(50))),
    )
    .on_event(|e: &AutonomousEvent| println!("{e:?}"))
    .on_checkpoint(|state| {
        let _json = serde_json::to_string(state); // persist somewhere safe
    });

let run = agent.run("Compile a competitor pricing report for Acme Corp.").await?;
match &run.outcome {
    RunOutcome::Completed { answer } => println!("{answer}"),
    other => println!("stopped early ({other}); last result: {}", run.output()),
}
println!("{} LLM calls, {}", run.state.llm_calls, run.state.cost);
# Ok(())
# }
```

### Resuming

```rust,no_run
# use std::sync::Arc;
# use rune_chain_autonomous::{AgentState, AutonomousAgent};
# async fn run(agent: AutonomousAgent, saved_json: &str) -> Result<(), Box<dyn std::error::Error>> {
let state: AgentState = serde_json::from_str(saved_json)?;
let run = agent.resume(state).await?;
# Ok(())
# }
```

Spent budget carries over, so a run that ran out of budget only continues if
the resuming agent has higher limits, or after an explicit
`state.reset_budget()`.

### Planners

`LlmPlanner` (the default) asks the model for a numbered task list and
reviews with a strict `STATUS: DONE` / `STATUS: CONTINUE` format. With
`.create_tasks_after_each(true)` it also proposes follow-up tasks after every
task, BabyAGI-style. `StaticPlanner` runs a fixed list with no planning calls.
Implement `TaskPlanner` for your own planning and `prioritize` to reorder the
queue.

### Events

`on_event` takes a closure or a `tokio::sync::mpsc::UnboundedSender`, so a run
can feed an event stream: run start, queued and dropped tasks, task start and
finish, every tool call and result (from `rune-chain-agent`), running token
and cost totals after each LLM call, reviews and the final outcome.

### As a `Chain`

`AutonomousAgent` implements `rune_chain_core::Chain` with the `"input"` key as
the goal. A completed run returns the answer with the run's token usage; any
other outcome is an error that names it.

## Security

An autonomous loop lets model output decide what happens next, again and
again. The agent treats that output as possibly wrong or hostile.

- **Hard limits, all on by default.** 25 tasks, 4 planning cycles, 100 LLM
  calls, 10 minutes, 200 000 tokens, $1.00 (when a `Pricing` is set), 100
  generated tasks, 20 queued tasks, 10 new tasks per planner reply. One
  governor wraps the LLM for the planner, the task loop and custom planners
  alike, and checks the limits before every call, so spend can overshoot by
  at most the call in flight. Wall time also bounds each LLM call and tool
  call.
- **Stopping is not up to the model.** Limits are configuration, never part
  of a prompt. `StopHandle::stop` and `stop_when` end a run from outside. The
  model can end a run early by declaring the goal done, but nothing it writes
  can extend one. A review reply without a `STATUS:` line is an error rather
  than being read as "done".
- **Loop detection.** A task (compared case- and punctuation-insensitively)
  runs at most `max_task_repeats` times (2). A review that only proposes such
  tasks, or none, ends the run with `LoopDetected`. A tool called with
  identical arguments more than `max_identical_tool_calls` times (3) is
  refused and ends the run.
- **Tool calls are checked.** Unknown tools and arguments that do not match
  the tool's JSON schema are rejected before anything runs. Tools registered
  with `tool_requiring_approval` need an `Approver` (fail-closed without one),
  which can allow, deny or edit (re-validated) each call. Tool calls have
  timeouts, output size caps and secret redaction in errors.
- **Untrusted text is fenced.** Generated tasks, task results and tool output
  only ever appear in user or tool turns, inside `<task>`, `<task_result>` and
  `<tool_output>` blocks whose closing tags are escaped if they show up in the
  content. System prompts are fixed and tell the model that fenced text is
  data. Task text is cleaned to a single line and capped at 500 bytes.
- **Bounded memory.** The state keeps the last 20 task records, each result
  capped at 4 KiB, and prompts quote at most 16 KiB of earlier results.
- **Checkpoints.** Resuming re-applies the size bounds and rejects unknown
  checkpoint versions, but trusts the spend counters. Keep checkpoints where
  the model and its tools cannot write.

What it does not do: it cannot tell whether a tool's side effects are safe.
Put anything with real-world effects behind `tool_requiring_approval`, and
keep tools narrow.

## Migrating from 0.1

- Uses `rune-chain-core` 0.2 and `rune-chain-agent` 0.3.
- `AutonomousAgent::run` returns `AutonomousRun { outcome, state }` instead of
  `AutonomousResult`. `RunStatus::Completed`, `Blocked` and
  `StepBudgetExhausted` became `RunOutcome::Completed { answer }`,
  `LoopDetected` / `BudgetExceeded(Cycles)` and `BudgetExceeded(Tasks)`.
  `result.output` is `run.output()`, `result.history` is `run.state.history`
  (now `TaskRecord`s with `task.description` and `result`), and
  `result.tokens` is `run.usage()`. Per-cycle plans are reported through
  `AutonomousEvent::Planned` instead of a `plans` field.
- LLM failures no longer return `Err` from `run`; they end the run with
  `RunOutcome::Error`. `run` only fails for invalid tool sets.
- `max_steps` is `max_tasks`, `max_replans(n)` is `max_cycles(n + 1)`, and
  `max_tool_iterations(n)` is `task_limits(AgentLimits::default().max_iterations(n))`.
- New limits are on by default (wall time, LLM calls, tokens, cost with
  pricing, queue length, repeats). Raise them with `Limits` if a workload
  needs more.
- Tools now go through `rune-chain-agent`'s checks: arguments must match the
  tool's schema, and tool output reaches the model fenced.
- Review replies without `STATUS:` are no longer guessed at; one without a
  numbered list is an error.
- `Chain::call` returns an error for runs that did not complete instead of
  the last partial result.

## License

MIT
