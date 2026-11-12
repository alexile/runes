# rune-chain-autonomous

> Autonomous goal-driven agent for rune-chain: plans tasks, executes them with
> tools, and self-evaluates until the goal is met.

[![crates.io](https://img.shields.io/crates/v/rune-chain-autonomous)](https://crates.io/crates/rune-chain-autonomous)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-autonomous)](https://docs.rs/rune-chain-autonomous)
[![license](https://img.shields.io/crates/l/rune-chain-autonomous)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-chain-agent`'s `AgentExecutor` and `FunctionCallingAgent` each answer a
single input in one bounded reasoning loop. `AutonomousAgent` sits a level
above: give it a **goal**, and it drives itself to completion with no further
input.

1. **Plan** — the LLM breaks the goal into an ordered list of concrete tasks.
2. **Execute** — each task runs in turn, calling registered tools as needed.
3. **Reflect** — once the plan is exhausted, the LLM judges whether the goal
   is fully achieved. If not, it produces a revised task list and the loop
   continues from step 2.

The run ends when reflection reports the goal is done (`Completed`), the
replanning limit is hit without success (`Blocked`), or the total step budget
runs out (`StepBudgetExhausted`) — whichever comes first.

## Installation

```toml
[dependencies]
rune-chain-autonomous = "0.2"
rune-chain-core        = "0.1"
```

## Usage

```rust,no_run
use std::sync::Arc;
use rune_chain_core::{Llm, Tool, ToolError};
use rune_chain_autonomous::AutonomousAgent;
use async_trait::async_trait;

struct WebSearch;

#[async_trait]
impl Tool for WebSearch {
    fn name(&self) -> &str { "web_search" }
    fn description(&self) -> &str { "Searches the web and returns a summary of results." }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        Ok(format!("search results for: {input}"))
    }
}

# async fn run() -> Result<(), rune_chain_core::ChainError> {
# let llm: Arc<dyn Llm> = unimplemented!();
let agent = AutonomousAgent::new(llm)
    .tool(WebSearch)
    .max_steps(25)
    .max_replans(3);

let result = agent.run("Compile a competitor pricing report for Acme Corp.").await?;

println!("status: {:?}", result.status);
println!("{}", result.output);

for plan in &result.plans {
    println!("plan: {plan:?}");
}
# Ok(())
# }
```

### As a `Chain`

`AutonomousAgent` implements `rune_chain_core::Chain`, so it composes with
sequential chains and other `rune-chain` building blocks:

```rust,no_run
use std::sync::Arc;
use rune_chain_core::{Chain, Llm, prompt_args};
use rune_chain_autonomous::AutonomousAgent;

# async fn run() -> Result<(), rune_chain_core::ChainError> {
# let llm: Arc<dyn Llm> = unimplemented!();
let agent = AutonomousAgent::new(llm);
let answer = agent.invoke(prompt_args! { "input" => "Ship the v2 release." }).await?;
println!("{answer}");
# Ok(())
# }
```

## Builder API

| Method | Description |
|---|---|
| `AutonomousAgent::new(llm)` | Create agent with an `Arc<dyn Llm>` |
| `.tool(t)` | Register a `Tool` implementation |
| `.max_steps(n)` | Cap total tasks executed across every plan (default: 25) |
| `.max_replans(n)` | Cap how many times reflection may revise the plan (default: 3) |
| `.max_tool_iterations(n)` | Cap tool-call rounds spent on a single task (default: 5) |
| `.system_prompt(s)` | Override the system prompt used while executing tasks |
| `.run(goal)` | Execute and return `AutonomousResult` |
| `.call(prompt_args)` | `Chain` interface — reads the `"input"` key as the goal |

## Output

`AutonomousResult` exposes everything the run did, not just the final answer:

```text
status: Completed
output: "Competitor pricing report compiled and saved."

plans:
["Search competitor pricing pages", "Summarize findings"]

history:
1. Search competitor pricing pages -> found 4 competitors with public pricing
2. Summarize findings -> report compiled and saved
```

If the agent gets stuck, `status` is `Blocked(reason)` after
`max_replans` revisions fail to close the goal, or `StepBudgetExhausted` if
`max_steps` tasks run out first — either way, `history` and `plans` show
exactly how far it got.

## Design notes

- Tasks run with native function calling (`Llm::generate_with_tools`) when
  tools are registered, and fall back to plain `generate` otherwise — so an
  `AutonomousAgent` with no tools works against any `Llm`, including
  providers without function-calling support.
- Planning and reflection prompts are deliberately strict about output format
  (`STATUS: DONE` / `STATUS: CONTINUE`), but parsing falls back to a lenient
  heuristic if a model drifts from it, rather than failing the run outright.

## Migrating from 0.1

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- No behaviour change.

## License

MIT
