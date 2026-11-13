# rune-chain-agent

> Hardened tool-calling agents for rune-chain: ReAct and native function calling with schema validation, limits, approval and fenced tool output.

[![crates.io](https://img.shields.io/crates/v/rune-chain-agent)](https://crates.io/crates/rune-chain-agent)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-agent)](https://docs.rs/rune-chain-agent)
[![license](https://img.shields.io/crates/l/rune-chain-agent)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Two agent loops over any `rune-chain-core::Llm`:

- `FunctionCallingAgent` uses the provider's native tool calling (`Llm::generate_with_tools`).
  Several calls in one turn run concurrently, and their results go back in call order.
- `AgentExecutor` is a text [ReAct](https://arxiv.org/abs/2210.03629) loop
  (`Thought` / `Action` / `Action Input` / `Observation` / `Final Answer`). It works with any model.

The model decides which tools run, and tool output goes back into the model, so the agent
treats both directions as untrusted:

| Concern | What the agent does |
|---|---|
| Bad calls | Each call is checked against the tool's schema with `ToolCall::validate` (1 MiB cap) before it runs. An unknown tool or invalid arguments become an error result for the model, never a panic. Invalid or duplicate tool names are rejected when the run starts. |
| Runaway loops | `AgentLimits` sets the iterations (10), tool calls per turn (16, extra calls are answered `skipped`), concurrency (4), per-tool timeout (60 s), total wall time (10 min) and output size (64 KiB, cut with a `[truncated N bytes]` marker). |
| Indirect prompt injection | Tool output is wrapped in `<tool_output tool=".." status="..">` fences. Closing tags inside the output are escaped, and the system prompt says fenced text is data. Tool output never changes the system prompt. ReAct drops `Observation:` lines that the model writes itself. |
| Sensitive tools | `tool_requiring_approval` plus an async `Approver` that can allow a call, deny it, or edit its arguments. Edited arguments are validated again. Without an approver, these tools never run. |
| Failures | Tool errors, timeouts and panics go back to the model as results (`ToolErrorMode::ReturnToModel`), truncated to 1 KiB with secrets redacted. Set `ToolErrorMode::Abort` to fail the run instead. |
| Observability | `on_event` receives `StepStarted`, `ToolCalled`, `ToolResult`, `FinalAnswer` and `Stopped` events. |

The timeouts use Tokio's timer, so run agents inside a Tokio runtime.

## Installation

```toml
[dependencies]
rune-chain-agent = "0.3"
rune-chain-core  = "0.1"
```

## Usage

```rust,no_run
use std::{sync::Arc, time::Duration};

use rune_chain_agent::{AgentEvent, AgentLimits, Approval, ApprovalRequest, FunctionCallingAgent};
use rune_chain_core::Llm;

# async fn run(llm: Arc<dyn Llm>, search: impl rune_chain_core::Tool + 'static,
#              send_email: impl rune_chain_core::Tool + 'static) -> Result<(), rune_chain_core::ChainError> {
let agent = FunctionCallingAgent::new(llm)
    .tool(search)
    .tool_requiring_approval(send_email)
    .approver(|req: ApprovalRequest| async move {
        if req.arguments.contains("@example.com") { Approval::Allow } else { Approval::Deny("external recipient".into()) }
    })
    .limits(
        AgentLimits::default()
            .max_iterations(6)
            .tool_timeout(Some(Duration::from_secs(10)))
            .max_tool_output_bytes(16 * 1024),
    )
    .on_event(|e: &AgentEvent| eprintln!("{e:?}"));

let result = agent.run("Find the release date and email it to ops@example.com").await?;
println!("{} ({:?}, {} tool calls)", result.output, result.stop_reason, result.tool_invocations.len());
# Ok(())
# }
```

Both agents implement `rune_chain_core::Chain` and read the `"input"` key. Through `Chain`,
a run that stops on a limit is an error, so a half-finished answer is never passed on. `run`
returns it with `stop_reason` set.

## Builder API

| Method | Description |
|---|---|
| `::new(llm)` | Create an agent with an `Arc<dyn Llm>` and default limits |
| `.tool(t)` / `.tools(boxed)` | Register tools |
| `.tool_requiring_approval(t)` | Register a tool that runs only after the approver allows it |
| `.approver(a)` | `impl Approver`, e.g. an `async` closure over `ApprovalRequest` |
| `.limits(AgentLimits)` / `.max_iterations(n)` | Resource limits |
| `.tool_error_mode(mode)` | `ReturnToModel` (default) or `Abort` |
| `.fence_tool_outputs(bool)` | Fence tool output (default on) |
| `.on_event(f)` | Observer for `AgentEvent`s |
| `.system_prompt(s)` | Override the system prompt; the untrusted-output notice is still appended |
| `.tool_choice(c)` | `FunctionCallingAgent` only |

## Migrating from 0.2

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- No behaviour change in the agents themselves; build `GenerateResult`s in custom `Llm`s with the core builders.

## Migrating from 0.1

- `AgentResult` and `FunctionAgentResult` are `#[non_exhaustive]` and have new fields: `stop_reason` and `tool_invocations: Vec<ToolInvocation>`.
  `FunctionAgentResult::tool_invocations` used to hold `(name, input, output)` tuples. Use `.name`, `.arguments` and `.output` instead.
- Tool calls are validated before they run. A tool that reads JSON arguments must declare them in `Tool::schema`.
  The default schema needs `{"input": string}`; it does not set `"additionalProperties": false`, so extra
  arguments pass unless your schema closes the object.
- Tool output reaches the model fenced in `<tool_output>` tags, and a notice is appended to the system prompt.
  Call `.fence_tool_outputs(false)` to get the old raw output.
  `AgentResult::scratchpad` still records unfenced observations.
- New default limits apply: 60 s per tool, 10 min per run, 64 KiB of tool output, 16 calls per turn.
  Raise them with `.limits(...)`.
- With native tool calling, several calls in one turn now run concurrently, up to 4 at a time.
- Through `Chain::call`, a run that hits a limit returns `ChainError::Other` instead of the last partial response.
- Registering two tools with the same name, or a name that is not 1-64 `[A-Za-z0-9_-]` characters, fails the run.
- Agents need a Tokio runtime with the time driver enabled.

## License

MIT
