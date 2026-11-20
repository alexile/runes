# rune-chain-graph

> Stateful graph orchestration for LLM workflows and agents: typed state with reducers, parallel supersteps, checkpoints, time travel, human-in-the-loop interrupts and a prebuilt ReAct agent.

[![crates.io](https://img.shields.io/crates/v/rune-chain-graph)](https://crates.io/crates/rune-chain-graph)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-graph)](https://docs.rs/rune-chain-graph)
[![license](https://img.shields.io/crates/l/rune-chain-graph)](LICENSE)

## What it does

You describe a workflow as a graph of nodes over a shared, typed state. The
runner moves through it in supersteps, saving a checkpoint after each one, so
runs can loop, branch, fan out, pause for a person and resume later.

- **Typed state.** Your own struct. Nodes return a partial update and
  per-field reducers fold it in: `Replace`, `Append`, `AddMessages`
  (replace by `Message::id`), `Sum`, `MergeMap`, or your own `Reducer`.
  The `state!` macro writes the update type and the merge.
- **Nodes.** Async closures, any `Llm` (`LlmNode`, with tools and token
  streaming), tool execution (`ToolNode`) and any `Chain` (`ChainNode`).
- **Edges.** Fixed edges, routers that return one or more node names, `START`
  and `END`, parallel fan-out, `SendTo` for map-reduce over dynamic items,
  and `ctx.goto(..)` from inside a node.
- **Deterministic supersteps.** Every task of a step sees the same state
  snapshot; their updates merge in task order, however long each one took.
- **Checkpoints.** `InMemoryCheckpointer`, or `SqliteCheckpointer` with the
  `sqlite` feature. Resume a thread, list its history, edit its state, or
  replay from any past checkpoint.
- **Human in the loop.** `interrupt_before` / `interrupt_after` on nodes, and
  `ctx.interrupt(value)` inside a node. Continue with `Command::resume(..)`,
  `Command::goto(..)` or `Command::update(..)`.
- **Prebuilt agent.** `create_react_agent(llm, tools)`: model node, tool
  node and router, built from the same parts.
- **Diagram.** `draw_mermaid()` renders the graph as a Mermaid flowchart.

## Installation

```toml
[dependencies]
rune-chain-graph = "0.1"
rune-chain-core = "0.2"
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Or through the facade: `rune-chain = { version = "0.1", features = ["graph"] }`.

## Quick start

```rust
use std::sync::Arc;

use rune_chain_graph::{Append, END, GraphError, RunConfig, START, StateGraph, Sum, state};
use serde::{Deserialize, Serialize};

state! {
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct Essay => EssayUpdate {
        drafts: Vec<String> = Append,
        revisions: u32 = Sum,
    }
}

# tokio_test::block_on(async {
let mut graph = StateGraph::<Essay>::new();
graph
    .add_node("write", |s: Arc<Essay>, _ctx| async move {
        let draft = format!("draft {}", s.revisions + 1);
        Ok(EssayUpdate::default().drafts(vec![draft]).revisions(1))
    })
    .add_edge(START, "write")
    .add_conditional_edges(
        "write",
        |s: &Essay| if s.revisions < 3 { "write" } else { END },
        ["write", END],
    );
let app = graph.compile()?;

let out = app.invoke(Essay::default(), &RunConfig::default()).await?;
assert_eq!(out.state.drafts, ["draft 1", "draft 2", "draft 3"]);
# Ok::<(), GraphError>(())
# }).unwrap();
```

A tool-calling agent with a real model (any `rune-chain-core::Llm`):

```rust,ignore
use rune_chain_graph::{MessagesState, RunConfig, ToolExecutor, create_react_agent};

let agent = create_react_agent(llm, ToolExecutor::new().tool(search).tool(calculator))?;
let out = agent.invoke(MessagesState::new(vec![Message::human("What is 2^10?")]), &RunConfig::default()).await?;
println!("{}", out.state.last_text());
```

Pause before tools run so a person can approve them:

```rust,ignore
let app = react_agent_graph::<MessagesState>(llm, tools, None).compile_with(
    CompileOptions::default()
        .checkpointer(Arc::new(InMemoryCheckpointer::new()))
        .interrupt_before(["tools"]),
)?;
let config = RunConfig::thread("user-42");
let paused = app.invoke(question, &config).await?;          // stops before "tools"
let pending = &paused.state.messages.last().unwrap().tool_calls;
let done = app.invoke(Command::default(), &config).await?;  // approved: carry on
```

The `examples/` directory has a runnable react agent, a human approval flow
and a map-reduce, all offline:

```sh
cargo run -p rune-chain-graph --example react_agent
cargo run -p rune-chain-graph --example human_approval
cargo run -p rune-chain-graph --example map_reduce
```

## Coming from LangGraph

| LangGraph (Python) | rune-chain-graph |
|---|---|
| `class State(TypedDict)` with `Annotated[list, operator.add]` | `state! { struct S => SUpdate { items: Vec<T> = Append, .. } }` |
| `add_messages`, `MessagesState` | `AddMessages`, `MessagesState` / `MessagesUpdate` |
| `StateGraph(State)` | `StateGraph::<S>::new()` |
| `builder.add_node("name", fn)` | `graph.add_node("name", \|state, ctx\| async { Ok(update) })` |
| `add_edge(START, "a")`, `add_edge("a", END)` | `add_edge(START, "a")`, `add_edge("a", END)` |
| `add_conditional_edges("a", router, path_map)` | `add_conditional_edges("a", router, ["b", "c", END])` |
| `Send("node", state)` | `SendTo::new("node", update)` |
| `Command(goto="b", update=...)` returned by a node | `ctx.goto("b")` and return the update |
| `compile(checkpointer=MemorySaver())` | `compile_with(CompileOptions::default().checkpointer(Arc::new(InMemoryCheckpointer::new())))` |
| `SqliteSaver` | `SqliteCheckpointer` (feature `sqlite`) |
| `config={"configurable": {"thread_id": "1"}}` | `RunConfig::thread("1")` |
| `recursion_limit` (25) | `CompileOptions::recursion_limit` / `RunConfig::recursion_limit` (25) |
| `graph.invoke(input, config)` | `app.invoke(state, &config).await?` |
| `graph.stream(input, stream_mode="updates")` | `app.stream(state, &config)` yielding `Event::Update`, `Event::Token`, `Event::Done` |
| `interrupt_before=["tools"]` | `CompileOptions::interrupt_before(["tools"])` |
| `interrupt(value)` | `let answer: T = ctx.interrupt(value)?;` |
| `graph.invoke(Command(resume=v), config)` | `app.invoke(Command::resume(v), &config)` |
| `graph.invoke(None, config)` | `app.invoke(Command::default(), &config)` |
| `get_state`, `get_state_history`, `update_state(config, values, as_node)` | `get_state`, `get_state_history`, `update_state(&config, update, Some("node"))` |
| replay with `checkpoint_id` | `RunConfig::thread(t).checkpoint(id)` |
| `ToolNode`, `tools_condition` | `ToolNode`, `tools_condition` |
| `create_react_agent(model, tools)` | `create_react_agent(llm, ToolExecutor::new().tool(..))` |
| `graph.get_graph().draw_mermaid()` | `app.draw_mermaid()` |

Differences worth knowing:

- Updates are typed. A node returns `S::Update`, never a loose dict, and a
  router that names an unknown node or one outside its declared targets is an
  error, not a silent no-op.
- A node that calls `interrupt` runs again from the top on resume, as in
  LangGraph. All tasks of the paused superstep run again too, so keep side
  effects after the last `interrupt` or make them idempotent.
- `Message` ids are optional. `AddMessages` replaces a message only when it
  has an id (`Message::with_id`); otherwise it appends.

## Limits and safety

| Concern | Default |
|---|---|
| Runaway loops | 25 supersteps per run, then `GraphError::RecursionLimit` |
| Fan-out | at most 256 tasks per superstep, 16 running at once |
| Slow nodes | optional timeout for every node, or per node (`timeout_for`) |
| Stopping a run | `CancelToken` in `RunConfig`; dropping a stream cancels it too |
| Bad routing | unknown or undeclared targets fail the run; panicking nodes and routers become errors |
| Checkpoint size | 16 MiB per checkpoint on write; `SqliteCheckpointer` refuses oversized rows on read |
| Thread ids | 1-256 bytes, no control characters |
| Tool calls | `ToolNode` runs them through `rune-chain-agent`'s `ToolExecutor`: schema validation, calls-per-turn and concurrency limits, timeouts, output caps, approval gates, secret redaction and fenced output |

One run per thread at a time: two concurrent runs on the same thread would
interleave their checkpoints.

## License

MIT
