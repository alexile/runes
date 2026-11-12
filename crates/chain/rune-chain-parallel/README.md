# rune-chain-parallel

> `ParallelChain` for rune-chain: fan-out with bounded concurrency, per-branch timeouts, fail-fast cancellation or collect-all errors, ordered outputs and summed usage.

[![crates.io](https://img.shields.io/crates/v/rune-chain-parallel)](https://crates.io/crates/rune-chain-parallel)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-parallel)](https://docs.rs/rune-chain-parallel)
[![license](https://img.shields.io/crates/l/rune-chain-parallel)](LICENSE)

## What it does

`ParallelChain` runs several chains on the same input concurrently, on the
calling task (nothing is spawned), and stores each answer under its branch's
output key.

- **Bounded concurrency** with `max_concurrency(n)`, or a `Semaphore` shared
  between chains (`with_semaphore`) to cap the load on a provider across a
  whole application.
- **Timeouts** per branch, or a default for all. Time spent waiting for a
  slot does not count.
- **Error handling**: `ErrorMode::FailFast` (default) returns the first
  failure and cancels the branches still running; `ErrorMode::CollectAll`
  lets every branch finish and reports each outcome from `run()`.
- **Deterministic output**: outcomes are in declaration order whatever order
  the branches finish in, and `call` returns the last declared branch's
  result.
- **Usage** summed across branches, cache and reasoning tokens included.

## Installation

```toml
[dependencies]
rune-chain-parallel = "0.3"
rune-chain-core = "0.2"
```

## Usage

```rust,ignore
use std::{sync::Arc, time::Duration};
use rune_chain_core::{Chain, prompt_args};
use rune_chain_parallel::{Branch, ErrorMode, ParallelChain, Semaphore};

// At most 4 requests in flight to this provider, across every fan-out.
let provider_limit = Arc::new(Semaphore::new(4));

let review = ParallelChain::new()
    .with_semaphore(Arc::clone(&provider_limit))
    .branch_timeout(Duration::from_secs(30))
    .branch(security_chain, "security")
    .branch(style_chain, "style")
    .with_branch(Branch::new(perf_chain, "performance").timeout(Duration::from_secs(60)))
    .error_mode(ErrorMode::CollectAll);

let run = review.run(prompt_args! { "diff" => diff }).await?;
for (key, error) in run.errors() {
    eprintln!("{key} review failed: {error}");
}
let answers = run.outputs();       // the branches that succeeded
let tokens = run.usage();          // summed over them
```

As a plain `Chain`:

```rust,ignore
let out = review.execute(prompt_args! { "diff" => diff }).await?;
println!("{}", out["security"]);
```

## Errors

- A branch timeout is a `ChainError::LlmError` of kind `LlmErrorKind::Timeout`
  naming the branch.
- With `CollectAll`, the `Chain` methods fail if any branch failed: a single
  failure comes back unchanged, several are summarised in a
  `ChainError::Other`. Use `run()` to get partial results.
- Duplicate, empty or reserved (`"generate_result"`) output keys fail every
  run before any branch starts; `validate()` checks them up front.

## Migrating from 0.2

- **Fail-fast now cancels.** On the first failure the remaining branches are
  dropped instead of being awaited.
- **The result keeps the last branch's finish reason**, tool calls and
  reasoning; only `tokens` is replaced by the sum.
- **`input_keys()` is the union** of every branch's input keys, not just the
  first branch's.
- **Duplicate output keys are an error** instead of silently overwriting.
- New: `Branch`, `with_branch`, `max_concurrency`, `with_semaphore`,
  `branch_timeout`, `error_mode` / `ErrorMode`, `validate`, `run` /
  `ParallelRun` / `BranchOutcome`, and the `Semaphore` re-export.

## License

MIT
