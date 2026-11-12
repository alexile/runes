# rune-chain-sequential

> `SequentialChain` — ordered `rune-chain` pipelines with build-time key checks, per-step timeouts and retries, early exit, step events and summed token usage.

[![crates.io](https://img.shields.io/crates/v/rune-chain-sequential)](https://crates.io/crates/rune-chain-sequential)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-sequential)](https://docs.rs/rune-chain-sequential)
[![license](https://img.shields.io/crates/l/rune-chain-sequential)](LICENSE)

## What it does

`SequentialChain` runs `Chain`s one after another. Each step's answer is
stored under its output key and is visible to every later step, alongside the
original input.

- **Wiring checked at build time.** `build()` rejects a step that needs a
  variable no declared input or earlier step provides, duplicate or reserved
  output keys, and output mappings the chain does not produce.
- **Key mapping.** `map_input("text", "draft")` hands a chain the `draft`
  variable under the name `text`; `map_output("title", "headline")` lifts an
  extra key out of a multi-output chain's `execute` map.
- **Timeouts** per step (or a default for all), per attempt.
- **Retries** per step with exponential backoff that honours a provider's
  retry-after. Transient errors (rate limits, overload, timeouts, network and
  server faults) are retried by default; plug in your own predicate.
- **Early exit**: `exit_if(|result| ...)` makes a step's answer final and
  skips the rest.
- **Events**: one callback receives `Started`, `Retrying`, `Finished`,
  `Failed` and `Exited` for each step, for logging and tracing.
- **Usage**: token usage (cache and reasoning tokens included) is summed
  across steps; `run()` also returns a report per step.
- **Streaming**: earlier steps run to completion, then the last step streams.

## Installation

```toml
[dependencies]
rune-chain-sequential = "0.3"
rune-chain-core = "0.2"
```

## Usage

```rust,ignore
use std::time::Duration;
use rune_chain_core::{Chain, prompt_args};
use rune_chain_llm::LlmChain;
use rune_chain_prompt::{ChatTemplate, MessageTemplate};
use rune_chain_sequential::{RetryPolicy, SequentialChain, Step, StepEvent};

let name_chain = LlmChain::new(llm.clone(), ChatTemplate::new(vec![
    MessageTemplate::human("Give a one-word name for a {category} store, or NONE."),
]));
let slogan_chain = LlmChain::new(llm, ChatTemplate::new(vec![
    MessageTemplate::human("Write a short slogan for a store called {store}."),
]));

let pipeline = SequentialChain::builder()
    .inputs(["category"])
    .step_timeout(Duration::from_secs(30))
    .step(
        Step::new(name_chain, "name")
            .retry(RetryPolicy::new(3))
            .exit_if(|r| r.generation.trim() == "NONE"),
    )
    .step(Step::new(slogan_chain, "slogan").map_input("store", "name"))
    .on_event(|e| {
        if let StepEvent::Finished { name, result, elapsed, .. } = e {
            tracing::info!(step = name, tokens = ?result.tokens, ?elapsed, "step done");
        }
    })
    .build()?; // a typo such as `{stroe}` in the template fails here

let run = pipeline.run(prompt_args! { "category" => "book" }).await?;
println!("{} (total {:?} tokens)", run.result.generation, run.usage());
```

## Output keys

`execute()` returns every step's output under its key (mapped outputs first,
then the step's own key), plus `"generate_result"` with the final
`GenerateResult`: the last step's result with usage summed over all steps.
After an early exit, skipped steps' keys hold `null` and the last step's key
holds the final answer.

## Errors

- A missing pipeline input fails with `ChainError::MissingVariable` before any
  step runs.
- A step timeout is a `ChainError::LlmError` of kind `LlmErrorKind::Timeout`
  naming the step, so retry and fallback layers treat it as transient.
- `BuildError` converts into `ChainError::Other` for use with `?`.

## Migrating from 0.2

- **Construction goes through the builder.** Replace
  `SequentialChain::new().chain(a, "x").chain(b, "y")` with
  `SequentialChain::builder().chain(a, "x").chain(b, "y").build()?`.
  `SequentialChain::new` and `Default` are gone.
- **Wiring is checked.** `build()` fails on duplicate output keys (including
  an output that shadows an input) and, when `inputs` are declared, on
  variables nothing provides.
- **Inputs are checked up front.** `input_keys()` now lists every variable the
  steps need that no earlier step produces (or the declared inputs), and a
  call missing one fails before the first step runs.
- **The final result keeps the last step's finish reason**, tool calls and
  reasoning; only `tokens` is replaced by the sum. 0.2 returned bare text.
- **`stream()` works**: it runs the earlier steps and streams the last one.
- New: `Step`, `RetryPolicy`, `is_transient`, `StepEvent`, `StepReport`,
  `SequentialRun`, `BuildError`, `SequentialChain::run`, `step_names`.

## License

MIT
