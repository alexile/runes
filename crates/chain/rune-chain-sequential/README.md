# rune-chain-sequential

> `SequentialChain` — run `rune-chain` chains in order, piping each output as input to the next.

[![crates.io](https://img.shields.io/crates/v/rune-chain-sequential)](https://crates.io/crates/rune-chain-sequential)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-sequential)](https://docs.rs/rune-chain-sequential)
[![license](https://img.shields.io/crates/l/rune-chain-sequential)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`SequentialChain` lets you wire multiple `Chain` impls into an ordered pipeline.
Each step declares an output key; that key and the generated text are merged into
the running variable map so later steps can reference them as template variables.
Token usage is summed across all steps.

## Installation

```toml
[dependencies]
rune-chain-sequential = "0.2"
rune-chain-core = "0.2"
```

## Usage

```rust,no_run
use rune_chain_sequential::SequentialChain;
use rune_chain_llm::LlmChain;
use rune_chain_anthropic::Anthropic;
use rune_chain_prompt::{ChatTemplate, MessageTemplate};
use rune_chain_core::{Chain, prompt_args};

#[tokio::main]
async fn main() {
    let llm = Anthropic::from_env().unwrap();

    // Step 1: generate a product name
    let name_chain = LlmChain::new(
        Anthropic::from_env().unwrap(),
        ChatTemplate::new(vec![
            MessageTemplate::human("Give a one-word product name for a {category} store."),
        ]),
    );

    // Step 2: write a slogan using the name from step 1
    let slogan_chain = LlmChain::new(
        Anthropic::from_env().unwrap(),
        ChatTemplate::new(vec![
            MessageTemplate::human("Write a short slogan for a store called {name}."),
        ]),
    );

    let pipeline = SequentialChain::new()
        .chain(name_chain, "name")
        .chain(slogan_chain, "slogan");

    let result = pipeline
        .invoke(prompt_args! { "category" => "book" })
        .await
        .unwrap();

    println!("{result}");
}
```

## Output keys

Each step's text output is stored under its declared key. `execute()` returns a
map with all step outputs plus `"generate_result"` containing the final
`GenerateResult` (with summed token usage).

## Migrating from 0.1

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- No behaviour change; aggregated usage now also sums cache and reasoning tokens.

## License

MIT
