# rune-chain-conversational

> `ConversationalChain` — LLM + memory for ergonomic multi-turn dialogue.

[![crates.io](https://img.shields.io/crates/v/rune-chain-conversational)](https://crates.io/crates/rune-chain-conversational)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-conversational)](https://docs.rs/rune-chain-conversational)
[![license](https://img.shields.io/crates/l/rune-chain-conversational)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`ConversationalChain` wires an LLM with an in-process memory store for multi-turn
conversation. Every call saves the human turn and AI response; the next call
automatically sees the full prior context. Backed by `SimpleMemory` by default —
swap in `WindowedMemory` to cap the context window.

## Installation

```toml
[dependencies]
rune-chain-conversational = "0.2"
rune-chain-core = "0.2"
```

## Usage

```rust,no_run
use rune_chain_conversational::ConversationalChain;
use rune_chain_anthropic::Anthropic;
use rune_chain_core::{Chain, prompt_args};

#[tokio::main]
async fn main() {
    let chain = ConversationalChain::new(Anthropic::from_env().unwrap())
        .with_system("You are a helpful coding assistant.");

    let r1 = chain.invoke(prompt_args! { "input" => "What is a Rust lifetime?" }).await.unwrap();
    println!("{r1}");

    // Memory is automatic — no extra setup needed.
    let r2 = chain.invoke(prompt_args! { "input" => "Give me an example." }).await.unwrap();
    println!("{r2}");
}
```

## Custom memory

```rust,no_run
use std::sync::Arc;
use rune_chain_conversational::ConversationalChain;
use rune_chain_anthropic::Anthropic;
use rune_chain_memory::WindowedMemory;

let chain = ConversationalChain::new(Anthropic::from_env().unwrap())
    .with_memory(Arc::new(WindowedMemory::new(20))); // keep last 20 messages
```

## Migrating from 0.1

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- No behaviour change.

## License

MIT
