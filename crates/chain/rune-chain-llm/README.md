# rune-chain-llm

> LlmChain — wire a prompt template, an LLM, and optional memory into a single Chain.

[![crates.io](https://img.shields.io/crates/v/rune-chain-llm)](https://crates.io/crates/rune-chain-llm)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-llm)](https://docs.rs/rune-chain-llm)
[![license](https://img.shields.io/crates/l/rune-chain-llm)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-chain-llm` is the main composition point in the `rune-chain` ecosystem. It wires together:

- A `ChatTemplate` from `rune-chain-prompt` for `{variable}` interpolation
- Any `Llm` implementation (e.g. `rune-chain-openai`)
- An optional `Memory` store (e.g. from `rune-chain-memory`) for conversation history
- A token budget guard via `rune-tokenize`

Into a single `LlmChain` that implements the `Chain` trait.

## Installation

```toml
[dependencies]
rune-chain-llm = "0.2"
rune-chain-openai = "0.2"   # or any other Llm provider
rune-chain-memory = "0.2"   # optional, for conversation history
```

## Usage

One-shot question answering:

```rust,no_run
use rune_chain_llm::LlmChain;
use rune_chain_openai::OpenAi;
use rune_chain_prompt::{ChatTemplate, MessageTemplate};
use rune_chain_core::{Chain, prompt_args};

let llm = OpenAi::from_env()?;

let chain = LlmChain::new(llm, ChatTemplate::new(vec![
    MessageTemplate::system("You are a helpful assistant."),
    MessageTemplate::human("{question}"),
]));

let answer = chain.invoke(prompt_args! { "question" => "What is Rust?" }).await?;
println!("{answer}");
```

Multi-turn conversation with memory:

```rust,no_run
use std::sync::Arc;
use rune_chain_llm::LlmChain;
use rune_chain_openai::OpenAi;
use rune_chain_memory::SimpleMemory;
use rune_chain_prompt::{ChatTemplate, MessageTemplate};
use rune_chain_core::{Chain, prompt_args};

let chain = LlmChain::new(OpenAi::from_env()?, ChatTemplate::new(vec![
    MessageTemplate::system("You are a helpful assistant."),
    MessageTemplate::human("{input}"),
]))
.with_memory(Arc::new(SimpleMemory::new()))
.with_max_context_tokens(4096);

// Each call carries forward the conversation
let _ = chain.invoke(prompt_args! { "input" => "My name is Alice." }).await?;
let reply = chain.invoke(prompt_args! { "input" => "What is my name?" }).await?;
println!("{reply}"); // "Your name is Alice."
```

## Message order

On every call, messages reach the LLM in this order:

```
System (from template, always first)
↓ prior Human / Ai turns (from memory)
↓ current Human input (from template)
```

`System` messages are never written to memory — they are re-applied fresh from the template on every call.

## Migrating from 0.1

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- No behaviour change.

## License

MIT
