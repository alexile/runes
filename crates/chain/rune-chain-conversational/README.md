# rune-chain-conversational

> `ConversationalChain` — multi-turn dialogue with a pinned system prompt, bounded memory, and streams that still land in memory.

[![crates.io](https://img.shields.io/crates/v/rune-chain-conversational)](https://crates.io/crates/rune-chain-conversational)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-conversational)](https://docs.rs/rune-chain-conversational)
[![license](https://img.shields.io/crates/l/rune-chain-conversational)](LICENSE)

## What it does

`ConversationalChain` wires an LLM to a conversation memory. Every call sends:

```text
System prompt (pinned, never stored in memory)
↓ history (a running summary first, for summarizing memories)
↓ the new human message
```

and then records the human message and the answer.

- **Bounded by default**: history lives in a `TokenBufferMemory` of about
  4 000 tokens (`DEFAULT_HISTORY_TOKENS`), so long chats do not overflow the
  context window.
- **Pinned system prompt**: it is kept out of memory, so no eviction or
  summarization policy can drop or reorder it. It is sent verbatim, with no
  template substitution.
- **Any `rune-chain-memory` policy**: token budget, sliding window, LLM-written
  summaries, or your own `Memory`.
- **Streaming**: once a stream has been read to the end, the full answer is
  recorded in memory. A stream that fails or is dropped early records nothing,
  and so does a failed call.
- `call` returns the model's `GenerateResult` unchanged, so token usage and
  the finish reason are available.

## Installation

```toml
[dependencies]
rune-chain-conversational = "0.3"
rune-chain-core = "0.2"
rune-chain-memory = "0.2"   # for LlmSummarizer or a custom memory
```

## Usage

```rust,ignore
use rune_chain_conversational::ConversationalChain;
use rune_chain_anthropic::Anthropic;
use rune_chain_core::{Chain, prompt_args};

let chain = ConversationalChain::new(Anthropic::from_env()?)
    .with_system("You are a helpful coding assistant.");

let r1 = chain.invoke(prompt_args! { "input" => "What is a Rust lifetime?" }).await?;
let r2 = chain.invoke(prompt_args! { "input" => "Give me an example." }).await?;
```

## Choosing the history policy

```rust,ignore
use std::sync::Arc;
use rune_chain_memory::{LlmSummarizer, TokenBufferMemory};

// Newest turns within ~8k tokens (character estimate).
let chain = ConversationalChain::new(llm).with_token_budget(8_000);

// Newest turns within a budget measured by your tokenizer.
let chain = ConversationalChain::new(llm).with_memory(Arc::new(
    TokenBufferMemory::new(8_000, |m: &Message| tokenizer.count(&m.content.text_content())),
));

// Recent turns verbatim, older ones folded into an LLM-written summary.
let chain = ConversationalChain::new(llm)
    .with_summary(LlmSummarizer::new(Arc::new(cheap_llm)), 4_000);

// Last 20 messages, or everything (unbounded).
let chain = ConversationalChain::new(llm).with_window(20);
let chain = ConversationalChain::new(llm).with_unbounded_history();
```

## Streaming

```rust,ignore
use futures::StreamExt;

let mut stream = chain.stream(prompt_args! { "input" => "Tell me a story." }).await?;
while let Some(chunk) = stream.next().await {
    print!("{}", chunk?.content);
}
// The human message and the full story are now in memory.
```

## Migrating from 0.2

- **History is bounded by default.** `new` now uses a `TokenBufferMemory` of
  `DEFAULT_HISTORY_TOKENS` instead of an unbounded `SimpleMemory`. Call
  `with_unbounded_history()` for the old behaviour.
- **Streams record into memory.** A stream read to the end now saves the human
  message and the full answer.
- New: `with_token_budget`, `with_window`, `with_summary`,
  `with_unbounded_history`, `without_system`, `with_input_key`, `history`,
  `clear_history`, `memory`, `system`, `llm`, and the `DEFAULT_*` constants.
- The unused `rune-chain-prompt` dependency is gone; `rune-chain-llm` is now
  0.3.

## License

MIT
