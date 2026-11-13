# rune-chain-llm

> `LlmChain` — a prompt template, an LLM, optional memory and an optional output parser, wired into a single `Chain`.

[![crates.io](https://img.shields.io/crates/v/rune-chain-llm)](https://crates.io/crates/rune-chain-llm)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-llm)](https://docs.rs/rune-chain-llm)
[![license](https://img.shields.io/crates/l/rune-chain-llm)](LICENSE)

## What it does

`LlmChain` is the basic building block of a `rune-chain` pipeline. It:

- renders a `ChatTemplate` from `rune-chain-prompt` with your variables,
  including `MessagesPlaceholder`s filled from a `messages_value` input
  (history passed in this way is sent as is and not written to memory);
- splices in history from any `Memory` (e.g. `rune-chain-memory`);
- calls any `Llm` provider and returns its `GenerateResult` untouched, so token
  usage (with cache and reasoning tokens) and the finish reason reach you;
- optionally asks for structured output through `Llm::generate_structured`
  and parses the JSON;
- optionally runs any `OutputParser` from `rune-chain-output-parser` and adds
  its format instructions to the prompt;
- streams, and still records the full answer in memory when the stream ends;
- refuses prompts over a token budget before calling the model.

## Installation

```toml
[dependencies]
rune-chain-llm = "0.3"
rune-chain-openai = "0.2"   # or any other Llm provider
rune-chain-memory = "0.2"   # optional, for conversation history
```

## Usage

One-shot question answering:

```rust,ignore
use rune_chain_llm::LlmChain;
use rune_chain_openai::OpenAi;
use rune_chain_prompt::{ChatTemplate, MessageTemplate};
use rune_chain_core::{Chain, prompt_args};

let chain = LlmChain::new(OpenAi::from_env()?, ChatTemplate::new(vec![
    MessageTemplate::system("You are a helpful assistant."),
    MessageTemplate::human("{question}"),
]));

let answer = chain.invoke(prompt_args! { "question" => "What is Rust?" }).await?;
```

Everything about one run, including usage and why the model stopped:

```rust,ignore
let out = chain.run(prompt_args! { "question" => "What is Rust?" }).await?;
println!("{} ({:?} tokens, stopped: {:?})", out.text(), out.usage(), out.finish_reason());
if out.is_truncated() {
    // raise max_tokens and try again
}
```

Structured output (native JSON / JSON-Schema mode where the provider has one,
prompted JSON otherwise):

```rust,ignore
use rune_chain_core::ResponseFormat;
use serde_json::json;

#[derive(serde::Deserialize)]
struct City { name: String, population: u64 }

let chain = LlmChain::new(llm, ChatTemplate::new(vec![
    MessageTemplate::human("Biggest city in {country}?"),
]))
.with_response_format(ResponseFormat::json_schema("city", json!({
    "type": "object",
    "properties": { "name": { "type": "string" }, "population": { "type": "integer" } },
    "required": ["name", "population"]
})));

let city: City = chain.invoke_structured(prompt_args! { "country" => "Japan" }).await?;
```

Output parsers:

```rust,ignore
use rune_chain_output_parser::ListOutputParser;

let chain = LlmChain::new(llm, ChatTemplate::new(vec![
    MessageTemplate::human("Name three {thing}."),
]))
.with_output_parser(ListOutputParser::new()); // adds "Return a newline-separated list…"

let items: Vec<String> = chain.invoke_structured(prompt_args! { "thing" => "colours" }).await?;
```

Multi-turn conversation with memory, streaming:

```rust,ignore
use std::sync::Arc;
use futures::StreamExt;
use rune_chain_memory::TokenBufferMemory;

let chain = LlmChain::new(llm, ChatTemplate::new(vec![
    MessageTemplate::system("You are a helpful assistant."),
    MessageTemplate::human("{input}"),
]))
.with_memory(Arc::new(TokenBufferMemory::with_char_estimate(4_000)))
.with_max_context_tokens(8_000);

let mut stream = chain.stream(prompt_args! { "input" => "My name is Alice." }).await?;
while let Some(chunk) = stream.next().await {
    print!("{}", chunk?.content);
}
// The full answer is now in memory.
```

## Message order

```text
System (from the template's own message templates, always first)
↓ parser format instructions (if any)
↓ prior Human / Ai turns (from memory)
↓ the rest of the template, in order: placeholder history and new input
```

`System` messages are never written to memory; they are rendered fresh from
the template on every call. Only the Human messages the template itself
renders are recorded as the new turn: messages a `MessagesPlaceholder`
inserts (system ones included) stay where the placeholder is and are never
written back to memory.

## `execute` keys

`execute()` returns the answer under the output key (default `"output"`,
change it with `with_output_key`), the full `GenerateResult` under
`"generate_result"`, and, when a parser or a JSON response format is set, the
parsed JSON under `"<output_key>_parsed"`.

## Migrating from 0.2

- **Streams now record into memory.** With memory attached, a stream read to
  the end saves the human turn and the full answer, just like `call`. A stream
  that errors or is dropped early records nothing.
- **Over-budget prompts** fail with `ChainError::LlmError` of kind
  `LlmErrorKind::ContextLengthExceeded` instead of `ChainError::Other`. The
  estimate now also counts the format instructions.
- `output_keys()` gains `"<output_key>_parsed"` when a parser or JSON
  response format is configured; `primary_output_key()` is the output key.
- New: `run` / `LlmOutput`, `invoke_structured`, `with_response_format`,
  `with_output_parser`, `inject_format_instructions`, `with_output_key`,
  `with_stream_completion`, `ChainStream`.
- The `rune-tokenize` dependency is gone; `rune-chain-output-parser` is new.

## License

MIT
