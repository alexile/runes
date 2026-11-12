# rune-chain-output-parser

> Typed LLM output for rune-chain: instructor-style extraction with re-ask, JSON Schema validation, partial streaming, and classic parsers.

[![crates.io](https://img.shields.io/crates/v/rune-chain-output-parser)](https://crates.io/crates/rune-chain-output-parser)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-output-parser)](https://docs.rs/rune-chain-output-parser)
[![license](https://img.shields.io/crates/l/rune-chain-output-parser)](LICENSE)

The Rust answer to Python's [`instructor`](https://python.useinstructor.com/):
ask any `rune-chain` model for a typed `T` and get back a validated value.

- **Typed extraction** — `extract::<T>(llm, messages)` with the schema
  derived from `T` (`schemars` feature), or an `Extractor<T>` for full control.
- **Native when possible** — requests `ResponseFormat::JsonSchema` through
  `Llm::generate_structured`; providers without native structured output
  fall back to prompt instructions (or force that with `Mode::Prompt`).
- **Re-ask on failure** — no JSON, schema violations, type mismatches and
  your own validators' errors are shown to the model, which is asked again,
  up to N retries.
- **Tolerant parsing** — code fences, leading prose, trailing commas and
  truncated output are handled (`extract_json`).
- **Partial streaming** — `Extractor::stream`, `PartialJsonParser` and
  `parse_partial` turn incomplete JSON into progressively growing values
  for live UIs.
- **Hardened** — input capped at 4 MiB (`MAX_INPUT_BYTES`), nesting at 128
  (`MAX_NESTING`), iterative scanners, property-tested never to panic.

Classic `OutputParser`s are still here, composable with any `Chain` via
`ParsedChain`:

| Type | Description |
|------|-------------|
| `StringOutputParser` | Identity — returns text as-is |
| `JsonOutputParser<T>` | Deserialise JSON (with markdown fence stripping) |
| `ListOutputParser` | Split text into `Vec<String>` on a delimiter |
| `BoolOutputParser` | Parse `yes`/`no`/`true`/`false` variants |
| `RegexOutputParser` | Extract the first regex match group |
| `NumberOutputParser` | Parse the first number in the text |
| `StructuredOutputParser<T>` | JSON-schema-validated typed output, with repair-by-retry |
| `Extractor<T>` | `instructor`-style extraction: native/prompt modes, validators, re-ask, streaming |

## Installation

```sh
cargo add rune-chain-output-parser --features schemars
```

The `schemars` feature adds `extract`, `Extractor::for_type` and
`schema_for`. Without it, pass a JSON Schema to `Extractor::new`.

## Typed extraction

```rust
use rune_chain_core::Message;
use rune_chain_output_parser::{extract, Extractor};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
struct Person { name: String, age: u32 }

// One call: schema from the type, native structured output, 2 re-asks.
let p: Person = extract(&llm, &[Message::human("Ada Lovelace, 36")]).await?;

// Full control: custom validators feed the re-ask loop.
let out = Extractor::<Person>::for_type()?
    .with_max_retries(4)
    .with_validator(|p| if p.age < 150 { Ok(()) } else { Err("age is implausible".into()) })
    .extract(&llm, &[Message::human("Ada Lovelace, 36")])
    .await?;
println!("{:?} after {} attempt(s), {:?} tokens", out.value, out.attempts, out.usage);
```

## Streaming partial values

```rust
use futures::StreamExt;
use rune_chain_output_parser::{Extractor, StreamEvent};

let mut events = Extractor::<Story>::for_type()?.stream(&llm, &messages).await?;
while let Some(event) = events.next().await {
    match event? {
        StreamEvent::Partial(p) => render(&p.json),     // unvalidated preview
        StreamEvent::Done(out) => save(out.value),      // validated
        _ => {}
    }
}
```

Give the type `#[serde(default)]` (or `Option`) fields to get typed
`Partial::value`s before every field has arrived.

## Classic parsers

```rust
use rune_chain_output_parser::{OutputParser, JsonOutputParser};
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
struct Answer { value: i32 }

let parser = JsonOutputParser::<Answer>::new();
let result = parser.parse(r#"{"value": 42}"#).unwrap();
assert_eq!(result.value, 42);
```

## Structured output with repair

Weaker and local models often wrap JSON in prose, leave trailing commas,
get cut off mid-object, or return values that don't fit the expected shape.
`StructuredOutputParser<T>`:

1. leniently extracts JSON from the reply (`extract_json`: Markdown fences,
   surrounding prose, trailing commas, truncated output);
2. validates it against a JSON Schema (`JsonSchema`, a dependency-light
   subset of draft 2020-12: `type`, `enum`, `const`, `properties`,
   `required`, `additionalProperties`, `patternProperties`, `items`,
   `prefixItems`, string/number/array/object bounds, `pattern`, `allOf`,
   `anyOf`, `oneOf`, `not`, local `$ref`);
3. deserializes it into `T`;
4. on failure, re-asks the model with the rejected answer and a precise list
   of violations, up to `max_retries` times (default 2).

```rust
use rune_chain_core::{Message, GenerateResult, ChainError};
use rune_chain_output_parser::{OutputParser, StructuredOutputParser};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
struct Finding { rule: String, line: u32 }

let parser = StructuredOutputParser::<Finding>::new(json!({
    "type": "object",
    "properties": {
        "rule": { "type": "string" },
        "line": { "type": "integer", "minimum": 1 }
    },
    "required": ["rule", "line"]
}))?
.with_max_retries(3);

// With any `Llm`: put the format instructions in the prompt, then
let messages = vec![
    Message::system(parser.format_instructions().unwrap_or_default()),
    Message::human("Find the SQL injection in: ..."),
];
let out = parser.generate(&llm, &messages).await?;
println!("{:?} after {} attempt(s)", out.value, out.attempts);

// With a `Chain` or anything else: drive the loop yourself.
let out = parser.repair_loop(|req| async move {
    let feedback = req.map(|r| r.feedback).unwrap_or_default();
    chain.call(prompt_args! { "input" => code, "feedback" => feedback }).await
}).await?;
```

## Migrating from 0.1

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- No behaviour change.

## License

MIT
