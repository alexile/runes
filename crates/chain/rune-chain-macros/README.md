# rune-chain-macros

> Proc macros for rune-chain: #[tool] turns a function into an LLM tool with a generated JSON Schema, #[derive(Embed)] marks the text fields to embed

[![crates.io](https://img.shields.io/crates/v/rune-chain-macros)](https://crates.io/crates/rune-chain-macros)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-macros)](https://docs.rs/rune-chain-macros)
[![license](https://img.shields.io/crates/l/rune-chain-macros)](LICENSE)

Two macros:

- **`#[tool]`** on a plain or `async fn` generates a unit struct that
  implements `rune_chain_core::Tool`. The JSON Schema is built from the
  argument types with `schemars`, and the descriptions come from doc
  comments.
- **`#[derive(Embed)]`** implements `rune_chain_embed::Embed` from the
  fields you mark `#[embed]`. Paired with `add_documents`, it turns a slice
  of structs into vector store records in one call.

You normally get them through a feature of the runtime crate rather than
depending on this crate directly:

```toml
rune-chain-core = { version = "0.2", features = ["macros"] }                 # #[tool]
rune-chain-embed = { version = "0.3", features = ["derive", "vectorstore"] } # #[derive(Embed)]
```

## `#[tool]`

```rust
use rune_chain_core::{tool, Tool, ToolError};

#[derive(serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
enum Unit { Celsius, Fahrenheit }

#[derive(serde::Serialize)]
struct Weather { city: String, temp: f64 }

/// Current weather for a city.
#[tool]
async fn get_weather(
    /// City name, like "Oslo".
    city: &str,
    #[arg(desc = "Temperature unit, Celsius by default")] unit: Option<Unit>,
) -> Result<Weather, ToolError> {
    if city.is_empty() {
        return Err(ToolError::InvalidInput("city is empty".into()));
    }
    let temp = match unit { Some(Unit::Fahrenheit) => 70.0, _ => 21.0 };
    Ok(Weather { city: city.to_owned(), temp })
}

let out = GetWeather.run(r#"{"city": "Oslo"}"#).await?;
assert_eq!(out, r#"{"city":"Oslo","temp":21.0}"#);

// Ready for native function calling.
let def = GetWeather.function_definition();
```

The generated schema:

```json
{
  "type": "object",
  "properties": {
    "city": { "type": "string", "description": "City name, like \"Oslo\"." },
    "unit": {
      "type": ["string", "null"],
      "enum": ["celsius", "fahrenheit", null],
      "description": "Temperature unit, Celsius by default"
    }
  },
  "required": ["city"],
  "additionalProperties": false
}
```

What you get:

| | |
| --- | --- |
| Name | The function name, or `#[tool(name = "...")]`. Checked at compile time against `[A-Za-z0-9_-]{1,64}`. |
| Description | The function's `///` comment, or `#[tool(description = "...")]`. A tool without one doesn't compile. |
| Arguments | Anything `Deserialize + JsonSchema`: primitives, `String`, `Vec`, maps, enums, your own structs (recursive ones too). `&str`, `&[T]` and `&T` work and are deserialized as owned values. Described by `///` or `#[arg(desc = "...")]`. |
| Optional arguments | `Option<T>`, or `#[arg(default)]` for `Default::default()`. Not in `required`. |
| Return value | Any `T: Serialize`, or `Result<T, E>` with `E: Display`. Strings come back as is, other values as compact JSON. A returned `ToolError` passes through unchanged; other errors become `ToolError::ExecutionFailed`. |
| Sync or async | Both. A plain `fn` runs on the executor, so keep it cheap. |
| Hostile input | Parsed with the limits of `ToolCall::parse_arguments` (1 MiB cap, empty input reads as `{}`). Bad JSON, a wrong type, or a missing or unknown property gives `ToolError::InvalidInput`, never a panic. |
| Schema | Draft 2020-12 with subschemas inlined (no `$defs` except for recursive types). It is built once and cached. |

Misuse is a compile error at the right span: methods (`&self`), generic
functions, destructuring patterns, `&mut` or nested borrows such as
`Option<&str>`, a missing description, an invalid name, or an unknown
option.

**Methods are not supported.** `#[tool]` can't add a struct inside an
`impl` block. Write a free function that calls the method, or implement
`Tool` by hand for a tool that needs state.

## `#[derive(Embed)]`

```rust
use rune_chain_embed::{Embed, OpenAiEmbedder, VectorStoreExt};
use rune_vectorstore::{InMemoryVectorStore, Options, Query, VectorStore};

#[derive(Embed, serde::Serialize)]
struct Article {
    #[embed_id]
    slug: String,
    #[embed]
    title: String,
    #[embed]
    paragraphs: Vec<String>,
    year: u16,
}

let embedder = OpenAiEmbedder::from_env()?;
let store = InMemoryVectorStore::new(Options::default());

// One embed_documents call, one upsert.
store.add_documents(&embedder, &articles).await?;

let q = embedder.embed_query("what changed in the 2024 edition?").await?;
let hits = store.query(&Query::new(q, 5)).await?;
```

- `#[embed]` fields can be `String`, `&str`, `Vec<String>`,
  `Option<String>`, `Box<str>`, `Cow<str>`, arrays and nestings of those,
  or any type that implements `EmbedText`.
- Each non-blank text becomes one record. Its content is the text, and its
  metadata is the struct's serialized fields, usable in `Filter`s.
- Record ids come from the `#[embed_id]` field (any `Display` type), or else
  from a hash of the serialized struct, so adding the same document again
  replaces it. A document with several texts gets `"{id}#{n}"`.
- `to_records(&embedder, &docs)` gives you the records without a store.
- A struct with no `#[embed]` field, an enum, or two `#[embed_id]` fields
  is a compile error.

## Side by side with rig

<table>
<tr><th>rig-core</th><th>rune-chain</th></tr>
<tr><td>

```rust
#[rig_tool(
    description = "Add two numbers",
    params(
        a = "First number",
        b = "Second number",
    ),
    required(a, b),
)]
fn add(a: i64, b: i64)
    -> Result<i64, rig::tool::ToolError>
{
    Ok(a + b)
}
```

</td><td>

```rust
/// Add two numbers.
#[tool]
fn add(
    /// First number.
    a: i64,
    /// Second number.
    b: i64,
) -> i64 {
    a + b
}
```

</td></tr>
<tr><td>

```rust
#[derive(rig::Embed, Serialize)]
struct Doc {
    id: String,
    #[embed]
    text: String,
}

let embeddings = EmbeddingsBuilder::new(model)
    .documents(docs)?
    .build()
    .await?;
let index = InMemoryVectorStore::from_documents(embeddings);
```

</td><td>

```rust
#[derive(Embed, Serialize)]
struct Doc {
    #[embed_id]
    id: String,
    #[embed]
    text: String,
}

store.add_documents(&embedder, &docs).await?;
```

</td></tr>
</table>

The differences that matter: descriptions come from the doc comments you
already write, `Option` arguments are optional in the schema, plain return
values work without wrapping them in `Ok`, unknown properties are rejected,
and the input size is capped before parsing.

## Paths and the `crate` option

The generated code finds the runtime crates with `proc-macro-crate`. A
direct dependency on `rune-chain-core` or `rune-chain-embed` wins, renamed
or not. Next comes the `rune-chain` facade (`rune_chain` re-exports the
core crate at its root and the embed crate as `rune_chain::embed`). If you
re-export the crates under
another path, say where they are, as with serde:

```rust
/// Health check.
#[tool(crate = "my_app::deps::rune_chain_core")]
fn ping() -> &'static str { "pong" }

#[derive(Embed)]
#[embed(crate = "my_app::deps::rune_chain_embed")]
struct Note { #[embed] body: String }
```

## License

MIT
