//! Proc macros for `rune-chain`.
//!
//! - [`macro@tool`] turns a function into an LLM tool: a unit struct that
//!   implements `rune_chain_core::Tool`, with a JSON Schema generated from
//!   the argument types and descriptions taken from doc comments.
//! - [`macro@Embed`] marks the text fields of a struct to embed, for
//!   `rune_chain_embed::Embed` and one-call vector store ingestion.
//!
//! Most people don't depend on this crate directly: turn on the `macros`
//! feature of `rune-chain-core` (for `#[tool]`) or the `derive` feature of
//! `rune-chain-embed` (for `#[derive(Embed)]`), which re-export them.
//!
//! # Paths
//!
//! The generated code finds `rune_chain_core` and `rune_chain_embed` through
//! `proc-macro-crate`: a direct dependency (renamed or not) wins, then the
//! `rune-chain` facade. If neither fits, say where the crate is, the way
//! serde does: `#[tool(crate = "my_app::deps::rune_chain_core")]` or
//! `#[embed(crate = "my_app::deps::rune_chain_embed")]` on the struct.
#![forbid(unsafe_code)]

use proc_macro::TokenStream;

mod embed;
mod paths;
mod tool;

/// Turn a function into an LLM tool.
///
/// Generates a unit struct named after the function in `PascalCase`
/// (`get_weather` -> `GetWeather`) that implements `rune_chain_core::Tool`.
/// The function itself is kept as is, so it can still be called directly.
///
/// - **Name**: the function name, or `#[tool(name = "...")]`. It must be 1
///   to 64 characters of `A-Z a-z 0-9 _ -`, checked at compile time.
/// - **Description**: the function's `///` doc comment, or
///   `#[tool(description = "...")]`. One of the two is required.
/// - **Arguments**: each becomes a property of the JSON Schema object,
///   described by its `///` comment or `#[arg(desc = "...")]`. `Option<T>`
///   arguments and `#[arg(default)]` ones (filled with `Default::default()`)
///   are not required. Any type that implements `serde::Deserialize` and
///   `schemars::JsonSchema` works: primitives, `String`, `Vec`, maps, enums
///   and your own structs. `&str`, `&[T]` and `&T` are accepted and
///   deserialized as `String`, `Vec<T>` and `T`. Unknown properties are
///   rejected.
/// - **Return value**: any `T: Serialize`, or `Result<T, E>` with
///   `E: Display` (a `ToolError` is passed through unchanged). A string is
///   returned as is; anything else as compact JSON.
/// - **`async fn` or plain `fn`**: both work. A plain `fn` runs on the async
///   executor, so keep it cheap.
///
/// `run` parses the input with the same size limit and rules as
/// `ToolCall::parse_arguments`: bad JSON, a wrong type, a missing or
/// unknown property all become `ToolError::InvalidInput`, never a panic.
///
/// Methods (`&self`) are not supported: write a free function that calls
/// the method.
///
/// # Example
///
/// ```ignore
/// use rune_chain_core::{tool, Tool};
///
/// /// Current temperature for a city, in Celsius.
/// #[tool]
/// async fn get_weather(
///     /// City name, e.g. "Oslo".
///     city: String,
///     #[arg(desc = "Round to whole degrees")] round: Option<bool>,
/// ) -> Result<f64, std::io::Error> {
///     Ok(if round.unwrap_or(false) { 21.0 } else { 21.4 })
/// }
///
/// let out = GetWeather.run(r#"{"city":"Oslo"}"#).await?;
/// assert_eq!(out, "21.4");
/// ```
#[proc_macro_attribute]
pub fn tool(attr: TokenStream, item: TokenStream) -> TokenStream {
    tool::expand(attr.into(), item.into())
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// Implement `rune_chain_embed::Embed` for a struct.
///
/// Mark one or more fields `#[embed]`: `String`, `&str`, `Vec<String>`,
/// `Option<String>`, `Box<str>`, `Cow<str>` and anything else that
/// implements `rune_chain_embed::EmbedText`. Each non-empty text becomes one
/// embedding (and one vector store record).
///
/// Mark at most one field `#[embed_id]` (any `Display` type) to set the
/// record id; without it the id is a hash of the serialized struct.
///
/// # Example
///
/// ```ignore
/// use rune_chain_embed::Embed;
///
/// #[derive(Embed, serde::Serialize)]
/// struct Article {
///     #[embed_id]
///     slug: String,
///     #[embed]
///     title: String,
///     #[embed]
///     paragraphs: Vec<String>,
///     year: u16,
/// }
/// ```
#[proc_macro_derive(Embed, attributes(embed, embed_id))]
pub fn derive_embed(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);
    embed::expand(&input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}
