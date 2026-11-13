//! Output parsers for `rune-chain`.
//!
//! An [`OutputParser`] converts the raw text output of an LLM into a typed Rust
//! value. Parsers can be composed with any [`Chain`](rune_chain_core::Chain)
//! using [`ParsedChain`], which runs the chain and then parses the result.
//!
//! # Available parsers
//!
//! | Type | Description |
//! |------|-------------|
//! | [`StringOutputParser`] | Identity — returns text as-is |
//! | [`JsonOutputParser<T>`] | Deserialise JSON (with markdown fence stripping) |
//! | [`ListOutputParser`] | Split text into `Vec<String>` on a delimiter |
//! | [`BoolOutputParser`] | Parse `yes`/`no`/`true`/`false` variants |
//! | [`RegexOutputParser`] | Extract the first regex match group |
//! | [`NumberOutputParser`] | Parse the first number in the text |
//! | [`StructuredOutputParser<T>`] | JSON-schema-validated typed output, with repair-by-retry |
//!
//! # Typed extraction (`instructor`-style)
//!
//! [`Extractor`] (and, with the `schemars` feature, the one-call
//! [`extract()`]) asks a model for a `T`: it requests the provider's native
//! JSON-Schema output ([`Mode::Native`], falling back to prompt
//! instructions for providers without it), leniently extracts the JSON,
//! validates it against the schema and any custom validators, and re-asks
//! with the error on failure. [`Extractor::stream`] and
//! [`PartialJsonParser`] turn a streamed answer into progressively more
//! complete [`Partial`] values for live UIs; parsing is incremental, so a
//! stream costs time linear in its length. [`Extractor::stream_with_reask`]
//! also re-asks (without streaming) when the streamed answer is rejected.
//!
//! All parsing is size-capped ([`MAX_INPUT_BYTES`]), depth-limited
//! ([`MAX_NESTING`]) and panic-free on adversarial output.
//!
//! # Structured output
//!
//! [`StructuredOutputParser`] is for models that cannot be trusted to emit
//! valid JSON: weaker and local models, or providers without native
//! structured-output support. It leniently extracts JSON from the reply
//! ([`extract_json`]), validates it against a JSON Schema ([`JsonSchema`]),
//! deserializes it into `T`, and — via [`StructuredOutputParser::generate`]
//! or [`StructuredOutputParser::repair_loop`] — re-asks the model with a
//! precise list of violations, up to N times.
//!
//! ```rust
//! use rune_chain_output_parser::{OutputParser, StructuredOutputParser};
//! use serde_json::json;
//!
//! let parser = StructuredOutputParser::<Vec<String>>::new(json!({
//!     "type": "array", "items": {"type": "string"}, "maxItems": 2
//! })).unwrap();
//! assert_eq!(parser.parse("Tags: [\"a\", \"b\",]").unwrap(), ["a", "b"]);
//! assert!(parser.parse(r#"["a", "b", "c"]"#).is_err());
//! ```
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_output_parser::{OutputParser, JsonOutputParser};
//! use serde::Deserialize;
//!
//! #[derive(Debug, Deserialize, PartialEq)]
//! struct Answer { value: i32 }
//!
//! let parser = JsonOutputParser::<Answer>::new();
//! let result = parser.parse(r#"{"value": 42}"#).unwrap();
//! assert_eq!(result.value, 42);
//! ```

mod bool_parser;
mod extract;
mod extractor;
mod json_parser;
mod list_parser;
mod number_parser;
mod parsed_chain;
mod partial;
mod regex_parser;
mod schema;
mod string_parser;
mod structured;

pub use bool_parser::BoolOutputParser;
pub use extract::{MAX_INPUT_BYTES, MAX_NESTING, extract_json};
pub use extractor::{ExtractStream, Extractor, Mode, ReaskStream, StreamEvent};
pub use json_parser::JsonOutputParser;
pub use list_parser::ListOutputParser;
pub use number_parser::NumberOutputParser;
pub use parsed_chain::ParsedChain;
pub use partial::{Partial, PartialJsonParser, parse_partial};
pub use regex_parser::RegexOutputParser;
pub use schema::{JsonSchema, Violation};
pub use string_parser::StringOutputParser;
pub use structured::{
    DEFAULT_MAX_RETRIES, RepairRequest, StructuredError, StructuredOutput, StructuredOutputParser,
};

use rune_chain_core::ChainError;

/// The JSON Schema [`schemars`] generates for `T`, as a [`serde_json::Value`].
///
/// # Example
///
/// ```rust
/// #[derive(schemars::JsonSchema)]
/// #[allow(dead_code)]
/// struct Point { x: i32, y: i32 }
///
/// let schema = rune_chain_output_parser::schema_for::<Point>();
/// assert_eq!(schema["required"], serde_json::json!(["x", "y"]));
/// ```
#[cfg(feature = "schemars")]
#[must_use]
pub fn schema_for<T: schemars::JsonSchema>() -> serde_json::Value {
    schemars::schema_for!(T).to_value()
}

/// Extract a `T` from `llm` in one call.
///
/// The schema comes from `T`'s [`schemars::JsonSchema`] derive, the
/// provider's native structured output is used when it has one, and bad
/// output is re-asked up to [`DEFAULT_MAX_RETRIES`] times. For more control
/// (validators, retries, [`Mode`], token usage) build an [`Extractor`].
///
/// # Example
///
/// ```rust
/// use async_trait::async_trait;
/// use rune_chain_core::{GenerateResult, Llm, LlmError, Message};
/// use rune_chain_output_parser::extract;
///
/// struct Mock;
///
/// #[async_trait]
/// impl Llm for Mock {
///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
///         Ok(GenerateResult::from_text(r#"{"city": "Oslo", "temp_c": -3.5}"#))
///     }
/// }
///
/// #[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
/// struct Weather { city: String, temp_c: f64 }
///
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
/// let w: Weather = extract(&Mock, &[Message::human("Oslo is at -3.5 °C")]).await.unwrap();
/// assert_eq!(w.city, "Oslo");
/// # });
/// ```
#[cfg(feature = "schemars")]
pub async fn extract<T, L>(
    llm: &L,
    messages: &[rune_chain_core::Message],
) -> Result<T, StructuredError>
where
    T: serde::de::DeserializeOwned + schemars::JsonSchema,
    L: rune_chain_core::Llm + ?Sized,
{
    Ok(Extractor::<T>::for_type()?
        .extract(llm, messages)
        .await?
        .value)
}

/// Parse LLM text output into a typed value `T`.
///
/// Implement this trait to add a custom parsing strategy. The
/// [`format_instructions`](Self::format_instructions) method returns an optional prompt snippet that
/// can be injected into the prompt to guide the model toward the expected format.
///
/// # Example
///
/// ```rust
/// use rune_chain_output_parser::OutputParser;
/// use rune_chain_core::ChainError;
///
/// struct UpperParser;
///
/// impl OutputParser<String> for UpperParser {
///     fn parse(&self, text: &str) -> Result<String, ChainError> {
///         Ok(text.to_uppercase())
///     }
///     fn format_instructions(&self) -> Option<String> {
///         None
///     }
/// }
///
/// let p = UpperParser;
/// assert_eq!(p.parse("hello").unwrap(), "HELLO");
/// ```
pub trait OutputParser<T>: Send + Sync {
    /// Parse `text` into a value of type `T`.
    fn parse(&self, text: &str) -> Result<T, ChainError>;

    /// Optional prompt instructions to help the model produce parseable output.
    ///
    /// Inject this into your prompt template to nudge the model format.
    fn format_instructions(&self) -> Option<String>;
}
