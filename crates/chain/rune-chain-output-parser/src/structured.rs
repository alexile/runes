//! Schema-validated structured output with repair-by-retry.

use std::fmt::{self, Write as _};
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;

use rune_chain_core::{ChainError, GenerateResult, Llm, LlmError, Message, TokenUsage};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{JsonSchema, MAX_INPUT_BYTES, OutputParser, Violation, extract_json};

/// Default number of repair attempts after the first generation.
pub const DEFAULT_MAX_RETRIES: usize = 2;

/// How many violations a repair prompt lists before summarising the rest.
const MAX_LISTED_VIOLATIONS: usize = 20;

/// How many characters of bad output an error message quotes.
const MAX_QUOTED_CHARS: usize = 200;

/// Errors from structured output parsing and repair.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StructuredError {
    /// The schema itself is malformed or uses an unsupported feature.
    #[error("invalid JSON schema {0}")]
    InvalidSchema(String),
    /// No JSON value could be found in the model output.
    #[error("no JSON value found in the output: {0}")]
    NoJson(String),
    /// The JSON value does not satisfy the schema.
    #[error("output does not match the JSON schema: {}", join_violations(.0))]
    SchemaViolation(Vec<Violation>),
    /// The value satisfies the schema but does not deserialize into the
    /// target type (the schema and the type disagree).
    #[error("output matches the schema but does not fit the target type: {0}")]
    Deserialize(String),
    /// A custom validator (see
    /// [`StructuredOutputParser::with_validator`]) rejected the value.
    #[error("validation failed: {0}")]
    Validation(String),
    /// The output is longer than the configured cap. Not retried.
    #[error("output is {len} bytes, above the {limit}-byte limit")]
    TooLarge {
        /// Length of the output in bytes.
        len: usize,
        /// The cap in bytes.
        limit: usize,
    },
    /// The LLM call itself failed. Not retried.
    #[error("LLM call failed: {0}")]
    Llm(#[from] LlmError),
    /// A chain call failed. Not retried.
    #[error("chain call failed: {0}")]
    Chain(#[from] ChainError),
    /// Every attempt produced invalid output.
    #[error("no valid output after {attempts} attempt(s); last error: {last}")]
    RetriesExhausted {
        /// Total generations made, including the first.
        attempts: usize,
        /// Why the final attempt was rejected.
        last: Box<Self>,
        /// The final attempt's raw output.
        raw: String,
    },
}

impl StructuredError {
    /// Return `true` for errors that a new generation might fix (bad output),
    /// as opposed to configuration or transport failures.
    #[must_use]
    pub const fn is_repairable(&self) -> bool {
        matches!(
            self,
            Self::NoJson(_) | Self::SchemaViolation(_) | Self::Deserialize(_) | Self::Validation(_)
        )
    }
}

impl From<StructuredError> for ChainError {
    fn from(e: StructuredError) -> Self {
        match e {
            StructuredError::Llm(e) => Self::LlmError(e),
            StructuredError::Chain(e) => e,
            other => Self::ParseError(other.to_string()),
        }
    }
}

fn join_violations(v: &[Violation]) -> String {
    v.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

fn quote(text: &str) -> String {
    let mut out: String = text.chars().take(MAX_QUOTED_CHARS).collect();
    if text.chars().nth(MAX_QUOTED_CHARS).is_some() {
        out.push('…');
    }
    out
}

/// What a repair attempt needs to know about the previous, rejected one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepairRequest {
    /// 1-based number of the attempt about to be made (so `2` for the first
    /// repair).
    pub attempt: usize,
    /// The rejected raw output.
    pub previous: String,
    /// A prompt telling the model what was wrong and how to fix it.
    pub feedback: String,
}

/// A validated, typed result plus how it was obtained.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct StructuredOutput<T> {
    /// The typed value.
    pub value: T,
    /// The validated JSON value `value` was deserialized from.
    pub json: Value,
    /// The raw text of the accepted generation.
    pub raw: String,
    /// Total generations made, including the first (`1` = no repair needed).
    pub attempts: usize,
    /// Token usage summed over every attempt, if any attempt reported it.
    pub usage: Option<TokenUsage>,
}

/// Parse model output into `T`, validated against a JSON Schema, and repair
/// invalid output by re-asking the model.
///
/// Parsing is sans-I/O ([`OutputParser::parse`], [`parse_value`](Self::parse_value)):
/// it extracts JSON from the text (leniently by default, see
/// [`extract_json`]), validates it against the schema and deserializes it.
/// The async helpers [`generate`](Self::generate) and
/// [`repair_loop`](Self::repair_loop) add the retry: on invalid output they
/// show the model its previous answer with a precise list of what was wrong,
/// up to [`max_retries`](Self::with_max_retries) times.
///
/// The schema should describe `T`; for types that implement
/// `schemars::JsonSchema`, pass `serde_json::to_value(schemars::schema_for!(T))`.
///
/// # Example
///
/// ```rust
/// use rune_chain_output_parser::{OutputParser, StructuredOutputParser};
/// use serde::Deserialize;
/// use serde_json::json;
///
/// #[derive(Debug, Deserialize, PartialEq)]
/// struct Verdict { severity: String, cwe: u32 }
///
/// let parser = StructuredOutputParser::<Verdict>::new(json!({
///     "type": "object",
///     "properties": {
///         "severity": { "enum": ["low", "medium", "high"] },
///         "cwe": { "type": "integer", "minimum": 1 }
///     },
///     "required": ["severity", "cwe"],
///     "additionalProperties": false
/// })).unwrap();
///
/// let v = parser.parse("Result:\n```json\n{\"severity\": \"high\", \"cwe\": 89}\n```").unwrap();
/// assert_eq!(v, Verdict { severity: "high".into(), cwe: 89 });
///
/// // Schema violations are reported precisely, ready to feed back to the model.
/// let err = parser.parse_value(r#"{"severity": "critical", "cwe": 89}"#).unwrap_err();
/// assert!(parser.repair_prompt(&err).contains("/severity"));
/// ```
pub struct StructuredOutputParser<T> {
    schema: JsonSchema,
    max_retries: usize,
    lenient: bool,
    max_input_bytes: usize,
    validators: Vec<Validator<T>>,
    _phantom: PhantomData<fn() -> T>,
}

/// A custom check on a parsed value; `Err` carries a message for the model.
type Validator<T> = Arc<dyn Fn(&T) -> Result<(), String> + Send + Sync>;

impl<T> Clone for StructuredOutputParser<T> {
    fn clone(&self) -> Self {
        Self {
            schema: self.schema.clone(),
            max_retries: self.max_retries,
            lenient: self.lenient,
            max_input_bytes: self.max_input_bytes,
            validators: self.validators.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<T> fmt::Debug for StructuredOutputParser<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructuredOutputParser")
            .field("schema", &self.schema)
            .field("max_retries", &self.max_retries)
            .field("lenient", &self.lenient)
            .field("max_input_bytes", &self.max_input_bytes)
            .field("validators", &self.validators.len())
            .finish()
    }
}

impl<T> StructuredOutputParser<T> {
    /// Create a parser for `schema` with lenient extraction and
    /// [`DEFAULT_MAX_RETRIES`] repair attempts.
    pub fn new(schema: Value) -> Result<Self, StructuredError> {
        Ok(Self::from_schema(JsonSchema::new(schema)?))
    }

    /// Create a parser from an already compiled schema.
    #[must_use]
    pub const fn from_schema(schema: JsonSchema) -> Self {
        Self {
            schema,
            max_retries: DEFAULT_MAX_RETRIES,
            lenient: true,
            max_input_bytes: MAX_INPUT_BYTES,
            validators: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Add a custom validator, run after the schema check and
    /// deserialization. An `Err(message)` rejects the value with
    /// [`StructuredError::Validation`]; in [`generate`](Self::generate) and
    /// [`repair_loop`](Self::repair_loop) the message is shown to the model,
    /// which is re-asked. Validators run in the order they were added and
    /// the first failure wins.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_output_parser::{StructuredError, StructuredOutputParser};
    /// use serde_json::json;
    ///
    /// let parser = StructuredOutputParser::<Vec<u32>>::new(json!({"type": "array"}))
    ///     .unwrap()
    ///     .with_validator(|v| {
    ///         if v.windows(2).all(|w| w[0] <= w[1]) { Ok(()) } else { Err("sort the list".into()) }
    ///     });
    /// assert!(parser.parse_value("[1, 2, 3]").is_ok());
    /// assert!(matches!(parser.parse_value("[3, 1]"), Err(StructuredError::Validation(_))));
    /// ```
    #[must_use]
    pub fn with_validator<F>(mut self, validator: F) -> Self
    where
        F: Fn(&T) -> Result<(), String> + Send + Sync + 'static,
    {
        self.validators.push(Arc::new(validator));
        self
    }

    /// Set the largest output, in bytes, that will be parsed (default and
    /// ceiling: [`MAX_INPUT_BYTES`]). Larger outputs fail with
    /// [`StructuredError::TooLarge`] before any parsing.
    #[must_use]
    pub fn with_max_input_bytes(mut self, max: usize) -> Self {
        self.max_input_bytes = max.min(MAX_INPUT_BYTES);
        self
    }

    /// Set how many repair attempts follow a rejected first generation
    /// (`0` disables repair).
    #[must_use]
    pub const fn with_max_retries(mut self, max_retries: usize) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Choose lenient extraction ([`extract_json`]: prose, fences, trailing
    /// commas, truncation; the default) or strict (the whole text, minus a
    /// surrounding code fence, must be JSON).
    #[must_use]
    pub const fn with_lenient(mut self, lenient: bool) -> Self {
        self.lenient = lenient;
        self
    }

    /// The compiled schema.
    #[must_use]
    pub const fn schema(&self) -> &JsonSchema {
        &self.schema
    }

    /// The largest output, in bytes, that will be parsed.
    #[must_use]
    pub const fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    /// The configured number of repair attempts.
    #[must_use]
    pub const fn max_retries(&self) -> usize {
        self.max_retries
    }

    /// Extract and validate the JSON value in `text`, without deserializing.
    pub fn validate_text(&self, text: &str) -> Result<Value, StructuredError> {
        if text.len() > self.max_input_bytes {
            return Err(StructuredError::TooLarge {
                len: text.len(),
                limit: self.max_input_bytes,
            });
        }
        let value = if self.lenient {
            extract_json(text)
                .ok_or_else(|| StructuredError::NoJson(format!("got {:?}", quote(text.trim()))))?
        } else {
            let cleaned = strip_outer_fence(text);
            serde_json::from_str(cleaned)
                .map_err(|e| StructuredError::NoJson(format!("{e} in {:?}", quote(cleaned))))?
        };
        self.schema
            .validate(&value)
            .map_err(StructuredError::SchemaViolation)?;
        Ok(value)
    }

    /// Prompt text telling the model what was wrong with its last answer.
    #[must_use]
    pub fn repair_prompt(&self, error: &StructuredError) -> String {
        let mut p = String::from("Your previous response was rejected: ");
        match error {
            StructuredError::SchemaViolation(vs) => {
                p.push_str("it does not match the JSON schema.\nProblems:\n");
                for v in vs.iter().take(MAX_LISTED_VIOLATIONS) {
                    let _ = writeln!(p, "- {v}");
                }
                if vs.len() > MAX_LISTED_VIOLATIONS {
                    let _ = writeln!(p, "- … and {} more", vs.len() - MAX_LISTED_VIOLATIONS);
                }
            }
            other => {
                let _ = writeln!(p, "{other}.");
            }
        }
        p.push_str(
            "\nRespond again with only the corrected JSON value, conforming to this JSON schema, \
             with no explanation or markdown fences:\n",
        );
        p.push_str(&schema_text(&self.schema));
        p
    }
}

impl<T: DeserializeOwned> StructuredOutputParser<T> {
    /// Extract, validate and deserialize `text`, keeping the JSON value.
    pub fn parse_value(&self, text: &str) -> Result<(T, Value), StructuredError> {
        let value = self.validate_text(text)?;
        let typed =
            T::deserialize(&value).map_err(|e| StructuredError::Deserialize(e.to_string()))?;
        self.check(&typed)?;
        Ok((typed, value))
    }

    /// Run the custom validators on an already parsed value.
    pub fn check(&self, value: &T) -> Result<(), StructuredError> {
        for validate in &self.validators {
            validate(value).map_err(StructuredError::Validation)?;
        }
        Ok(())
    }

    /// Run the parse-and-repair loop around any generator.
    ///
    /// `generate` is called with `None` for the first attempt and with a
    /// [`RepairRequest`] for each retry; it returns the model's
    /// [`GenerateResult`]. Errors from `generate` end the loop immediately
    /// (they are transport failures, not bad output). This is how to use the
    /// repair loop with a [`Chain`](rune_chain_core::Chain): put
    /// `request.feedback` into the prompt arguments.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{ChainError, GenerateResult};
    /// use rune_chain_output_parser::StructuredOutputParser;
    /// use serde_json::json;
    ///
    /// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
    /// let parser = StructuredOutputParser::<Vec<u8>>::new(json!({
    ///     "type": "array", "items": {"type": "integer", "maximum": 255}
    /// })).unwrap();
    ///
    /// let out = parser
    ///     .repair_loop(|req| async move {
    ///         // A real caller would invoke a chain or model here.
    ///         Ok::<_, ChainError>(GenerateResult::from_text(match req {
    ///             None => "[1, 2, 300]",     // rejected: 300 > 255
    ///             Some(_) => "[1, 2, 255]",  // repaired
    ///         }))
    ///     })
    ///     .await
    ///     .unwrap();
    /// assert_eq!(out.value, vec![1, 2, 255]);
    /// assert_eq!(out.attempts, 2);
    /// # });
    /// ```
    pub async fn repair_loop<F, Fut, E>(
        &self,
        mut generate: F,
    ) -> Result<StructuredOutput<T>, StructuredError>
    where
        F: FnMut(Option<RepairRequest>) -> Fut,
        Fut: Future<Output = Result<GenerateResult, E>>,
        E: Into<StructuredError>,
    {
        let mut usage: Option<TokenUsage> = None;
        let mut request = None;
        let total = self.max_retries.saturating_add(1);
        for attempt in 1..=total {
            let result = generate(request.take()).await.map_err(Into::into)?;
            if let Some(t) = &result.tokens {
                usage = Some(usage.map_or_else(|| t.clone(), |u| u.combine(t)));
            }
            let raw = result.generation;
            match self.parse_value(&raw) {
                Ok((value, json)) => {
                    return Ok(StructuredOutput {
                        value,
                        json,
                        raw,
                        attempts: attempt,
                        usage,
                    });
                }
                Err(e) if !e.is_repairable() => return Err(e),
                Err(e) if attempt == total => {
                    return Err(StructuredError::RetriesExhausted {
                        attempts: attempt,
                        last: Box::new(e),
                        raw,
                    });
                }
                Err(e) => {
                    request = Some(RepairRequest {
                        attempt: attempt + 1,
                        feedback: self.repair_prompt(&e),
                        previous: raw,
                    });
                }
            }
        }
        // `total >= 1`, so the loop always returns; this keeps the compiler
        // and the no-panic lint happy without an `unreachable!`.
        Err(StructuredError::NoJson("no attempt was made".into()))
    }

    /// Ask `llm` for structured output, repairing invalid answers.
    ///
    /// The first call sends `messages` unchanged, so include
    /// [`format_instructions`](OutputParser::format_instructions) in them.
    /// Each retry sends `messages` followed by the rejected answer (as an AI
    /// turn) and the [`repair_prompt`](Self::repair_prompt) (as a human
    /// turn). Only the latest rejected exchange is kept, so the context
    /// grows by at most two messages.
    pub async fn generate<L>(
        &self,
        llm: &L,
        messages: &[Message],
    ) -> Result<StructuredOutput<T>, StructuredError>
    where
        L: Llm + ?Sized,
    {
        self.repair_loop(|req| {
            let mut msgs = messages.to_vec();
            if let Some(req) = req {
                msgs.push(Message::ai(req.previous));
                msgs.push(Message::human(req.feedback));
            }
            async move { llm.generate(&msgs).await }
        })
        .await
    }
}

impl<T: DeserializeOwned + Send + Sync> OutputParser<T> for StructuredOutputParser<T> {
    fn parse(&self, text: &str) -> Result<T, ChainError> {
        self.parse_value(text)
            .map(|(t, _)| t)
            .map_err(ChainError::from)
    }

    fn format_instructions(&self) -> Option<String> {
        Some(format!(
            "Respond with only a JSON value that conforms to the following JSON schema, \
             with no explanation or markdown fences:\n{}",
            schema_text(&self.schema)
        ))
    }
}

fn schema_text(schema: &JsonSchema) -> String {
    serde_json::to_string_pretty(schema.as_value())
        .unwrap_or_else(|_| schema.as_value().to_string())
}

/// Strip one surrounding Markdown code fence, if any.
fn strip_outer_fence(text: &str) -> &str {
    let t = text.trim();
    let Some(inner) = t.strip_prefix("```") else {
        return t;
    };
    let Some(inner) = inner.trim_end().strip_suffix("```") else {
        return t;
    };
    // Drop the info string (e.g. `json`) when the fence has its own line.
    match inner.split_once('\n') {
        Some((info, body)) if !info.contains(['{', '[']) => body.trim(),
        _ => inner.trim(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use rune_chain_core::Role;
    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Finding {
        rule: String,
        line: u32,
    }

    fn parser() -> StructuredOutputParser<Finding> {
        StructuredOutputParser::new(json!({
            "type": "object",
            "properties": {
                "rule": {"type": "string", "minLength": 1},
                "line": {"type": "integer", "minimum": 1}
            },
            "required": ["rule", "line"],
            "additionalProperties": false
        }))
        .unwrap()
    }

    /// Replays canned responses and records the messages it was sent.
    struct ScriptedLlm {
        replies: Mutex<Vec<Result<GenerateResult, LlmError>>>,
        seen: Mutex<Vec<Vec<Message>>>,
    }

    impl ScriptedLlm {
        fn new(replies: &[&str]) -> Self {
            let replies = replies
                .iter()
                .rev()
                .map(|r| {
                    Ok(GenerateResult::from_text((*r).to_owned())
                        .with_tokens(TokenUsage::new(10, 5).with_total_tokens(15)))
                })
                .collect();
            Self {
                replies: Mutex::new(replies),
                seen: Mutex::new(vec![]),
            }
        }
    }

    #[async_trait]
    impl Llm for ScriptedLlm {
        async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
            self.seen.lock().unwrap().push(messages.to_vec());
            self.replies
                .lock()
                .unwrap()
                .pop()
                .unwrap_or_else(|| Err(LlmError::other("script exhausted")))
        }
    }

    #[test]
    fn parses_valid_output() {
        let f = parser().parse(r#"{"rule": "sqli", "line": 3}"#).unwrap();
        assert_eq!(
            f,
            Finding {
                rule: "sqli".into(),
                line: 3
            }
        );
    }

    #[test]
    fn lenient_vs_strict() {
        let text = "Found it: {\"rule\": \"xss\", \"line\": 9,} hope that helps";
        assert!(parser().parse(text).is_ok());
        let strict = parser().with_lenient(false);
        assert!(matches!(
            strict.parse_value(text),
            Err(StructuredError::NoJson(_))
        ));
        assert!(
            strict
                .parse("```json\n{\"rule\": \"xss\", \"line\": 9}\n```")
                .is_ok()
        );
        assert!(
            strict
                .parse("```{\"rule\": \"xss\", \"line\": 9}```")
                .is_ok()
        );
    }

    #[test]
    fn schema_violation_is_reported() {
        let err = parser()
            .parse_value(r#"{"rule": "", "line": 0, "extra": 1}"#)
            .unwrap_err();
        let StructuredError::SchemaViolation(vs) = &err else {
            panic!("{err:?}")
        };
        let mut paths: Vec<_> = vs.iter().map(|v| v.path.as_str()).collect();
        // The order follows serde_json's map, which is sorted by key unless
        // its `preserve_order` feature is on, so compare sorted.
        paths.sort_unstable();
        assert_eq!(paths, ["/extra", "/line", "/rule"]);
        let prompt = parser().repair_prompt(&err);
        assert!(prompt.contains("- at /line"));
        assert!(prompt.contains("\"additionalProperties\": false"));
    }

    #[test]
    fn deserialize_error_when_schema_and_type_disagree() {
        let p = StructuredOutputParser::<Finding>::new(json!({"type": "object"})).unwrap();
        assert!(matches!(
            p.parse_value("{}"),
            Err(StructuredError::Deserialize(_))
        ));
    }

    #[test]
    fn errors_convert_to_chain_error() {
        let e: ChainError = StructuredError::NoJson("x".into()).into();
        assert!(matches!(e, ChainError::ParseError(_)));
        let e: ChainError = StructuredError::Llm(LlmError::other("x")).into();
        assert!(matches!(e, ChainError::LlmError(_)));
        assert!(parser().parse("nope").is_err());
    }

    #[test]
    fn repairable_classification() {
        assert!(StructuredError::NoJson(String::new()).is_repairable());
        assert!(!StructuredError::InvalidSchema(String::new()).is_repairable());
        assert!(!StructuredError::Llm(LlmError::other(String::new())).is_repairable());
    }

    #[test]
    fn format_instructions_embed_schema() {
        let text = parser().format_instructions().unwrap();
        assert!(text.contains("\"required\""));
    }

    #[test]
    fn long_output_is_truncated_in_errors() {
        let long = "x".repeat(1000);
        let err = parser().parse_value(&long).unwrap_err().to_string();
        assert!(err.len() < 400, "{err}");
    }

    #[tokio::test]
    async fn generate_succeeds_first_try() {
        let llm = ScriptedLlm::new(&[r#"{"rule": "a", "line": 1}"#]);
        let out = parser()
            .generate(&llm, &[Message::human("go")])
            .await
            .unwrap();
        assert_eq!(out.attempts, 1);
        assert_eq!(out.usage.unwrap().total_tokens, 15);
        assert_eq!(out.json, json!({"rule": "a", "line": 1}));
    }

    #[tokio::test]
    async fn generate_repairs_invalid_output() {
        let llm = ScriptedLlm::new(&[
            "I think the rule is sqli",
            r#"{"rule": "sqli", "line": "7"}"#,
            r#"{"rule": "sqli", "line": 7}"#,
        ]);
        let out = parser()
            .generate(&llm, &[Message::human("go")])
            .await
            .unwrap();
        assert_eq!(
            out.value,
            Finding {
                rule: "sqli".into(),
                line: 7
            }
        );
        assert_eq!(out.attempts, 3);
        assert_eq!(out.usage.unwrap().total_tokens, 45);

        let seen = llm.seen.lock().unwrap().clone();
        assert_eq!(seen[0].len(), 1);
        // Only the latest rejected exchange is replayed.
        assert_eq!(seen[2].len(), 3);
        assert_eq!(seen[2][1].role, Role::Ai);
        assert_eq!(
            seen[2][1].content.text_content(),
            r#"{"rule": "sqli", "line": "7"}"#
        );
        assert_eq!(seen[2][2].role, Role::Human);
        assert!(
            seen[2][2]
                .content
                .text_content()
                .contains("expected type integer")
        );
    }

    #[tokio::test]
    async fn generate_gives_up_after_max_retries() {
        let llm = ScriptedLlm::new(&["no", "still no", "never", "unused"]);
        let err = parser()
            .with_max_retries(2)
            .generate(&llm, &[Message::human("go")])
            .await
            .unwrap_err();
        let StructuredError::RetriesExhausted {
            attempts,
            last,
            raw,
        } = err
        else {
            panic!("{err:?}")
        };
        assert_eq!(attempts, 3);
        assert_eq!(raw, "never");
        assert!(matches!(*last, StructuredError::NoJson(_)));
        assert_eq!(llm.seen.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn zero_retries_means_one_attempt() {
        let llm = ScriptedLlm::new(&["bad", r#"{"rule": "a", "line": 1}"#]);
        let err = parser()
            .with_max_retries(0)
            .generate(&llm, &[])
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StructuredError::RetriesExhausted { attempts: 1, .. }
        ));
    }

    #[tokio::test]
    async fn llm_errors_are_not_retried() {
        let llm = ScriptedLlm::new(&[]);
        let err = parser().generate(&llm, &[]).await.unwrap_err();
        assert!(matches!(err, StructuredError::Llm(_)));
        assert_eq!(llm.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn repair_loop_passes_attempt_numbers() {
        let mut attempts_seen = vec![];
        let p = parser().with_max_retries(1);
        let _ = p
            .repair_loop(|req| {
                attempts_seen.push(req.map(|r| r.attempt));
                async { Ok::<_, ChainError>(GenerateResult::from_text("bad")) }
            })
            .await;
        assert_eq!(attempts_seen, [None, Some(2)]);
    }
}
