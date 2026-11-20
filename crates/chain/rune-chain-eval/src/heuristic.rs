//! Deterministic evaluators that need no model: string matching, regex,
//! JSON checks, edit distance, BLEU, ROUGE-L and embedding similarity.

use std::sync::Arc;

use async_trait::async_trait;
use regex::{Regex, RegexBuilder};
use rune_chain_embed::{Embedder, try_cosine_similarity};
use rune_chain_output_parser::{JsonSchema, extract_json};
use serde_json::{Value, json};

use crate::evaluator::reference;
use crate::metrics::{
    Smoothing, levenshtein_similarity, normalize_answer, rouge_l, sentence_bleu, tokenize,
};
use crate::{EvalError, Evaluator, Example, Score, TargetOutput};

/// Default cap on characters fed to the quadratic metrics (Levenshtein).
pub const DEFAULT_MAX_CHARS: usize = 8_192;
/// Default cap on tokens fed to BLEU and ROUGE-L.
pub const DEFAULT_MAX_TOKENS: usize = 8_192;
/// Default cap on output bytes parsed as JSON.
pub const DEFAULT_MAX_JSON_BYTES: usize = 1 << 20;
/// Compiled-size cap for user regexes.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

macro_rules! named {
    ($t:ty) => {
        impl $t {
            /// Rename the metric (builder style), e.g. to run two
            /// configurations side by side.
            #[must_use]
            pub fn with_name(mut self, name: impl Into<String>) -> Self {
                self.name = name.into();
                self
            }
        }
    };
}

macro_rules! thresholded {
    ($t:ty) => {
        impl $t {
            /// Pass when the score is at least `threshold` (builder style).
            #[must_use]
            pub const fn with_threshold(mut self, threshold: f64) -> Self {
                self.threshold = threshold;
                self
            }
        }
    };
}

/// The output equals the reference (`exact_match`). Surrounding whitespace
/// is ignored unless [`strict`](Self::strict) is set.
#[derive(Debug, Clone)]
pub struct ExactMatch {
    name: String,
    trim: bool,
}

impl Default for ExactMatch {
    fn default() -> Self {
        Self::new()
    }
}

impl ExactMatch {
    /// Exact match, ignoring surrounding whitespace.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "exact_match".into(),
            trim: true,
        }
    }

    /// Compare byte for byte, whitespace included (builder style).
    #[must_use]
    pub const fn strict(mut self) -> Self {
        self.trim = false;
        self
    }
}
named!(ExactMatch);

#[async_trait]
impl Evaluator for ExactMatch {
    fn name(&self) -> &str {
        &self.name
    }
    async fn evaluate(&self, ex: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let r = reference(ex)?;
        Ok(Score::binary(if self.trim {
            out.output.trim() == r.trim()
        } else {
            out.output == r
        }))
    }
}

/// The output equals the reference after `SQuAD` normalization
/// ([`normalize_answer`]) (`normalized_match`).
#[derive(Debug, Clone)]
pub struct NormalizedMatch {
    name: String,
}

impl Default for NormalizedMatch {
    fn default() -> Self {
        Self::new()
    }
}

impl NormalizedMatch {
    /// Normalized exact match.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "normalized_match".into(),
        }
    }
}
named!(NormalizedMatch);

#[async_trait]
impl Evaluator for NormalizedMatch {
    fn name(&self) -> &str {
        &self.name
    }
    async fn evaluate(&self, ex: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let r = reference(ex)?;
        Ok(Score::binary(
            normalize_answer(&out.output) == normalize_answer(r),
        ))
    }
}

/// The output contains given substrings, or the reference (`contains`).
///
/// The score is the fraction of needles found; the example passes when
/// all are found (or any, with [`any`](Self::any)).
#[derive(Debug, Clone)]
pub struct Contains {
    name: String,
    needles: Option<Vec<String>>,
    any: bool,
    ignore_case: bool,
}

impl Contains {
    /// Look for each of `needles`.
    pub fn new(needles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            name: "contains".into(),
            needles: Some(needles.into_iter().map(Into::into).collect()),
            any: false,
            ignore_case: false,
        }
    }

    /// Look for the example's reference.
    #[must_use]
    pub fn reference() -> Self {
        Self {
            name: "contains".into(),
            needles: None,
            any: false,
            ignore_case: false,
        }
    }

    /// Pass when any needle is found (builder style).
    #[must_use]
    pub const fn any(mut self) -> Self {
        self.any = true;
        self
    }

    /// Match case-insensitively (builder style).
    #[must_use]
    pub const fn ignore_case(mut self) -> Self {
        self.ignore_case = true;
        self
    }
}
named!(Contains);

#[async_trait]
impl Evaluator for Contains {
    fn name(&self) -> &str {
        &self.name
    }
    #[allow(clippy::cast_precision_loss)]
    async fn evaluate(&self, ex: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let owned;
        let needles: &[String] = if let Some(n) = &self.needles {
            n
        } else {
            owned = [reference(ex)?.to_owned()];
            &owned
        };
        if needles.is_empty() {
            return Err(EvalError::Config("no substrings to look for".into()));
        }
        let fold = |s: &str| {
            if self.ignore_case {
                s.to_lowercase()
            } else {
                s.to_owned()
            }
        };
        let hay = fold(&out.output);
        let found = needles.iter().filter(|n| hay.contains(&fold(n))).count();
        let passed = if self.any {
            found > 0
        } else {
            found == needles.len()
        };
        Ok(Score::new(found as f64 / needles.len() as f64, passed))
    }
}

/// The output matches a regular expression (`regex`).
#[derive(Debug, Clone)]
pub struct RegexMatch {
    name: String,
    re: Regex,
    full: bool,
}

impl RegexMatch {
    /// Pass when `pattern` matches somewhere in the output.
    ///
    /// # Errors
    ///
    /// [`EvalError::Config`] when the pattern is invalid or too large.
    pub fn new(pattern: &str) -> Result<Self, EvalError> {
        let re = RegexBuilder::new(pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map_err(|e| EvalError::Config(format!("invalid regex: {e}")))?;
        Ok(Self {
            name: "regex".into(),
            re,
            full: false,
        })
    }

    /// Require the pattern to match the whole (trimmed) output (builder
    /// style).
    #[must_use]
    pub const fn full_match(mut self) -> Self {
        self.full = true;
        self
    }
}
named!(RegexMatch);

#[async_trait]
impl Evaluator for RegexMatch {
    fn name(&self) -> &str {
        &self.name
    }
    async fn evaluate(&self, _: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let text = out.output.trim();
        let ok = if self.full {
            self.re
                .find(text)
                .is_some_and(|m| m.start() == 0 && m.end() == text.len())
        } else {
            self.re.is_match(text)
        };
        Ok(Score::binary(ok))
    }
}

fn parse_json(text: &str, lenient: bool, max_bytes: usize) -> Result<Option<Value>, EvalError> {
    if text.len() > max_bytes {
        return Err(EvalError::TooLarge(format!(
            "output is {} bytes, above the {max_bytes}-byte JSON cap",
            text.len()
        )));
    }
    Ok(if lenient {
        extract_json(text)
    } else {
        serde_json::from_str(text.trim()).ok()
    })
}

/// The output is valid JSON (`json_valid`). Strict by default; lenient
/// mode accepts JSON inside prose or a code fence.
#[derive(Debug, Clone)]
pub struct JsonValid {
    name: String,
    lenient: bool,
    max_bytes: usize,
}

impl Default for JsonValid {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonValid {
    /// Strict JSON validity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "json_valid".into(),
            lenient: false,
            max_bytes: DEFAULT_MAX_JSON_BYTES,
        }
    }

    /// Accept JSON embedded in prose or fences (builder style).
    #[must_use]
    pub const fn lenient(mut self) -> Self {
        self.lenient = true;
        self
    }
}
named!(JsonValid);

#[async_trait]
impl Evaluator for JsonValid {
    fn name(&self) -> &str {
        &self.name
    }
    async fn evaluate(&self, _: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        Ok(Score::binary(
            parse_json(&out.output, self.lenient, self.max_bytes)?.is_some(),
        ))
    }
}

/// The output is JSON that satisfies a JSON Schema (`json_schema`).
/// Violations are listed in the score's reasoning.
#[derive(Debug, Clone)]
pub struct JsonSchemaMatch {
    name: String,
    schema: JsonSchema,
    lenient: bool,
    max_bytes: usize,
}

impl JsonSchemaMatch {
    /// Validate against `schema`.
    ///
    /// # Errors
    ///
    /// [`EvalError::Config`] when the schema is malformed.
    pub fn new(schema: Value) -> Result<Self, EvalError> {
        Ok(Self {
            name: "json_schema".into(),
            schema: JsonSchema::new(schema).map_err(|e| EvalError::Config(e.to_string()))?,
            lenient: false,
            max_bytes: DEFAULT_MAX_JSON_BYTES,
        })
    }

    /// Accept JSON embedded in prose or fences (builder style).
    #[must_use]
    pub const fn lenient(mut self) -> Self {
        self.lenient = true;
        self
    }
}
named!(JsonSchemaMatch);

#[async_trait]
impl Evaluator for JsonSchemaMatch {
    fn name(&self) -> &str {
        &self.name
    }
    async fn evaluate(&self, _: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let Some(value) = parse_json(&out.output, self.lenient, self.max_bytes)? else {
            return Ok(Score::binary(false).with_reasoning("output is not valid JSON"));
        };
        Ok(match self.schema.validate(&value) {
            Ok(()) => Score::binary(true),
            Err(violations) => {
                let listed: Vec<String> = violations
                    .iter()
                    .take(10)
                    .map(ToString::to_string)
                    .collect();
                Score::binary(false).with_reasoning(listed.join("; "))
            }
        })
    }
}

fn capped_chars<'a>(text: &'a str, max: usize, what: &str) -> Result<&'a str, EvalError> {
    if text.chars().nth(max).is_some() {
        return Err(EvalError::TooLarge(format!(
            "{what} is longer than {max} characters"
        )));
    }
    Ok(text)
}

fn capped_tokens(text: &str, max: usize, what: &str) -> Result<Vec<String>, EvalError> {
    let t = tokenize(text);
    if t.len() > max {
        return Err(EvalError::TooLarge(format!(
            "{what} has more than {max} tokens"
        )));
    }
    Ok(t)
}

/// Normalized Levenshtein similarity to the reference, `1 - d / max_len`
/// (`levenshtein`). Passes at 0.8 by default.
#[derive(Debug, Clone)]
pub struct LevenshteinSimilarity {
    name: String,
    threshold: f64,
    max_chars: usize,
}

impl Default for LevenshteinSimilarity {
    fn default() -> Self {
        Self::new()
    }
}

impl LevenshteinSimilarity {
    /// Levenshtein similarity, threshold 0.8, at most
    /// [`DEFAULT_MAX_CHARS`] characters per side.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "levenshtein".into(),
            threshold: 0.8,
            max_chars: DEFAULT_MAX_CHARS,
        }
    }

    /// Cap characters per side; the metric is quadratic (builder style).
    #[must_use]
    pub const fn with_max_chars(mut self, max: usize) -> Self {
        self.max_chars = max;
        self
    }
}
named!(LevenshteinSimilarity);
thresholded!(LevenshteinSimilarity);

#[async_trait]
impl Evaluator for LevenshteinSimilarity {
    fn name(&self) -> &str {
        &self.name
    }
    async fn evaluate(&self, ex: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let r = capped_chars(reference(ex)?, self.max_chars, "reference")?;
        let o = capped_chars(&out.output, self.max_chars, "output")?;
        Ok(Score::at_least(
            levenshtein_similarity(o, r),
            self.threshold,
        ))
    }
}

/// Sentence BLEU-4 against the reference plus any extra references in
/// `metadata.references` (`bleu`). Tokens are lower-cased alphanumeric
/// runs; epsilon smoothing by default. Passes at 0.3 by default.
#[derive(Debug, Clone)]
pub struct Bleu {
    name: String,
    threshold: f64,
    max_n: usize,
    smoothing: Smoothing,
    max_tokens: usize,
}

impl Default for Bleu {
    fn default() -> Self {
        Self::new()
    }
}

impl Bleu {
    /// BLEU-4, epsilon smoothing, threshold 0.3.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "bleu".into(),
            threshold: 0.3,
            max_n: 4,
            smoothing: Smoothing::Epsilon,
            max_tokens: DEFAULT_MAX_TOKENS,
        }
    }

    /// Highest n-gram order, 1 to 8 (builder style).
    #[must_use]
    pub fn with_max_n(mut self, n: usize) -> Self {
        self.max_n = n.clamp(1, 8);
        self
    }

    /// Smoothing for orders with no match (builder style).
    #[must_use]
    pub const fn with_smoothing(mut self, smoothing: Smoothing) -> Self {
        self.smoothing = smoothing;
        self
    }
}
named!(Bleu);
thresholded!(Bleu);

#[async_trait]
impl Evaluator for Bleu {
    fn name(&self) -> &str {
        &self.name
    }
    async fn evaluate(&self, ex: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let mut refs = vec![capped_tokens(reference(ex)?, self.max_tokens, "reference")?];
        for extra in ex.metadata_strings("references").into_iter().take(16) {
            refs.push(capped_tokens(extra, self.max_tokens, "reference")?);
        }
        let hyp = capped_tokens(&out.output, self.max_tokens, "output")?;
        let refs: Vec<&[String]> = refs.iter().map(Vec::as_slice).collect();
        let v = sentence_bleu(&hyp, &refs, self.max_n, self.smoothing);
        Ok(Score::at_least(v, self.threshold))
    }
}

/// ROUGE-L F1 against the reference (`rouge_l`), precision and recall in
/// the details. Passes at 0.5 by default.
#[derive(Debug, Clone)]
pub struct RougeL {
    name: String,
    threshold: f64,
    max_tokens: usize,
}

impl Default for RougeL {
    fn default() -> Self {
        Self::new()
    }
}

impl RougeL {
    /// ROUGE-L F1, threshold 0.5.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "rouge_l".into(),
            threshold: 0.5,
            max_tokens: DEFAULT_MAX_TOKENS,
        }
    }
}
named!(RougeL);
thresholded!(RougeL);

#[async_trait]
impl Evaluator for RougeL {
    fn name(&self) -> &str {
        &self.name
    }
    async fn evaluate(&self, ex: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let r = capped_tokens(reference(ex)?, self.max_tokens, "reference")?;
        let o = capped_tokens(&out.output, self.max_tokens, "output")?;
        let s = rouge_l(&o, &r);
        Ok(Score::at_least(s.f1, self.threshold)
            .with_details(json!({"precision": s.precision, "recall": s.recall})))
    }
}

/// Cosine similarity of the output and reference embeddings
/// (`embedding_similarity`). Passes at 0.8 by default.
#[derive(Clone)]
pub struct EmbeddingSimilarity {
    name: String,
    embedder: Arc<dyn Embedder>,
    threshold: f64,
    max_chars: usize,
}

impl std::fmt::Debug for EmbeddingSimilarity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingSimilarity")
            .field("name", &self.name)
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}

impl EmbeddingSimilarity {
    /// Compare with `embedder`, threshold 0.8.
    pub fn new(embedder: impl Embedder + 'static) -> Self {
        Self::from_arc(Arc::new(embedder))
    }

    /// Like [`new`](Self::new) with a shared embedder.
    #[must_use]
    pub fn from_arc(embedder: Arc<dyn Embedder>) -> Self {
        Self {
            name: "embedding_similarity".into(),
            embedder,
            threshold: 0.8,
            max_chars: 32_768,
        }
    }
}
named!(EmbeddingSimilarity);
thresholded!(EmbeddingSimilarity);

#[async_trait]
impl Evaluator for EmbeddingSimilarity {
    fn name(&self) -> &str {
        &self.name
    }
    async fn evaluate(&self, ex: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let reference_text = capped_chars(reference(ex)?, self.max_chars, "reference")?;
        let output = capped_chars(&out.output, self.max_chars, "output")?;
        let vectors = self.embedder.embed_batch(&[output, reference_text]).await?;
        let [a, b] = vectors.as_slice() else {
            return Err(EvalError::Other(format!(
                "embedder returned {} vectors for 2 texts",
                vectors.len()
            )));
        };
        let cos = f64::from(try_cosine_similarity(a, b)?);
        if !cos.is_finite() {
            return Err(EvalError::Other(
                "embedding similarity is not finite".into(),
            ));
        }
        Ok(Score::at_least(cos.clamp(-1.0, 1.0), self.threshold))
    }
}
