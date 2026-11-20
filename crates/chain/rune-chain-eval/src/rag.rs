//! RAG metrics in the style of Ragas: faithfulness, answer relevancy,
//! context precision and context recall.
//!
//! Contexts come from the target's [`TargetOutput::contexts`] (what was
//! actually retrieved), or from `metadata.contexts` on the example.

use std::sync::Arc;

use async_trait::async_trait;
use rune_chain_embed::{Embedder, try_cosine_similarity};
use rune_chain_output_parser::Extractor;
use serde::Deserialize;
use serde_json::json;

use crate::evaluator::reference;
use crate::judge::{Judge, MAX_CONTEXTS, context_blocks, contexts};
use crate::{EvalError, Evaluator, Example, Score, TargetOutput};

/// Most claims a judge may list for one answer or reference.
const MAX_CLAIMS: usize = 64;

macro_rules! rag_builders {
    ($t:ty) => {
        impl $t {
            /// Rename the metric (builder style).
            #[must_use]
            pub fn with_name(mut self, name: impl Into<String>) -> Self {
                self.name = name.into();
                self
            }

            /// Pass at this score (builder style).
            #[must_use]
            pub const fn with_threshold(mut self, threshold: f64) -> Self {
                self.threshold = threshold;
                self
            }
        }
    };
}

fn ready<T>(e: &Result<Extractor<T>, String>) -> Result<&Extractor<T>, EvalError> {
    e.as_ref().map_err(|m| EvalError::Config(m.clone()))
}

fn require_contexts<'a>(ex: &'a Example, out: &'a TargetOutput) -> Result<Vec<&'a str>, EvalError> {
    let mut c = contexts(ex, out);
    if c.is_empty() {
        return Err(EvalError::Missing("contexts".into()));
    }
    c.truncate(MAX_CONTEXTS);
    Ok(c)
}

#[derive(Debug, Clone, Deserialize)]
struct Claim {
    statement: String,
    supported: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct Claims {
    statements: Vec<Claim>,
}

fn claims_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "statements": {
                "type": "array",
                "maxItems": MAX_CLAIMS,
                "items": {
                    "type": "object",
                    "properties": {
                        "statement": {"type": "string"},
                        "supported": {"type": "boolean"}
                    },
                    "required": ["statement", "supported"]
                }
            }
        },
        "required": ["statements"]
    })
}

#[allow(clippy::cast_precision_loss)]
fn claim_score(
    judge: &Judge,
    claims: &Claims,
    threshold: f64,
    what: &str,
) -> Result<Score, EvalError> {
    let total = claims.statements.len();
    if total == 0 {
        return Err(EvalError::Missing(format!("{what}: no claims to check")));
    }
    let ok = claims.statements.iter().filter(|c| c.supported).count();
    let details: Vec<serde_json::Value> = claims
        .statements
        .iter()
        .map(|c| json!({"statement": judge.reasoning(&c.statement), "supported": c.supported}))
        .collect();
    Ok(Score::at_least(ok as f64 / total as f64, threshold)
        .with_reasoning(format!("{ok} of {total} {what} supported"))
        .with_details(serde_json::Value::Array(details)))
}

/// Faithfulness: the share of the answer's claims that the contexts
/// support (`faithfulness`). Passes at 0.8 by default.
#[derive(Debug, Clone)]
pub struct Faithfulness {
    name: String,
    judge: Judge,
    threshold: f64,
    extractor: Result<Extractor<Claims>, String>,
}

impl Faithfulness {
    /// Faithfulness with `judge`.
    #[must_use]
    pub fn new(judge: Judge) -> Self {
        let extractor = judge
            .extractor("faithfulness", claims_schema())
            .map_err(|e| e.to_string());
        Self {
            name: "faithfulness".into(),
            judge,
            threshold: 0.8,
            extractor,
        }
    }
}
rag_builders!(Faithfulness);

#[async_trait]
impl Evaluator for Faithfulness {
    fn name(&self) -> &str {
        &self.name
    }
    async fn evaluate(&self, ex: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let ctx = require_contexts(ex, out)?;
        let j = &self.judge;
        let body = format!(
            "{}{}\n\n{}",
            context_blocks(j, &ctx),
            j.block("question", ex.question().unwrap_or_default()),
            j.block("candidate_output", &out.output)
        );
        let claims = j
            .ask(
                ready(&self.extractor)?,
                "Break the candidate output into short, standalone factual statements. For each \
                 one, decide whether it can be directly inferred from the contexts \
                 (supported: true) or not (supported: false). Reply with JSON only.",
                &body,
            )
            .await?;
        claim_score(j, &claims, self.threshold, "claims")
    }
}

/// Context recall: the share of the reference's claims that the contexts
/// support (`context_recall`). Needs a reference. Passes at 0.8 by default.
#[derive(Debug, Clone)]
pub struct ContextRecall {
    name: String,
    judge: Judge,
    threshold: f64,
    extractor: Result<Extractor<Claims>, String>,
}

impl ContextRecall {
    /// Context recall with `judge`.
    #[must_use]
    pub fn new(judge: Judge) -> Self {
        let extractor = judge
            .extractor("context_recall", claims_schema())
            .map_err(|e| e.to_string());
        Self {
            name: "context_recall".into(),
            judge,
            threshold: 0.8,
            extractor,
        }
    }
}
rag_builders!(ContextRecall);

#[async_trait]
impl Evaluator for ContextRecall {
    fn name(&self) -> &str {
        &self.name
    }
    async fn evaluate(&self, ex: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let ctx = require_contexts(ex, out)?;
        let j = &self.judge;
        let body = format!(
            "{}{}\n\n{}",
            context_blocks(j, &ctx),
            j.block("question", ex.question().unwrap_or_default()),
            j.block("reference", reference(ex)?)
        );
        let claims = j
            .ask(
                ready(&self.extractor)?,
                "Break the reference answer into short, standalone factual statements. For each \
                 one, decide whether it can be attributed to the contexts (supported: true) or \
                 not (supported: false). Reply with JSON only.",
                &body,
            )
            .await?;
        claim_score(j, &claims, self.threshold, "reference claims")
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Usefulness {
    index: usize,
    useful: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct Usefulnesses {
    verdicts: Vec<Usefulness>,
}

/// Mean precision@k over the ranks `k` that hold a useful context
/// (Ragas' context precision, i.e. average precision). `0.0` when none is
/// useful.
///
/// ```rust
/// use rune_chain_eval::rag::average_precision;
///
/// // Useful at ranks 1 and 3: (1/1 + 2/3) / 2.
/// assert!((average_precision(&[true, false, true]) - 5.0 / 6.0).abs() < 1e-12);
/// assert_eq!(average_precision(&[false, false]), 0.0);
/// ```
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn average_precision(useful: &[bool]) -> f64 {
    let mut hits = 0usize;
    let mut sum = 0.0;
    for (k, &u) in useful.iter().enumerate() {
        if u {
            hits += 1;
            sum += hits as f64 / (k + 1) as f64;
        }
    }
    if hits == 0 { 0.0 } else { sum / hits as f64 }
}

/// Context precision: are the useful contexts ranked first?
///
/// Metric name `context_precision`. The judge marks each context as useful or not
/// for reaching the reference answer (or, without one, the given answer);
/// the score is [`average_precision`]. Passes at 0.5 by default.
#[derive(Debug, Clone)]
pub struct ContextPrecision {
    name: String,
    judge: Judge,
    threshold: f64,
}

impl ContextPrecision {
    /// Context precision with `judge`.
    #[must_use]
    pub fn new(judge: Judge) -> Self {
        Self {
            name: "context_precision".into(),
            judge,
            threshold: 0.5,
        }
    }
}
rag_builders!(ContextPrecision);

#[async_trait]
impl Evaluator for ContextPrecision {
    fn name(&self) -> &str {
        &self.name
    }
    async fn evaluate(&self, ex: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let ctx = require_contexts(ex, out)?;
        let n = ctx.len();
        let j = &self.judge;
        let (tag, answer) = ex
            .reference
            .as_deref()
            .map_or(("candidate_output", out.output.as_str()), |r| {
                ("reference", r)
            });
        let extractor = j
            .extractor::<Usefulnesses>(
                "context_precision",
                json!({
                    "type": "object",
                    "properties": {
                        "verdicts": {
                            "type": "array",
                            "minItems": n,
                            "maxItems": n,
                            "items": {
                                "type": "object",
                                "properties": {
                                    "index": {"type": "integer", "minimum": 0, "maximum": n - 1},
                                    "useful": {"type": "boolean"}
                                },
                                "required": ["index", "useful"]
                            }
                        }
                    },
                    "required": ["verdicts"]
                }),
            )?
            .with_validator(move |v: &Usefulnesses| {
                let mut seen = vec![false; n];
                for u in &v.verdicts {
                    if u.index >= n || std::mem::replace(&mut seen[u.index], true) {
                        return Err(format!("give exactly one verdict per context index 0..{n}"));
                    }
                }
                Ok(())
            });
        let body = format!(
            "{}{}\n\n{}",
            context_blocks(j, &ctx),
            j.block("question", ex.question().unwrap_or_default()),
            j.block(tag, answer)
        );
        let v = j
            .ask(
                &extractor,
                "For each numbered context, decide whether it was useful for arriving at the \
                 given answer to the question (useful: true) or not. Give one verdict per \
                 context index. Reply with JSON only.",
                &body,
            )
            .await?;
        let mut useful = vec![false; n];
        for u in &v.verdicts {
            useful[u.index] = u.useful;
        }
        Ok(Score::at_least(average_precision(&useful), self.threshold)
            .with_details(json!({"useful": useful})))
    }
}

#[derive(Debug, Clone, Deserialize)]
struct GeneratedQuestions {
    questions: Vec<String>,
    noncommittal: bool,
}

/// Answer relevancy: does the answer address the question?
///
/// The judge writes questions that the answer would answer, and the score is their mean cosine similarity to the real
/// question; a noncommittal answer ("I don't know") scores 0
/// (`answer_relevancy`). Passes at 0.7 by default.
#[derive(Clone)]
pub struct AnswerRelevancy {
    name: String,
    judge: Judge,
    embedder: Arc<dyn Embedder>,
    questions: usize,
    threshold: f64,
}

impl std::fmt::Debug for AnswerRelevancy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnswerRelevancy")
            .field("name", &self.name)
            .field("questions", &self.questions)
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}

impl AnswerRelevancy {
    /// Answer relevancy with `judge` and `embedder`, three generated
    /// questions.
    pub fn new(judge: Judge, embedder: impl Embedder + 'static) -> Self {
        Self::from_arc(judge, Arc::new(embedder))
    }

    /// Like [`new`](Self::new) with a shared embedder.
    #[must_use]
    pub fn from_arc(judge: Judge, embedder: Arc<dyn Embedder>) -> Self {
        Self {
            name: "answer_relevancy".into(),
            judge,
            embedder,
            questions: 3,
            threshold: 0.7,
        }
    }

    /// How many questions to generate, 1 to 10 (builder style).
    #[must_use]
    pub fn with_questions(mut self, n: usize) -> Self {
        self.questions = n.clamp(1, 10);
        self
    }
}
rag_builders!(AnswerRelevancy);

#[async_trait]
impl Evaluator for AnswerRelevancy {
    fn name(&self) -> &str {
        &self.name
    }
    #[allow(clippy::cast_precision_loss)]
    async fn evaluate(&self, ex: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let question = ex
            .question()
            .ok_or_else(|| EvalError::Missing("question".into()))?;
        let j = &self.judge;
        let n = self.questions;
        let extractor = j.extractor::<GeneratedQuestions>(
            "answer_relevancy",
            json!({
                "type": "object",
                "properties": {
                    "questions": {
                        "type": "array", "minItems": n, "maxItems": n,
                        "items": {"type": "string", "minLength": 1}
                    },
                    "noncommittal": {"type": "boolean"}
                },
                "required": ["questions", "noncommittal"]
            }),
        )?;
        let prompt = format!(
            "Write {n} different questions that the candidate output answers. Also say whether \
             the output is noncommittal (evasive or vague, like \"I don't know\"). Reply with \
             JSON only."
        );
        let g = j
            .ask(
                &extractor,
                &prompt,
                &j.block("candidate_output", &out.output),
            )
            .await?;
        if g.noncommittal {
            return Ok(Score::at_least(0.0, self.threshold).with_reasoning("noncommittal answer"));
        }
        let generated: Vec<String> = g.questions.iter().map(|q| j.reasoning(q)).collect();
        let mut texts: Vec<&str> = Vec::with_capacity(generated.len() + 1);
        texts.push(question);
        texts.extend(generated.iter().map(String::as_str));
        let vectors = self.embedder.embed_batch(&texts).await?;
        if vectors.len() != texts.len() {
            return Err(EvalError::Other(format!(
                "embedder returned {} vectors for {} texts",
                vectors.len(),
                texts.len()
            )));
        }
        let mut sum = 0.0;
        for v in &vectors[1..] {
            sum += f64::from(try_cosine_similarity(&vectors[0], v)?);
        }
        let value = (sum / generated.len() as f64).clamp(0.0, 1.0);
        if !value.is_finite() {
            return Err(EvalError::Other("answer relevancy is not finite".into()));
        }
        Ok(Score::at_least(value, self.threshold)
            .with_details(json!({"generated_questions": generated})))
    }
}
