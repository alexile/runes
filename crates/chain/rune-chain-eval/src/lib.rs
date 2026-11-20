//! Evaluation harness for LLM apps built on `rune-chain`: what `LangSmith`
//! evals, Ragas and `OpenAI` evals do in Python.
//!
//! - **[`Dataset`]**: [`Example`]s with inputs, an optional reference
//!   output and metadata. Load JSON Lines or CSV under size caps
//!   ([`DatasetLimits`]); take seeded [samples](Dataset::sample) and
//!   [splits](Dataset::split).
//! - **[`Target`]**: any [`Chain`](rune_chain_core::Chain)
//!   ([`chain_target`]), an async closure ([`target_fn`]), or (feature
//!   `retrieval`) a retriever plus a chain (`RagTarget`).
//! - **[`Evaluation`]**: runs the target over the dataset with bounded
//!   concurrency, per-example timeouts and retries, and records tokens,
//!   cost (via `rune-chain-usage`) and latency.
//! - **[`Evaluator`]s**:
//!   - heuristic ([`heuristic`]): exact, normalized, contains, regex,
//!     JSON validity, JSON Schema, Levenshtein, BLEU, ROUGE-L, embedding
//!     cosine;
//!   - LLM-as-judge ([`judge`]): correctness, criteria, rubric, pairwise
//!     with position swap, groundedness;
//!   - RAG ([`rag`]): faithfulness, answer relevancy, context precision,
//!     context recall;
//!   - agent [`trajectory`]: expected tool calls, exact, in order or as a
//!     set.
//! - **[`RunResult`]**: per-example results plus mean, pass rate, p50/p95
//!   latency and seeded bootstrap confidence intervals; export to JSON,
//!   JSONL and Markdown. [`compare`] two runs for regressions and
//!   improvements and gate CI on [`Thresholds`].
//!
//! # Hardening
//!
//! - Judge prompts put the answer, question, reference and contexts in
//!   tagged blocks with look-alike tags escaped, and tell the judge they
//!   are data ([`judge::fence`]).
//! - Outputs, judge replies, judge reasoning, error messages, dataset
//!   records and quadratic metrics all have length caps.
//! - A malformed judge reply is re-asked, then becomes an error outcome:
//!   errors never count as passes, and nothing panics on model output.
//!
//! # Example
//!
//! ```rust
//! use rune_chain_core::testing::FakeLlm;
//! use rune_chain_eval::judge::{CorrectnessJudge, Judge};
//! use rune_chain_eval::{Dataset, DatasetLimits, Evaluation, RougeL, TargetOutput, target_fn};
//!
//! # tokio_test::block_on(async {
//! let ds = Dataset::from_jsonl_str(
//!     r#"{"id": "fr", "question": "Capital of France?", "reference": "Paris"}"#,
//!     &DatasetLimits::default(),
//! )
//! .unwrap();
//!
//! // The app under test.
//! let app = target_fn(|_ex| async { Ok::<_, rune_chain_core::ChainError>(TargetOutput::text("Paris")) });
//!
//! // A scripted judge; use a real model in practice.
//! let judge = Judge::new(FakeLlm::with_replies([
//!     r#"{"reasoning": "Same city.", "verdict": "correct"}"#,
//! ]));
//!
//! let run = Evaluation::new("v1")
//!     .evaluator(RougeL::new())
//!     .evaluator(CorrectnessJudge::new(judge))
//!     .run(&ds, &app)
//!     .await
//!     .unwrap();
//! assert_eq!(run.metric("correctness").unwrap().pass_rate, 1.0);
//! assert!(run.to_markdown().contains("correctness"));
//! # });
//! ```

#![forbid(unsafe_code)]

mod compare;
mod dataset;
mod error;
mod evaluator;
pub mod heuristic;
pub mod judge;
pub mod metrics;
pub mod rag;
mod report;
mod runner;
pub mod stats;
mod target;
pub mod trajectory;

pub use compare::{
    Change, Comparison, ExampleChange, GateResult, MetricComparison, Thresholds, compare,
};
pub use dataset::{CsvOptions, Dataset, DatasetLimits, Example};
pub use error::EvalError;
pub use evaluator::{Evaluator, MetricOutcome, Score};
pub use heuristic::{
    Bleu, Contains, EmbeddingSimilarity, ExactMatch, JsonSchemaMatch, JsonValid,
    LevenshteinSimilarity, NormalizedMatch, RegexMatch, RougeL,
};
pub use report::{
    ExampleResult, LatencySummary, MAX_REPORT_BYTES, MetricSummary, RunResult, Summary,
};
pub use runner::{DEFAULT_MAX_OUTPUT_BYTES, Evaluation};
#[cfg(feature = "retrieval")]
pub use target::RagTarget;
pub use target::{ChainTarget, FnTarget, Target, TargetOutput, chain_target, target_fn};

/// The README examples, compiled and run as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
