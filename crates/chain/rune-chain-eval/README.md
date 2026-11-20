# rune-chain-eval

> Evaluation harness for rune-chain LLM apps: datasets, bounded concurrent runs, heuristic, LLM-as-judge, RAG and trajectory metrics, bootstrap CIs, and run comparison for CI gates

[![crates.io](https://img.shields.io/crates/v/rune-chain-eval)](https://crates.io/crates/rune-chain-eval)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-eval)](https://docs.rs/rune-chain-eval)
[![license](https://img.shields.io/crates/l/rune-chain-eval)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Measure your LLM app the way LangSmith evals, Ragas and OpenAI evals do in Python. Run it over a
dataset, score every answer, and fail CI when a change makes things worse.

- **Datasets.** Examples have inputs, an optional reference output and metadata. Load them from
  JSON Lines or RFC 4180 CSV under size caps. Take seeded samples, shuffles and train/test splits.
- **Targets.** Evaluate any `Chain`, any async closure, or (feature `retrieval`) a retriever plus a
  chain. Runs use bounded concurrency, per-example timeouts and retries on retryable errors. Each
  example records its tokens, its cost (priced with `rune-chain-usage`, optionally into a shared
  `UsageMeter`) and its latency.
- **Heuristic metrics.** Exact, normalized (SQuAD-style), contains, regex, JSON validity, JSON
  Schema, Levenshtein similarity, BLEU, ROUGE-L and embedding cosine similarity. BLEU and ROUGE-L
  match NLTK and `rouge-score` to the last digit on their reference examples.
- **LLM-as-judge.** Correctness against the reference, named criteria, an integer rubric, pairwise
  A/B with position-swap debiasing, and a groundedness (hallucination) check. Verdicts are typed
  and schema-validated through `rune-chain-output-parser`, with a re-ask on bad replies.
- **RAG metrics (Ragas style).** Faithfulness, answer relevancy, context precision and context
  recall, built on the judge plus any `Embedder`.
- **Agent trajectories.** Checks whether the expected tool calls happened: exactly, in order, or as
  a set, with optional argument matching.
- **Reports.** Per-example results plus the mean, pass rate, min/max, p50/p95 latency, tokens,
  cost and a seeded bootstrap confidence interval per metric. Export to JSON, JSONL or Markdown.
- **Comparison.** `compare(baseline, candidate, &thresholds)` shows the change in each metric and
  lists the examples that flipped between pass and fail. It returns a gate result with an exit code
  for CI.

## Installation

```toml
[dependencies]
rune-chain-eval = "0.1"
```

Or through the facade: `rune-chain = { version = "0.1", features = ["eval"] }`, then
`rune_chain::eval`.

## Quick start

```rust
use rune_chain_core::testing::FakeLlm;
use rune_chain_eval::judge::{CorrectnessJudge, Judge};
use rune_chain_eval::{
    Dataset, DatasetLimits, Evaluation, RougeL, TargetOutput, Thresholds, compare, target_fn,
};

# tokio_test::block_on(async {
let dataset = Dataset::from_jsonl_str(
    r#"{"id": "fr", "question": "Capital of France?", "reference": "Paris"}
{"id": "de", "question": "Capital of Germany?", "reference": "Berlin"}"#,
    &DatasetLimits::default(),
)
.unwrap();

// The app under test: any Chain (`chain_target(chain)`) or an async closure.
let app = target_fn(|ex| async move {
    let q = ex.question().unwrap_or_default().to_owned();
    let answer = if q.contains("France") { "Paris" } else { "Munich" };
    Ok::<_, rune_chain_core::ChainError>(TargetOutput::text(answer))
});

// The judge is any Llm. A scripted fake keeps this example offline.
let judge = Judge::new(FakeLlm::with_replies([
    r#"{"reasoning": "Same city.", "verdict": "correct"}"#,
    r#"{"reasoning": "Wrong city.", "verdict": "incorrect"}"#,
]));

let run = Evaluation::new("v2")
    .evaluator(RougeL::new())
    .evaluator(CorrectnessJudge::new(judge))
    .concurrency(1)
    .run(&dataset, &app)
    .await
    .unwrap();

assert_eq!(run.metric("correctness").unwrap().pass_rate, 0.5);
let markdown = run.to_markdown(); // or run.to_json(), run.to_jsonl()

// In CI: compare with a stored baseline and fail on a regression.
let baseline = run.clone(); // e.g. RunResult::from_json(&std::fs::read_to_string("baseline.json")?)?
let gate = Thresholds::new().min_pass_rate("correctness", 0.5).max_mean_drop(0.02);
let cmp = compare(&baseline, &run, &gate);
assert!(cmp.passed());
// std::process::exit(cmp.exit_code());
# let _ = markdown;
# });
```

`examples/eval_quickstart.rs` runs two versions of an app, prints both reports and the comparison,
and shows a failing gate: `cargo run -p rune-chain-eval --example eval_quickstart`.

## Dataset format

One JSON object per line:

```json
{"id": "q1", "inputs": {"question": "..."}, "reference": "...", "metadata": {"contexts": ["..."], "expected_tools": ["search"]}}
```

`id` defaults to the line's position. `reference` may also be called `expected`. Without `inputs`,
every other top-level key is an input. For CSV, a column named `id` is the id, `reference` is the
reference, the `metadata_columns` you list go to metadata, and the other columns are inputs.

Evaluators read these metadata keys:

| Key | Used by |
|---|---|
| `contexts` (or `context`) | groundedness and the RAG metrics, when the target recorded no contexts |
| `expected_tools` | `TrajectoryEvaluator`: tool names, or `{"name": .., "args": {..}}` |
| `baseline` | `PairwiseJudge`: the answer to compare against |
| `references` | `Bleu`: extra references |

## Coming from LangSmith or Ragas

| LangSmith / Ragas / OpenAI evals | rune-chain-eval |
|---|---|
| `Client.create_dataset` / `create_examples` | `Dataset::new(examples)`, `Dataset::from_jsonl_path`, `from_csv_path` |
| example `inputs` / `outputs` / `metadata` | `Example { inputs, reference, metadata }` |
| `evaluate(target, data=..., evaluators=[...])` | `Evaluation::new(name).evaluator(..).run(&dataset, &target)` |
| `max_concurrency` | `.concurrency(n)` |
| target function | `target_fn(\|ex\| async { .. })` or `chain_target(chain)` |
| custom evaluator `(run, example) -> {"score": ..}` | `impl Evaluator` returning a `Score` |
| `exact_match`, `embedding_distance`, `string_distance`, `json_validity` | `ExactMatch`, `EmbeddingSimilarity`, `LevenshteinSimilarity`, `JsonValid` / `JsonSchemaMatch` |
| `LangChainStringEvaluator("cot_qa")` / `correctness` | `CorrectnessJudge` |
| `criteria` / `labeled_score_string` | `CriteriaJudge` / `RubricJudge` |
| pairwise experiments | `PairwiseJudge` (asks twice, swapped, to cancel position bias) |
| hallucination evaluator | `GroundednessJudge` |
| Ragas `faithfulness`, `answer_relevancy` | `rag::Faithfulness`, `rag::AnswerRelevancy` |
| Ragas `context_precision`, `context_recall` | `rag::ContextPrecision`, `rag::ContextRecall` |
| agentevals trajectory match (`strict`, `unordered`, `subset`) | `TrajectoryEvaluator` with `TrajectoryMode::Exact` / `Unordered` / `InOrder` |
| experiment results, `to_pandas()` | `RunResult`, `to_json` / `to_jsonl` / `to_markdown` / `examples_markdown` |
| comparing experiments | `compare(&baseline, &candidate, &thresholds)` |
| OpenAI evals `sample` / `n` | `Dataset::sample(n, seed)`, `Dataset::split(fraction, seed)` |

## How scores work

Each evaluator returns a `Score { value, passed, reasoning, details }`. Each run aggregates per
metric:

- `mean`, `min` and `max` over the examples that were scored;
- `pass_rate = passed / count`. A failed target or a failed evaluator is an error outcome, and it
  counts as a failure, never as a pass;
- a percentile-bootstrap confidence interval for the mean (`BootstrapConfig`: 1000 resamples, 95%,
  seed 0 by default). The same seed always gives the same interval.

In a comparison, a metric is `Improved` or `Regressed` when its mean moves by more than the
tolerance. It is also `significant` when the two confidence intervals don't overlap.

## Security

- **Prompt injection.** Judge prompts put the answer, question, reference and contexts in tagged
  blocks (`<candidate_output>`, `<context>`, ...). Any look-alike tag inside the content is escaped,
  in any letter case and with whitespace or invisible characters slipped in. The system prompt
  tells the judge to treat those blocks as data.
- **Malformed judge replies.** These are re-asked (twice by default), then recorded as errors.
  Nothing panics on model output, and a verdict that contradicts itself (for example "grounded"
  with unsupported claims listed) does not pass.
- **Length caps.** Target outputs (256 KiB), judge replies (64 KiB), judge reasoning (2000
  characters), untrusted blocks (12 000 characters), error messages, dataset records (1 MiB), whole
  datasets (64 MiB), CSV columns and the inputs to quadratic metrics (Levenshtein, LCS) are all
  capped.
- **Error messages.** Dataset errors give the line or record number, never the content.

## License

MIT
