//! Evaluate two versions of a small QA app, compare them and gate on the
//! result, fully offline: the app is a closure and the judge is a scripted
//! `FakeLlm`. Swap in a real chain and a real model for actual use.
//!
//! Run with `cargo run -p rune-chain-eval --example eval_quickstart`.

#![allow(clippy::print_stdout, reason = "an example prints its results")]

use rune_chain_core::testing::FakeLlm;
use rune_chain_core::{ChainError, GenerateResult, Pricing, TokenUsage};
use rune_chain_eval::judge::{CorrectnessJudge, Judge};
use rune_chain_eval::{
    Dataset, DatasetLimits, Evaluation, NormalizedMatch, RougeL, TargetOutput, Thresholds, compare,
    target_fn,
};

const DATA: &str = r#"
{"id": "fr", "question": "What is the capital of France?", "reference": "Paris"}
{"id": "de", "question": "What is the capital of Germany?", "reference": "Berlin"}
{"id": "it", "question": "What is the capital of Italy?", "reference": "Rome"}
{"id": "es", "question": "What is the capital of Spain?", "reference": "Madrid"}
"#;

/// A judge that calls an answer correct when it contains the reference.
/// A real judge would be e.g. `Judge::new(anthropic_client.model(..))`.
fn fake_judge() -> Judge {
    Judge::new(FakeLlm::from_fn(|req| {
        let prompt = req.prompt().unwrap_or_default();
        let block = |tag: &str| {
            let open = format!("<{tag}>\n");
            let close = format!("\n</{tag}>");
            prompt
                .split_once(&open)
                .and_then(|(_, rest)| rest.split_once(&close))
                .map(|(inner, _)| inner.to_owned())
                .unwrap_or_default()
        };
        let verdict = if block("candidate_output").contains(&block("reference")) {
            "correct"
        } else {
            "incorrect"
        };
        Ok(GenerateResult::from_text(format!(
            r#"{{"reasoning": "Compared with the reference.", "verdict": "{verdict}"}}"#
        )))
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dataset = Dataset::from_jsonl_str(DATA, &DatasetLimits::default())?;

    let v1 = target_fn(|ex| async move {
        let q = ex.question().unwrap_or_default().to_owned();
        let answer = match q.rsplit(' ').next().unwrap_or_default() {
            "France?" => "Paris",
            "Germany?" => "Berlin",
            "Italy?" => "Rome",
            _ => "Barcelona",
        };
        Ok::<_, ChainError>(TargetOutput::text(answer).with_usage(TokenUsage::new(20, 2)))
    });
    let v2 = target_fn(|ex| async move {
        let q = ex.question().unwrap_or_default().to_owned();
        let answer = match q.rsplit(' ').next().unwrap_or_default() {
            "France?" => "It is Paris.",
            "Germany?" => "Berlin",
            "Italy?" => "Milan",
            _ => "Madrid",
        };
        Ok::<_, ChainError>(TargetOutput::text(answer).with_usage(TokenUsage::new(20, 4)))
    });

    let eval = |name: &str| {
        Evaluation::new(name)
            .evaluator(NormalizedMatch::new())
            .evaluator(RougeL::new())
            .evaluator(CorrectnessJudge::new(fake_judge()))
            .concurrency(4)
            .pricing(Pricing::per_mtok(3_000_000, 15_000_000))
    };
    let baseline = eval("v1").run(&dataset, &v1).await?;
    let candidate = eval("v2").run(&dataset, &v2).await?;

    println!("{}", baseline.to_markdown());
    println!("{}", candidate.to_markdown());
    println!("{}", candidate.examples_markdown());

    let gate = Thresholds::new()
        .min_pass_rate("correctness", 0.75)
        .max_pass_rate_drop(0.0);
    let cmp = compare(&baseline, &candidate, &gate);
    println!("{}", cmp.to_markdown());
    println!("exit code for CI: {}", cmp.exit_code());
    Ok(())
}
