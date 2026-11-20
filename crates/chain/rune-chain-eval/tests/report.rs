//! Aggregation, export and run comparison.

#![allow(
    clippy::unwrap_used,
    clippy::float_cmp,
    reason = "test helpers fail loudly"
)]

use rune_chain_core::ChainError;
use rune_chain_eval::stats::BootstrapConfig;
use rune_chain_eval::{
    Change, Dataset, Evaluation, ExactMatch, Example, RougeL, RunResult, TargetOutput, Thresholds,
    compare, target_fn,
};

fn dataset() -> Dataset {
    Dataset::new(
        ["a", "b", "c", "d"]
            .iter()
            .map(|id| {
                Example::from_question(*id, format!("q-{id}"))
                    .with_reference(format!("answer {id}"))
            })
            .collect(),
    )
    .unwrap()
}

/// Answers correctly for the ids in `right`.
async fn run_with(name: &str, right: &'static [&'static str]) -> RunResult {
    let target = target_fn(move |ex: Example| async move {
        if ex.id == "d" && right.is_empty() {
            return Err(ChainError::Other("boom".into()));
        }
        let answer = if right.contains(&ex.id.as_str()) {
            format!("answer {}", ex.id)
        } else {
            "something | else".to_owned()
        };
        Ok::<_, ChainError>(TargetOutput::text(answer))
    });
    Evaluation::new(name)
        .evaluator(ExactMatch::new())
        .evaluator(RougeL::new())
        .bootstrap(BootstrapConfig {
            resamples: 400,
            level: 0.95,
            seed: 5,
        })
        .run(&dataset(), &target)
        .await
        .unwrap()
}

#[tokio::test]
async fn aggregates() {
    let run = run_with("v1", &["a", "b", "c"]).await;
    let m = run.metric("exact_match").unwrap();
    assert_eq!((m.count, m.scored, m.passed, m.errors), (4, 4, 3, 0));
    assert_eq!(m.pass_rate, 0.75);
    assert_eq!(m.mean, Some(0.75));
    assert_eq!((m.min, m.max), (Some(0.0), Some(1.0)));
    let ci = m.ci.unwrap();
    assert!(ci.low <= 0.75 && ci.high >= 0.75 && ci.high <= 1.0);
    // Rouge-L of "something else" vs "answer d" is 0.
    let r = run.metric("rouge_l").unwrap();
    assert_eq!(r.mean, Some(0.75));

    // Target failure counts as an error for every metric.
    let bad = run_with("v0", &[]).await;
    let m = bad.metric("exact_match").unwrap();
    assert_eq!((m.errors, m.scored, m.passed), (1, 3, 0));
    assert_eq!(bad.summary.target_errors, 1);
}

#[tokio::test]
async fn confidence_intervals_are_deterministic() {
    let a = run_with("v1", &["a", "b", "c"]).await;
    let b = run_with("v1", &["a", "b", "c"]).await;
    assert_eq!(
        a.metric("exact_match").unwrap().ci,
        b.metric("exact_match").unwrap().ci
    );
    let rebuilt = RunResult::new(
        "x",
        a.examples.clone(),
        &BootstrapConfig {
            resamples: 400,
            level: 0.95,
            seed: 5,
        },
    );
    assert_eq!(rebuilt.summary.metrics, a.summary.metrics);
}

#[tokio::test]
async fn exports() {
    let run = run_with("v1 | <b>", &["a", "b"]).await;
    let json = run.to_json().unwrap();
    let back = RunResult::from_json(&json).unwrap();
    assert_eq!(back, run);
    let jsonl = run.to_jsonl().unwrap();
    assert_eq!(jsonl.lines().count(), 4);
    for line in jsonl.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(v["scores"]["exact_match"]["status"].is_string());
    }
    let md = run.to_markdown();
    assert!(md.contains("| exact_match | 0.500 |"), "{md}");
    assert!(md.contains("v1 \\| &lt;b&gt;"));
    let table = run.examples_markdown();
    assert_eq!(table.lines().count(), 6);
    assert!(table.contains("something \\| else"));
    assert!(table.contains("0.000 ✗"));
    assert!(RunResult::from_json("{").is_err());
}

#[tokio::test]
async fn comparison_and_gate() {
    let baseline = run_with("v1", &["a", "b", "c"]).await;
    let candidate = run_with("v2", &["a", "d"]).await;
    let cmp = compare(&baseline, &candidate, &Thresholds::new());
    assert!(cmp.passed());
    let em = cmp
        .metrics
        .iter()
        .find(|m| m.name == "exact_match")
        .unwrap();
    assert_eq!(em.change, Change::Regressed);
    assert_eq!(em.mean_delta, Some(-0.25));
    assert_eq!(em.pass_rate_delta, -0.25);
    let regressed: Vec<(&str, &str)> = cmp
        .regressions
        .iter()
        .map(|c| (c.id.as_str(), c.metric.as_str()))
        .collect();
    assert!(regressed.contains(&("b", "exact_match")) && regressed.contains(&("c", "rouge_l")));
    assert!(
        cmp.improvements
            .iter()
            .any(|c| c.id == "d" && c.metric == "exact_match")
    );

    let gate = Thresholds::new()
        .max_mean_drop(0.1)
        .min_pass_rate("exact_match", 0.6)
        .min_mean("rouge_l", 0.4);
    let cmp = compare(&baseline, &candidate, &gate);
    assert!(!cmp.passed());
    assert_eq!(cmp.exit_code(), 1);
    assert!(
        cmp.gate
            .failures
            .iter()
            .any(|f| f.contains("exact_match: mean dropped"))
    );
    assert!(
        cmp.gate
            .failures
            .iter()
            .any(|f| f.contains("pass rate 0.5000 is below 0.6"))
    );
    let md = cmp.to_markdown();
    assert!(md.contains("Gate: failed") && md.contains("▼ regressed"));

    // Same run: unchanged, gate passes, nothing flipped.
    let same = compare(
        &baseline,
        &baseline,
        &gate.clone().min_pass_rate("exact_match", 0.75),
    );
    assert!(same.passed() && same.regressions.is_empty());
    assert!(
        same.metrics
            .iter()
            .all(|m| m.change == Change::Unchanged && !m.significant)
    );

    // Tolerance hides small changes.
    let tol = compare(&baseline, &candidate, &Thresholds::new().tolerance(0.3));
    assert!(tol.metrics.iter().all(|m| m.change == Change::Unchanged));

    // Single-run gate.
    assert!(
        Thresholds::new()
            .min_pass_rate("exact_match", 0.7)
            .check(&baseline)
            .passed()
    );
    let g = Thresholds::new().min_mean("missing", 0.1).check(&baseline);
    assert_eq!(g.exit_code(), 1);
    let failed = run_with("v0", &[]).await;
    assert!(
        !Thresholds::new()
            .max_target_error_rate(0.1)
            .check(&failed)
            .passed()
    );
}

#[tokio::test]
async fn missing_metric_fails_the_gate() {
    let baseline = run_with("v1", &["a"]).await;
    let target = target_fn(|_ex| async { Ok::<_, ChainError>(TargetOutput::text("x")) });
    let candidate = Evaluation::new("v2")
        .evaluator(ExactMatch::new())
        .run(&dataset(), &target)
        .await
        .unwrap();
    let cmp = compare(&baseline, &candidate, &Thresholds::new());
    assert!(!cmp.passed());
    assert!(cmp.gate.failures[0].contains("rouge_l: missing"));
}

#[tokio::test]
async fn compare_reports_unmatched_examples() {
    let baseline = run_with("v1", &["a"]).await;
    let mut candidate = baseline.clone();
    candidate.examples.retain(|e| e.id != "a");
    let cmp = compare(&baseline, &candidate, &Thresholds::new());
    assert_eq!(cmp.only_in_baseline, ["a"]);
    assert_eq!(cmp.only_in_candidate.len(), 0);
}
