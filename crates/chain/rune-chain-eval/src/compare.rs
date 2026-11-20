//! Comparing two runs and gating CI on thresholds.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::report::md_cell;
use crate::{MetricOutcome, RunResult};

/// Direction of a metric's change between two runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// The candidate is better by more than the tolerance.
    Improved,
    /// The candidate is worse by more than the tolerance.
    Regressed,
    /// Within the tolerance.
    Unchanged,
}

/// One metric across two runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricComparison {
    /// Metric name.
    pub name: String,
    /// Baseline mean score.
    pub baseline_mean: Option<f64>,
    /// Candidate mean score.
    pub candidate_mean: Option<f64>,
    /// `candidate_mean - baseline_mean`.
    pub mean_delta: Option<f64>,
    /// Baseline pass rate.
    pub baseline_pass_rate: f64,
    /// Candidate pass rate.
    pub candidate_pass_rate: f64,
    /// `candidate_pass_rate - baseline_pass_rate`.
    pub pass_rate_delta: f64,
    /// Direction of the mean change (the pass rate when there is no mean).
    pub change: Change,
    /// Whether the two bootstrap intervals do not overlap.
    pub significant: bool,
}

/// One example that flipped between pass and fail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExampleChange {
    /// Example id.
    pub id: String,
    /// Metric name.
    pub metric: String,
    /// Baseline score (`None` on an error).
    pub baseline: Option<f64>,
    /// Candidate score (`None` on an error).
    pub candidate: Option<f64>,
}

/// Limits that make a run, or a comparison, fail.
///
/// ```rust
/// use rune_chain_eval::Thresholds;
///
/// let gate = Thresholds::new()
///     .min_pass_rate("correctness", 0.9)
///     .min_mean("rouge_l", 0.4)
///     .max_mean_drop(0.02);
/// # let _ = gate;
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Smallest allowed mean per metric.
    pub min_mean: BTreeMap<String, f64>,
    /// Smallest allowed pass rate per metric.
    pub min_pass_rate: BTreeMap<String, f64>,
    /// Largest allowed drop in any metric's mean versus the baseline.
    pub max_mean_drop: Option<f64>,
    /// Largest allowed drop in any metric's pass rate versus the baseline.
    pub max_pass_rate_drop: Option<f64>,
    /// Largest allowed share of examples whose target failed.
    pub max_target_error_rate: Option<f64>,
    /// Changes smaller than this are [`Change::Unchanged`] (default 0).
    pub tolerance: f64,
}

impl Thresholds {
    /// No limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Require `metric`'s mean to be at least `min` (builder style).
    #[must_use]
    pub fn min_mean(mut self, metric: impl Into<String>, min: f64) -> Self {
        self.min_mean.insert(metric.into(), min);
        self
    }

    /// Require `metric`'s pass rate to be at least `min` (builder style).
    #[must_use]
    pub fn min_pass_rate(mut self, metric: impl Into<String>, min: f64) -> Self {
        self.min_pass_rate.insert(metric.into(), min);
        self
    }

    /// Fail when any mean drops by more than `drop` (builder style).
    #[must_use]
    pub const fn max_mean_drop(mut self, drop: f64) -> Self {
        self.max_mean_drop = Some(drop);
        self
    }

    /// Fail when any pass rate drops by more than `drop` (builder style).
    #[must_use]
    pub const fn max_pass_rate_drop(mut self, drop: f64) -> Self {
        self.max_pass_rate_drop = Some(drop);
        self
    }

    /// Fail when more than this share of target calls failed (builder
    /// style).
    #[must_use]
    pub const fn max_target_error_rate(mut self, rate: f64) -> Self {
        self.max_target_error_rate = Some(rate);
        self
    }

    /// Ignore changes up to `tolerance` (builder style).
    #[must_use]
    pub const fn tolerance(mut self, tolerance: f64) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// Check one run against the absolute limits.
    #[must_use]
    pub fn check(&self, run: &RunResult) -> GateResult {
        let mut failures = Vec::new();
        self.check_absolute(run, &mut failures);
        GateResult { failures }
    }

    #[allow(clippy::cast_precision_loss)]
    fn check_absolute(&self, run: &RunResult, failures: &mut Vec<String>) {
        for (name, &min) in &self.min_mean {
            match run.metric(name).and_then(|m| m.mean) {
                Some(mean) if mean >= min => {}
                Some(mean) => failures.push(format!("{name}: mean {mean:.4} is below {min}")),
                None => failures.push(format!("{name}: no scores")),
            }
        }
        for (name, &min) in &self.min_pass_rate {
            match run.metric(name) {
                Some(m) if m.pass_rate >= min => {}
                Some(m) => failures.push(format!(
                    "{name}: pass rate {:.4} is below {min}",
                    m.pass_rate
                )),
                None => failures.push(format!("{name}: no scores")),
            }
        }
        if let Some(max) = self.max_target_error_rate {
            let s = &run.summary;
            let rate = if s.examples == 0 {
                0.0
            } else {
                s.target_errors as f64 / s.examples as f64
            };
            if rate > max {
                failures.push(format!("target error rate {rate:.4} is above {max}"));
            }
        }
    }
}

/// Whether a gate passed, and why not.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Every limit that was broken.
    pub failures: Vec<String>,
}

impl GateResult {
    /// No limit was broken.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.failures.is_empty()
    }

    /// `0` when passed, `1` otherwise: a process exit code for CI.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        i32::from(!self.passed())
    }
}

/// A baseline run compared with a candidate run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Comparison {
    /// Baseline run name.
    pub baseline: String,
    /// Candidate run name.
    pub candidate: String,
    /// Every metric in either run.
    pub metrics: Vec<MetricComparison>,
    /// Examples that passed in the baseline and not in the candidate.
    pub regressions: Vec<ExampleChange>,
    /// Examples that failed in the baseline and pass in the candidate.
    pub improvements: Vec<ExampleChange>,
    /// Example ids only in the baseline.
    pub only_in_baseline: Vec<String>,
    /// Example ids only in the candidate.
    pub only_in_candidate: Vec<String>,
    /// The gate verdict.
    pub gate: GateResult,
}

impl Comparison {
    /// Whether the candidate passed the thresholds.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.gate.passed()
    }

    /// `0` when passed, `1` otherwise.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        self.gate.exit_code()
    }

    /// A Markdown report: a metric table, flipped examples and the gate.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = format!(
            "## {} vs {}\n\n| Metric | Baseline | Candidate | Δ mean | Δ pass rate | Change |\n|---|---:|---:|---:|---:|---|\n",
            md_cell(&self.baseline),
            md_cell(&self.candidate)
        );
        let f = |v: Option<f64>| v.map_or_else(|| "–".to_owned(), |v| format!("{v:.3}"));
        for m in &self.metrics {
            let change = match m.change {
                Change::Improved => "▲ improved",
                Change::Regressed => "▼ regressed",
                Change::Unchanged => "unchanged",
            };
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {:+.1} pp | {change}{} |",
                md_cell(&m.name),
                f(m.baseline_mean),
                f(m.candidate_mean),
                m.mean_delta
                    .map_or_else(|| "–".to_owned(), |d| format!("{d:+.3}")),
                m.pass_rate_delta * 100.0,
                if m.significant { " (significant)" } else { "" }
            );
        }
        let list = |out: &mut String, title: &str, items: &[ExampleChange]| {
            if !items.is_empty() {
                let _ = writeln!(out, "\n**{title}** ({}):\n", items.len());
                for c in items.iter().take(50) {
                    let _ = writeln!(
                        out,
                        "- `{}` {}: {} → {}",
                        md_cell(&c.id),
                        md_cell(&c.metric),
                        f(c.baseline),
                        f(c.candidate)
                    );
                }
            }
        };
        list(&mut out, "Regressions", &self.regressions);
        list(&mut out, "Improvements", &self.improvements);
        if self.gate.passed() {
            out.push_str("\n**Gate: passed**\n");
        } else {
            out.push_str("\n**Gate: failed**\n\n");
            for r in &self.gate.failures {
                let _ = writeln!(out, "- {}", md_cell(r));
            }
        }
        out
    }
}

fn classify(delta: Option<f64>, pass_delta: f64, tolerance: f64) -> Change {
    let d = delta.unwrap_or(pass_delta);
    if d > tolerance {
        Change::Improved
    } else if d < -tolerance {
        Change::Regressed
    } else {
        Change::Unchanged
    }
}

/// Compare `candidate` with `baseline` and check `thresholds`.
///
/// Absolute limits apply to the candidate; drop limits to the change from
/// the baseline. A metric present in the baseline but missing from the
/// candidate fails the gate.
///
/// ```rust
/// use rune_chain_eval::{Thresholds, compare};
/// # use rune_chain_eval::{Dataset, Evaluation, Example, ExactMatch, TargetOutput, target_fn};
/// # tokio_test::block_on(async {
/// # let ds = Dataset::new(vec![Example::from_question("1", "q").with_reference("a")]).unwrap();
/// # let good = target_fn(|_| async { Ok::<_, rune_chain_core::ChainError>(TargetOutput::text("a")) });
/// # let bad = target_fn(|_| async { Ok::<_, rune_chain_core::ChainError>(TargetOutput::text("b")) });
/// # let eval = Evaluation::new("v1").evaluator(ExactMatch::new());
/// # let baseline = eval.run(&ds, &good).await.unwrap();
/// # let candidate = eval.run(&ds, &bad).await.unwrap();
/// let cmp = compare(&baseline, &candidate, &Thresholds::new().max_pass_rate_drop(0.0));
/// assert!(!cmp.passed());
/// assert_eq!(cmp.regressions.len(), 1);
/// assert_eq!(cmp.exit_code(), 1);
/// # });
/// ```
#[must_use]
pub fn compare(baseline: &RunResult, candidate: &RunResult, thresholds: &Thresholds) -> Comparison {
    let mut failures = Vec::new();
    thresholds.check_absolute(candidate, &mut failures);
    let mut names: Vec<&String> = baseline
        .summary
        .metrics
        .keys()
        .chain(candidate.summary.metrics.keys())
        .collect();
    names.sort_unstable();
    names.dedup();
    let mut metrics = Vec::with_capacity(names.len());
    for name in names {
        let (Some(b), Some(c)) = (baseline.metric(name), candidate.metric(name)) else {
            if baseline.metric(name).is_some() {
                failures.push(format!("{name}: missing from the candidate run"));
            }
            continue;
        };
        let mean_delta = match (b.mean, c.mean) {
            (Some(x), Some(y)) => Some(y - x),
            _ => None,
        };
        let pass_rate_delta = c.pass_rate - b.pass_rate;
        if let (Some(max), Some(d)) = (thresholds.max_mean_drop, mean_delta)
            && -d > max
        {
            failures.push(format!("{name}: mean dropped by {:.4} (limit {max})", -d));
        }
        if let Some(max) = thresholds.max_pass_rate_drop
            && -pass_rate_delta > max + 1e-12
        {
            failures.push(format!(
                "{name}: pass rate dropped by {:.4} (limit {max})",
                -pass_rate_delta
            ));
        }
        metrics.push(MetricComparison {
            name: name.clone(),
            baseline_mean: b.mean,
            candidate_mean: c.mean,
            mean_delta,
            baseline_pass_rate: b.pass_rate,
            candidate_pass_rate: c.pass_rate,
            pass_rate_delta,
            change: classify(mean_delta, pass_rate_delta, thresholds.tolerance),
            significant: matches!((b.ci, c.ci), (Some(x), Some(y)) if !x.overlaps(&y)),
        });
    }

    let base_by_id: HashMap<&str, _> = baseline
        .examples
        .iter()
        .map(|e| (e.id.as_str(), e))
        .collect();
    let cand_ids: HashMap<&str, _> = candidate
        .examples
        .iter()
        .map(|e| (e.id.as_str(), e))
        .collect();
    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    for c in &candidate.examples {
        let Some(b) = base_by_id.get(c.id.as_str()) else {
            continue;
        };
        for (metric, bo) in &b.scores {
            let co = c.scores.get(metric);
            let was = bo.passed();
            let now = co.is_some_and(MetricOutcome::passed);
            if was == now {
                continue;
            }
            let change = ExampleChange {
                id: c.id.clone(),
                metric: metric.clone(),
                baseline: bo.value(),
                candidate: co.and_then(MetricOutcome::value),
            };
            if was {
                regressions.push(change);
            } else {
                improvements.push(change);
            }
        }
    }
    Comparison {
        baseline: baseline.name.clone(),
        candidate: candidate.name.clone(),
        metrics,
        regressions,
        improvements,
        only_in_baseline: baseline
            .examples
            .iter()
            .filter(|e| !cand_ids.contains_key(e.id.as_str()))
            .map(|e| e.id.clone())
            .collect(),
        only_in_candidate: candidate
            .examples
            .iter()
            .filter(|e| !base_by_id.contains_key(e.id.as_str()))
            .map(|e| e.id.clone())
            .collect(),
        gate: GateResult { failures },
    }
}
