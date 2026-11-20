//! Run results: per-example records, aggregates, and JSON / JSONL /
//! Markdown export.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rune_chain_core::{Cost, TokenUsage};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::stats::{
    BootstrapConfig, ConfidenceInterval, bootstrap_mean_ci, mean, percentile_sorted,
};
use crate::{EvalError, MetricOutcome};

/// Largest report [`RunResult::from_json`] accepts (256 MiB).
pub const MAX_REPORT_BYTES: usize = 256 << 20;

/// Characters per cell in Markdown tables.
const MD_CELL_CHARS: usize = 80;

/// Everything recorded for one example.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExampleResult {
    /// The example id.
    pub id: String,
    /// The example inputs.
    pub inputs: BTreeMap<String, Value>,
    /// The reference output, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// The target's output (`None` when it failed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    /// Whether the stored output was cut to the run's length cap.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub output_truncated: bool,
    /// The target's error after all retries, if it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Wall time of the target call that produced the output (the last
    /// attempt), in milliseconds.
    pub latency_ms: f64,
    /// Attempts made (1 = no retry).
    pub attempts: u32,
    /// Token usage reported by the target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<TokenUsage>,
    /// Cost of that usage at the run's pricing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<Cost>,
    /// Names of the tools the target called, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<String>,
    /// One outcome per metric.
    pub scores: BTreeMap<String, MetricOutcome>,
}

impl ExampleResult {
    /// Whether every metric passed (and the target did not fail).
    #[must_use]
    pub fn passed_all(&self) -> bool {
        self.error.is_none() && self.scores.values().all(MetricOutcome::passed)
    }
}

/// Aggregates for one metric.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricSummary {
    /// Examples in the run.
    pub count: usize,
    /// Examples with a score.
    pub scored: usize,
    /// Examples where the metric (or the target) failed.
    pub errors: usize,
    /// Examples that passed.
    pub passed: usize,
    /// `passed / count`: errors count as failures.
    pub pass_rate: f64,
    /// Mean of the scores (errors excluded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mean: Option<f64>,
    /// Smallest score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    /// Largest score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    /// Bootstrap confidence interval for the mean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci: Option<ConfidenceInterval>,
}

/// Latency percentiles over the examples whose target succeeded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct LatencySummary {
    /// Mean, ms.
    pub mean_ms: f64,
    /// Median, ms.
    pub p50_ms: f64,
    /// 95th percentile, ms.
    pub p95_ms: f64,
    /// Maximum, ms.
    pub max_ms: f64,
}

/// Run-level aggregates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    /// Examples in the run.
    pub examples: usize,
    /// Examples where the target failed.
    pub target_errors: usize,
    /// Latency of successful target calls.
    pub latency: LatencySummary,
    /// Token usage summed over the examples that reported it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<TokenUsage>,
    /// Total cost, when pricing was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<Cost>,
    /// Per-metric aggregates.
    pub metrics: BTreeMap<String, MetricSummary>,
}

/// The result of an evaluation run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunResult {
    /// Run name (e.g. the model or prompt version).
    pub name: String,
    /// Aggregates.
    pub summary: Summary,
    /// Per-example records, in dataset order.
    pub examples: Vec<ExampleResult>,
}

impl RunResult {
    /// Build a result and compute its summary.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        examples: Vec<ExampleResult>,
        bootstrap: &BootstrapConfig,
    ) -> Self {
        let summary = summarize(&examples, bootstrap);
        Self {
            name: name.into(),
            summary,
            examples,
        }
    }

    /// The summary of one metric.
    #[must_use]
    pub fn metric(&self, name: &str) -> Option<&MetricSummary> {
        self.summary.metrics.get(name)
    }

    /// The record of one example.
    #[must_use]
    pub fn example(&self, id: &str) -> Option<&ExampleResult> {
        self.examples.iter().find(|e| e.id == id)
    }

    /// Pretty-printed JSON of the whole run.
    pub fn to_json(&self) -> Result<String, EvalError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Read a run written by [`to_json`](Self::to_json), e.g. a stored
    /// baseline.
    ///
    /// # Errors
    ///
    /// [`EvalError::TooLarge`] above [`MAX_REPORT_BYTES`], otherwise a
    /// JSON error.
    pub fn from_json(text: &str) -> Result<Self, EvalError> {
        if text.len() > MAX_REPORT_BYTES {
            return Err(EvalError::TooLarge(format!(
                "report is larger than {MAX_REPORT_BYTES} bytes"
            )));
        }
        Ok(serde_json::from_str(text)?)
    }

    /// One JSON object per example, one per line.
    pub fn to_jsonl(&self) -> Result<String, EvalError> {
        let mut out = String::new();
        for e in &self.examples {
            out.push_str(&serde_json::to_string(e)?);
            out.push('\n');
        }
        Ok(out)
    }

    /// A Markdown summary: one row per metric, then run totals.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let s = &self.summary;
        let mut out = String::new();
        let _ = writeln!(out, "## {}\n", md_cell(&self.name));
        out.push_str("| Metric | Mean | 95% CI | Pass rate | Passed | Errors |\n");
        out.push_str("|---|---:|---|---:|---:|---:|\n");
        for (name, m) in &s.metrics {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {:.1}% | {}/{} | {} |",
                md_cell(name),
                opt3(m.mean),
                m.ci.map_or_else(
                    || "–".to_owned(),
                    |c| format!("[{:.3}, {:.3}]", c.low, c.high)
                ),
                m.pass_rate * 100.0,
                m.passed,
                m.count,
                m.errors
            );
        }
        let _ = writeln!(
            out,
            "\n{} examples, {} target errors. Latency p50 {:.1} ms, p95 {:.1} ms.",
            s.examples, s.target_errors, s.latency.p50_ms, s.latency.p95_ms
        );
        if let Some(u) = &s.usage {
            let _ = write!(
                out,
                "Tokens: {} ({} in, {} out).",
                u.total_tokens, u.prompt_tokens, u.completion_tokens
            );
            if let Some(c) = s.cost {
                let _ = write!(out, " Cost: {c}.");
            }
            out.push('\n');
        }
        out
    }

    /// A Markdown table with one row per example: id, output, and each
    /// metric's score (`✗` marks a failure, `err` an error). Cells are
    /// escaped and cut to 80 characters.
    #[must_use]
    pub fn examples_markdown(&self) -> String {
        let metrics: Vec<&String> = self.summary.metrics.keys().collect();
        let mut out = String::from("| Id | Output |");
        for m in &metrics {
            let _ = write!(out, " {} |", md_cell(m));
        }
        out.push_str("\n|---|---|");
        for _ in &metrics {
            out.push_str("---:|");
        }
        out.push('\n');
        for e in &self.examples {
            let output = e.output.as_deref().map_or_else(
                || format!("error: {}", e.error.as_deref().unwrap_or("")),
                str::to_owned,
            );
            let _ = write!(out, "| {} | {} |", md_cell(&e.id), md_cell(&output));
            for m in &metrics {
                let cell = match e.scores.get(*m) {
                    Some(MetricOutcome::Scored(s)) => {
                        format!("{:.3}{}", s.value, if s.passed { "" } else { " ✗" })
                    }
                    Some(MetricOutcome::Error { .. }) => "err".to_owned(),
                    None => "–".to_owned(),
                };
                let _ = write!(out, " {cell} |");
            }
            out.push('\n');
        }
        out
    }
}

fn opt3(v: Option<f64>) -> String {
    v.map_or_else(|| "–".to_owned(), |v| format!("{v:.3}"))
}

/// Make text safe for one Markdown table cell: no newlines or pipes,
/// HTML-ish characters escaped, cut to a fixed length.
pub fn md_cell(text: &str) -> String {
    let mut out = String::new();
    for (i, c) in text.chars().enumerate() {
        if i == MD_CELL_CHARS {
            out.push('…');
            break;
        }
        match c {
            '|' => out.push_str("\\|"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '`' => out.push('\''),
            '\n' | '\r' | '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

#[allow(clippy::cast_precision_loss)]
fn summarize(examples: &[ExampleResult], bootstrap: &BootstrapConfig) -> Summary {
    let mut latencies: Vec<f64> = examples
        .iter()
        .filter(|e| e.error.is_none() && e.latency_ms.is_finite())
        .map(|e| e.latency_ms)
        .collect();
    latencies.sort_by(f64::total_cmp);
    let latency = LatencySummary {
        mean_ms: mean(&latencies).unwrap_or(0.0),
        p50_ms: percentile_sorted(&latencies, 0.5).unwrap_or(0.0),
        p95_ms: percentile_sorted(&latencies, 0.95).unwrap_or(0.0),
        max_ms: latencies.last().copied().unwrap_or(0.0),
    };
    let mut usage = None;
    let mut cost: Option<Cost> = None;
    for e in examples {
        TokenUsage::accumulate(&mut usage, e.usage.as_ref());
        if let Some(c) = e.cost {
            cost = Some(cost.unwrap_or(Cost::ZERO) + c);
        }
    }
    let mut names: Vec<&String> = examples.iter().flat_map(|e| e.scores.keys()).collect();
    names.sort_unstable();
    names.dedup();
    let count = examples.len();
    let metrics = names
        .into_iter()
        .map(|name| {
            let mut values = Vec::new();
            let mut passed = 0;
            for e in examples {
                match e.scores.get(name) {
                    Some(MetricOutcome::Scored(s)) if s.value.is_finite() => {
                        values.push(s.value);
                        passed += usize::from(s.passed);
                    }
                    _ => {}
                }
            }
            let scored = values.len();
            let m = MetricSummary {
                count,
                scored,
                errors: count - scored,
                passed,
                pass_rate: if count == 0 {
                    0.0
                } else {
                    passed as f64 / count as f64
                },
                mean: mean(&values),
                min: values.iter().copied().reduce(f64::min),
                max: values.iter().copied().reduce(f64::max),
                ci: bootstrap_mean_ci(&values, bootstrap),
            };
            (name.clone(), m)
        })
        .collect();
    Summary {
        examples: count,
        target_errors: examples.iter().filter(|e| e.error.is_some()).count(),
        latency,
        usage,
        cost,
        metrics,
    }
}
