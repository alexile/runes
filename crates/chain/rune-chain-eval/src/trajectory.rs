//! Agent trajectory evaluation: did the expected tool calls happen?

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{EvalError, Evaluator, Example, Score, TargetOutput};

/// Most expected or actual calls compared.
const MAX_CALLS: usize = 1024;

/// How the actual tool calls are compared with the expected ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrajectoryMode {
    /// The calls are exactly the expected ones, in order, nothing extra.
    Exact,
    /// The expected calls appear in order; other calls may come between.
    #[default]
    InOrder,
    /// The expected calls all appear (as a multiset), in any order.
    Unordered,
}

/// One expected tool call: a name and, optionally, arguments that must
/// match (every expected key must be present with an equal value; extra
/// actual keys are fine).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedCall {
    /// Tool name.
    pub name: String,
    /// Arguments that must match, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Value>,
}

impl ExpectedCall {
    /// Expect a call to `name` with any arguments.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            args: None,
        }
    }

    /// Require these arguments (builder style).
    #[must_use]
    pub fn with_args(mut self, args: Value) -> Self {
        self.args = Some(args);
        self
    }

    fn matches(&self, name: &str, args: Option<&Value>) -> bool {
        if self.name != name {
            return false;
        }
        match (&self.args, args) {
            (None, _) => true,
            (Some(want), Some(got)) => subset(want, got),
            (Some(_), None) => false,
        }
    }
}

/// Whether `want` is contained in `got`: objects by key (recursively),
/// everything else by equality.
fn subset(want: &Value, got: &Value) -> bool {
    match (want, got) {
        (Value::Object(w), Value::Object(g)) => w
            .iter()
            .all(|(k, v)| g.get(k).is_some_and(|gv| subset(v, gv))),
        _ => want == got,
    }
}

/// Expected calls from `metadata[key]`: an array of tool names or of
/// `{"name": .., "args": {..}}` objects.
fn expected_from(ex: &Example, key: &str) -> Result<Vec<ExpectedCall>, EvalError> {
    let Some(Value::Array(items)) = ex.metadata.get(key) else {
        return Err(EvalError::Missing(format!("metadata.{key}")));
    };
    if items.len() > MAX_CALLS {
        return Err(EvalError::TooLarge(format!(
            "more than {MAX_CALLS} expected calls"
        )));
    }
    items
        .iter()
        .map(|v| match v {
            Value::String(s) => Ok(ExpectedCall::named(s.clone())),
            Value::Object(_) => serde_json::from_value(v.clone())
                .map_err(|_| EvalError::Config(format!("metadata.{key}: bad expected call"))),
            _ => Err(EvalError::Config(format!(
                "metadata.{key} must hold names or {{name, args}} objects"
            ))),
        })
        .collect()
}

/// Checks the target's tool calls against the expected trajectory
/// (`trajectory`).
///
/// Expected calls come from `metadata.expected_tools` (key configurable)
/// or a fixed list. The score is the fraction of expected calls matched
/// (for [`TrajectoryMode::InOrder`], the longest in-order match); it
/// passes when all are matched and, in [`TrajectoryMode::Exact`] mode,
/// nothing else was called.
///
/// ```rust
/// use rune_chain_core::ToolCall;
/// use rune_chain_eval::{Evaluator, Example, TargetOutput};
/// use rune_chain_eval::trajectory::{TrajectoryEvaluator, TrajectoryMode};
/// use serde_json::json;
///
/// # tokio_test::block_on(async {
/// let ex = Example::from_question("1", "weather in Paris?")
///     .with_metadata("expected_tools", json!(["geocode", "forecast"]));
/// let out = TargetOutput::text("Sunny").with_tool_calls([
///     ToolCall::new("1", "geocode", r#"{"city":"Paris"}"#),
///     ToolCall::new("2", "log", "{}"),
///     ToolCall::new("3", "forecast", r#"{"lat":48.9}"#),
/// ]);
/// let s = TrajectoryEvaluator::new().evaluate(&ex, &out).await.unwrap();
/// assert!(s.passed);
/// let s = TrajectoryEvaluator::new().mode(TrajectoryMode::Exact).evaluate(&ex, &out).await.unwrap();
/// assert!(!s.passed);
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct TrajectoryEvaluator {
    name: String,
    mode: TrajectoryMode,
    key: String,
    fixed: Option<Vec<ExpectedCall>>,
}

impl Default for TrajectoryEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl TrajectoryEvaluator {
    /// In-order matching against `metadata.expected_tools`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: "trajectory".into(),
            mode: TrajectoryMode::InOrder,
            key: "expected_tools".into(),
            fixed: None,
        }
    }

    /// Expect the same calls for every example (builder style).
    #[must_use]
    pub fn expect(mut self, calls: impl IntoIterator<Item = ExpectedCall>) -> Self {
        self.fixed = Some(calls.into_iter().collect());
        self
    }

    /// Matching mode (builder style).
    #[must_use]
    pub const fn mode(mut self, mode: TrajectoryMode) -> Self {
        self.mode = mode;
        self
    }

    /// Metadata key with the expected calls (builder style).
    #[must_use]
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.key = key.into();
        self
    }

    /// Rename the metric (builder style).
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
}

/// Longest in-order match of `expected` within `actual` (an LCS where only
/// expected→actual matches count).
fn in_order_matches(expected: &[ExpectedCall], actual: &[(&str, Option<Value>)]) -> usize {
    let mut row = vec![0usize; actual.len() + 1];
    for e in expected {
        let mut diag = 0;
        for (j, (name, args)) in actual.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = if e.matches(name, args.as_ref()) {
                diag + 1
            } else {
                above.max(row[j])
            };
            diag = above;
        }
    }
    row[actual.len()]
}

/// Greedy multiset matching; most-specific expectations (with args) first
/// so a bare name does not steal the only call that satisfies an args
/// check.
fn unordered_matches(expected: &[ExpectedCall], actual: &[(&str, Option<Value>)]) -> usize {
    let mut order: Vec<&ExpectedCall> = expected.iter().collect();
    order.sort_by_key(|e| e.args.is_none());
    let mut used = vec![false; actual.len()];
    let mut n = 0;
    for e in order {
        if let Some(j) =
            (0..actual.len()).find(|&j| !used[j] && e.matches(actual[j].0, actual[j].1.as_ref()))
        {
            used[j] = true;
            n += 1;
        }
    }
    n
}

#[async_trait]
impl Evaluator for TrajectoryEvaluator {
    fn name(&self) -> &str {
        &self.name
    }
    #[allow(clippy::cast_precision_loss)]
    async fn evaluate(&self, ex: &Example, out: &TargetOutput) -> Result<Score, EvalError> {
        let expected = match &self.fixed {
            Some(f) => f.clone(),
            None => expected_from(ex, &self.key)?,
        };
        if out.tool_calls.len() > MAX_CALLS {
            return Err(EvalError::TooLarge(format!(
                "more than {MAX_CALLS} tool calls"
            )));
        }
        let actual: Vec<(&str, Option<Value>)> = out
            .tool_calls
            .iter()
            .map(|c| (c.name.as_str(), c.parse_arguments().ok()))
            .collect();
        let matched = match self.mode {
            TrajectoryMode::Exact => {
                let all = expected.len() == actual.len()
                    && expected
                        .iter()
                        .zip(&actual)
                        .all(|(e, (n, a))| e.matches(n, a.as_ref()));
                if all {
                    expected.len()
                } else {
                    in_order_matches(&expected, &actual)
                }
            }
            TrajectoryMode::InOrder => in_order_matches(&expected, &actual),
            TrajectoryMode::Unordered => unordered_matches(&expected, &actual),
        };
        let value = if expected.is_empty() {
            if actual.is_empty() || self.mode != TrajectoryMode::Exact {
                1.0
            } else {
                0.0
            }
        } else {
            matched as f64 / expected.len() as f64
        };
        let passed = matched == expected.len()
            && (self.mode != TrajectoryMode::Exact || actual.len() == expected.len());
        let names: Vec<&str> = actual.iter().map(|(n, _)| *n).collect();
        Ok(Score::new(value, passed).with_details(json!({
            "expected": expected.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            "actual": names,
            "matched": matched,
        })))
    }
}
