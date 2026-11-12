use rune_graph::Value;

/// A predicate used in [`has_p`](crate::VertexTraversal::has_p) filter steps.
///
/// Mirrors the `P` class in Apache `TinkerPop` — a composable comparison against
/// a [`Value`]. Predicates are always evaluated against a single property value
/// on the current element.
///
/// # Example
///
/// ```rust
/// use rune_graph::{Graph, Value, props};
/// use rune_graph_gremlin::{GraphTraversalSource, P};
///
/// let mut g = Graph::new();
/// let alice = g.add_node(&["Person"], props! { "name" => "Alice", "age" => 30_i64 });
/// let bob   = g.add_node(&["Person"], props! { "name" => "Bob",   "age" => 22_i64 });
///
/// let src = GraphTraversalSource::new(&g);
/// let adults: Vec<_> = src.v().has_p("age", P::gte(25_i64)).collect();
/// assert_eq!(adults.len(), 1);
/// assert_eq!(adults[0], alice);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum P {
    /// Equal to `value`.
    Eq(Value),
    /// Not equal to `value`.
    Neq(Value),
    /// Strictly less than `value`.
    Lt(Value),
    /// Less than or equal to `value`.
    Lte(Value),
    /// Strictly greater than `value`.
    Gt(Value),
    /// Greater than or equal to `value`.
    Gte(Value),
    /// Equal to any value in the set.
    Within(Vec<Value>),
    /// Not equal to any value in the set.
    Without(Vec<Value>),
}

impl P {
    /// Equal to `v`.
    pub fn eq(v: impl Into<Value>) -> Self {
        Self::Eq(v.into())
    }
    /// Not equal to `v`.
    pub fn neq(v: impl Into<Value>) -> Self {
        Self::Neq(v.into())
    }
    /// Less than `v`.
    pub fn lt(v: impl Into<Value>) -> Self {
        Self::Lt(v.into())
    }
    /// Less than or equal to `v`.
    pub fn lte(v: impl Into<Value>) -> Self {
        Self::Lte(v.into())
    }
    /// Greater than `v`.
    pub fn gt(v: impl Into<Value>) -> Self {
        Self::Gt(v.into())
    }
    /// Greater than or equal to `v`.
    pub fn gte(v: impl Into<Value>) -> Self {
        Self::Gte(v.into())
    }

    /// Equal to any of `values`.
    pub fn within(values: impl IntoIterator<Item = impl Into<Value>>) -> Self {
        Self::Within(values.into_iter().map(Into::into).collect())
    }
    /// Equal to none of `values`.
    pub fn without(values: impl IntoIterator<Item = impl Into<Value>>) -> Self {
        Self::Without(values.into_iter().map(Into::into).collect())
    }

    /// Test `value` against this predicate.
    #[must_use]
    pub fn test(&self, value: &Value) -> bool {
        match self {
            Self::Eq(v) => value == v,
            Self::Neq(v) => value != v,
            Self::Lt(v) => cmp_values(value, v) == Some(std::cmp::Ordering::Less),
            Self::Lte(v) => matches!(
                cmp_values(value, v),
                Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
            ),
            Self::Gt(v) => cmp_values(value, v) == Some(std::cmp::Ordering::Greater),
            Self::Gte(v) => matches!(
                cmp_values(value, v),
                Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
            ),
            Self::Within(vs) => vs.iter().any(|v| value == v),
            Self::Without(vs) => vs.iter().all(|v| value != v),
        }
    }
}

/// Partial comparison between two [`Value`]s. Only numeric and string types
/// are ordered; mismatched or unordered types return `None`.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
fn cmp_values(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x.partial_cmp(y),
        (Value::Float(x), Value::Float(y)) => x.partial_cmp(y),
        (Value::Int(x), Value::Float(y)) => (*x as f64).partial_cmp(y),
        (Value::Float(x), Value::Int(y)) => x.partial_cmp(&(*y as f64)),
        (Value::Str(x), Value::Str(y)) => x.partial_cmp(y),
        _ => None,
    }
}
