//! Metadata filters over JSON values.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ops::Bound;

use serde_json::Value;

use crate::{Record, StoreError};

/// Deepest `And` / `Or` / `Not` nesting [`Filter::validate`] accepts.
pub const MAX_FILTER_DEPTH: usize = 32;

/// A predicate over a record's JSON metadata.
///
/// Filters look up **top-level** metadata keys. The rules:
///
/// - [`Filter::Eq`] matches when the field equals the value. Numbers compare
///   by value, so `1` matches `1.0`. If the field is an array and the value
///   is not, it matches when any element equals the value (tag lists).
/// - [`Filter::In`] matches when [`Filter::Eq`] would match any of the values.
/// - [`Filter::Range`] compares numbers with numbers and strings with
///   strings (byte-wise, so ISO-8601 dates sort correctly). Any other
///   combination, including a missing field, does not match. Array fields
///   match when any element is in range.
/// - [`Filter::Exists`] matches when the key is present and not `null`.
/// - [`Filter::And`] / [`Filter::Or`] / [`Filter::Not`] combine filters. An
///   empty `And` (the [`Default`]) matches everything; an empty `Or`
///   matches nothing.
///
/// # Example
///
/// ```
/// use rune_vectorstore::{Filter, Record};
///
/// let doc = Record::new("a", vec![1.0])
///     .with_meta("lang", "en")
///     .with_meta("year", 2021)
///     .with_meta("tags", serde_json::json!(["rust", "db"]));
///
/// let f = Filter::eq("lang", "en")
///     .and(Filter::between("year", 2020, 2022))
///     .and(Filter::is_in("tags", ["go", "rust"]));
/// assert!(f.matches(&doc));
/// assert!(!(!f).matches(&doc));
/// assert!(!Filter::gt("year", 2021).matches(&doc));
/// assert!(Filter::default().matches(&doc));
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Filter {
    /// Every sub-filter matches.
    And(Vec<Self>),
    /// At least one sub-filter matches.
    Or(Vec<Self>),
    /// The sub-filter does not match.
    Not(Box<Self>),
    /// `metadata[key] == value`.
    Eq {
        /// Metadata key.
        key: String,
        /// Expected value.
        value: Value,
    },
    /// `metadata[key]` equals one of `values`.
    In {
        /// Metadata key.
        key: String,
        /// Accepted values.
        values: Vec<Value>,
    },
    /// `lower <= metadata[key] <= upper`, with each bound inclusive,
    /// exclusive or open.
    Range {
        /// Metadata key.
        key: String,
        /// Lower bound.
        lower: Bound<Value>,
        /// Upper bound.
        upper: Bound<Value>,
    },
    /// The key is present and not `null`.
    Exists {
        /// Metadata key.
        key: String,
    },
}

impl Default for Filter {
    /// The filter that matches everything.
    fn default() -> Self {
        Self::And(Vec::new())
    }
}

impl std::ops::Not for Filter {
    type Output = Self;

    fn not(self) -> Self {
        match self {
            Self::Not(inner) => *inner,
            other => Self::Not(Box::new(other)),
        }
    }
}

impl Filter {
    /// `metadata[key] == value`.
    #[must_use]
    pub fn eq(key: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::Eq {
            key: key.into(),
            value: value.into(),
        }
    }

    /// `metadata[key]` is one of `values`.
    #[must_use]
    pub fn is_in<V: Into<Value>>(
        key: impl Into<String>,
        values: impl IntoIterator<Item = V>,
    ) -> Self {
        Self::In {
            key: key.into(),
            values: values.into_iter().map(Into::into).collect(),
        }
    }

    /// `metadata[key] > value`.
    #[must_use]
    pub fn gt(key: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::range(key, Bound::Excluded(value.into()), Bound::Unbounded)
    }

    /// `metadata[key] >= value`.
    #[must_use]
    pub fn gte(key: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::range(key, Bound::Included(value.into()), Bound::Unbounded)
    }

    /// `metadata[key] < value`.
    #[must_use]
    pub fn lt(key: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::range(key, Bound::Unbounded, Bound::Excluded(value.into()))
    }

    /// `metadata[key] <= value`.
    #[must_use]
    pub fn lte(key: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::range(key, Bound::Unbounded, Bound::Included(value.into()))
    }

    /// `low <= metadata[key] <= high`.
    #[must_use]
    pub fn between(key: impl Into<String>, low: impl Into<Value>, high: impl Into<Value>) -> Self {
        Self::range(
            key,
            Bound::Included(low.into()),
            Bound::Included(high.into()),
        )
    }

    /// A range with explicit bounds.
    #[must_use]
    pub fn range(key: impl Into<String>, lower: Bound<Value>, upper: Bound<Value>) -> Self {
        Self::Range {
            key: key.into(),
            lower,
            upper,
        }
    }

    /// The key is present and not `null`.
    #[must_use]
    pub fn exists(key: impl Into<String>) -> Self {
        Self::Exists { key: key.into() }
    }

    /// Both `self` and `other` must match. Flattens nested `And`s.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        match self {
            Self::And(mut all) => {
                match other {
                    Self::And(more) => all.extend(more),
                    other => all.push(other),
                }
                Self::And(all)
            }
            first => match other {
                Self::And(mut more) => {
                    more.insert(0, first);
                    Self::And(more)
                }
                other => Self::And(vec![first, other]),
            },
        }
    }

    /// Either `self` or `other` must match. Flattens nested `Or`s.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Or(mut any), Self::Or(more)) => {
                any.extend(more);
                Self::Or(any)
            }
            (Self::Or(mut any), other) => {
                any.push(other);
                Self::Or(any)
            }
            (first, other) => Self::Or(vec![first, other]),
        }
    }

    /// Shorthand for `self.and(Filter::eq(key, value))`.
    #[must_use]
    pub fn must_equal(self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.and(Self::eq(key, value))
    }

    /// `true` if the filter trivially matches everything (an empty `And`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::And(all) if all.iter().all(Self::is_empty))
    }

    /// Check that the filter is well formed: range bounds are numbers or
    /// strings of one kind, and nesting is at most [`MAX_FILTER_DEPTH`] deep.
    ///
    /// Stores call this before running a query.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidFilter`] describing the first problem found.
    ///
    /// # Example
    ///
    /// ```
    /// use rune_vectorstore::Filter;
    ///
    /// assert!(Filter::gt("year", 2020).validate().is_ok());
    /// assert!(Filter::gt("year", true).validate().is_err());
    /// assert!(Filter::between("x", 1, "z").validate().is_err());
    /// ```
    pub fn validate(&self) -> Result<(), StoreError> {
        self.validate_at(0)
    }

    fn validate_at(&self, depth: usize) -> Result<(), StoreError> {
        if depth > MAX_FILTER_DEPTH {
            return Err(StoreError::InvalidFilter(format!(
                "nested deeper than {MAX_FILTER_DEPTH} levels"
            )));
        }
        match self {
            Self::And(all) | Self::Or(all) => all.iter().try_for_each(|f| f.validate_at(depth + 1)),
            Self::Not(inner) => inner.validate_at(depth + 1),
            Self::Eq { .. } | Self::In { .. } | Self::Exists { .. } => Ok(()),
            Self::Range { key, lower, upper } => {
                let kind = |b: &Bound<Value>| match b {
                    Bound::Unbounded => Ok(None),
                    Bound::Included(v) | Bound::Excluded(v) => match v {
                        Value::Number(_) => Ok(Some(0u8)),
                        Value::String(_) => Ok(Some(1u8)),
                        other => Err(StoreError::InvalidFilter(format!(
                            "range bound on {key:?} must be a number or string, got {other}"
                        ))),
                    },
                };
                match (kind(lower)?, kind(upper)?) {
                    (Some(a), Some(b)) if a != b => Err(StoreError::InvalidFilter(format!(
                        "range bounds on {key:?} mix a number and a string"
                    ))),
                    _ => Ok(()),
                }
            }
        }
    }

    /// `true` if `record`'s metadata satisfies the filter.
    #[must_use]
    pub fn matches(&self, record: &Record) -> bool {
        self.matches_metadata(&record.metadata)
    }

    /// `true` if `metadata` satisfies the filter.
    #[must_use]
    pub fn matches_metadata(&self, metadata: &BTreeMap<String, Value>) -> bool {
        match self {
            Self::And(all) => all.iter().all(|f| f.matches_metadata(metadata)),
            Self::Or(any) => any.iter().any(|f| f.matches_metadata(metadata)),
            Self::Not(inner) => !inner.matches_metadata(metadata),
            Self::Eq { key, value } => metadata.get(key).is_some_and(|f| field_eq(f, value)),
            Self::In { key, values } => metadata
                .get(key)
                .is_some_and(|f| values.iter().any(|v| field_eq(f, v))),
            Self::Range { key, lower, upper } => metadata
                .get(key)
                .is_some_and(|f| any_element(f, |x| in_range(x, lower, upper))),
            Self::Exists { key } => metadata.get(key).is_some_and(|v| !v.is_null()),
        }
    }
}

/// Apply `pred` to `field`, or to each element if `field` is an array.
fn any_element(field: &Value, mut pred: impl FnMut(&Value) -> bool) -> bool {
    match field {
        Value::Array(items) => items.iter().any(pred),
        other => pred(other),
    }
}

fn field_eq(field: &Value, value: &Value) -> bool {
    if values_eq(field, value) {
        return true;
    }
    !value.is_array()
        && matches!(field, Value::Array(items) if items.iter().any(|x| values_eq(x, value)))
}

fn values_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_f64(), y.as_f64()) {
            // Integers that do not fit f64 exactly fall back to exact comparison.
            (Some(fx), Some(fy)) if x.is_f64() || y.is_f64() => fx == fy,
            _ => x == y,
        },
        _ => a == b,
    }
}

fn compare(a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => {
            if let (Some(i), Some(j)) = (x.as_i64(), y.as_i64()) {
                return Some(i.cmp(&j));
            }
            if let (Some(i), Some(j)) = (x.as_u64(), y.as_u64()) {
                return Some(i.cmp(&j));
            }
            x.as_f64()?.partial_cmp(&y.as_f64()?)
        }
        (Value::String(x), Value::String(y)) => Some(x.cmp(y)),
        _ => None,
    }
}

fn in_range(x: &Value, lower: &Bound<Value>, upper: &Bound<Value>) -> bool {
    let lower_ok = match lower {
        Bound::Unbounded => matches!(x, Value::Number(_) | Value::String(_)),
        Bound::Included(b) => matches!(compare(x, b), Some(Ordering::Greater | Ordering::Equal)),
        Bound::Excluded(b) => compare(x, b) == Some(Ordering::Greater),
    };
    let upper_ok = match upper {
        Bound::Unbounded => true,
        Bound::Included(b) => matches!(compare(x, b), Some(Ordering::Less | Ordering::Equal)),
        Bound::Excluded(b) => compare(x, b) == Some(Ordering::Less),
    };
    lower_ok && upper_ok
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn rec(meta: &Value) -> Record {
        let mut r = Record::new("x", vec![1.0]);
        if let Value::Object(m) = meta {
            r.metadata = m.clone().into_iter().collect();
        }
        r
    }

    #[test]
    fn equality_and_numbers() {
        let r = rec(&json!({"n": 1, "f": 1.5, "s": "a", "b": true, "big": u64::MAX}));
        assert!(Filter::eq("n", 1.0).matches(&r));
        assert!(Filter::eq("n", 1).matches(&r));
        assert!(!Filter::eq("n", "1").matches(&r));
        assert!(Filter::eq("f", 1.5).matches(&r));
        assert!(Filter::eq("b", true).matches(&r));
        assert!(Filter::eq("big", u64::MAX).matches(&r));
        assert!(!Filter::eq("big", u64::MAX - 1).matches(&r));
        assert!(!Filter::eq("missing", 1).matches(&r));
    }

    #[test]
    fn arrays_match_any_element() {
        let r = rec(&json!({"tags": ["a", "b"], "nums": [1, 5, 9]}));
        assert!(Filter::eq("tags", "b").matches(&r));
        assert!(Filter::eq("tags", json!(["a", "b"])).matches(&r));
        assert!(!Filter::eq("tags", json!(["a"])).matches(&r));
        assert!(Filter::is_in("tags", ["z", "a"]).matches(&r));
        assert!(Filter::between("nums", 4, 6).matches(&r));
        assert!(!Filter::between("nums", 6, 8).matches(&r));
    }

    #[test]
    fn ranges() {
        let r = rec(&json!({"y": 2020, "d": "2024-03-01", "x": null, "neg": -3}));
        assert!(Filter::gte("y", 2020).matches(&r));
        assert!(!Filter::gt("y", 2020).matches(&r));
        assert!(Filter::lt("y", 2020.5).matches(&r));
        assert!(Filter::lte("neg", -3).matches(&r));
        assert!(Filter::between("d", "2024-01-01", "2024-12-31").matches(&r));
        assert!(!Filter::gt("d", 5).matches(&r));
        assert!(!Filter::gt("x", 0).matches(&r));
        assert!(Filter::range("y", Bound::Unbounded, Bound::Unbounded).matches(&r));
        assert!(!Filter::range("x", Bound::Unbounded, Bound::Unbounded).matches(&r));
    }

    #[test]
    fn combinators() {
        let r = rec(&json!({"a": 1, "b": 2, "n": null}));
        assert!(Filter::default().matches(&r));
        assert!(Filter::default().is_empty());
        assert!(Filter::default().and(Filter::default()).is_empty());
        assert!(!Filter::Or(vec![]).matches(&r));
        assert!(Filter::eq("a", 1).or(Filter::eq("a", 2)).matches(&r));
        assert!(!Filter::eq("a", 1).and(Filter::eq("b", 3)).matches(&r));
        assert!((!Filter::eq("c", 1)).matches(&r));
        assert_eq!(!!Filter::eq("a", 1), Filter::eq("a", 1));
        assert!(Filter::exists("a").matches(&r));
        assert!(!Filter::exists("n").matches(&r));
        let f = Filter::eq("a", 1)
            .and(Filter::eq("b", 2))
            .and(Filter::exists("a"));
        assert!(matches!(&f, Filter::And(v) if v.len() == 3));
        let f = Filter::eq("a", 1)
            .or(Filter::eq("b", 2))
            .or(Filter::exists("a"));
        assert!(matches!(&f, Filter::Or(v) if v.len() == 3));
        let f = Filter::exists("z").and(Filter::eq("a", 1).and(Filter::eq("b", 2)));
        assert!(matches!(&f, Filter::And(v) if v.len() == 3));
    }

    #[test]
    fn validation() {
        assert!(Filter::default().validate().is_ok());
        assert!(Filter::gt("a", json!([1])).validate().is_err());
        assert!(Filter::lt("a", json!(null)).validate().is_err());
        assert!(Filter::between("a", 1, "b").validate().is_err());
        assert!(Filter::between("a", "a", "b").validate().is_ok());
        let mut deep = Filter::eq("a", 1);
        for _ in 0..=MAX_FILTER_DEPTH {
            deep = Filter::Not(Box::new(deep));
        }
        assert!(deep.validate().is_err());
        // Nested inside an otherwise valid filter.
        assert!(
            Filter::eq("a", 1)
                .and(Filter::Or(vec![Filter::gt("b", false)]))
                .validate()
                .is_err()
        );
    }
}
