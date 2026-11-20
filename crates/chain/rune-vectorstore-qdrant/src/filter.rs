//! Translating `rune-vectorstore` filters into Qdrant filters.

use std::ops::Bound;

use rune_vectorstore::{Filter, StoreError};
use serde_json::{Map, Value, json};

/// A [`Filter`] translated for Qdrant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QdrantFilter {
    /// Matches every point; send no filter.
    All,
    /// Matches no point (for example an empty `Or` or `In`); the store
    /// answers without asking the server.
    Nothing,
    /// A Qdrant filter object (`must` / `should` / `must_not`).
    Filter(Value),
}

/// Translate `filter` into a Qdrant filter over metadata stored under
/// `metadata_key` in the payload (keys become `"{metadata_key}.{key}"`).
///
/// | `Filter`                      | Qdrant                                          |
/// | ----------------------------- | ----------------------------------------------- |
/// | `And` / `Or` / `Not`          | `must` / `should` / `must_not`                  |
/// | `Eq` string or bool           | `match: {value}`                                |
/// | `Eq` number                   | `range: {gte: x, lte: x}` (so `1` finds `1.0`)  |
/// | `Eq` integer beyond ±2^53     | `match: {value}` (exact)                        |
/// | `Eq` null                     | `is_null`                                       |
/// | `In` strings                  | `match: {any}`                                  |
/// | `In` other values             | `should` of the `Eq`s                           |
/// | `Range` on numbers            | `range: {gt, gte, lt, lte}`                     |
/// | `Range` on ISO-8601 dates     | `range` with datetime strings                   |
/// | `Exists`                      | `must_not: [is_empty]`                          |
///
/// Arrays behave the same on both sides: a condition on an array field
/// matches when any element does.
///
/// # Errors
///
/// [`StoreError::InvalidFilter`] for anything Qdrant cannot express
/// faithfully, rather than dropping it: equality with an array or object,
/// integers above `i64::MAX`, ranges with no bounds, string ranges whose
/// bounds are not ISO-8601 dates, and keys containing `.`, `[`, `]` or `"`
/// (Qdrant would read those as a nested path). Malformed filters fail
/// [`Filter::validate`] first.
///
/// # Example
///
/// ```
/// use rune_vectorstore::Filter;
/// use rune_vectorstore_qdrant::{QdrantFilter, qdrant_filter};
/// use serde_json::json;
///
/// let f = Filter::eq("lang", "en").and(Filter::gte("year", 2020));
/// assert_eq!(
///     qdrant_filter(&f, "metadata")?,
///     QdrantFilter::Filter(json!({"must": [
///         {"key": "metadata.lang", "match": {"value": "en"}},
///         {"key": "metadata.year", "range": {"gte": 2020}},
///     ]}))
/// );
/// assert!(qdrant_filter(&Filter::eq("tags", json!(["a"])), "metadata").is_err());
/// # Ok::<(), rune_vectorstore::StoreError>(())
/// ```
pub fn qdrant_filter(filter: &Filter, metadata_key: &str) -> Result<QdrantFilter, StoreError> {
    filter.validate()?;
    Ok(match translate(filter, metadata_key)? {
        Tri::All => QdrantFilter::All,
        Tri::Nothing => QdrantFilter::Nothing,
        Tri::Cond(c) if is_filter_object(&c) => QdrantFilter::Filter(c),
        Tri::Cond(c) => QdrantFilter::Filter(json!({ "must": [c] })),
    })
}

/// A condition, or one of the two constants that Qdrant has no literal for.
enum Tri {
    All,
    Nothing,
    Cond(Value),
}

fn is_filter_object(v: &Value) -> bool {
    v.as_object().is_some_and(|o| {
        o.keys()
            .all(|k| matches!(k.as_str(), "must" | "should" | "must_not"))
    })
}

fn translate(filter: &Filter, prefix: &str) -> Result<Tri, StoreError> {
    Ok(match filter {
        Filter::And(all) => {
            let mut conds = Vec::with_capacity(all.len());
            for f in all {
                match translate(f, prefix)? {
                    Tri::All => {}
                    Tri::Nothing => return Ok(Tri::Nothing),
                    Tri::Cond(c) => conds.push(c),
                }
            }
            match conds.len() {
                0 => Tri::All,
                1 => Tri::Cond(conds.swap_remove(0)),
                _ => Tri::Cond(json!({ "must": conds })),
            }
        }
        Filter::Or(any) => {
            let mut conds = Vec::with_capacity(any.len());
            for f in any {
                match translate(f, prefix)? {
                    Tri::All => return Ok(Tri::All),
                    Tri::Nothing => {}
                    Tri::Cond(c) => conds.push(c),
                }
            }
            match conds.len() {
                0 => Tri::Nothing,
                1 => Tri::Cond(conds.swap_remove(0)),
                _ => Tri::Cond(json!({ "should": conds })),
            }
        }
        Filter::Not(inner) => match &**inner {
            Filter::Exists { key } => {
                Tri::Cond(json!({ "is_empty": { "key": path(prefix, key)? } }))
            }
            other => match translate(other, prefix)? {
                Tri::All => Tri::Nothing,
                Tri::Nothing => Tri::All,
                Tri::Cond(c) => Tri::Cond(json!({ "must_not": [c] })),
            },
        },
        Filter::Eq { key, value } => Tri::Cond(eq(&path(prefix, key)?, value)?),
        Filter::In { key, values } => is_in(&path(prefix, key)?, values)?,
        Filter::Range { key, lower, upper } => Tri::Cond(range(&path(prefix, key)?, lower, upper)?),
        Filter::Exists { key } => Tri::Cond(json!({
            "must_not": [{ "is_empty": { "key": path(prefix, key)? } }]
        })),
        // `Filter` is non-exhaustive; refuse what we do not know.
        other => {
            return Err(StoreError::InvalidFilter(format!(
                "filter {other:?} has no Qdrant translation"
            )));
        }
    })
}

/// The payload path of a metadata key, refusing keys Qdrant would parse
/// as a nested path.
fn path(prefix: &str, key: &str) -> Result<String, StoreError> {
    if key.is_empty() {
        return Err(StoreError::InvalidFilter("empty metadata key".into()));
    }
    if key.contains(['.', '[', ']', '"']) {
        return Err(StoreError::InvalidFilter(format!(
            "metadata key {key:?} contains '.', '[', ']' or '\"', which Qdrant reads as a nested path"
        )));
    }
    Ok(format!("{prefix}.{key}"))
}

fn eq(key: &str, value: &Value) -> Result<Value, StoreError> {
    Ok(match value {
        Value::String(_) | Value::Bool(_) => json!({ "key": key, "match": { "value": value } }),
        Value::Number(n) => {
            // A range matches `1` and `1.0` alike, as the in-memory store
            // does; `match` would only find integers. Past 2^53 an f64
            // range is inexact, so exact `match` takes over.
            if let Some(i) = n.as_i64().filter(|i| i.unsigned_abs() > MAX_EXACT_F64_INT) {
                json!({ "key": key, "match": { "value": i } })
            } else if n.as_i64().is_none() && n.is_u64() {
                return Err(StoreError::InvalidFilter(format!(
                    "{n} on {key:?} is above i64::MAX; Qdrant integers are signed 64-bit"
                )));
            } else {
                json!({ "key": key, "range": { "gte": n, "lte": n } })
            }
        }
        Value::Null => json!({ "is_null": { "key": key } }),
        Value::Array(_) | Value::Object(_) => {
            return Err(StoreError::InvalidFilter(format!(
                "Qdrant cannot test {key:?} for equality with an array or object"
            )));
        }
    })
}

fn is_in(key: &str, values: &[Value]) -> Result<Tri, StoreError> {
    match values {
        [] => return Ok(Tri::Nothing),
        [one] => return Ok(Tri::Cond(eq(key, one)?)),
        _ => {}
    }
    if values.iter().all(Value::is_string) {
        return Ok(Tri::Cond(json!({ "key": key, "match": { "any": values } })));
    }
    let conds = values
        .iter()
        .map(|v| eq(key, v))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Tri::Cond(json!({ "should": conds })))
}

/// Integers up to this magnitude are exact in an f64.
const MAX_EXACT_F64_INT: u64 = 1 << 53;

fn range(key: &str, lower: &Bound<Value>, upper: &Bound<Value>) -> Result<Value, StoreError> {
    let mut bounds = Map::new();
    for (bound, inclusive, exclusive) in [(lower, "gte", "gt"), (upper, "lte", "lt")] {
        let (op, v) = match bound {
            Bound::Unbounded => continue,
            Bound::Included(v) => (inclusive, v),
            Bound::Excluded(v) => (exclusive, v),
        };
        // `Filter::validate` already rejected anything but numbers and strings
        // and mixed kinds.
        if let Value::String(s) = v
            && !is_iso_datetime(s)
        {
            return Err(StoreError::InvalidFilter(format!(
                "string range on {key:?} needs ISO-8601 dates (Qdrant compares strings only as datetimes), got {s:?}"
            )));
        }
        bounds.insert(op.to_owned(), v.clone());
    }
    if bounds.is_empty() {
        return Err(StoreError::InvalidFilter(format!(
            "range on {key:?} has no bounds; Qdrant cannot express \"any number or string\""
        )));
    }
    // Qdrant's `range` takes numbers, or RFC 3339 strings as a datetime range.
    Ok(json!({ "key": key, "range": bounds }))
}

/// `YYYY-MM-DD`, optionally followed by `T` or a space, `HH:MM`, optional
/// `:SS` and fraction, and an optional `Z` or `±HH:MM` offset.
fn is_iso_datetime(s: &str) -> bool {
    let b = s.as_bytes();
    let digits =
        |r: std::ops::Range<usize>| b.get(r).is_some_and(|d| d.iter().all(u8::is_ascii_digit));
    if !(digits(0..4)
        && b.get(4) == Some(&b'-')
        && digits(5..7)
        && b.get(7) == Some(&b'-')
        && digits(8..10))
    {
        return false;
    }
    if b.len() == 10 {
        return true;
    }
    let time = digits(11..13) && b.get(13) == Some(&b':') && digits(14..16);
    if !matches!(b[10], b'T' | b't' | b' ') || !time {
        return false;
    }
    let mut i = 16;
    if b.get(i) == Some(&b':') {
        if !digits(i + 1..i + 3) {
            return false;
        }
        i += 3;
        if b.get(i) == Some(&b'.') {
            let start = i + 1;
            i = start;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            if i == start {
                return false;
            }
        }
    }
    match &b[i..] {
        [] | [b'Z' | b'z'] => true,
        [b'+' | b'-', ..] => {
            b.len() == i + 6 && digits(i + 1..i + 3) && b[i + 3] == b':' && digits(i + 4..i + 6)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tr(f: &Filter) -> QdrantFilter {
        qdrant_filter(f, "metadata").unwrap()
    }

    fn cond(f: &Filter) -> Value {
        match tr(f) {
            QdrantFilter::Filter(v) => v,
            other => panic!("expected a filter, got {other:?}"),
        }
    }

    fn err(f: &Filter) -> String {
        qdrant_filter(f, "metadata").unwrap_err().to_string()
    }

    #[test]
    fn leaves() {
        assert_eq!(
            cond(&Filter::eq("lang", "en")),
            json!({"must": [{"key": "metadata.lang", "match": {"value": "en"}}]})
        );
        assert_eq!(
            cond(&Filter::eq("ok", true)),
            json!({"must": [{"key": "metadata.ok", "match": {"value": true}}]})
        );
        assert_eq!(
            cond(&Filter::eq("n", -3)),
            json!({"must": [{"key": "metadata.n", "range": {"gte": -3, "lte": -3}}]})
        );
        let big = (1i64 << 53) + 1;
        assert_eq!(
            cond(&Filter::eq("n", big)),
            json!({"must": [{"key": "metadata.n", "match": {"value": big}}]})
        );
        assert_eq!(
            cond(&Filter::eq("f", 1.5)),
            json!({"must": [{"key": "metadata.f", "range": {"gte": 1.5, "lte": 1.5}}]})
        );
        assert_eq!(
            cond(&Filter::eq("x", Value::Null)),
            json!({"must": [{"is_null": {"key": "metadata.x"}}]})
        );
        assert_eq!(
            cond(&Filter::exists("x")),
            json!({"must_not": [{"is_empty": {"key": "metadata.x"}}]})
        );
        assert_eq!(
            cond(&!Filter::exists("x")),
            json!({"must": [{"is_empty": {"key": "metadata.x"}}]})
        );
    }

    #[test]
    fn membership() {
        assert_eq!(
            cond(&Filter::is_in("t", ["a", "b"])),
            json!({"must": [{"key": "metadata.t", "match": {"any": ["a", "b"]}}]})
        );
        assert_eq!(
            cond(&Filter::is_in("n", [1, 2])),
            json!({"should": [
                {"key": "metadata.n", "range": {"gte": 1, "lte": 1}},
                {"key": "metadata.n", "range": {"gte": 2, "lte": 2}},
            ]})
        );
        assert_eq!(
            cond(&Filter::is_in("t", ["a"])),
            json!({"must": [{"key": "metadata.t", "match": {"value": "a"}}]})
        );
        assert_eq!(
            cond(&Filter::is_in("m", [json!("a"), json!(2.5)])),
            json!({"should": [
                {"key": "metadata.m", "match": {"value": "a"}},
                {"key": "metadata.m", "range": {"gte": 2.5, "lte": 2.5}},
            ]})
        );
        assert_eq!(
            tr(&Filter::is_in("t", Vec::<String>::new())),
            QdrantFilter::Nothing
        );
    }

    #[test]
    fn ranges() {
        assert_eq!(
            cond(&Filter::between("y", 2020, 2022)),
            json!({"must": [{"key": "metadata.y", "range": {"gte": 2020, "lte": 2022}}]})
        );
        assert_eq!(
            cond(&Filter::gt("y", 1.5)),
            json!({"must": [{"key": "metadata.y", "range": {"gt": 1.5}}]})
        );
        assert_eq!(
            cond(&Filter::lt("y", 0)),
            json!({"must": [{"key": "metadata.y", "range": {"lt": 0}}]})
        );
        assert_eq!(
            cond(&Filter::between("d", "2024-01-01", "2024-12-31T23:59:59Z")),
            json!({"must": [{"key": "metadata.d", "range": {
                "gte": "2024-01-01", "lte": "2024-12-31T23:59:59Z"
            }}]})
        );
        assert!(err(&Filter::gt("name", "m")).contains("ISO-8601"));
        assert!(err(&Filter::range("y", Bound::Unbounded, Bound::Unbounded)).contains("no bounds"));
        // Malformed filters are caught by validation first.
        assert!(err(&Filter::gt("y", true)).contains("number or string"));
        assert!(err(&Filter::between("y", 1, "z")).contains("mix"));
    }

    #[test]
    fn combinators() {
        let f = Filter::eq("a", 1)
            .or(Filter::eq("b", 2))
            .and(!Filter::eq("c", "x"));
        assert_eq!(
            cond(&f),
            json!({"must": [
                {"should": [
                    {"key": "metadata.a", "range": {"gte": 1, "lte": 1}},
                    {"key": "metadata.b", "range": {"gte": 2, "lte": 2}},
                ]},
                {"must_not": [{"key": "metadata.c", "match": {"value": "x"}}]},
            ]})
        );
    }

    #[test]
    fn constants_fold() {
        assert_eq!(tr(&Filter::default()), QdrantFilter::All);
        assert_eq!(tr(&Filter::Or(vec![])), QdrantFilter::Nothing);
        assert_eq!(tr(&!Filter::default()), QdrantFilter::Nothing);
        assert_eq!(tr(&!Filter::Or(vec![])), QdrantFilter::All);
        // Or with an always-true branch is always true.
        assert_eq!(
            tr(&Filter::eq("a", 1).or(Filter::default())),
            QdrantFilter::All
        );
        // And with an always-false branch is always false.
        assert_eq!(
            tr(&Filter::eq("a", 1).and(Filter::Or(vec![]))),
            QdrantFilter::Nothing
        );
        // Neutral parts disappear.
        assert_eq!(
            cond(&Filter::eq("a", 1).and(Filter::default())),
            json!({"must": [{"key": "metadata.a", "range": {"gte": 1, "lte": 1}}]})
        );
        assert_eq!(
            cond(&Filter::eq("a", 1).or(Filter::Or(vec![]))),
            json!({"must": [{"key": "metadata.a", "range": {"gte": 1, "lte": 1}}]})
        );
    }

    #[test]
    fn untranslatable_is_an_error_not_a_drop() {
        assert!(err(&Filter::eq("t", json!(["a"]))).contains("array or object"));
        assert!(err(&Filter::eq("t", json!({"a": 1}))).contains("array or object"));
        assert!(err(&Filter::eq("n", u64::MAX)).contains("i64::MAX"));
        assert!(err(&Filter::is_in("n", [json!(1), json!(u64::MAX)])).contains("i64::MAX"));
        for key in ["a.b", "a[0]", "x\"y", ""] {
            assert!(
                qdrant_filter(&Filter::eq(key, 1), "metadata").is_err(),
                "{key}"
            );
        }
        // Deep in an otherwise fine filter.
        let f = Filter::eq("a", 1).and(Filter::Or(vec![
            Filter::eq("b", 2),
            !Filter::eq("c", json!([1])),
        ]));
        assert!(qdrant_filter(&f, "metadata").is_err());
    }

    #[test]
    fn iso_dates() {
        for ok in [
            "2024-03-01",
            "2024-03-01T10:20",
            "2024-03-01T10:20:30",
            "2024-03-01 10:20:30.123456",
            "2024-03-01T10:20:30Z",
            "2024-03-01T10:20:30.5+02:00",
            "2024-03-01T10:20:30-05:30",
        ] {
            assert!(is_iso_datetime(ok), "{ok}");
        }
        for bad in [
            "",
            "2024",
            "2024-3-01",
            "2024-03-01T",
            "2024-03-01T10",
            "2024-03-01T10:20:3",
            "2024-03-01T10:20:30.",
            "2024-03-01T10:20:30+0200",
            "2024-03-01T10:20:30Zx",
            "abcd-ef-gh",
            "２０２４-03-01",
        ] {
            assert!(!is_iso_datetime(bad), "{bad}");
        }
    }
}
