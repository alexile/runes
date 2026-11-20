//! Metadata filters compiled to SQLite `WHERE` clauses.
//!
//! Keys and values only ever reach SQLite as bound parameters: the SQL text
//! is built from fixed fragments and `?N` placeholders. Each key becomes a
//! bound JSON path `$."key"` read with `json_type` / `json_each`.
//!
//! The compiled clause is a *pre-filter*: it may let through rows the
//! filter rejects (never the reverse), and the store re-checks every
//! candidate with [`Filter::matches_metadata`] before keeping it. Most
//! clauses are exact; the ones that are not (float comparisons, keys that
//! cannot be written as a JSON path, very large filters) are widened
//! instead, so results always follow the in-memory semantics.

use std::fmt::Write as _;
use std::ops::Bound;

use rune_vectorstore::{Filter, Value};

/// A value bound to a placeholder.
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    Int(i64),
    Real(f64),
    Text(String),
}

impl rusqlite::ToSql for Param {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(match self {
            Self::Int(i) => (*i).into(),
            Self::Real(r) => (*r).into(),
            Self::Text(s) => s.as_str().into(),
        })
    }
}

/// A compiled clause plus its parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct Compiled {
    /// SQL boolean expression over the metadata column.
    pub sql: String,
    /// Parameters for `?first..`, in order.
    pub params: Vec<Param>,
    /// `true` if the clause matches exactly the rows the filter does.
    pub exact: bool,
}

/// SQLite's default host parameter cap is 32 766; stay well under it.
const MAX_PARAMS: usize = 30_000;
/// SQLite caps expression depth at 1000; long `AND` / `OR` lists nest one
/// level per term, so wider lists are cut down (`AND`) or dropped (`OR`).
const MAX_TERMS: usize = 100;
/// Values per `IN` list before numeric bands are no longer pushed down.
const MAX_BANDS: usize = 64;
/// Integers up to 2^53 compare exactly as SQLite integers and reals.
const EXACT_INT: i64 = 1 << 53;

/// Compile `filter` against the JSON column `column` (a trusted, quoted
/// identifier). Placeholders are numbered from `first`.
pub fn compile(filter: &Filter, column: &str, first: usize) -> Compiled {
    let mut c = Compiler {
        column,
        first,
        params: Vec::new(),
    };
    let (sql, exact) = c.node(filter);
    if c.params.len() > MAX_PARAMS {
        return Compiled {
            sql: "1".into(),
            params: Vec::new(),
            exact: false,
        };
    }
    Compiled {
        sql,
        params: c.params,
        exact,
    }
}

struct Compiler<'a> {
    column: &'a str,
    first: usize,
    params: Vec<Param>,
}

impl Compiler<'_> {
    /// Bind `p` and return its placeholder.
    fn bind(&mut self, p: Param) -> String {
        self.params.push(p);
        format!("?{}", self.first + self.params.len() - 1)
    }

    fn node(&mut self, f: &Filter) -> (String, bool) {
        match f {
            Filter::And(all) => self.all(all),
            Filter::Or(any) => self.any(any),
            Filter::Not(inner) => {
                let mark = self.params.len();
                let (sql, exact) = self.node(inner);
                if exact {
                    (format!("NOT ({sql})"), true)
                } else {
                    // NOT of a widened clause would narrow it: no push-down.
                    self.params.truncate(mark);
                    ("1".into(), false)
                }
            }
            Filter::Eq { key, value } => self.is_in(key, std::slice::from_ref(value)),
            Filter::In { key, values } => self.is_in(key, values),
            Filter::Range { key, lower, upper } => self.range(key, lower, upper),
            Filter::Exists { key } => match self.path(key) {
                Some(p) => (
                    format!("COALESCE(json_type({}, {p}) <> 'null', 0)", self.column),
                    true,
                ),
                None => ("1".into(), false),
            },
            _ => ("1".into(), false),
        }
    }

    fn all(&mut self, all: &[Filter]) -> (String, bool) {
        if all.is_empty() {
            return ("1".into(), true);
        }
        // Dropping terms from an AND only widens it.
        let mut exact = all.len() <= MAX_TERMS;
        let mut parts = Vec::with_capacity(all.len().min(MAX_TERMS));
        for f in all.iter().take(MAX_TERMS) {
            let (sql, e) = self.node(f);
            exact &= e;
            parts.push(format!("({sql})"));
        }
        (parts.join(" AND "), exact)
    }

    fn any(&mut self, any: &[Filter]) -> (String, bool) {
        if any.is_empty() {
            return ("0".into(), true);
        }
        if any.len() > MAX_TERMS {
            return ("1".into(), false);
        }
        let mut exact = true;
        let mut parts = Vec::with_capacity(any.len());
        for f in any {
            let (sql, e) = self.node(f);
            exact &= e;
            parts.push(format!("({sql})"));
        }
        (parts.join(" OR "), exact)
    }

    /// Bind the JSON path for a top-level key, or `None` if the key cannot
    /// be written as a quoted path label.
    fn path(&mut self, key: &str) -> Option<String> {
        let plain =
            !key.is_empty() && !key.chars().any(|c| c == '"' || c == '\\' || c.is_control());
        plain.then(|| self.bind(Param::Text(format!("$.\"{key}\""))))
    }

    /// `Eq` / `In`: the field equals a value, or is an array holding a
    /// non-array value.
    fn is_in(&mut self, key: &str, values: &[Value]) -> (String, bool) {
        if values.is_empty() {
            return ("0".into(), true);
        }
        let Some(path) = self.path(key) else {
            return ("1".into(), false);
        };
        let col = self.column;
        let mut exact = true;
        let mut elem = Vec::new(); // conditions on one element `e`
        let mut whole = Vec::new(); // conditions on the field's JSON type
        let (mut texts, mut ints, mut reals) = (Vec::new(), Vec::new(), Vec::new());
        for v in values {
            match v {
                Value::Null => elem.push("e.type = 'null'".to_owned()),
                Value::Bool(true) => elem.push("e.type = 'true'".to_owned()),
                Value::Bool(false) => elem.push("e.type = 'false'".to_owned()),
                Value::String(s) if !s.contains('\0') => texts.push(s.clone()),
                Value::String(_) => {
                    exact = false;
                    elem.push("e.type = 'text'".to_owned());
                }
                Value::Number(n) => match n.as_i64() {
                    Some(i) if (-EXACT_INT..=EXACT_INT).contains(&i) => ints.push(i),
                    _ => reals.push(n.as_f64().unwrap_or(0.0)),
                },
                // Structural equality is re-checked in Rust; only the
                // field's type is pushed down.
                Value::Array(_) => {
                    exact = false;
                    whole.push(format!("json_type({col}, {path}) = 'array'"));
                }
                Value::Object(_) => {
                    exact = false;
                    whole.push(format!("json_type({col}, {path}) IN ('object', 'array')"));
                }
            }
        }
        if !texts.is_empty() {
            let list = self.list(texts.into_iter().map(Param::Text));
            elem.push(format!("(e.type = 'text' AND e.atom IN ({list}))"));
        }
        if !ints.is_empty() {
            let list = self.list(ints.into_iter().map(Param::Int));
            elem.push(format!(
                "(e.type IN ('integer', 'real') AND e.atom IN ({list}))"
            ));
        }
        if !reals.is_empty() {
            exact = false;
            elem.push(self.bands(&reals));
        }
        let mut parts = whole;
        if !elem.is_empty() {
            parts.push(format!(
                "{} AND EXISTS (SELECT 1 FROM json_each({col}, {path}) AS e WHERE {})",
                not_object(col, &path),
                elem.join(" OR ")
            ));
        }
        (parts.join(" OR "), exact)
    }

    fn list(&mut self, items: impl Iterator<Item = Param>) -> String {
        let mut out = String::new();
        for p in items {
            if !out.is_empty() {
                out.push_str(", ");
            }
            let ph = self.bind(p);
            out.push_str(&ph);
        }
        out
    }

    /// Numbers that may not compare exactly (floats, huge integers): match
    /// a narrow band around each, re-checked in Rust.
    fn bands(&mut self, reals: &[f64]) -> String {
        if reals.len() > MAX_BANDS {
            return "e.type IN ('integer', 'real')".into();
        }
        let mut out = String::from("(e.type IN ('integer', 'real') AND (");
        for (i, &x) in reals.iter().enumerate() {
            if i > 0 {
                out.push_str(" OR ");
            }
            let (lo, hi) = (widen_down(x), widen_up(x));
            let lo = self.bind(Param::Real(lo));
            let hi = self.bind(Param::Real(hi));
            let _ = write!(out, "e.atom BETWEEN {lo} AND {hi}");
        }
        out.push_str("))");
        out
    }

    fn range(&mut self, key: &str, lower: &Bound<Value>, upper: &Bound<Value>) -> (String, bool) {
        let Some(path) = self.path(key) else {
            return ("1".into(), false);
        };
        let numeric = [lower, upper].iter().any(|b| {
            matches!(
                b,
                Bound::Included(Value::Number(_)) | Bound::Excluded(Value::Number(_))
            )
        });
        let textual = [lower, upper].iter().any(|b| {
            matches!(
                b,
                Bound::Included(Value::String(_)) | Bound::Excluded(Value::String(_))
            )
        });
        let mut exact = true;
        let mut conds = vec![
            if numeric {
                exact = false;
                "e.type IN ('integer', 'real')"
            } else if textual {
                "e.type = 'text'"
            } else {
                "e.type IN ('integer', 'real', 'text')"
            }
            .to_owned(),
        ];
        for (bound, is_lower) in [(lower, true), (upper, false)] {
            match bound {
                Bound::Unbounded => {}
                Bound::Included(Value::Number(n)) | Bound::Excluded(Value::Number(n)) => {
                    let x = n.as_f64().unwrap_or(0.0);
                    let (op, edge) = if is_lower {
                        (">=", widen_down(x))
                    } else {
                        ("<=", widen_up(x))
                    };
                    let ph = self.bind(Param::Real(edge));
                    conds.push(format!("e.atom {op} {ph}"));
                }
                Bound::Included(Value::String(s)) | Bound::Excluded(Value::String(s))
                    if !s.contains('\0') =>
                {
                    let op = match (bound, is_lower) {
                        (Bound::Included(_), true) => ">=",
                        (Bound::Included(_), false) => "<=",
                        (_, true) => ">",
                        (_, false) => "<",
                    };
                    let ph = self.bind(Param::Text(s.clone()));
                    conds.push(format!("e.atom {op} {ph}"));
                }
                // Validation rejects other bound types; NUL strings are
                // left to the Rust check.
                _ => exact = false,
            }
        }
        (
            format!(
                "{} AND EXISTS (SELECT 1 FROM json_each({}, {path}) AS e WHERE {})",
                not_object(self.column, &path),
                self.column,
                conds.join(" AND ")
            ),
            exact,
        )
    }
}

/// `json_each` walks arrays element by element, which is what the filter
/// semantics want, but it would also walk an object's members: objects are
/// excluded up front.
fn not_object(column: &str, path: &str) -> String {
    format!("COALESCE(json_type({column}, {path}) <> 'object', 0)")
}

/// Relative slack for float comparisons: far above any parse rounding
/// difference, far below any meaningful gap.
const SLACK: f64 = 1e-9;

fn widen_down(x: f64) -> f64 {
    x.abs().mul_add(-SLACK, x) - f64::MIN_POSITIVE
}

fn widen_up(x: f64) -> f64 {
    x.abs().mul_add(SLACK, x) + f64::MIN_POSITIVE
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sql(f: &Filter) -> Compiled {
        compile(f, "metadata", 3)
    }

    #[test]
    fn empty_and_or() {
        assert_eq!(sql(&Filter::default()).sql, "1");
        assert!(sql(&Filter::default()).exact);
        assert_eq!(sql(&Filter::Or(vec![])).sql, "0");
        assert_eq!(sql(&Filter::is_in("a", Vec::<i32>::new())).sql, "0");
    }

    #[test]
    fn eq_string_is_exact_and_bound() {
        let c = sql(&Filter::eq("lang", "en"));
        assert!(c.exact);
        assert_eq!(
            c.sql,
            "COALESCE(json_type(metadata, ?3) <> 'object', 0) AND \
             EXISTS (SELECT 1 FROM json_each(metadata, ?3) AS e WHERE (e.type = 'text' AND e.atom IN (?4)))"
        );
        assert_eq!(
            c.params,
            [Param::Text("$.\"lang\"".into()), Param::Text("en".into())]
        );
    }

    #[test]
    fn numbers_and_floats() {
        let c = sql(&Filter::is_in("n", [json!(1), json!(2.5)]));
        assert!(!c.exact);
        assert_eq!(c.params.len(), 4);
        assert_eq!(c.params[1], Param::Int(1));
        let c = sql(&Filter::eq("n", u64::MAX));
        assert!(!c.exact);
    }

    #[test]
    fn not_of_inexact_is_not_pushed_down() {
        let c = sql(&!Filter::eq("x", 1.5));
        assert_eq!(c.sql, "1");
        assert!(!c.exact);
        let c = sql(&!Filter::eq("x", 1));
        assert!(c.sql.starts_with("NOT ("));
        assert!(c.exact);
    }

    #[test]
    fn hostile_keys_never_reach_sql_text() {
        let build = |key: &str| {
            Filter::eq(key, "v")
                .and(Filter::exists(key))
                .and(!Filter::gt(key, 1))
        };
        let reference = sql(&build("k")).sql;
        let degraded = "(1) AND (1) AND (1)";
        for key in [
            "a'; DROP TABLE t; --",
            "x\") OR 1=1 --",
            "x') OR 1=1 --",
            "$.a[0]",
            "a\\b",
            "",
            "\0",
            "e.atom",
            "\u{202e}",
        ] {
            let c = sql(&build(key));
            assert!(
                c.sql == reference || c.sql == degraded,
                "{key:?}: {}",
                c.sql
            );
        }
    }

    #[test]
    fn hostile_values_are_params() {
        let evil = "' OR 1=1; DROP TABLE t; --";
        let c = sql(&Filter::eq("k", evil).or(Filter::between("k", evil, "z")));
        assert!(!c.sql.contains("DROP"));
        assert!(c.params.contains(&Param::Text(evil.into())));
    }

    #[test]
    fn wide_filters_degrade_safely() {
        let many: Vec<Filter> = (0..500).map(|i| Filter::eq("k", i)).collect();
        let c = sql(&Filter::Or(many.clone()));
        assert_eq!((c.sql.as_str(), c.exact), ("1", false));
        let c = sql(&Filter::And(many));
        assert!(!c.exact);
        assert_eq!(c.params.len(), MAX_TERMS * 2);
        let c = sql(&Filter::is_in("k", 0..50_000));
        assert_eq!((c.sql.as_str(), c.exact), ("1", false));
    }

    #[test]
    fn widening_brackets_the_value() {
        for x in [0.0, 1.0, -1.0, 1e300, -1e-300, f64::MAX] {
            assert!(widen_down(x) <= x && x <= widen_up(x), "{x}");
        }
    }

    /// Run compiled clauses directly in SQLite against `matches_metadata`:
    /// the clause must never drop a match, and must be exact when it says so.
    #[test]
    fn clauses_are_supersets_and_exact_when_flagged() {
        let values = [
            json!(0),
            json!(1),
            json!(-2),
            json!(2.5),
            json!(1.0),
            json!(u64::MAX),
            json!("a"),
            json!("b"),
            json!(""),
            json!("é"),
            json!("a\"b"),
            json!(true),
            json!(false),
            json!(null),
            json!([1, "a"]),
            json!([]),
            json!([[1]]),
            json!({"x": 1}),
            json!([{"x": 1}]),
            json!("\u{0}"),
        ];
        let keys = ["k", "j", "we\"ird"];
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (pk INTEGER PRIMARY KEY, metadata TEXT NOT NULL)")
            .unwrap();
        let mut rows = Vec::new();
        for (i, v) in values.iter().enumerate() {
            for (j, w) in values.iter().enumerate().step_by(3) {
                let mut m = std::collections::BTreeMap::new();
                m.insert(keys[i % 3].to_owned(), v.clone());
                m.insert(keys[(i + 1) % 3].to_owned(), w.clone());
                if j % 2 == 0 {
                    m.remove("j");
                }
                conn.execute(
                    "INSERT INTO t (metadata) VALUES (?1)",
                    [serde_json::to_string(&m).unwrap()],
                )
                .unwrap();
                rows.push(m);
            }
        }
        let mut filters = Vec::new();
        for key in keys {
            for v in &values {
                filters.push(Filter::eq(key, v.clone()));
                if v.is_number() || v.is_string() {
                    filters.push(Filter::gt(key, v.clone()));
                    filters.push(Filter::lte(key, v.clone()));
                }
            }
            filters.push(Filter::exists(key));
            filters.push(Filter::range(key, Bound::Unbounded, Bound::Unbounded));
            filters.push(Filter::is_in(key, [json!(1), json!("b"), json!(null)]));
        }
        let negated: Vec<Filter> = filters.iter().map(|f| !f.clone()).collect();
        filters.extend(negated);
        for f in &filters {
            let c = compile(f, "metadata", 1);
            let sql = format!("SELECT pk FROM t WHERE {} ORDER BY pk", c.sql);
            let mut stmt = conn.prepare(&sql).unwrap();
            let got: Vec<i64> = stmt
                .query_map(rusqlite::params_from_iter(&c.params), |r| r.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            let want: Vec<i64> = rows
                .iter()
                .zip(1..)
                .filter(|(m, _)| f.matches_metadata(m))
                .map(|(_, pk)| pk)
                .collect();
            assert!(
                want.iter().all(|pk| got.contains(pk)),
                "dropped a match: {f:?}"
            );
            if c.exact {
                assert_eq!(got, want, "exact clause disagrees: {f:?}");
            }
        }
    }
}
