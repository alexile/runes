//! SQL generation. Pure functions, so every statement can be unit tested
//! without a database.
//!
//! Identifiers (schema, table, index) are validated by [`check_identifier`]
//! and then double-quoted; integers in DDL come from typed config fields.
//! Everything else — ids, vectors, content, metadata keys and values,
//! limits and search settings — is a bound parameter.

use std::fmt::Write as _;
use std::ops::Bound;

use rune_vectorstore::{Filter, Metric, StoreError, Value};

/// Most conditions one filter may hold. Each costs at most three bound
/// parameters, so this stays far below Postgres' 65 535-parameter limit.
pub const MAX_FILTER_CONDITIONS: usize = 10_000;

/// Largest dimension the `vector` type stores.
pub const MAX_DIMENSION: usize = 16_000;

/// Largest dimension HNSW and `IVFFlat` can index for `vector`.
pub const MAX_INDEXED_DIMENSION: usize = 2_000;

/// The approximate index to build on the embedding column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PgIndex {
    /// No vector index: every query is an exact sequential scan.
    None,
    /// HNSW graph index: best recall/latency trade-off, slower to build.
    Hnsw {
        /// Links per node (pgvector default 16).
        m: u32,
        /// Candidate list size while building (pgvector default 64).
        ef_construction: u32,
    },
    /// `IVFFlat` index: fast to build, needs data present before creation
    /// for good recall.
    IvfFlat {
        /// Number of inverted lists; rows / 1000 is a good start.
        lists: u32,
    },
}

impl Default for PgIndex {
    fn default() -> Self {
        Self::Hnsw {
            m: 16,
            ef_construction: 64,
        }
    }
}

impl PgIndex {
    const fn tag(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Hnsw { .. } => "hnsw",
            Self::IvfFlat { .. } => "ivfflat",
        }
    }
}

/// Check that `name` is a plain SQL identifier: ASCII letters, digits and
/// `_`, not starting with a digit, at most 63 bytes, not starting with
/// `pg_`.
///
/// # Errors
///
/// [`StoreError::Backend`] naming what is wrong (never echoing the input).
pub fn check_identifier(what: &str, name: &str) -> Result<(), StoreError> {
    let mut chars = name.chars();
    let ok = name.len() <= 63
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.to_ascii_lowercase().starts_with("pg_");
    if ok {
        Ok(())
    } else {
        Err(StoreError::Backend(format!(
            "{what} must be a plain identifier: ASCII letters, digits and '_', \
             not starting with a digit or pg_, at most 63 bytes"
        )))
    }
}

/// Distance operator, operator class and distance-to-score conversion for
/// a metric.
pub const fn operator(metric: Metric) -> (&'static str, &'static str) {
    match metric {
        Metric::Cosine => ("<=>", "vector_cosine_ops"),
        Metric::DotProduct => ("<#>", "vector_ip_ops"),
        _ => ("<->", "vector_l2_ops"),
    }
}

/// Turn a pgvector distance into the store's "higher is closer" score.
#[allow(clippy::cast_possible_truncation, reason = "scores are f32 everywhere")]
pub fn score(metric: Metric, distance: f64) -> f32 {
    let s = match metric {
        Metric::Cosine => 1.0 - distance,
        // `<#>` is the negative inner product; `<->` the L2 distance.
        _ => -distance,
    } as f32;
    if s.is_nan() { f32::NEG_INFINITY } else { s }
}

/// Validated names and the statements built from them.
#[derive(Debug, Clone)]
pub struct Statements {
    /// `"schema"."table"` or `"table"`.
    pub table: String,
    /// The same, as text for `::regclass`.
    pub regclass: String,
    pub index_name: String,
    pub metric: Metric,
    pub dimension: usize,
    pub index: PgIndex,
}

impl Statements {
    pub fn new(
        schema: Option<&str>,
        table: &str,
        index_name: Option<&str>,
        metric: Metric,
        dimension: usize,
        index: PgIndex,
    ) -> Result<Self, StoreError> {
        if let Some(s) = schema {
            check_identifier("schema name", s)?;
        }
        check_identifier("table name", table)?;
        if dimension == 0 || dimension > MAX_DIMENSION {
            return Err(StoreError::Backend(format!(
                "dimension must be within 1..={MAX_DIMENSION}"
            )));
        }
        if index != PgIndex::None && dimension > MAX_INDEXED_DIMENSION {
            return Err(StoreError::Backend(format!(
                "pgvector indexes vectors of at most {MAX_INDEXED_DIMENSION} dimensions; \
                 use PgIndex::None for exact search"
            )));
        }
        let ops = operator(metric).1;
        let short = ops.trim_start_matches("vector_").trim_end_matches("_ops");
        let index_name = index_name.map_or_else(
            || format!("{table}_{}_{short}_idx", index.tag()),
            str::to_owned,
        );
        if index != PgIndex::None {
            check_identifier("index name", &index_name)?;
        }
        let table = schema.map_or_else(
            || format!("\"{table}\""),
            |s| format!("\"{s}\".\"{table}\""),
        );
        Ok(Self {
            regclass: table.clone(),
            table,
            index_name,
            metric,
            dimension,
            index,
        })
    }

    /// DDL: extension (optional), table and index, all idempotent.
    pub fn create(&self, extension: bool) -> Vec<String> {
        let mut out = Vec::new();
        if extension {
            out.push("CREATE EXTENSION IF NOT EXISTS vector".to_owned());
        }
        out.push(format!(
            "CREATE TABLE IF NOT EXISTS {} (\
             id text PRIMARY KEY, \
             embedding vector({}) NOT NULL, \
             content text NOT NULL DEFAULT '', \
             metadata jsonb NOT NULL DEFAULT '{{}}'::jsonb)",
            self.table, self.dimension
        ));
        let ops = operator(self.metric).1;
        let with = match self.index {
            PgIndex::None => return out,
            PgIndex::Hnsw { m, ef_construction } => {
                format!(
                    "hnsw (embedding {ops}) WITH (m = {m}, ef_construction = {ef_construction})"
                )
            }
            PgIndex::IvfFlat { lists } => {
                format!("ivfflat (embedding {ops}) WITH (lists = {lists})")
            }
        };
        out.push(format!(
            "CREATE INDEX IF NOT EXISTS \"{}\" ON {} USING {with}",
            self.index_name, self.table
        ));
        out
    }

    /// Reads the declared dimension of the embedding column; `$1` is
    /// [`Statements::regclass`].
    pub const fn column_dimension() -> &'static str {
        "SELECT atttypmod FROM pg_attribute \
         WHERE attrelid = $1::text::regclass AND attname = 'embedding' AND NOT attisdropped"
    }

    /// Batched upsert: `$1` ids, `$2` all vectors flattened, `$3`
    /// contents, `$4` metadata. Rows are sliced back out of `$2` by index.
    pub fn upsert(&self) -> String {
        format!(
            "INSERT INTO {t} (id, embedding, content, metadata) \
             SELECT ($1::text[])[i], (($2::real[])[(i - 1) * {d} + 1 : i * {d}])::vector, \
                    ($3::text[])[i], ($4::jsonb[])[i] \
             FROM generate_subscripts($1::text[], 1) AS i \
             ON CONFLICT (id) DO UPDATE SET embedding = EXCLUDED.embedding, \
             content = EXCLUDED.content, metadata = EXCLUDED.metadata",
            t = self.table,
            d = self.dimension
        )
    }

    pub fn delete(&self) -> String {
        format!("DELETE FROM {} WHERE id = ANY($1::text[])", self.table)
    }

    pub fn get(&self) -> String {
        format!(
            "SELECT id, content, metadata, embedding::real[] FROM {} WHERE id = $1::text",
            self.table
        )
    }

    pub fn count(&self) -> String {
        format!("SELECT count(*) FROM {}", self.table)
    }

    pub fn clear(&self) -> String {
        format!("DELETE FROM {}", self.table)
    }

    /// `DELETE ... WHERE <filter>`; parameters from `$1`.
    pub fn delete_where(&self, filter: &Filter) -> Result<(String, Vec<Param>), StoreError> {
        let c = compile(filter, 1)?;
        Ok((
            format!("DELETE FROM {} WHERE {}", self.table, c.sql),
            c.params,
        ))
    }

    /// Nearest-neighbour query: `$1` the query vector, `$2` the limit,
    /// filter parameters from `$3`. Columns: id, content, metadata,
    /// vector (or NULL), distance.
    pub fn query(
        &self,
        filter: &Filter,
        with_vectors: bool,
    ) -> Result<(String, Vec<Param>), StoreError> {
        let c = compile(filter, 3)?;
        let op = operator(self.metric).0;
        let vector = if with_vectors {
            "embedding::real[]"
        } else {
            "NULL::real[]"
        };
        let mut sql = format!(
            "SELECT id, content, metadata, {vector}, embedding {op} $1::real[]::vector AS distance \
             FROM {}",
            self.table
        );
        if c.sql != "TRUE" {
            let _ = write!(sql, " WHERE {}", c.sql);
        }
        let _ = write!(
            sql,
            " ORDER BY embedding {op} $1::real[]::vector LIMIT $2::bigint"
        );
        Ok((sql, c.params))
    }
}

/// A bound parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    Text(String),
    Json(Value),
}

/// A compiled filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    pub sql: String,
    pub params: Vec<Param>,
}

/// Compile `filter` to an exact SQL condition on the `metadata` column,
/// with parameters numbered from `first`.
///
/// # Errors
///
/// [`StoreError::InvalidFilter`] for a malformed filter, one with more than
/// [`MAX_FILTER_CONDITIONS`] conditions, or a range bound holding a NUL
/// character (Postgres text cannot carry one).
pub fn compile(filter: &Filter, first: usize) -> Result<Compiled, StoreError> {
    filter.validate()?;
    let mut c = Compiler {
        first,
        params: Vec::new(),
        conditions: 0,
    };
    let sql = c.node(filter)?;
    Ok(Compiled {
        sql,
        params: c.params,
    })
}

struct Compiler {
    first: usize,
    params: Vec<Param>,
    conditions: usize,
}

/// `true` if a JSON value contains a NUL character anywhere. Postgres
/// jsonb cannot store one, so such a value never equals a stored one.
pub fn has_nul(v: &Value) -> bool {
    match v {
        Value::String(s) => s.contains('\0'),
        Value::Array(items) => items.iter().any(has_nul),
        Value::Object(map) => map.iter().any(|(k, v)| k.contains('\0') || has_nul(v)),
        _ => false,
    }
}

impl Compiler {
    fn bind(&mut self, p: Param) -> String {
        self.params.push(p);
        format!("${}", self.first + self.params.len() - 1)
    }

    fn count(&mut self) -> Result<(), StoreError> {
        self.conditions += 1;
        if self.conditions > MAX_FILTER_CONDITIONS {
            return Err(StoreError::InvalidFilter(format!(
                "more than {MAX_FILTER_CONDITIONS} conditions"
            )));
        }
        Ok(())
    }

    fn join(&mut self, items: &[Filter], op: &str, empty: &str) -> Result<String, StoreError> {
        if items.is_empty() {
            return Ok(empty.to_owned());
        }
        let mut parts = Vec::with_capacity(items.len());
        for f in items {
            parts.push(format!("({})", self.node(f)?));
        }
        Ok(parts.join(op))
    }

    fn node(&mut self, f: &Filter) -> Result<String, StoreError> {
        self.count()?;
        match f {
            Filter::And(all) => self.join(all, " AND ", "TRUE"),
            Filter::Or(any) => self.join(any, " OR ", "FALSE"),
            Filter::Not(inner) => Ok(format!("NOT ({})", self.node(inner)?)),
            Filter::Eq { key, value } => Ok(self.is_in(key, std::slice::from_ref(value))),
            Filter::In { key, values } => Ok(self.is_in(key, values)),
            Filter::Range { key, lower, upper } => self.range(key, lower, upper),
            Filter::Exists { key } => Ok(if key.contains('\0') {
                "FALSE".to_owned()
            } else {
                let k = self.bind(Param::Text(key.clone()));
                format!("COALESCE(jsonb_typeof(metadata -> {k}::text) <> 'null', FALSE)")
            }),
            _ => Err(StoreError::InvalidFilter("unsupported filter".into())),
        }
    }

    /// The field equals one of `values`, or is an array with an element
    /// equal to one of the non-array values.
    fn is_in(&mut self, key: &str, values: &[Value]) -> String {
        // A key or value with NUL cannot be stored, so it never matches.
        let values: Vec<&Value> = values.iter().filter(|v| !has_nul(v)).collect();
        if values.is_empty() || key.contains('\0') {
            return "FALSE".to_owned();
        }
        let k = self.bind(Param::Text(key.to_owned()));
        let field = format!("(metadata -> {k}::text)");
        let all = self.bind(Param::Json(Value::Array(
            values.iter().map(|&v| v.clone()).collect(),
        )));
        let mut sql =
            format!("COALESCE({field} IN (SELECT jsonb_array_elements({all}::jsonb)), FALSE)");
        let scalars: Vec<Value> = values
            .iter()
            .filter(|v| !v.is_array())
            .map(|&v| v.clone())
            .collect();
        if !scalars.is_empty() {
            let s = self.bind(Param::Json(Value::Array(scalars)));
            let _ = write!(
                sql,
                " OR EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof({field}) = 'array' \
                 THEN {field} ELSE '[]'::jsonb END) AS e(x) \
                 WHERE e.x IN (SELECT jsonb_array_elements({s}::jsonb)))"
            );
        }
        sql
    }

    fn range(
        &mut self,
        key: &str,
        lower: &Bound<Value>,
        upper: &Bound<Value>,
    ) -> Result<String, StoreError> {
        if key.contains('\0') {
            return Ok("FALSE".to_owned());
        }
        let k = self.bind(Param::Text(key.to_owned()));
        let field = format!("(metadata -> {k}::text)");
        let is = |b: &Bound<Value>, f: fn(&Value) -> bool| match b {
            Bound::Included(v) | Bound::Excluded(v) => f(v),
            Bound::Unbounded => false,
        };
        let numeric = is(lower, Value::is_number) || is(upper, Value::is_number);
        let textual = is(lower, Value::is_string) || is(upper, Value::is_string);
        let mut conds = vec![
            if numeric {
                "jsonb_typeof(e.x) = 'number'"
            } else if textual {
                "jsonb_typeof(e.x) = 'string'"
            } else {
                "jsonb_typeof(e.x) IN ('number', 'string')"
            }
            .to_owned(),
        ];
        for (bound, lower) in [(lower, true), (upper, false)] {
            let (v, op) = match (bound, lower) {
                (Bound::Unbounded, _) => continue,
                (Bound::Included(v), true) => (v, ">="),
                (Bound::Excluded(v), true) => (v, ">"),
                (Bound::Included(v), false) => (v, "<="),
                (Bound::Excluded(v), false) => (v, "<"),
            };
            match v {
                // jsonb orders numbers by numeric value.
                Value::Number(_) => {
                    let p = self.bind(Param::Json(v.clone()));
                    conds.push(format!("e.x {op} {p}::jsonb"));
                }
                // Byte order, as in Rust, whatever the database collation.
                Value::String(s) if !s.contains('\0') => {
                    let p = self.bind(Param::Text(s.clone()));
                    conds.push(format!("(e.x #>> '{{}}') COLLATE \"C\" {op} {p}::text"));
                }
                _ => {
                    return Err(StoreError::InvalidFilter(format!(
                        "range bound on {key:?} cannot be sent to Postgres"
                    )));
                }
            }
        }
        Ok(format!(
            "EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof({field}) = 'array' \
             THEN {field} ELSE jsonb_build_array({field}) END) AS e(x) WHERE {})",
            conds.join(" AND ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn stmts(index: PgIndex) -> Statements {
        Statements::new(Some("rag"), "docs", None, Metric::Cosine, 3, index).unwrap()
    }

    #[test]
    fn ddl_for_each_index() {
        let s = stmts(PgIndex::default()).create(true);
        assert_eq!(s[0], "CREATE EXTENSION IF NOT EXISTS vector");
        assert_eq!(
            s[1],
            "CREATE TABLE IF NOT EXISTS \"rag\".\"docs\" (id text PRIMARY KEY, embedding vector(3) NOT NULL, \
             content text NOT NULL DEFAULT '', metadata jsonb NOT NULL DEFAULT '{}'::jsonb)"
        );
        assert_eq!(
            s[2],
            "CREATE INDEX IF NOT EXISTS \"docs_hnsw_cosine_idx\" ON \"rag\".\"docs\" USING hnsw \
             (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64)"
        );
        let s = stmts(PgIndex::IvfFlat { lists: 100 }).create(false);
        assert_eq!(s.len(), 2);
        assert!(s[1].ends_with("USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"));
        assert_eq!(stmts(PgIndex::None).create(false).len(), 1);
        let ip =
            Statements::new(None, "t", None, Metric::DotProduct, 2, PgIndex::default()).unwrap();
        assert!(
            ip.create(false)[1]
                .contains("\"t_hnsw_ip_idx\" ON \"t\" USING hnsw (embedding vector_ip_ops)")
        );
        let l2 = Statements::new(
            None,
            "t",
            Some("my_idx"),
            Metric::Euclidean,
            2,
            PgIndex::default(),
        )
        .unwrap();
        assert!(
            l2.create(false)[1]
                .contains("\"my_idx\" ON \"t\" USING hnsw (embedding vector_l2_ops)")
        );
    }

    #[test]
    fn identifiers_are_checked() {
        for bad in [
            "",
            "1a",
            "a-b",
            "a\"b",
            "a;drop",
            "pg_x",
            "é",
            &"a".repeat(64),
        ] {
            assert!(
                Statements::new(None, bad, None, Metric::Cosine, 3, PgIndex::None).is_err(),
                "{bad}"
            );
            assert!(
                Statements::new(Some(bad), "t", None, Metric::Cosine, 3, PgIndex::None).is_err()
            );
            assert!(
                Statements::new(None, "t", Some(bad), Metric::Cosine, 3, PgIndex::default())
                    .is_err()
            );
        }
        // The derived index name must fit too.
        let long = "a".repeat(60);
        assert!(Statements::new(None, &long, None, Metric::Cosine, 3, PgIndex::default()).is_err());
        assert!(Statements::new(None, &long, None, Metric::Cosine, 3, PgIndex::None).is_ok());
        assert!(
            Statements::new(
                None,
                &long,
                Some("ix"),
                Metric::Cosine,
                3,
                PgIndex::default()
            )
            .is_ok()
        );
        let err = Statements::new(
            None,
            "x\"; DROP TABLE y; --",
            None,
            Metric::Cosine,
            3,
            PgIndex::None,
        )
        .unwrap_err()
        .to_string();
        assert!(!err.contains("DROP"));
    }

    #[test]
    fn dimension_limits() {
        assert!(Statements::new(None, "t", None, Metric::Cosine, 0, PgIndex::None).is_err());
        assert!(Statements::new(None, "t", None, Metric::Cosine, 16_001, PgIndex::None).is_err());
        assert!(Statements::new(None, "t", None, Metric::Cosine, 16_000, PgIndex::None).is_ok());
        assert!(
            Statements::new(None, "t", None, Metric::Cosine, 2_001, PgIndex::default()).is_err()
        );
        assert!(
            Statements::new(None, "t", None, Metric::Cosine, 2_000, PgIndex::default()).is_ok()
        );
    }

    #[test]
    fn query_uses_metric_operator_and_binds() {
        let s = stmts(PgIndex::default());
        let (sql, params) = s.query(&Filter::default(), true).unwrap();
        assert_eq!(
            sql,
            "SELECT id, content, metadata, embedding::real[], embedding <=> $1::real[]::vector AS distance \
             FROM \"rag\".\"docs\" ORDER BY embedding <=> $1::real[]::vector LIMIT $2::bigint"
        );
        assert_eq!(params, []);
        let (sql, params) = s.query(&Filter::eq("lang", "en"), false).unwrap();
        assert!(sql.contains("NULL::real[]"));
        assert!(sql.contains(" WHERE COALESCE((metadata -> $3::text) IN (SELECT jsonb_array_elements($4::jsonb)), FALSE)"));
        assert_eq!(
            params,
            [
                Param::Text("lang".into()),
                Param::Json(json!(["en"])),
                Param::Json(json!(["en"]))
            ]
        );
        for (metric, op) in [(Metric::DotProduct, "<#>"), (Metric::Euclidean, "<->")] {
            let s = Statements::new(None, "t", None, metric, 3, PgIndex::None).unwrap();
            assert!(s.query(&Filter::default(), true).unwrap().0.contains(op));
        }
    }

    #[test]
    fn scores_from_distances() {
        assert!((score(Metric::Cosine, 0.25) - 0.75).abs() < 1e-6);
        assert!((score(Metric::DotProduct, -3.0) - 3.0).abs() < 1e-6);
        assert!((score(Metric::Euclidean, 2.0) + 2.0).abs() < 1e-6);
        assert_eq!(score(Metric::Euclidean, f64::NAN), f32::NEG_INFINITY);
    }

    #[test]
    fn upsert_and_other_statements() {
        let s = stmts(PgIndex::None);
        let up = s.upsert();
        assert!(up.contains("(($2::real[])[(i - 1) * 3 + 1 : i * 3])::vector"));
        assert!(up.contains("ON CONFLICT (id) DO UPDATE"));
        assert_eq!(
            s.delete(),
            "DELETE FROM \"rag\".\"docs\" WHERE id = ANY($1::text[])"
        );
        assert!(s.get().ends_with("WHERE id = $1::text"));
        let (sql, params) = s.delete_where(&Filter::exists("k")).unwrap();
        assert_eq!(
            sql,
            "DELETE FROM \"rag\".\"docs\" WHERE COALESCE(jsonb_typeof(metadata -> $1::text) <> 'null', FALSE)"
        );
        assert_eq!(params, [Param::Text("k".into())]);
    }

    #[test]
    fn filter_shapes() {
        let c = compile(&Filter::default(), 1).unwrap();
        assert_eq!(c.sql, "TRUE");
        assert_eq!(compile(&Filter::Or(vec![]), 1).unwrap().sql, "FALSE");
        let c = compile(&!Filter::eq("a", 1).or(Filter::exists("b")), 1).unwrap();
        assert!(c.sql.starts_with("NOT ((COALESCE("));
        let c = compile(&Filter::between("d", "2024-01-01", "2024-12-31"), 1).unwrap();
        assert!(c.sql.contains("jsonb_typeof(e.x) = 'string'"));
        assert!(c.sql.contains("(e.x #>> '{}') COLLATE \"C\" >= $2::text"));
        assert!(c.sql.contains("(e.x #>> '{}') COLLATE \"C\" <= $3::text"));
        let c = compile(&Filter::gt("n", 2.5), 1).unwrap();
        assert!(
            c.sql
                .contains("jsonb_typeof(e.x) = 'number' AND e.x > $2::jsonb")
        );
        assert_eq!(c.params[1], Param::Json(json!(2.5)));
        let c = compile(&Filter::eq("tags", json!(["a"])), 1).unwrap();
        assert!(
            !c.sql.contains("EXISTS"),
            "array values only match whole arrays"
        );
    }

    #[test]
    fn nul_keys_and_values_never_match() {
        assert_eq!(compile(&Filter::eq("a\0", 1), 1).unwrap().sql, "FALSE");
        assert_eq!(compile(&Filter::eq("a", "x\0"), 1).unwrap().sql, "FALSE");
        assert_eq!(compile(&Filter::exists("\0"), 1).unwrap().sql, "FALSE");
        assert_eq!(compile(&Filter::gt("\0", 1), 1).unwrap().sql, "FALSE");
        let c = compile(&Filter::is_in("a", ["x\0", "y"]), 1).unwrap();
        assert_eq!(c.params[1], Param::Json(json!(["y"])));
        assert!(compile(&Filter::gt("a", "x\0"), 1).is_err());
    }

    #[test]
    fn huge_filters_are_refused() {
        let wide = Filter::And(
            (0..MAX_FILTER_CONDITIONS)
                .map(|i| Filter::eq("k", i))
                .collect(),
        );
        assert!(matches!(
            compile(&wide, 1),
            Err(StoreError::InvalidFilter(_))
        ));
        let big_in = Filter::is_in("k", 0..100_000);
        let c = compile(&big_in, 1).unwrap();
        assert_eq!(c.params.len(), 3, "an IN list is one jsonb parameter");
    }

    /// Hostile keys and values must only ever appear as parameters: the
    /// SQL text for any key or value is the same as for a harmless one.
    #[test]
    fn injection_attempts_stay_in_parameters() {
        let shape = |key: &str, value: &str| {
            Filter::eq(key, value)
                .and(Filter::exists(key))
                .and(!Filter::between(key, value, "z"))
                .and(Filter::is_in(key, [json!(value), json!({ key: value })]))
        };
        let reference = compile(&shape("k", "v"), 3).unwrap().sql;
        for evil in [
            "'; DROP TABLE docs; --",
            "\") OR 1=1 --",
            "$1",
            "' || pg_sleep(10) || '",
            "metadata",
            "}'::jsonb OR TRUE --",
            "\\",
            "\u{202e}",
        ] {
            for (key, value) in [(evil, "v"), ("k", evil), (evil, evil)] {
                let c = compile(&shape(key, value), 3).unwrap();
                assert_eq!(c.sql, reference, "{key:?} / {value:?}");
                assert!(c.params.iter().any(|p| match p {
                    Param::Text(s) => s == evil,
                    Param::Json(v) =>
                        v.to_string().contains(&evil.replace('\\', "\\\\")) || v == evil,
                }));
            }
        }
    }
}
