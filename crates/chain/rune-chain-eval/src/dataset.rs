//! Evaluation datasets: examples with inputs, an optional reference output
//! and metadata, loaded from JSON Lines or CSV under size caps.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use rune_chain_core::PromptArgs;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::EvalError;
use crate::stats::SeededRng;

/// Input keys tried, in order, by [`Example::question`].
const QUESTION_KEYS: [&str; 4] = ["question", "query", "input", "prompt"];

/// One evaluation case.
///
/// `inputs` are what the target receives (as [`PromptArgs`] for a
/// [`Chain`](rune_chain_core::Chain)); `reference` is the expected answer,
/// when there is one; `metadata` holds anything else evaluators may use,
/// such as `contexts`, `expected_tools` or a `baseline` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Example {
    /// Unique id within the dataset.
    pub id: String,
    /// Named inputs.
    pub inputs: BTreeMap<String, Value>,
    /// The expected output, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Free-form extra data.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub metadata: Map<String, Value>,
}

impl Example {
    /// An example with the given id and inputs.
    pub fn new(
        id: impl Into<String>,
        inputs: impl IntoIterator<Item = (impl Into<String>, Value)>,
    ) -> Self {
        Self {
            id: id.into(),
            inputs: inputs.into_iter().map(|(k, v)| (k.into(), v)).collect(),
            reference: None,
            metadata: Map::new(),
        }
    }

    /// An example whose single input is `"question"`.
    ///
    /// ```rust
    /// use rune_chain_eval::Example;
    ///
    /// let ex = Example::from_question("q1", "Capital of France?").with_reference("Paris");
    /// assert_eq!(ex.question(), Some("Capital of France?"));
    /// assert_eq!(ex.reference.as_deref(), Some("Paris"));
    /// ```
    pub fn from_question(id: impl Into<String>, question: impl Into<String>) -> Self {
        Self::new(id, [("question", Value::String(question.into()))])
    }

    /// Set the reference output (builder style).
    #[must_use]
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }

    /// Add a metadata entry (builder style).
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// The inputs as [`PromptArgs`], ready for [`Chain::call`](rune_chain_core::Chain::call).
    #[must_use]
    pub fn prompt_args(&self) -> PromptArgs {
        self.inputs
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// The string input under `key`.
    #[must_use]
    pub fn input_str(&self, key: &str) -> Option<&str> {
        self.inputs.get(key).and_then(Value::as_str)
    }

    /// The user question: the first string input named `question`, `query`,
    /// `input` or `prompt`, or the only input when there is exactly one
    /// string input.
    #[must_use]
    pub fn question(&self) -> Option<&str> {
        QUESTION_KEYS
            .iter()
            .find_map(|k| self.input_str(k))
            .or_else(|| {
                let mut strings = self.inputs.values().filter_map(Value::as_str);
                match (strings.next(), strings.next()) {
                    (Some(s), None) => Some(s),
                    _ => None,
                }
            })
    }

    /// String items of the metadata array (or the single string) under `key`.
    #[must_use]
    pub fn metadata_strings(&self, key: &str) -> Vec<&str> {
        match self.metadata.get(key) {
            Some(Value::String(s)) => vec![s.as_str()],
            Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        }
    }
}

/// Size caps applied while loading a dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatasetLimits {
    /// Most examples (default 100 000).
    pub max_examples: usize,
    /// Most bytes read in total (default 64 MiB).
    pub max_bytes: usize,
    /// Most bytes in one JSONL line or CSV record (default 1 MiB).
    pub max_record_bytes: usize,
    /// Most CSV columns (default 1024).
    pub max_columns: usize,
}

impl Default for DatasetLimits {
    fn default() -> Self {
        Self {
            max_examples: 100_000,
            max_bytes: 64 << 20,
            max_record_bytes: 1 << 20,
            max_columns: 1024,
        }
    }
}

/// Which CSV columns hold what.
///
/// By default a column named `id` is the id, a column named `reference` is
/// the reference output, and every other column is an input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvOptions {
    /// The id column (default `"id"`; examples are numbered when absent).
    pub id_column: Option<String>,
    /// The reference column (default `"reference"`).
    pub reference_column: Option<String>,
    /// Columns copied into metadata instead of inputs.
    pub metadata_columns: Vec<String>,
    /// Field delimiter (default `,`).
    pub delimiter: u8,
    /// Size caps.
    pub limits: DatasetLimits,
}

impl Default for CsvOptions {
    fn default() -> Self {
        Self {
            id_column: Some("id".into()),
            reference_column: Some("reference".into()),
            metadata_columns: Vec::new(),
            delimiter: b',',
            limits: DatasetLimits::default(),
        }
    }
}

/// An ordered set of [`Example`]s with unique ids.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dataset {
    examples: Vec<Example>,
}

impl Dataset {
    /// A dataset from examples.
    ///
    /// # Errors
    ///
    /// [`EvalError::Dataset`] on an empty or duplicate id.
    pub fn new(examples: Vec<Example>) -> Result<Self, EvalError> {
        let mut seen = HashSet::with_capacity(examples.len());
        for (i, ex) in examples.iter().enumerate() {
            if ex.id.is_empty() {
                return Err(EvalError::Dataset(format!("example {i} has an empty id")));
            }
            if !seen.insert(ex.id.as_str()) {
                return Err(EvalError::Dataset(format!(
                    "duplicate example id at position {i}"
                )));
            }
        }
        Ok(Self { examples })
    }

    /// The examples, in order.
    #[must_use]
    pub fn examples(&self) -> &[Example] {
        &self.examples
    }

    /// Iterate over the examples.
    pub fn iter(&self) -> std::slice::Iter<'_, Example> {
        self.examples.iter()
    }

    /// Number of examples.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.examples.len()
    }

    /// Whether there are no examples.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.examples.is_empty()
    }

    /// The example with `id`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Example> {
        self.examples.iter().find(|e| e.id == id)
    }

    /// Load JSON Lines from a string. See [`from_jsonl_reader`](Self::from_jsonl_reader).
    pub fn from_jsonl_str(text: &str, limits: &DatasetLimits) -> Result<Self, EvalError> {
        Self::from_jsonl_reader(text.as_bytes(), limits)
    }

    /// Load JSON Lines from a file. See [`from_jsonl_reader`](Self::from_jsonl_reader).
    pub fn from_jsonl_path(
        path: impl AsRef<Path>,
        limits: &DatasetLimits,
    ) -> Result<Self, EvalError> {
        Self::from_jsonl_reader(BufReader::new(File::open(path)?), limits)
    }

    /// Load JSON Lines: one JSON object per line, blank lines skipped.
    ///
    /// Each object may have `id` (string or number; the line's position
    /// otherwise), `inputs` (an object, or a string stored as `input`),
    /// `reference` (alias `expected`; non-string values are stored as
    /// compact JSON) and `metadata`. Without `inputs`, every other top-level
    /// key is an input.
    ///
    /// ```rust
    /// use rune_chain_eval::{Dataset, DatasetLimits};
    ///
    /// let ds = Dataset::from_jsonl_str(
    ///     r#"{"id": "a", "inputs": {"question": "2+2?"}, "reference": "4"}
    /// {"question": "Capital of France?", "expected": "Paris", "metadata": {"topic": "geo"}}"#,
    ///     &DatasetLimits::default(),
    /// ).unwrap();
    /// assert_eq!(ds.len(), 2);
    /// assert_eq!(ds.examples()[1].id, "2");
    /// assert_eq!(ds.examples()[1].reference.as_deref(), Some("Paris"));
    /// ```
    ///
    /// # Errors
    ///
    /// [`EvalError::Dataset`] on invalid JSON, a cap being exceeded or a
    /// duplicate id (messages give the line number, never the content);
    /// [`EvalError::Io`] on a read error.
    pub fn from_jsonl_reader<R: BufRead>(
        mut reader: R,
        limits: &DatasetLimits,
    ) -> Result<Self, EvalError> {
        let mut examples = Vec::new();
        let mut total = 0usize;
        let mut line_no = 0usize;
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let n =
                read_bounded_line(&mut reader, &mut buf, limits.max_record_bytes).map_err(|e| {
                    match e {
                        LineError::Io(e) => EvalError::Io(e),
                        LineError::TooLong => EvalError::Dataset(format!(
                            "line {} is longer than {} bytes",
                            line_no + 1,
                            limits.max_record_bytes
                        )),
                    }
                })?;
            if n == 0 {
                break;
            }
            line_no += 1;
            total += n;
            if total > limits.max_bytes {
                return Err(EvalError::Dataset(format!(
                    "input is larger than {} bytes",
                    limits.max_bytes
                )));
            }
            let line = std::str::from_utf8(&buf)
                .map_err(|_| EvalError::Dataset(format!("line {line_no} is not UTF-8")))?
                .trim();
            if line.is_empty() {
                continue;
            }
            if examples.len() >= limits.max_examples {
                return Err(EvalError::Dataset(format!(
                    "more than {} examples",
                    limits.max_examples
                )));
            }
            let value: Value = serde_json::from_str(line).map_err(|e| {
                EvalError::Dataset(format!(
                    "line {line_no}: invalid JSON at column {}",
                    e.column()
                ))
            })?;
            let pos = examples.len() + 1;
            examples.push(
                example_from_json(value, pos)
                    .map_err(|m| EvalError::Dataset(format!("line {line_no}: {m}")))?,
            );
        }
        Self::new(examples)
    }

    /// Load CSV from a string. See [`from_csv_reader`](Self::from_csv_reader).
    pub fn from_csv_str(text: &str, options: &CsvOptions) -> Result<Self, EvalError> {
        Self::from_csv_reader(text.as_bytes(), options)
    }

    /// Load CSV from a file. See [`from_csv_reader`](Self::from_csv_reader).
    pub fn from_csv_path(path: impl AsRef<Path>, options: &CsvOptions) -> Result<Self, EvalError> {
        Self::from_csv_reader(BufReader::new(File::open(path)?), options)
    }

    /// Load RFC 4180 CSV with a header row: quoted fields may contain the
    /// delimiter, `""` and line breaks. Cells are stored as strings.
    ///
    /// ```rust
    /// use rune_chain_eval::{CsvOptions, Dataset};
    ///
    /// let csv = "id,question,reference\nq1,\"Hello, world?\",hi\n";
    /// let ds = Dataset::from_csv_str(csv, &CsvOptions::default()).unwrap();
    /// assert_eq!(ds.examples()[0].question(), Some("Hello, world?"));
    /// assert_eq!(ds.examples()[0].reference.as_deref(), Some("hi"));
    /// ```
    ///
    /// # Errors
    ///
    /// [`EvalError::Dataset`] on a malformed record, a row with the wrong
    /// number of fields, a cap being exceeded or a duplicate id.
    pub fn from_csv_reader<R: Read>(reader: R, options: &CsvOptions) -> Result<Self, EvalError> {
        let limits = &options.limits;
        let mut bytes = Vec::new();
        reader
            .take(limits.max_bytes as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limits.max_bytes {
            return Err(EvalError::Dataset(format!(
                "input is larger than {} bytes",
                limits.max_bytes
            )));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| EvalError::Dataset("CSV is not UTF-8".into()))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut parser = CsvParser {
            rest: text,
            delimiter: char::from(options.delimiter),
            limits,
            record: 0,
        };
        let Some(header) = parser.next_record()? else {
            return Self::new(Vec::new());
        };
        let col = |name: &Option<String>| {
            name.as_ref()
                .and_then(|n| header.iter().position(|h| h == n))
        };
        let id_col = col(&options.id_column);
        let ref_col = col(&options.reference_column);
        let mut examples = Vec::new();
        while let Some(row) = parser.next_record()? {
            if row.len() == 1 && row[0].is_empty() {
                continue;
            }
            if row.len() != header.len() {
                return Err(EvalError::Dataset(format!(
                    "record {} has {} fields, the header has {}",
                    parser.record,
                    row.len(),
                    header.len()
                )));
            }
            if examples.len() >= limits.max_examples {
                return Err(EvalError::Dataset(format!(
                    "more than {} examples",
                    limits.max_examples
                )));
            }
            let mut ex = Example::new(
                id_col.map_or_else(|| (examples.len() + 1).to_string(), |i| row[i].clone()),
                std::iter::empty::<(String, Value)>(),
            );
            for (i, (name, cell)) in header.iter().zip(row).enumerate() {
                if Some(i) == id_col {
                } else if Some(i) == ref_col {
                    ex.reference = Some(cell);
                } else if options.metadata_columns.iter().any(|m| m == name) {
                    ex.metadata.insert(name.clone(), Value::String(cell));
                } else {
                    ex.inputs.insert(name.clone(), Value::String(cell));
                }
            }
            examples.push(ex);
        }
        Self::new(examples)
    }

    /// Write the dataset as JSON Lines (the format
    /// [`from_jsonl_str`](Self::from_jsonl_str) reads).
    pub fn to_jsonl(&self) -> Result<String, EvalError> {
        let mut out = String::new();
        for ex in &self.examples {
            out.push_str(&serde_json::to_string(ex)?);
            out.push('\n');
        }
        Ok(out)
    }

    /// The examples in a seeded random order.
    #[must_use]
    pub fn shuffled(&self, seed: u64) -> Self {
        let mut examples = self.examples.clone();
        SeededRng::new(seed).shuffle(&mut examples);
        Self { examples }
    }

    /// A seeded random sample of `n` examples (all of them when `n >= len`),
    /// kept in dataset order. The same seed gives the same sample.
    ///
    /// ```rust
    /// use rune_chain_eval::{Dataset, Example};
    ///
    /// let ds = Dataset::new((0..10).map(|i| Example::from_question(i.to_string(), "q")).collect()).unwrap();
    /// let a = ds.sample(3, 42);
    /// assert_eq!(a.len(), 3);
    /// assert_eq!(a, ds.sample(3, 42));
    /// ```
    #[must_use]
    pub fn sample(&self, n: usize, seed: u64) -> Self {
        let mut idx: Vec<usize> = (0..self.examples.len()).collect();
        let mut rng = SeededRng::new(seed);
        let n = n.min(idx.len());
        // Partial Fisher-Yates: the first `n` slots end up a uniform sample.
        for i in 0..n {
            let j = i + rng.below(idx.len() - i);
            idx.swap(i, j);
        }
        idx.truncate(n);
        idx.sort_unstable();
        Self {
            examples: idx.into_iter().map(|i| self.examples[i].clone()).collect(),
        }
    }

    /// Split into `(rest, holdout)` with `holdout` holding
    /// `round(fraction * len)` seeded-random examples. Both halves keep
    /// dataset order.
    ///
    /// ```rust
    /// use rune_chain_eval::{Dataset, Example};
    ///
    /// let ds = Dataset::new((0..10).map(|i| Example::from_question(i.to_string(), "q")).collect()).unwrap();
    /// let (train, test) = ds.split(0.3, 1).unwrap();
    /// assert_eq!((train.len(), test.len()), (7, 3));
    /// ```
    ///
    /// # Errors
    ///
    /// [`EvalError::Config`] when `fraction` is not in `0.0..=1.0`.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn split(&self, fraction: f64, seed: u64) -> Result<(Self, Self), EvalError> {
        if !(0.0..=1.0).contains(&fraction) {
            return Err(EvalError::Config(
                "split fraction must be between 0 and 1".into(),
            ));
        }
        let k = (fraction * self.examples.len() as f64).round() as usize;
        let mut idx: Vec<usize> = (0..self.examples.len()).collect();
        SeededRng::new(seed).shuffle(&mut idx);
        let mut holdout = vec![false; idx.len()];
        for &i in &idx[..k] {
            holdout[i] = true;
        }
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for (ex, h) in self.examples.iter().zip(holdout) {
            if h { &mut b } else { &mut a }.push(ex.clone());
        }
        Ok((Self { examples: a }, Self { examples: b }))
    }

    /// The examples for which `keep` returns `true`.
    #[must_use]
    pub fn filter(&self, keep: impl Fn(&Example) -> bool) -> Self {
        Self {
            examples: self.examples.iter().filter(|e| keep(e)).cloned().collect(),
        }
    }
}

impl<'a> IntoIterator for &'a Dataset {
    type Item = &'a Example;
    type IntoIter = std::slice::Iter<'a, Example>;
    fn into_iter(self) -> Self::IntoIter {
        self.examples.iter()
    }
}

fn example_from_json(value: Value, position: usize) -> Result<Example, String> {
    let Value::Object(mut obj) = value else {
        return Err("expected a JSON object".into());
    };
    let id = match obj.remove("id") {
        None | Some(Value::Null) => position.to_string(),
        Some(Value::String(s)) => s,
        Some(Value::Number(n)) => n.to_string(),
        Some(_) => return Err("`id` must be a string or a number".into()),
    };
    let reference = match obj.remove("reference").or_else(|| obj.remove("expected")) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s),
        Some(other) => Some(other.to_string()),
    };
    let metadata = match obj.remove("metadata") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m,
        Some(_) => return Err("`metadata` must be an object".into()),
    };
    let inputs = match obj.remove("inputs") {
        Some(Value::Object(m)) => m.into_iter().collect(),
        Some(Value::String(s)) => BTreeMap::from([("input".to_owned(), Value::String(s))]),
        Some(_) => return Err("`inputs` must be an object or a string".into()),
        None => obj.into_iter().collect(),
    };
    Ok(Example {
        id,
        inputs,
        reference,
        metadata,
    })
}

enum LineError {
    Io(std::io::Error),
    TooLong,
}

/// Read one `\n`-terminated line into `buf`, failing once it passes `max`
/// bytes instead of buffering an unbounded line. Returns bytes consumed.
fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> Result<usize, LineError> {
    let mut consumed = 0;
    loop {
        let chunk = match reader.fill_buf() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(LineError::Io(e)),
        };
        if chunk.is_empty() {
            return Ok(consumed);
        }
        let (take, done) = chunk
            .iter()
            .position(|&b| b == b'\n')
            .map_or((chunk.len(), false), |i| (i + 1, true));
        if buf.len() + take > max.saturating_add(1) {
            return Err(LineError::TooLong);
        }
        buf.extend_from_slice(&chunk[..take]);
        reader.consume(take);
        consumed += take;
        if done {
            return Ok(consumed);
        }
    }
}

struct CsvParser<'a> {
    rest: &'a str,
    delimiter: char,
    limits: &'a DatasetLimits,
    record: usize,
}

impl CsvParser<'_> {
    fn next_record(&mut self) -> Result<Option<Vec<String>>, EvalError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        self.record += 1;
        let start_len = self.rest.len();
        let mut fields = Vec::new();
        let mut field = String::new();
        let mut chars = self.rest.char_indices().peekable();
        let mut in_quotes = false;
        let mut quoted = false;
        let mut end = self.rest.len();
        while let Some((i, c)) = chars.next() {
            if i > self.limits.max_record_bytes {
                return Err(EvalError::Dataset(format!(
                    "record {} is longer than {} bytes",
                    self.record, self.limits.max_record_bytes
                )));
            }
            if in_quotes {
                if c == '"' {
                    if chars.next_if(|&(_, c)| c == '"').is_some() {
                        field.push('"');
                    } else {
                        in_quotes = false;
                    }
                } else {
                    field.push(c);
                }
            } else if c == '"' && field.is_empty() && !quoted {
                in_quotes = true;
                quoted = true;
            } else if c == self.delimiter {
                self.push_field(&mut fields, &mut field)?;
                quoted = false;
            } else if c == '\n' || c == '\r' {
                if c == '\r' {
                    chars.next_if(|&(_, c)| c == '\n');
                }
                end = chars.peek().map_or(self.rest.len(), |&(j, _)| j);
                break;
            } else if quoted {
                return Err(EvalError::Dataset(format!(
                    "record {}: text after a closing quote",
                    self.record
                )));
            } else {
                field.push(c);
            }
        }
        if in_quotes {
            return Err(EvalError::Dataset(format!(
                "record {}: unterminated quoted field",
                self.record
            )));
        }
        self.push_field(&mut fields, &mut field)?;
        self.rest = &self.rest[end.min(start_len)..];
        Ok(Some(fields))
    }

    fn push_field(&self, fields: &mut Vec<String>, field: &mut String) -> Result<(), EvalError> {
        if fields.len() >= self.limits.max_columns {
            return Err(EvalError::Dataset(format!(
                "record {} has more than {} fields",
                self.record, self.limits.max_columns
            )));
        }
        fields.push(std::mem::take(field));
        Ok(())
    }
}
