//! JSON documents: an array (or single object) of records, each becoming a
//! [`Document`]. See [`jsonl`](crate::jsonl) for JSON Lines.
//!
//! Parsing uses `serde_json`, whose nesting limit (128 levels) bounds
//! recursion on hostile input.

use std::path::Path;

use serde_json::{Map, Value};

use crate::Document;
use crate::error::LoadError;
use crate::io::read_file;
use crate::jail::Jail;
use crate::limits::Limits;
use crate::meta;

/// A field selector: a bare top-level key (`"text"`) or an RFC 6901 JSON
/// Pointer (`"/body/text"`, `"/items/0"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    given: String,
    pointer: String,
}

impl Selector {
    /// Parse a selector. Bare keys are taken literally (no escaping needed).
    pub fn new(selector: &str) -> Result<Self, LoadError> {
        if selector.is_empty() {
            return Err(LoadError::InvalidPattern {
                pattern: String::new(),
                reason: "empty field selector",
            });
        }
        let pointer = if selector.starts_with('/') {
            selector.to_string()
        } else {
            format!("/{}", selector.replace('~', "~0").replace('/', "~1"))
        };
        Ok(Self {
            given: selector.to_string(),
            pointer,
        })
    }

    /// The selector as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.given
    }

    /// Look the selector up in `value`.
    #[must_use]
    pub fn get<'a>(&self, value: &'a Value) -> Option<&'a Value> {
        value.pointer(&self.pointer)
    }

    /// The top-level key this selector names, if it names exactly one.
    fn top_level_key(&self) -> Option<String> {
        let rest = self.pointer.strip_prefix('/')?;
        (!rest.contains('/')).then(|| rest.replace("~1", "/").replace("~0", "~"))
    }
}

/// Which fields of a record become metadata.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MetadataFields {
    /// Every top-level field except the content field (the default).
    #[default]
    All,
    /// Only these selectors; the metadata key is the selector as given.
    Only(Vec<Selector>),
    /// No record fields (loader metadata such as `line` is still added).
    None,
}

/// How records map to documents: the content field and the metadata fields.
///
/// The content field must hold a string; records without one are
/// [`LoadError::MissingField`]. Non-string metadata values are stored as
/// their JSON text (`42`, `true`, `null`, `{"a":1}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fields {
    content: Selector,
    metadata: MetadataFields,
}

impl Default for Fields {
    fn default() -> Self {
        Self {
            content: Selector {
                given: "content".to_string(),
                pointer: "/content".to_string(),
            },
            metadata: MetadataFields::All,
        }
    }
}

impl Fields {
    /// `content` as the content field, every other field as metadata.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Select the content field.
    pub fn content(mut self, selector: &str) -> Result<Self, LoadError> {
        self.content = Selector::new(selector)?;
        Ok(self)
    }

    /// Choose the metadata fields.
    #[must_use]
    pub fn metadata(mut self, fields: MetadataFields) -> Self {
        self.metadata = fields;
        self
    }

    /// Keep only these metadata selectors.
    pub fn metadata_only(self, selectors: &[&str]) -> Result<Self, LoadError> {
        let selectors = selectors
            .iter()
            .map(|s| Selector::new(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self.metadata(MetadataFields::Only(selectors)))
    }

    /// Turn one record into a document; `line` is used in errors.
    pub(crate) fn to_document(&self, record: &Value, line: u64) -> Result<Document, LoadError> {
        let content = self
            .content
            .get(record)
            .and_then(Value::as_str)
            .ok_or_else(|| LoadError::MissingField {
                line,
                field: self.content.given.clone(),
            })?;
        let mut doc = Document::new(content);
        match &self.metadata {
            MetadataFields::All => {
                if let Some(obj) = record.as_object() {
                    let skip = self.content.top_level_key();
                    add_all(&mut doc, obj, skip.as_deref());
                }
            }
            MetadataFields::Only(selectors) => {
                for selector in selectors {
                    if let Some(value) = selector.get(record) {
                        doc.metadata
                            .insert(selector.given.clone(), stringify(value));
                    }
                }
            }
            MetadataFields::None => {}
        }
        Ok(doc)
    }
}

fn add_all(doc: &mut Document, obj: &Map<String, Value>, skip: Option<&str>) {
    for (key, value) in obj {
        if Some(key.as_str()) != skip {
            doc.metadata.insert(key.clone(), stringify(value));
        }
    }
}

fn stringify(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Loads a JSON document whose records are an array (or a single object),
/// optionally found at a [`Selector`] inside the document.
///
/// Each document gets [`meta::RECORD`] (1-based), [`meta::CONTENT_SHA256`]
/// and, for files, [`meta::SOURCE`] unless the record has its own `source`.
///
/// # Example
///
/// ```rust
/// use rune_chain_loader::json::{Fields, JsonLoader};
///
/// let input = r#"{"data": {"items": [
///     {"body": "first", "id": 1},
///     {"body": "second", "id": 2}
/// ]}}"#;
/// let docs = JsonLoader::new()
///     .records("/data/items").unwrap()
///     .fields(Fields::new().content("body").unwrap())
///     .load_str(input)
///     .unwrap();
/// assert_eq!(docs.len(), 2);
/// assert_eq!(docs[1].content, "second");
/// assert_eq!(docs[1].metadata["id"], "2");
/// assert_eq!(docs[1].metadata["record"], "2");
/// ```
#[derive(Debug, Clone, Default)]
pub struct JsonLoader {
    records: Option<Selector>,
    fields: Fields,
    limits: Limits,
    jail: Option<Jail>,
    skip_invalid: bool,
}

impl JsonLoader {
    /// Records at the top level, `content` field, default [`Limits`], strict.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Where the records live inside the document.
    pub fn records(mut self, selector: &str) -> Result<Self, LoadError> {
        self.records = Some(Selector::new(selector)?);
        Ok(self)
    }

    /// Set the content / metadata field mapping.
    #[must_use]
    pub fn fields(mut self, fields: Fields) -> Self {
        self.fields = fields;
        self
    }

    /// Replace the limits (`max_file_bytes` and `max_records` apply).
    #[must_use]
    pub const fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Confine file paths to a [`Jail`].
    #[must_use]
    pub fn jail(mut self, jail: Jail) -> Self {
        self.jail = Some(jail);
        self
    }

    /// Skip records without a string content field instead of failing
    /// (default `false`).
    #[must_use]
    pub const fn skip_invalid(mut self, skip: bool) -> Self {
        self.skip_invalid = skip;
        self
    }

    /// Parse a JSON string.
    pub fn load_str(&self, input: &str) -> Result<Vec<Document>, LoadError> {
        if input.len() as u64 > self.limits.max_file_bytes {
            return Err(LoadError::TooLarge {
                path: None,
                limit: self.limits.max_file_bytes,
            });
        }
        self.load_bytes(input.as_bytes(), None)
    }

    /// Load a JSON file.
    pub fn load_file(&self, path: impl AsRef<Path>) -> Result<Vec<Document>, LoadError> {
        let path = path.as_ref();
        let bytes = read_file(path, self.jail.as_ref(), self.limits.max_file_bytes)?;
        self.load_bytes(&bytes, Some(&path.display().to_string()))
    }

    fn load_bytes(&self, bytes: &[u8], source: Option<&str>) -> Result<Vec<Document>, LoadError> {
        let value: Value = serde_json::from_slice(bytes).map_err(|e| LoadError::Parse {
            line: e.line() as u64,
            message: e.to_string(),
        })?;
        let root = match &self.records {
            Some(selector) => selector
                .get(&value)
                .ok_or_else(|| LoadError::MissingField {
                    line: 1,
                    field: selector.given.clone(),
                })?,
            None => &value,
        };
        let records: &[Value] = match root {
            Value::Array(items) => items,
            other => std::slice::from_ref(other),
        };
        let mut docs = Vec::new();
        for (index, record) in records.iter().enumerate() {
            let number = index as u64 + 1;
            let mut doc = match self.fields.to_document(record, number) {
                Ok(doc) => doc,
                Err(_) if self.skip_invalid => continue,
                Err(err) => return Err(err),
            };
            if docs.len() >= self.limits.max_records {
                return Err(LoadError::TooManyRecords {
                    limit: self.limits.max_records,
                });
            }
            meta::default_source(&mut doc, source);
            meta::stamp_position(&mut doc, &[(meta::RECORD, number)]);
            meta::stamp_hash(&mut doc);
            docs.push(doc);
        }
        Ok(docs)
    }
}
