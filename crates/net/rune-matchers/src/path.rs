//! JSON paths (RFC 6901 pointers and a jq-lite subset) and a minimal `XPath`
//! subset evaluated over `quick_xml` events.

use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};

use crate::{MAX_EXTRACTED_VALUES, MatchError, clip};

fn path_error(path: &str, message: impl Into<String>) -> MatchError {
    MatchError::InvalidPath {
        path: clip(path),
        message: message.into(),
    }
}

/// One jq-lite step.
#[derive(Debug, Clone)]
pub enum Step {
    Key(String),
    Index(usize),
}

/// A compiled JSON path.
#[derive(Debug, Clone)]
pub enum JsonPath {
    /// An RFC 6901 pointer, used verbatim.
    Pointer(String),
    /// jq-lite steps (`.a.b[0]`).
    Steps(Vec<Step>),
}

impl JsonPath {
    /// Parses a pointer (empty or starting with `/`) or a jq-lite path
    /// (`.`, `.a.b[0]`, `a.b`, `[1].x`).
    pub fn parse(path: &str) -> Result<Self, MatchError> {
        if path.is_empty() || path.starts_with('/') {
            return Ok(Self::Pointer(path.to_owned()));
        }
        let mut steps = Vec::new();
        for segment in path.split('.') {
            let (key, mut rest) = segment.find('[').map_or((segment, ""), |index| {
                (&segment[..index], &segment[index..])
            });
            if !key.is_empty() {
                steps.push(Step::Key(key.to_owned()));
            }
            while !rest.is_empty() {
                let close = rest
                    .find(']')
                    .filter(|_| rest.starts_with('['))
                    .ok_or_else(|| path_error(path, "expected `[index]`"))?;
                let index = rest[1..close].trim().parse::<usize>().map_err(|_| {
                    path_error(path, "only non-negative integer indexes are supported")
                })?;
                steps.push(Step::Index(index));
                rest = &rest[close + 1..];
            }
        }
        Ok(Self::Steps(steps))
    }

    /// Resolves the path inside `value`.
    pub fn resolve<'v>(&self, value: &'v serde_json::Value) -> Option<&'v serde_json::Value> {
        match self {
            Self::Pointer(pointer) => value.pointer(pointer),
            Self::Steps(steps) => steps.iter().try_fold(value, |current, step| match step {
                Step::Key(key) => current.get(key.as_str()),
                Step::Index(index) => current.get(*index),
            }),
        }
    }
}

/// Renders a JSON value: strings unquoted, everything else compact JSON.
pub fn json_scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// What a matched `XPath` element yields.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Text,
    Attribute(String),
}

/// A compiled minimal `XPath` expression.
#[derive(Debug, Clone)]
pub struct XPath {
    descendant: bool,
    steps: Vec<String>,
    target: Target,
}

impl XPath {
    /// Parses `/a/b`, `//b`, `//a/*/c`, with an optional final `text()` or
    /// `@attr` step. `attribute` overrides the target with an attribute.
    pub fn parse(path: &str, attribute: Option<&str>) -> Result<Self, MatchError> {
        let (descendant, rest) = if let Some(rest) = path.strip_prefix("//") {
            (true, rest)
        } else if let Some(rest) = path.strip_prefix('/') {
            (false, rest)
        } else {
            return Err(path_error(path, "path must start with `/` or `//`"));
        };
        let mut segments: Vec<&str> = rest.split('/').collect();
        let mut target = Target::Text;
        match segments.last().copied() {
            Some("text()") => {
                segments.pop();
            }
            Some(last) if last.starts_with('@') => {
                target = Target::Attribute(last[1..].to_owned());
                segments.pop();
            }
            _ => {}
        }
        let mut steps = Vec::with_capacity(segments.len());
        for segment in segments {
            if segment.is_empty() {
                return Err(path_error(path, "`//` is only supported as the first step"));
            }
            if segment.contains(['[', ']', '(', ')', '@', '|', '=']) || segment.contains("::") {
                return Err(path_error(
                    path,
                    "predicates, axes, functions and unions are unsupported",
                ));
            }
            let local = segment.rsplit(':').next().unwrap_or(segment);
            steps.push(local.to_owned());
        }
        if steps.is_empty() {
            return Err(path_error(path, "path selects no element"));
        }
        if let Some(name) = attribute {
            target = Target::Attribute(name.to_owned());
        }
        Ok(Self {
            descendant,
            steps,
            target,
        })
    }

    fn selects(&self, stack: &[String]) -> bool {
        let fits = if self.descendant {
            stack.len() >= self.steps.len()
        } else {
            stack.len() == self.steps.len()
        };
        fits && stack[stack.len() - self.steps.len()..]
            .iter()
            .zip(&self.steps)
            .all(|(name, step)| step == "*" || name == step)
    }

    /// Evaluates the expression over `text`, appending values to `out`.
    /// Malformed input stops evaluation and keeps what was found so far.
    pub fn evaluate(&self, text: &str, out: &mut Vec<String>) {
        let mut walker = Walker {
            path: self,
            stack: Vec::new(),
            open: Vec::new(),
            out,
        };
        let mut reader = Reader::from_str(text);
        reader.config_mut().check_end_names = false;
        loop {
            if walker.out.len() >= MAX_EXTRACTED_VALUES {
                return;
            }
            match reader.read_event() {
                Ok(Event::Start(element)) => walker.open_element(&element, false),
                Ok(Event::Empty(element)) => walker.open_element(&element, true),
                Ok(Event::End(_)) => walker.close_element(),
                Ok(Event::Text(text)) => walker.text(&text.xml10_content()),
                Ok(Event::CData(data)) => walker.text(&data.xml10_content()),
                Ok(Event::GeneralRef(reference)) => {
                    let resolved = if let Ok(Some(ch)) = reference.resolve_char_ref() {
                        ch.to_string()
                    } else {
                        let name: &str = &reference;
                        resolve_predefined_entity(name)
                            .map_or_else(|| format!("&{name};"), str::to_owned)
                    };
                    walker.text(&resolved);
                }
                Ok(Event::Eof) | Err(_) => break,
                Ok(_) => {}
            }
        }
        // Unclosed elements still yield their text.
        while walker.open.pop().is_some_and(|(_, value)| {
            walker.out.push(value.trim().to_owned());
            true
        }) {}
        walker.out.truncate(MAX_EXTRACTED_VALUES);
    }
}

/// Event-walking state for one `XPath` evaluation.
struct Walker<'p, 'o> {
    path: &'p XPath,
    stack: Vec<String>,
    open: Vec<(usize, String)>,
    out: &'o mut Vec<String>,
}

impl Walker<'_, '_> {
    fn open_element(&mut self, element: &quick_xml::events::BytesStart<'_>, empty: bool) {
        self.stack.push(element.local_name().as_ref().to_owned());
        if self.path.selects(&self.stack) {
            match &self.path.target {
                Target::Attribute(name) => {
                    let value = element.html_attributes().flatten().find_map(|attribute| {
                        (attribute.key.local_name().as_ref() == name.as_str()).then(|| {
                            attribute
                                .normalized_value(XmlVersion::Implicit1_0)
                                .map_or_else(
                                    |_| attribute.value.clone().into_owned(),
                                    std::borrow::Cow::into_owned,
                                )
                        })
                    });
                    if let Some(value) = value {
                        self.out.push(value);
                    }
                }
                Target::Text if empty => self.out.push(String::new()),
                Target::Text => self.open.push((self.stack.len(), String::new())),
            }
        }
        if empty {
            self.stack.pop();
        }
    }

    fn close_element(&mut self) {
        // `>=` also closes captures orphaned by unbalanced (HTML-ish) markup.
        while self
            .open
            .last()
            .is_some_and(|(depth, _)| *depth >= self.stack.len())
            && let Some((_, value)) = self.open.pop()
        {
            self.out.push(value.trim().to_owned());
        }
        self.stack.pop();
    }

    fn text(&mut self, text: &str) {
        for (_, value) in &mut self.open {
            value.push_str(text);
        }
    }
}
