use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use rune_chain_core::{ChainError, PromptArgs};
use serde_json::Value;

use crate::error::TemplateError;
use crate::guard::{ValueGuard, is_invisible};

/// A template that produces a formatted `String` from [`PromptArgs`].
///
/// Implementors must handle `{variable}` substitution for all variables
/// returned by [`input_variables`](PromptTemplate::input_variables).
pub trait PromptTemplate: Send + Sync {
    /// Substitute all `{variable}` placeholders and return the formatted string.
    ///
    /// Returns [`ChainError::MissingVariable`] if a required variable is absent.
    fn format(&self, args: &PromptArgs) -> Result<String, ChainError>;

    /// Names of all variables this template requires.
    fn input_variables(&self) -> Vec<String>;
}

/// One parsed piece of a template.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Var(String),
}

fn push_literal(segments: &mut Vec<Segment>, text: &str) {
    if let Some(Segment::Literal(last)) = segments.last_mut() {
        last.push_str(text);
    } else {
        segments.push(Segment::Literal(text.to_owned()));
    }
}

fn valid_name(name: &str) -> bool {
    name.chars()
        .all(|c| c != '{' && c != '}' && !c.is_whitespace() && !c.is_control() && !is_invisible(c))
}

/// Parse a template. In lenient mode malformed syntax is recovered from the
/// same way 0.1.0 did; in strict mode it is reported.
fn parse(template: &str, strict: bool) -> Result<Vec<Segment>, TemplateError> {
    let mut segments = Vec::new();
    let mut chars = template.char_indices().peekable();

    while let Some((pos, ch)) = chars.next() {
        match ch {
            '{' if chars.peek().map(|&(_, c)| c) == Some('{') => {
                chars.next();
                push_literal(&mut segments, "{");
            }
            '{' => {
                let mut var = String::new();
                let mut closed = false;
                for (_, c) in chars.by_ref() {
                    if c == '}' {
                        closed = true;
                        break;
                    }
                    var.push(c);
                }
                if strict && !closed {
                    return Err(TemplateError::Syntax {
                        position: pos,
                        message: "unclosed `{` (write `{{` for a literal brace)".into(),
                    });
                }
                // `{}` (or a lone trailing `{`) names no variable: keep it
                // literally, so JSON snippets such as `Reply with {}` work.
                if var.is_empty() {
                    push_literal(&mut segments, if closed { "{}" } else { "{" });
                    continue;
                }
                if strict && !valid_name(&var) {
                    return Err(TemplateError::Syntax {
                        position: pos,
                        message: format!(
                            "invalid variable name `{var}`: names cannot contain braces, \
                             whitespace, control or invisible formatting characters"
                        ),
                    });
                }
                segments.push(Segment::Var(var));
            }
            '}' if chars.peek().map(|&(_, c)| c) == Some('}') => {
                chars.next();
                push_literal(&mut segments, "}");
            }
            '}' if strict => {
                return Err(TemplateError::Syntax {
                    position: pos,
                    message: "unmatched `}` (write `}}` for a literal brace)".into(),
                });
            }
            c => {
                let mut buf = [0; 4];
                push_literal(&mut segments, c.encode_utf8(&mut buf));
            }
        }
    }
    Ok(segments)
}

/// Render a JSON value the way it is inserted into a prompt.
fn value_text(value: &Value) -> Cow<'_, str> {
    match value {
        Value::String(s) => Cow::Borrowed(s),
        other => Cow::Owned(other.to_string()),
    }
}

/// Names in order of first appearance, without duplicates. A set backs the
/// lookups so templates with many variables stay linear.
#[derive(Default)]
pub struct UniqueNames {
    names: Vec<String>,
    seen: HashSet<String>,
}

impl UniqueNames {
    /// Add `name` unless it is already there.
    pub fn push(&mut self, name: &str) {
        if !self.seen.contains(name) {
            self.seen.insert(name.to_owned());
            self.names.push(name.to_owned());
        }
    }

    /// The names in order of first appearance.
    pub fn into_vec(self) -> Vec<String> {
        self.names
    }
}

/// Compare the variables a template uses with the ones a caller declared.
pub fn check_declared<S: AsRef<str>>(used: &[String], declared: &[S]) -> Result<(), TemplateError> {
    let declared_set: HashSet<&str> = declared.iter().map(AsRef::as_ref).collect();
    let used_set: HashSet<&str> = used.iter().map(String::as_str).collect();
    let undeclared: Vec<String> = used
        .iter()
        .filter(|u| !declared_set.contains(u.as_str()))
        .cloned()
        .collect();
    let mut unused = UniqueNames::default();
    for d in declared {
        if !used_set.contains(d.as_ref()) {
            unused.push(d.as_ref());
        }
    }
    let unused = unused.into_vec();
    if undeclared.is_empty() && unused.is_empty() {
        Ok(())
    } else {
        Err(TemplateError::DeclarationMismatch { undeclared, unused })
    }
}

/// Map a [`TemplateError`] to the [`ChainError`] 0.1.0 returned: a missing
/// variable error names only the first missing variable.
pub fn legacy_error(err: TemplateError) -> ChainError {
    match err {
        TemplateError::MissingVariables(mut names) if !names.is_empty() => {
            ChainError::MissingVariable(names.swap_remove(0))
        }
        other => other.into(),
    }
}

/// A string template using `{variable}` placeholder substitution.
///
/// Syntax:
/// - `{name}` is replaced by the value of `"name"` in [`PromptArgs`].
/// - `{{` produces a literal `{`; `}}` produces a literal `}`.
/// - String values are inserted verbatim; non-string JSON values use their
///   compact JSON representation (`42`, `true`, `["a","b"]`, …).
/// - Inserted values are never re-parsed, so braces inside a value are safe.
///
/// The template is parsed once, at construction. [`new`](Self::new) is
/// lenient and never fails: an empty placeholder `{}` and a lone `{` or `}`
/// are kept as written, and an unclosed `{name` at the end still names
/// `name`. [`try_new`](Self::try_new) rejects those mistakes instead.
///
/// On top of plain substitution a template can carry
/// [partial variables](Self::with_partial) (defaults),
/// [guards](Self::guard) that sanitise untrusted values, and a
/// [maximum rendered length](Self::with_max_len).
///
/// # Example
///
/// ```rust
/// use rune_chain_prompt::{StringTemplate, PromptTemplate};
/// use rune_chain_core::prompt_args;
///
/// let tmpl = StringTemplate::new("Hello, {name}! Age: {age}.");
/// let result = tmpl.format(&prompt_args! { "name" => "Alice", "age" => 30 }).unwrap();
/// assert_eq!(result, "Hello, Alice! Age: 30.");
/// ```
///
/// Escaped braces:
///
/// ```rust
/// use rune_chain_prompt::{StringTemplate, PromptTemplate};
/// use rune_chain_core::PromptArgs;
///
/// let tmpl = StringTemplate::new("Use {{braces}} for literals.");
/// assert_eq!(
///     tmpl.format(&PromptArgs::new()).unwrap(),
///     "Use {braces} for literals.",
/// );
/// ```
///
/// An empty placeholder `{}` names no variable and is kept as written, so
/// JSON snippets such as `Reply with {}` need no escaping.
#[derive(Debug, Clone)]
pub struct StringTemplate {
    source: String,
    segments: Vec<Segment>,
    partials: PromptArgs,
    guards: HashMap<String, ValueGuard>,
    default_guard: Option<ValueGuard>,
    max_len: Option<usize>,
}

impl StringTemplate {
    fn from_parts(source: String, segments: Vec<Segment>) -> Self {
        Self {
            source,
            segments,
            partials: PromptArgs::new(),
            guards: HashMap::new(),
            default_guard: None,
            max_len: None,
        }
    }

    /// Create a new template from any string-like value.
    ///
    /// Never fails: malformed syntax is kept as literal text (see the type
    /// docs). Use [`try_new`](Self::try_new) to reject it.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::StringTemplate;
    ///
    /// let tmpl = StringTemplate::new("Translate '{text}' to {lang}.");
    /// ```
    pub fn new(template: impl Into<String>) -> Self {
        let source = template.into();
        // Lenient parsing cannot fail.
        let segments = parse(&source, false).unwrap_or_default();
        Self::from_parts(source, segments)
    }

    /// Create a template, rejecting malformed syntax.
    ///
    /// Errors with [`TemplateError::Syntax`] on an unclosed `{`, an
    /// unmatched `}`, or a variable name containing braces, whitespace,
    /// control characters or invisible formatting characters such as a
    /// zero-width space or byte-order mark (`{ name }`, `{\u{200B}name}`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::{StringTemplate, TemplateError};
    ///
    /// assert!(StringTemplate::try_new("Hello, {name}! {{ok}}").is_ok());
    /// let err = StringTemplate::try_new("Hello, {name").unwrap_err();
    /// assert!(matches!(err, TemplateError::Syntax { position: 7, .. }));
    /// assert!(StringTemplate::try_new("{ name }").is_err());
    /// assert!(StringTemplate::try_new("a } b").is_err());
    /// ```
    pub fn try_new(template: impl Into<String>) -> Result<Self, TemplateError> {
        let source = template.into();
        let segments = parse(&source, true)?;
        Ok(Self::from_parts(source, segments))
    }

    /// The template string as written.
    #[must_use]
    pub fn template(&self) -> &str {
        &self.source
    }

    /// Pre-fill a variable (a "partial variable" or default).
    ///
    /// A partial is used when the caller's arguments do not supply the
    /// variable, and it is no longer listed by
    /// [`input_variables`](PromptTemplate::input_variables). Arguments
    /// passed to `format` take precedence. Partial values are trusted:
    /// guards are not applied to them.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::{PromptTemplate, StringTemplate};
    /// use rune_chain_core::prompt_args;
    ///
    /// let tmpl = StringTemplate::new("Answer in {lang}: {q}").with_partial("lang", "English");
    /// assert_eq!(tmpl.input_variables(), ["q"]);
    /// assert_eq!(tmpl.format(&prompt_args! { "q" => "hi" }).unwrap(), "Answer in English: hi");
    /// let fr = tmpl.format(&prompt_args! { "q" => "hi", "lang" => "French" }).unwrap();
    /// assert_eq!(fr, "Answer in French: hi");
    /// ```
    #[must_use]
    pub fn with_partial(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.partials.insert(name.into(), value.into());
        self
    }

    /// Pre-fill several variables at once (see [`with_partial`](Self::with_partial)).
    #[must_use]
    pub fn with_partials(mut self, partials: PromptArgs) -> Self {
        self.partials.extend(partials);
        self
    }

    /// The partial variables set on this template.
    #[must_use]
    pub const fn partials(&self) -> &PromptArgs {
        &self.partials
    }

    /// Sanitise values of `name` with `guard` before inserting them.
    ///
    /// Overrides any [`guard_all`](Self::guard_all) default for that variable.
    #[must_use]
    pub fn guard(mut self, name: impl Into<String>, guard: ValueGuard) -> Self {
        self.guards.insert(name.into(), guard);
        self
    }

    /// Sanitise every caller-supplied value with `guard` (unless the
    /// variable has its own [`guard`](Self::guard)).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::{PromptTemplate, StringTemplate, ValueGuard};
    /// use rune_chain_core::prompt_args;
    ///
    /// let tmpl = StringTemplate::new("Q: {q}").guard_all(ValueGuard::StripInvisible);
    /// let out = tmpl.format(&prompt_args! { "q" => "hi\u{200B}\u{202E}!" }).unwrap();
    /// assert_eq!(out, "Q: hi!");
    /// ```
    #[must_use]
    pub fn guard_all(mut self, guard: ValueGuard) -> Self {
        self.default_guard = Some(guard);
        self
    }

    /// Reject renders longer than `max` bytes with [`TemplateError::TooLong`].
    ///
    /// Bounds prompt size (and so cost and context use) when values come
    /// from untrusted sources.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::{StringTemplate, TemplateError};
    /// use rune_chain_core::prompt_args;
    ///
    /// let tmpl = StringTemplate::new("Q: {q}").with_max_len(8);
    /// assert!(tmpl.try_format(&prompt_args! { "q" => "short" }).is_ok());
    /// let err = tmpl.try_format(&prompt_args! { "q" => "far too long" }).unwrap_err();
    /// assert_eq!(err, TemplateError::TooLong { len: 15, max: 8 });
    /// ```
    #[must_use]
    pub const fn with_max_len(mut self, max: usize) -> Self {
        self.max_len = Some(max);
        self
    }

    /// Every variable the template mentions, partials included, in order of
    /// first appearance.
    fn all_variables(&self) -> Vec<String> {
        let mut vars = UniqueNames::default();
        for seg in &self.segments {
            if let Segment::Var(v) = seg {
                vars.push(v);
            }
        }
        vars.into_vec()
    }

    /// The variables `args` (with partials) does not supply, in order of
    /// first appearance.
    #[must_use]
    pub fn missing_variables(&self, args: &PromptArgs) -> Vec<String> {
        self.all_variables()
            .into_iter()
            .filter(|v| !args.contains_key(v) && !self.partials.contains_key(v))
            .collect()
    }

    /// Check that the template uses exactly the `declared` input variables
    /// (partials excluded).
    ///
    /// Catches typos in templates at construction time instead of on the
    /// first request.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::{StringTemplate, TemplateError};
    ///
    /// let tmpl = StringTemplate::new("{question} in {langauge}");
    /// let err = tmpl.validate_input_variables(&["question", "language"]).unwrap_err();
    /// assert_eq!(err, TemplateError::DeclarationMismatch {
    ///     undeclared: vec!["langauge".into()],
    ///     unused: vec!["language".into()],
    /// });
    /// ```
    pub fn validate_input_variables<S: AsRef<str>>(
        &self,
        declared: &[S],
    ) -> Result<(), TemplateError> {
        check_declared(&PromptTemplate::input_variables(self), declared)
    }

    /// Format the template, reporting every missing variable at once.
    ///
    /// Unlike [`PromptTemplate::format`] (which keeps the 0.1.0 behaviour of
    /// naming only the first missing variable), the error lists all of them.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_prompt::{StringTemplate, TemplateError};
    /// use rune_chain_core::prompt_args;
    ///
    /// let tmpl = StringTemplate::new("{a} {b} {c}");
    /// let err = tmpl.try_format(&prompt_args! { "b" => 1 }).unwrap_err();
    /// assert_eq!(err, TemplateError::MissingVariables(vec!["a".into(), "c".into()]));
    /// assert_eq!(err.to_string(), "missing prompt variables: a, c");
    /// ```
    pub fn try_format(&self, args: &PromptArgs) -> Result<String, TemplateError> {
        let missing = self.missing_variables(args);
        if !missing.is_empty() {
            return Err(TemplateError::MissingVariables(missing));
        }
        let mut out = String::with_capacity(self.source.len());
        // Once past `max_len`, stop building the string and only measure the
        // rest, so the error can still report the full length.
        let mut len = 0usize;
        let mut too_long = false;
        for seg in &self.segments {
            let piece = match seg {
                Segment::Literal(text) => Cow::Borrowed(text.as_str()),
                Segment::Var(name) => {
                    if let Some(value) = args.get(name) {
                        let text = value_text(value);
                        match self.guards.get(name).or(self.default_guard.as_ref()) {
                            Some(guard) => Cow::Owned(guard.apply(&text)),
                            None => text,
                        }
                    } else if let Some(value) = self.partials.get(name) {
                        value_text(value)
                    } else {
                        continue;
                    }
                }
            };
            len = len.saturating_add(piece.len());
            if too_long {
                continue;
            }
            if self.max_len.is_some_and(|max| len > max) {
                too_long = true;
                out = String::new();
            } else {
                out.push_str(&piece);
            }
        }
        match self.max_len {
            Some(max) if too_long => Err(TemplateError::TooLong { len, max }),
            _ => Ok(out),
        }
    }
}

impl From<&str> for StringTemplate {
    fn from(template: &str) -> Self {
        Self::new(template)
    }
}

impl From<String> for StringTemplate {
    fn from(template: String) -> Self {
        Self::new(template)
    }
}

impl PromptTemplate for StringTemplate {
    fn format(&self, args: &PromptArgs) -> Result<String, ChainError> {
        self.try_format(args).map_err(legacy_error)
    }

    /// Variables the caller must supply: every variable in the template
    /// except those covered by partials, in order of first appearance.
    fn input_variables(&self) -> Vec<String> {
        self.all_variables()
            .into_iter()
            .filter(|v| !self.partials.contains_key(v))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_chain_core::prompt_args;

    #[test]
    fn substitutes_string_value() {
        let tmpl = StringTemplate::new("Hello, {name}!");
        let result = tmpl.format(&prompt_args! { "name" => "Alice" }).unwrap();
        assert_eq!(result, "Hello, Alice!");
    }

    #[test]
    fn substitutes_number_value() {
        let tmpl = StringTemplate::new("Age: {age}");
        let result = tmpl.format(&prompt_args! { "age" => 42 }).unwrap();
        assert_eq!(result, "Age: 42");
    }

    #[test]
    fn escapes_double_braces() {
        let tmpl = StringTemplate::new("Use {{literal}} braces.");
        let result = tmpl.format(&PromptArgs::new()).unwrap();
        assert_eq!(result, "Use {literal} braces.");
    }

    #[test]
    fn missing_variable_returns_error() {
        let tmpl = StringTemplate::new("Hello, {name}!");
        let err = tmpl.format(&PromptArgs::new()).unwrap_err();
        assert!(matches!(err, ChainError::MissingVariable(v) if v == "name"));
    }

    #[test]
    fn format_names_first_missing_only() {
        let tmpl = StringTemplate::new("{b} {a}");
        let err = tmpl.format(&PromptArgs::new()).unwrap_err();
        assert!(matches!(err, ChainError::MissingVariable(v) if v == "b"));
    }

    #[test]
    fn extracts_variable_names() {
        let tmpl = StringTemplate::new("{a} + {b} = {a}");
        let vars = tmpl.input_variables();
        assert_eq!(vars, vec!["a", "b"]);
    }

    #[test]
    fn no_variables_in_plain_text() {
        let tmpl = StringTemplate::new("no placeholders here");
        assert_eq!(tmpl.input_variables(), [] as [String; 0]);
    }

    #[test]
    fn lenient_parse_matches_legacy_quirks() {
        assert_eq!(
            parse("a } b {x{y} {", false).unwrap(),
            vec![
                Segment::Literal("a } b ".into()),
                Segment::Var("x{y".into()),
                Segment::Literal(" {".into()),
            ]
        );
    }

    #[test]
    fn strict_parse_reports_positions() {
        let pos = |t: &str| match StringTemplate::try_new(t) {
            Err(TemplateError::Syntax { position, .. }) => Some(position),
            _ => None,
        };
        assert_eq!(pos("ab {x"), Some(3));
        assert_eq!(pos("ab } x"), Some(3));
        assert_eq!(pos("é{x{y}"), Some(2));
        assert_eq!(pos("{a b}"), Some(0));
        assert_eq!(pos("{{ {a} }} {}"), None);
    }

    #[test]
    fn per_variable_guard_overrides_default() {
        let tmpl = StringTemplate::new("{a}|{b}")
            .guard_all(ValueGuard::EscapeXml)
            .guard("b", ValueGuard::Truncate(1));
        let out = tmpl
            .format(&prompt_args! { "a" => "<x>", "b" => "<x>" })
            .unwrap();
        assert_eq!(out, "&lt;x&gt;|<");
    }

    #[test]
    fn partials_are_not_guarded() {
        let tmpl = StringTemplate::new("{a}")
            .with_partial("a", "<trusted>")
            .guard_all(ValueGuard::EscapeXml);
        assert_eq!(tmpl.format(&PromptArgs::new()).unwrap(), "<trusted>");
    }

    #[test]
    fn too_long_maps_to_other() {
        let tmpl = StringTemplate::new("abc").with_max_len(2);
        assert!(matches!(
            tmpl.format(&PromptArgs::new()),
            Err(ChainError::Other(_))
        ));
    }

    #[test]
    fn strict_rejects_invisible_chars_in_names() {
        for t in ["{\u{FEFF}name}", "{na\u{200B}me}", "{name\u{202E}}"] {
            assert!(
                matches!(
                    StringTemplate::try_new(t),
                    Err(TemplateError::Syntax { position: 0, .. })
                ),
                "{t:?}"
            );
        }
        // Outside a placeholder they are ordinary text, and lenient parsing
        // keeps accepting them.
        let tmpl = StringTemplate::try_new("\u{FEFF}Hi {name}").unwrap();
        assert_eq!(tmpl.input_variables(), ["name"]);
        assert_eq!(
            StringTemplate::new("{\u{200B}x}").input_variables(),
            ["\u{200B}x"]
        );
    }

    #[test]
    fn max_len_error_reports_the_full_length() {
        let args = prompt_args! { "a" => "toolong", "b" => 7, "c" => "a<b" };
        let tmpl = StringTemplate::new("{a}-{b}-{c}{d}")
            .with_partial("d", "!!")
            .guard("c", ValueGuard::EscapeXml)
            .with_max_len(3);
        assert_eq!(
            tmpl.try_format(&args).unwrap_err(),
            TemplateError::TooLong { len: 18, max: 3 }
        );
        assert_eq!(
            tmpl.with_max_len(18).try_format(&args).unwrap(),
            "toolong-7-a&lt;b!!"
        );
    }

    #[test]
    fn validate_accepts_any_order() {
        let tmpl = StringTemplate::new("{a}{b}");
        assert!(tmpl.validate_input_variables(&["b", "a"]).is_ok());
    }
}
