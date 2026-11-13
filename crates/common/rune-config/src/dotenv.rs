//! A `.env` file parser and writer.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::read::{DEFAULT_MAX_FILE_SIZE, ReadError, read_text};
use crate::redact::{REDACTED, is_secret_key};

/// One `KEY=value` assignment from a `.env` file.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DotenvEntry {
    /// The variable name.
    pub key: String,
    /// The value after unquoting, unescaping and (if enabled) expansion.
    pub value: String,
    /// 1-based line of the key.
    pub line: usize,
    /// 1-based column (in characters) of the key.
    pub column: usize,
}

impl fmt::Debug for DotenvEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value: &dyn fmt::Debug = if is_secret_key(&self.key) {
            &REDACTED
        } else {
            &self.value
        };
        f.debug_struct("DotenvEntry")
            .field("key", &self.key)
            .field("value", value)
            .field("line", &self.line)
            .field("column", &self.column)
            .finish()
    }
}

/// What went wrong while reading or parsing a `.env` file.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DotenvErrorKind {
    /// A key that is not `[A-Za-z_][A-Za-z0-9_.]*`.
    #[error("invalid variable name")]
    InvalidKey,
    /// A line with a key but no `=`.
    #[error("expected `=` after the variable name")]
    MissingEquals,
    /// A quoted value with no closing quote.
    #[error("unterminated {0}-quoted value")]
    UnterminatedQuote(&'static str),
    /// A `${` with no closing `}`.
    #[error("unterminated `${{...}}` expansion")]
    UnterminatedExpansion,
    /// A `${...}` whose name is not a valid variable name.
    #[error("invalid variable name in `${{...}}` expansion")]
    InvalidExpansion,
    /// Text after a closing quote other than a `#` comment.
    #[error("unexpected text after the closing quote")]
    TrailingCharacters,
    /// A value with a NUL character, which no process environment can hold.
    #[error("value contains a NUL character")]
    NulInValue,
    /// The input exceeds the size limit.
    #[error("input is larger than the {0}-byte limit")]
    TooLarge(u64),
    /// The file is not UTF-8.
    #[error("file is not valid UTF-8")]
    NotUtf8,
    /// The file is writable by every user (only with
    /// [`DotenvOptions::reject_world_writable`]).
    #[error("file is writable by every user; refusing to read it")]
    WorldWritable,
    /// The file could not be read.
    #[error("cannot read file: {message}")]
    Io {
        /// The I/O error kind (`NotFound` for a missing file).
        kind: std::io::ErrorKind,
        /// The I/O error message.
        message: String,
    },
}

/// A `.env` problem, with its position when it comes from the text.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DotenvError {
    /// The file, when the text came from one.
    pub path: Option<PathBuf>,
    /// 1-based line, or 0 when the problem is not tied to a position (an
    /// unreadable file, say).
    pub line: usize,
    /// 1-based column in characters, or 0 like `line`.
    pub column: usize,
    /// What went wrong.
    pub kind: DotenvErrorKind,
}

impl DotenvError {
    const fn at(line: usize, column: usize, kind: DotenvErrorKind) -> Self {
        Self {
            path: None,
            line,
            column,
            kind,
        }
    }

    fn file(path: &Path, error: ReadError) -> Self {
        let kind = match error {
            ReadError::Io(error) => DotenvErrorKind::Io {
                kind: error.kind(),
                message: error.to_string(),
            },
            ReadError::TooLarge(limit) => DotenvErrorKind::TooLarge(limit),
            ReadError::NotUtf8 => DotenvErrorKind::NotUtf8,
            ReadError::WorldWritable => DotenvErrorKind::WorldWritable,
        };
        Self {
            path: Some(path.to_path_buf()),
            ..Self::at(0, 0, kind)
        }
    }

    /// Whether the error is a missing file.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(&self.kind, DotenvErrorKind::Io { kind, .. } if *kind == std::io::ErrorKind::NotFound)
    }
}

impl fmt::Display for DotenvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.path, self.line) {
            (Some(path), 0) => write!(f, "{}: {}", path.display(), self.kind),
            (Some(path), line) => {
                write!(
                    f,
                    "{}:{line}:{}: {}",
                    path.display(),
                    self.column,
                    self.kind
                )
            }
            (None, 0) => write!(f, "{}", self.kind),
            (None, line) => write!(f, "line {line}, column {}: {}", self.column, self.kind),
        }
    }
}

impl std::error::Error for DotenvError {}

/// How `.env` text is parsed and files are read.
///
/// ```
/// use rune_config::DotenvOptions;
///
/// let env = DotenvOptions::new()
///     .expand(true)
///     .parse("HOST=db\nURL=postgres://${HOST}:${PORT:-5432}/app\n")?;
/// assert_eq!(env.get("URL"), Some("postgres://db:5432/app"));
/// # Ok::<(), rune_config::DotenvError>(())
/// ```
#[derive(Clone)]
#[must_use]
pub struct DotenvOptions {
    expand: bool,
    env: BTreeMap<String, String>,
    max_size: u64,
    reject_world_writable: bool,
}

impl Default for DotenvOptions {
    fn default() -> Self {
        Self {
            expand: false,
            env: BTreeMap::new(),
            max_size: DEFAULT_MAX_FILE_SIZE,
            reject_world_writable: false,
        }
    }
}

impl fmt::Debug for DotenvOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DotenvOptions")
            .field("expand", &self.expand)
            .field("env", &format_args!("{} variables", self.env.len()))
            .field("max_size", &self.max_size)
            .field("reject_world_writable", &self.reject_world_writable)
            .finish()
    }
}

impl DotenvOptions {
    /// The defaults: no expansion, a 1 MiB size limit, no permission check.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables `${VAR}`, `${VAR:-default}`, `${VAR-default}` and `$VAR`
    /// expansion in unquoted and double-quoted values. Off by default, so
    /// a `$` is kept literally.
    ///
    /// A name resolves to the variables given with
    /// [`expansion_env`](Self::expansion_env) first, then to keys set
    /// earlier in the same file, and to the empty string otherwise.
    /// `$(...)` is never treated as a command; it stays literal text.
    pub const fn expand(mut self, on: bool) -> Self {
        self.expand = on;
        self
    }

    /// Variables that expansion looks up before the file's own keys,
    /// typically the real environment (`std::env::vars()`), which also
    /// overrides the file when the layers are merged. Has no effect unless
    /// [`expand`](Self::expand) is on.
    pub fn expansion_env<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.env = vars
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self
    }

    /// The largest input accepted, in bytes (default 1 MiB).
    pub const fn max_size(mut self, bytes: u64) -> Self {
        self.max_size = bytes;
        self
    }

    /// Refuses to read a file that every user may write to (Unix only; a
    /// no-op elsewhere). Off by default.
    pub const fn reject_world_writable(mut self, on: bool) -> Self {
        self.reject_world_writable = on;
        self
    }

    /// Parses `.env` text.
    ///
    /// # Errors
    ///
    /// The first syntax error, with its line and column, or
    /// [`DotenvErrorKind::TooLarge`].
    pub fn parse(&self, text: &str) -> Result<Dotenv, DotenvError> {
        if text.len() as u64 > self.max_size {
            return Err(DotenvError::at(
                0,
                0,
                DotenvErrorKind::TooLarge(self.max_size),
            ));
        }
        let entries = Parser::new(text, self).run()?;
        Ok(Dotenv {
            path: None,
            entries,
        })
    }

    /// Reads and parses the file at `path`.
    ///
    /// # Errors
    ///
    /// I/O, size, encoding and permission problems, and syntax errors, all
    /// carrying the path.
    pub fn read(&self, path: impl AsRef<Path>) -> Result<Dotenv, DotenvError> {
        let path = path.as_ref();
        let text = read_text(path, self.max_size, self.reject_world_writable)
            .map_err(|error| DotenvError::file(path, error))?;
        let mut dotenv = self.parse(&text).map_err(|mut error| {
            error.path = Some(path.to_path_buf());
            error
        })?;
        dotenv.path = Some(path.to_path_buf());
        Ok(dotenv)
    }
}

/// The parsed contents of a `.env` file.
///
/// Parsing never touches the process environment. Use [`get`](Self::get),
/// [`to_map`](Self::to_map) or [`vars`](Self::vars) to work with the
/// values, feed them to [`ConfigLoader::with_dotenv`] or
/// [`EnvReader::from_vars`], or, if you really need it, call the `unsafe`
/// [`load_into_process_env`](Self::load_into_process_env).
///
/// ```
/// use rune_config::Dotenv;
///
/// let env = Dotenv::parse(r#"
/// ## database
/// export DB_HOST=localhost   # inline comment
/// DB_PASSWORD='p@ss # not a comment'
/// GREETING="hello\nworld"
/// "#)?;
/// assert_eq!(env.get("DB_HOST"), Some("localhost"));
/// assert_eq!(env.get("DB_PASSWORD"), Some("p@ss # not a comment"));
/// assert_eq!(env.get("GREETING"), Some("hello\nworld"));
/// assert_eq!(env.entry("GREETING").map(|e| e.line), Some(5));
/// // Secret-looking values stay out of Debug output.
/// assert!(!format!("{env:?}").contains("p@ss"));
/// # Ok::<(), rune_config::DotenvError>(())
/// ```
///
/// [`ConfigLoader::with_dotenv`]: crate::ConfigLoader::with_dotenv
/// [`EnvReader::from_vars`]: crate::EnvReader::from_vars
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dotenv {
    path: Option<PathBuf>,
    entries: Vec<DotenvEntry>,
}

impl Dotenv {
    /// Parses `.env` text with the default [`DotenvOptions`].
    ///
    /// # Errors
    ///
    /// See [`DotenvOptions::parse`].
    pub fn parse(text: &str) -> Result<Self, DotenvError> {
        DotenvOptions::new().parse(text)
    }

    /// Reads and parses a file with the default [`DotenvOptions`].
    ///
    /// # Errors
    ///
    /// See [`DotenvOptions::read`].
    pub fn read(path: impl AsRef<Path>) -> Result<Self, DotenvError> {
        DotenvOptions::new().read(path)
    }

    /// The file this was read from, if any.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Every assignment, in file order, including repeated keys.
    #[must_use]
    pub fn entries(&self) -> &[DotenvEntry] {
        &self.entries
    }

    /// The last assignment of `key`.
    #[must_use]
    pub fn entry(&self, key: &str) -> Option<&DotenvEntry> {
        self.entries.iter().rev().find(|e| e.key == key)
    }

    /// The value of `key` (the last assignment wins).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entry(key).map(|e| e.value.as_str())
    }

    /// Every assignment as `(key, value)`, in file order; later ones win
    /// when the pairs are collected into a map.
    pub fn vars(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|e| (e.key.as_str(), e.value.as_str()))
    }

    /// The final value of every key.
    #[must_use]
    pub fn to_map(&self) -> BTreeMap<String, String> {
        self.vars()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    /// Number of assignments.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no assignments.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Writes the assignments back as `.env` text that [`Dotenv::parse`]
    /// reads to the same keys and values (see [`format_dotenv`]).
    #[must_use]
    pub fn to_dotenv_string(&self) -> String {
        let mut out = String::new();
        for entry in &self.entries {
            write_entry(&mut out, &entry.key, &entry.value);
        }
        out
    }

    /// Sets each variable in the process environment, returning how many
    /// were set. Existing variables are left alone unless `overwrite` is
    /// set.
    ///
    /// Prefer passing values around explicitly (the rest of this crate
    /// does). Changing the process environment is global, cannot be undone
    /// safely, and is visible to every library in the process.
    ///
    /// # Safety
    ///
    /// This calls [`std::env::set_var`], which is `unsafe` since Rust 2024:
    /// on most platforms it is undefined behaviour if any other thread
    /// reads or writes the environment at the same time, and that includes
    /// indirect reads such as DNS lookups or time-zone handling inside libc.
    /// Call it only while the program is single-threaded, typically first
    /// thing in `main` before any runtime or thread pool starts.
    ///
    /// # Errors
    ///
    /// [`DotenvErrorKind::NulInValue`] for a value containing NUL, checked
    /// for every entry before anything is set.
    ///
    /// ```
    /// use rune_config::Dotenv;
    ///
    /// let env = Dotenv::parse("RUNE_CONFIG_DOC_EXAMPLE=1")?;
    /// // SAFETY: doc tests run in their own single-threaded process.
    /// let set = unsafe { env.load_into_process_env(false)? };
    /// assert_eq!(set, 1);
    /// assert_eq!(std::env::var("RUNE_CONFIG_DOC_EXAMPLE").as_deref(), Ok("1"));
    /// # Ok::<(), rune_config::DotenvError>(())
    /// ```
    #[allow(unsafe_code, reason = "the caller upholds set_var's contract")]
    pub unsafe fn load_into_process_env(&self, overwrite: bool) -> Result<usize, DotenvError> {
        if let Some(entry) = self.entries.iter().find(|e| e.value.contains('\0')) {
            return Err(DotenvError {
                path: self.path.clone(),
                ..DotenvError::at(entry.line, entry.column, DotenvErrorKind::NulInValue)
            });
        }
        let mut set = 0;
        for (key, value) in self.to_map() {
            if overwrite || std::env::var_os(&key).is_none() {
                // SAFETY: forwarded to the caller, see `# Safety`.
                unsafe { std::env::set_var(&key, &value) };
                set += 1;
            }
        }
        Ok(set)
    }
}

/// Writes `(key, value)` pairs as `.env` text.
///
/// Each pair becomes one double-quoted assignment per line, escaping `\`, `"`, `$`, newlines, carriage returns
/// and tabs. Parsing the result, with or without expansion, gives back the
/// same pairs.
///
/// # Errors
///
/// [`DotenvErrorKind::InvalidKey`] (with `line` set to the pair's 1-based
/// index) for a key that is not a valid variable name.
///
/// ```
/// use rune_config::{Dotenv, format_dotenv};
///
/// let text = format_dotenv([("NAME", "a \"quoted\" $value\n")])?;
/// assert_eq!(text, "NAME=\"a \\\"quoted\\\" \\$value\\n\"\n");
/// assert_eq!(Dotenv::parse(&text)?.get("NAME"), Some("a \"quoted\" $value\n"));
/// # Ok::<(), rune_config::DotenvError>(())
/// ```
pub fn format_dotenv<I, K, V>(pairs: I) -> Result<String, DotenvError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut out = String::new();
    for (index, (key, value)) in pairs.into_iter().enumerate() {
        let key = key.as_ref();
        if !is_valid_key(key) {
            return Err(DotenvError::at(index + 1, 1, DotenvErrorKind::InvalidKey));
        }
        write_entry(&mut out, key, value.as_ref());
    }
    Ok(out)
}

fn write_entry(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str("=\"");
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push_str("\"\n");
}

const fn is_key_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

const fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.'
}

/// Whether `key` is a name the parser accepts.
fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars.next().is_some_and(is_key_start) && chars.all(is_key_char)
}

const fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Where the current value ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Quote {
    None,
    Double,
}

struct Parser<'a> {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    column: usize,
    options: &'a DotenvOptions,
    defined: BTreeMap<String, String>,
}

impl<'a> Parser<'a> {
    fn new(text: &str, options: &'a DotenvOptions) -> Self {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        Self {
            chars: text.replace("\r\n", "\n").chars().collect(),
            pos: 0,
            line: 1,
            column: 1,
            options,
            defined: BTreeMap::new(),
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        if c == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(c)
    }

    const fn here(&self, kind: DotenvErrorKind) -> DotenvError {
        DotenvError::at(self.line, self.column, kind)
    }

    /// Skips spaces and tabs, returning whether any were skipped.
    fn skip_blanks(&mut self) -> bool {
        let start = self.pos;
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.bump();
        }
        self.pos > start
    }

    fn skip_line(&mut self) {
        while let Some(c) = self.bump() {
            if c == '\n' {
                break;
            }
        }
    }

    fn run(mut self) -> Result<Vec<DotenvEntry>, DotenvError> {
        let mut entries = Vec::new();
        loop {
            self.skip_blanks();
            match self.peek() {
                None => return Ok(entries),
                Some('\n') => {
                    self.bump();
                }
                Some('#') => self.skip_line(),
                Some(_) => {
                    let entry = self.assignment()?;
                    self.defined.insert(entry.key.clone(), entry.value.clone());
                    entries.push(entry);
                }
            }
        }
    }

    fn assignment(&mut self) -> Result<DotenvEntry, DotenvError> {
        self.skip_export();
        let (line, column) = (self.line, self.column);
        let key = self.key()?;
        self.skip_blanks();
        if self.peek() != Some('=') {
            return Err(self.here(DotenvErrorKind::MissingEquals));
        }
        self.bump();
        let blank = self.skip_blanks();
        let value = match self.peek() {
            Some('\'') => {
                let value = self.single_quoted()?;
                self.end_of_quoted()?;
                value
            }
            Some('"') => {
                let value = self.double_quoted()?;
                self.end_of_quoted()?;
                value
            }
            _ => self.unquoted(blank)?,
        };
        Ok(DotenvEntry {
            key,
            value,
            line,
            column,
        })
    }

    /// Consumes `export` and the blanks after it when a key follows.
    fn skip_export(&mut self) {
        let word = "export";
        let matches = word
            .chars()
            .enumerate()
            .all(|(i, c)| self.peek_at(i) == Some(c));
        if !matches || !matches!(self.peek_at(word.len()), Some(' ' | '\t')) {
            return;
        }
        let mut after = word.len();
        while matches!(self.peek_at(after), Some(' ' | '\t')) {
            after += 1;
        }
        if self.peek_at(after).is_some_and(is_key_start) {
            for _ in 0..after {
                self.bump();
            }
        }
    }

    fn key(&mut self) -> Result<String, DotenvError> {
        if !self.peek().is_some_and(is_key_start) {
            return Err(self.here(DotenvErrorKind::InvalidKey));
        }
        let mut key = String::new();
        while let Some(c) = self.peek().filter(|c| is_key_char(*c)) {
            key.push(c);
            self.bump();
        }
        if !matches!(self.peek(), None | Some(' ' | '\t' | '=' | '\n')) {
            return Err(self.here(DotenvErrorKind::InvalidKey));
        }
        Ok(key)
    }

    fn single_quoted(&mut self) -> Result<String, DotenvError> {
        let open = self.here(DotenvErrorKind::UnterminatedQuote("single"));
        self.bump();
        let mut value = String::new();
        loop {
            match self.bump() {
                None => return Err(open),
                Some('\'') => return Ok(value),
                Some(c) => value.push(c),
            }
        }
    }

    fn double_quoted(&mut self) -> Result<String, DotenvError> {
        let open = self.here(DotenvErrorKind::UnterminatedQuote("double"));
        self.bump();
        let mut value = String::new();
        loop {
            match self.peek() {
                None => return Err(open),
                Some('"') => {
                    self.bump();
                    return Ok(value);
                }
                Some('\\') => {
                    self.bump();
                    match self.bump() {
                        None => return Err(open),
                        Some('n') => value.push('\n'),
                        Some('r') => value.push('\r'),
                        Some('t') => value.push('\t'),
                        Some(c @ ('"' | '\\' | '$')) => value.push(c),
                        Some(c) => {
                            value.push('\\');
                            value.push(c);
                        }
                    }
                }
                Some('$') if self.options.expand => self.expansion(&mut value, Quote::Double)?,
                Some(c) => {
                    value.push(c);
                    self.bump();
                }
            }
        }
    }

    /// After a closing quote: blanks, then a comment or the end of line.
    fn end_of_quoted(&mut self) -> Result<(), DotenvError> {
        self.skip_blanks();
        match self.peek() {
            None => Ok(()),
            Some('\n' | '#') => {
                self.skip_line();
                Ok(())
            }
            Some(_) => Err(self.here(DotenvErrorKind::TrailingCharacters)),
        }
    }

    /// An unquoted value runs to the end of the line or to a `#` that
    /// follows whitespace, and is trimmed.
    fn unquoted(&mut self, mut after_blank: bool) -> Result<String, DotenvError> {
        let mut value = String::new();
        loop {
            match self.peek() {
                None => break,
                Some('\n') => {
                    self.bump();
                    break;
                }
                Some('#') if after_blank => {
                    self.skip_line();
                    break;
                }
                Some('$') if self.options.expand => {
                    self.expansion(&mut value, Quote::None)?;
                    after_blank = false;
                }
                Some(c) => {
                    after_blank = c == ' ' || c == '\t';
                    value.push(c);
                    self.bump();
                }
            }
        }
        value.truncate(value.trim_end_matches([' ', '\t']).len());
        Ok(value)
    }

    /// Expands the `$...` at the cursor into `out`.
    fn expansion(&mut self, out: &mut String, quote: Quote) -> Result<(), DotenvError> {
        let start = self.here(DotenvErrorKind::UnterminatedExpansion);
        self.bump();
        match self.peek() {
            Some('{') => {
                self.bump();
                let name_at = self.here(DotenvErrorKind::InvalidExpansion);
                let name = self.name();
                if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
                    return Err(name_at);
                }
                let mut default = None;
                if self.peek() == Some(':') && self.peek_at(1) == Some('-') {
                    self.bump();
                    self.bump();
                    default = Some((self.until_brace(&start, quote)?, true));
                } else if self.peek() == Some('-') {
                    self.bump();
                    default = Some((self.until_brace(&start, quote)?, false));
                }
                match self.peek() {
                    Some('}') => {
                        self.bump();
                    }
                    None | Some('\n') => return Err(start),
                    Some(_) => return Err(name_at),
                }
                let value = self.lookup(&name);
                match default {
                    Some((text, colon)) if value.is_none() || (colon && value == Some("")) => {
                        out.push_str(&text);
                    }
                    _ => out.push_str(value.unwrap_or_default()),
                }
            }
            Some(c) if is_key_start(c) => {
                let name = self.name();
                if let Some(v) = self.lookup(&name) {
                    out.push_str(v);
                }
            }
            _ => out.push('$'),
        }
        Ok(())
    }

    fn name(&mut self) -> String {
        let mut name = String::new();
        while let Some(c) = self.peek().filter(|c| is_name_char(*c)) {
            name.push(c);
            self.bump();
        }
        name
    }

    /// Default text of `${VAR:-default}`, taken literally up to `}`.
    fn until_brace(&mut self, start: &DotenvError, quote: Quote) -> Result<String, DotenvError> {
        let mut text = String::new();
        loop {
            match self.peek() {
                Some('}') => return Ok(text),
                None | Some('\n') => return Err(start.clone()),
                Some('"') if quote == Quote::Double => return Err(start.clone()),
                Some(c) => {
                    text.push(c);
                    self.bump();
                }
            }
        }
    }

    fn lookup(&self, name: &str) -> Option<&str> {
        self.options
            .env
            .get(name)
            .or_else(|| self.defined.get(name))
            .map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Vec<(String, String)> {
        Dotenv::parse(text)
            .unwrap_or_else(|e| panic!("{text:?}: {e}"))
            .vars()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    fn one(text: &str) -> String {
        let vars = parse(text);
        assert_eq!(vars.len(), 1, "{text:?} -> {vars:?}");
        vars[0].1.clone()
    }

    fn expanded(text: &str) -> Dotenv {
        DotenvOptions::new()
            .expand(true)
            .parse(text)
            .unwrap_or_else(|e| panic!("{text:?}: {e}"))
    }

    fn err(text: &str) -> DotenvError {
        Dotenv::parse(text).expect_err(text)
    }

    #[test]
    fn basic_assignments() {
        assert_eq!(one("A=1"), "1");
        assert_eq!(one("A = 1 "), "1");
        assert_eq!(one("A="), "");
        assert_eq!(one("A=  "), "");
        assert_eq!(one("export A=1"), "1");
        assert_eq!(one("export   A=1"), "1");
        assert_eq!(one("A=a b  c"), "a b  c");
        assert_eq!(one("A.B_C=1"), "1");
        assert_eq!(parse("export=1"), [("export".to_owned(), "1".to_owned())]);
        assert_eq!(parse("exportX=1"), [("exportX".to_owned(), "1".to_owned())]);
    }

    #[test]
    fn comments() {
        assert_eq!(
            parse("# c\n\n  # indented\nA=1 # trailing\n"),
            [("A".to_owned(), "1".to_owned())]
        );
        assert_eq!(one("A=1#not-a-comment"), "1#not-a-comment");
        assert_eq!(one("A=#hash"), "#hash");
        assert_eq!(one("A= #comment"), "");
        assert_eq!(one("A='x' # c"), "x");
        assert_eq!(one("A=\"x\"# c"), "x");
    }

    #[test]
    fn quoting() {
        assert_eq!(one("A='raw \\n $X'"), "raw \\n $X");
        assert_eq!(one("A=\"a\\nb\\tc\\\"d\\\\e\\$f\""), "a\nb\tc\"d\\e$f");
        assert_eq!(one("A=\"keep \\q\""), "keep \\q");
        assert_eq!(one("A=\"  spaced  \""), "  spaced  ");
        assert_eq!(one("A=it's"), "it's");
        assert_eq!(one("A=\"multi\nline\""), "multi\nline");
        assert_eq!(one("A='multi\nline'"), "multi\nline");
        assert_eq!(one("A=\"crlf\r\nline\"\r\n"), "crlf\nline");
        assert_eq!(one("\u{feff}A=1"), "1");
    }

    #[test]
    fn positions_and_duplicates() {
        let env = Dotenv::parse("A=1\n  B=\"x\ny\"\nC=3\nA=4").unwrap();
        let positions: Vec<_> = env.entries().iter().map(|e| (e.line, e.column)).collect();
        assert_eq!(positions, [(1, 1), (2, 3), (4, 1), (5, 1)]);
        assert_eq!(env.get("A"), Some("4"));
        assert_eq!(env.to_map().len(), 3);
    }

    #[test]
    fn errors_have_positions() {
        let e = err("A=1\nB");
        assert_eq!(
            (e.line, e.column, &e.kind),
            (2, 2, &DotenvErrorKind::MissingEquals)
        );
        let e = err("A=1\n  1B=2");
        assert_eq!(
            (e.line, e.column, &e.kind),
            (2, 3, &DotenvErrorKind::InvalidKey)
        );
        let e = err("A=1\nB=\"open\n");
        assert_eq!(
            (e.line, e.column, &e.kind),
            (2, 3, &DotenvErrorKind::UnterminatedQuote("double"))
        );
        let e = err("A='x' y");
        assert_eq!(
            (e.line, e.column, &e.kind),
            (1, 7, &DotenvErrorKind::TrailingCharacters)
        );
        assert_eq!(err("A-B=1").kind, DotenvErrorKind::InvalidKey);
        assert_eq!(err("=1").kind, DotenvErrorKind::InvalidKey);
        assert_eq!(
            e.to_string(),
            "line 1, column 7: unexpected text after the closing quote"
        );
    }

    #[test]
    fn expansion_is_opt_in() {
        assert_eq!(one("A=$HOME ${X}"), "$HOME ${X}");
        let env = expanded("A=1\nB=${A}-$A-${MISSING}-$\nC=\"${B}x\"\nD='${A}'\nE=\\$A");
        assert_eq!(env.get("B"), Some("1-1--$"));
        assert_eq!(env.get("C"), Some("1-1--$x"));
        assert_eq!(env.get("D"), Some("${A}"));
        assert_eq!(env.get("E"), Some("\\1"));
        assert_eq!(expanded("A=\"\\${A}\"").get("A"), Some("${A}"));
    }

    #[test]
    #[allow(clippy::literal_string_with_formatting_args, reason = "shell syntax")]
    fn expansion_defaults_and_env() {
        let env = expanded("E=\nA=${U:-dflt}\nB=${E:-dflt}\nC=${E-dflt}\nD=${U-x y}");
        assert_eq!(env.get("A"), Some("dflt"));
        assert_eq!(env.get("B"), Some("dflt"));
        assert_eq!(env.get("C"), Some(""));
        assert_eq!(env.get("D"), Some("x y"));
        let env = DotenvOptions::new()
            .expand(true)
            .expansion_env([("HOST", "prod")])
            .parse("HOST=local\nURL=http://${HOST}/")
            .unwrap();
        assert_eq!(env.get("URL"), Some("http://prod/"));
    }

    #[test]
    fn no_command_substitution() {
        assert_eq!(expanded("A=$(echo hi)").get("A"), Some("$(echo hi)"));
        assert_eq!(expanded("A=\"`id`\"").get("A"), Some("`id`"));
    }

    #[test]
    fn bad_expansions() {
        let opts = DotenvOptions::new().expand(true);
        let e = opts.parse("A=${B").unwrap_err();
        assert_eq!(
            (e.line, e.column, &e.kind),
            (1, 3, &DotenvErrorKind::UnterminatedExpansion)
        );
        assert_eq!(
            opts.parse("A=${}").unwrap_err().kind,
            DotenvErrorKind::InvalidExpansion
        );
        assert_eq!(
            opts.parse("A=${1}").unwrap_err().kind,
            DotenvErrorKind::InvalidExpansion
        );
        assert_eq!(
            opts.parse("A=${B C}").unwrap_err().kind,
            DotenvErrorKind::InvalidExpansion
        );
        assert_eq!(
            opts.parse("A=\"${B:-x\"").unwrap_err().kind,
            DotenvErrorKind::UnterminatedExpansion
        );
    }

    #[test]
    fn size_limit() {
        let e = DotenvOptions::new().max_size(3).parse("A=12").unwrap_err();
        assert_eq!(e.kind, DotenvErrorKind::TooLarge(3));
    }

    #[test]
    fn writer_round_trips() {
        let text = format_dotenv([("A", "x\"y\\z$\n\r\t'#"), ("B", "")]).unwrap();
        let env = Dotenv::parse(&text).unwrap();
        assert_eq!(env.get("A"), Some("x\"y\\z$\n\r\t'#"));
        assert_eq!(env.get("B"), Some(""));
        assert_eq!(env.to_dotenv_string(), text);
        assert_eq!(
            format_dotenv([("ok", "1"), ("1bad", "")]).unwrap_err().line,
            2
        );
    }

    #[test]
    fn debug_hides_secret_values() {
        let env = Dotenv::parse("API_TOKEN=abc123\nHOST=example").unwrap();
        let debug = format!("{env:?}");
        assert!(!debug.contains("abc123"), "{debug}");
        assert!(debug.contains("example"), "{debug}");
        let debug = format!(
            "{:?}",
            DotenvOptions::new().expansion_env([("X", "secretvalue")])
        );
        assert!(!debug.contains("secretvalue"));
    }
}
