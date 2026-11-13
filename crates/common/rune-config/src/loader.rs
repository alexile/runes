//! Ordered layers, deep merge with provenance, typed deserialization.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;
use toml::de::DeTable;
use toml::{Table, Value};

use crate::dotenv::{Dotenv, DotenvOptions};
use crate::issue::{ConfigErrors, ConfigIssue, Source};
use crate::key::{format_key, join, lookup, nest, parse_key};
use crate::overrides::{CliOverrides, EnvMapping, Override};
use crate::read::{DEFAULT_MAX_FILE_SIZE, read_text};
use crate::redact::{REDACTED, is_secret_key, scrub};

/// What a layer holds before loading.
#[derive(Clone, Debug)]
enum Input {
    /// An already-parsed table.
    Table(Table),
    /// TOML text to parse.
    Text(String),
    /// A file to read and parse at load time.
    File { path: PathBuf, required: bool },
    /// A `.env` file to read at load time, mapped onto keys.
    Dotenv {
        path: PathBuf,
        required: bool,
        mapping: EnvMapping,
        options: DotenvOptions,
    },
    /// A problem found while building the loader, reported by `load`.
    Issue(ConfigIssue),
}

#[derive(Clone, Debug)]
struct Layer {
    source: Source,
    input: Input,
}

/// Builds a [`LoadedConfig`] from ordered layers.
///
/// Layers apply in the order they are added: **each layer overrides the
/// ones added before it**. The conventional order is defaults, user file,
/// project file, `.env` file, real environment, then explicit overrides
/// such as command-line flags:
///
/// ```
/// use rune_config::{CliOverrides, ConfigLoader, EnvMapping, Source};
///
/// let loaded = ConfigLoader::new()
///     .with_defaults_toml("[scan]\nrate_limit = 5\nconcurrency = 8")
///     .with_toml(Source::Inline("example".into()), "[scan]\nrate_limit = 10")
///     .with_env([("APP_CONCURRENCY", "2")], &EnvMapping::new().var("APP_CONCURRENCY", "scan.concurrency"))
///     .with_cli(&CliOverrides::new().set("--rps", "scan.rate_limit", 50))
///     .load()?;
///
/// assert_eq!(loaded.get("scan.rate_limit").and_then(|v| v.as_integer()), Some(50));
/// assert_eq!(loaded.source_of("scan.rate_limit"), Some(&Source::Cli("--rps".into())));
/// assert_eq!(loaded.source_of("scan.concurrency"), Some(&Source::Env("APP_CONCURRENCY".into())));
/// # Ok::<(), rune_config::ConfigErrors>(())
/// ```
///
/// Merging is deep for tables: a layer that sets `scan.rate_limit` leaves
/// `scan.concurrency` from lower layers alone. Any other value (including
/// arrays) replaces the lower value as a whole, and a value of a different
/// type (a table over a string, say) replaces it too; typed checks happen
/// in [`LoadedConfig::deserialize`].
///
/// Files are the only I/O, done in [`load`](Self::load), and each is
/// refused above [`max_file_size`](Self::max_file_size) (1 MiB by
/// default). Everything else works on values the caller passes in; the
/// process environment is read only by
/// [`with_process_env`](Self::with_process_env) and never written.
#[derive(Clone, Debug)]
#[must_use]
pub struct ConfigLoader {
    layers: Vec<Layer>,
    max_file_size: u64,
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self {
            layers: Vec::new(),
            max_file_size: DEFAULT_MAX_FILE_SIZE,
        }
    }
}

impl ConfigLoader {
    /// A loader with no layers.
    pub fn new() -> Self {
        Self::default()
    }

    /// The largest TOML file accepted, in bytes (default
    /// [`DEFAULT_MAX_FILE_SIZE`](crate::DEFAULT_MAX_FILE_SIZE), 1 MiB).
    /// `.env` files use the limit in their [`DotenvOptions`].
    pub const fn max_file_size(mut self, bytes: u64) -> Self {
        self.max_file_size = bytes;
        self
    }

    /// Adds `table` as a layer attributed to [`Source::Default`].
    pub fn with_defaults(self, table: Table) -> Self {
        self.with_table(Source::Default, table)
    }

    /// Adds TOML text as a layer attributed to [`Source::Default`].
    pub fn with_defaults_toml(self, text: impl Into<String>) -> Self {
        self.with_toml(Source::Default, text)
    }

    /// Serializes `defaults` (typically `T::default()` of the config
    /// struct) and adds it as a [`Source::Default`] layer. A value that
    /// does not serialize to a TOML table is reported by [`load`](Self::load).
    pub fn with_defaults_from<T: Serialize + ?Sized>(mut self, defaults: &T) -> Self {
        let input = match Table::try_from(defaults) {
            Ok(table) => Input::Table(table),
            Err(error) => Input::Issue(ConfigIssue::new(
                Source::Default,
                None,
                format!("defaults do not serialize to a TOML table: {error}"),
            )),
        };
        self.layers.push(Layer {
            source: Source::Default,
            input,
        });
        self
    }

    /// Adds an already-parsed table as a layer.
    pub fn with_table(mut self, source: Source, table: Table) -> Self {
        self.layers.push(Layer {
            source,
            input: Input::Table(table),
        });
        self
    }

    /// Adds TOML text as a layer; it is parsed by [`load`](Self::load),
    /// with syntax errors attributed to `source`.
    pub fn with_toml(mut self, source: Source, text: impl Into<String>) -> Self {
        self.layers.push(Layer {
            source,
            input: Input::Text(text.into()),
        });
        self
    }

    /// Adds the TOML file at `path`, read by [`load`](Self::load). A missing
    /// file is an error when `required`, and skipped otherwise.
    pub fn with_file(mut self, source: Source, path: impl Into<PathBuf>, required: bool) -> Self {
        self.layers.push(Layer {
            source,
            input: Input::File {
                path: path.into(),
                required,
            },
        });
        self
    }

    /// Adds the optional user file ([`Source::UserFile`]); `None` (no known
    /// location, see [`default_user_config_path`]) adds nothing.
    ///
    /// [`default_user_config_path`]: crate::default_user_config_path
    pub fn with_user_file(self, path: Option<PathBuf>) -> Self {
        match path {
            Some(path) => self.with_file(Source::UserFile(path.clone()), path, false),
            None => self,
        }
    }

    /// Adds the project file ([`Source::ProjectFile`]). Pass `required =
    /// true` for a path the user named explicitly (`--config`).
    pub fn with_project_file(self, path: impl Into<PathBuf>, required: bool) -> Self {
        let path = path.into();
        self.with_file(Source::ProjectFile(path.clone()), path, required)
    }

    /// Adds one layer per environment variable that `mapping` uses, each
    /// attributed to [`Source::Env`]. `vars` is typically `std::env::vars()`.
    pub fn with_env<I, K, V>(mut self, vars: I, mapping: &EnvMapping) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let vars: Vec<(String, String)> = vars
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        let (overrides, issues) = mapping.resolve(&vars);
        self.push_issues(issues);
        self.push_overrides(overrides);
        self
    }

    /// Like [`with_env`](Self::with_env) with the variables of this process
    /// (`std::env::vars_os`, skipping any that are not UTF-8). The
    /// environment is only read, never changed.
    pub fn with_process_env(self, mapping: &EnvMapping) -> Self {
        let vars = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)));
        self.with_env(vars, mapping)
    }

    /// Adds one layer per variable of an already-parsed `.env` file that
    /// `mapping` uses, each attributed to [`Source::DotenvVar`] with its
    /// file and line.
    ///
    /// ```
    /// use rune_config::{ConfigLoader, Dotenv, EnvMapping, Source};
    ///
    /// let dotenv = Dotenv::parse("APP_PORT=8080\nAPP_HOST=dotenv\n")?;
    /// let mapping = EnvMapping::new().prefix("APP_");
    /// let loaded = ConfigLoader::new()
    ///     .with_defaults_toml("host = \"default\"\nport = 80")
    ///     .with_dotenv(&dotenv, &mapping)
    ///     .with_env([("APP_HOST", "env")], &mapping)
    ///     .load()
    ///     .unwrap();
    /// assert_eq!(loaded.get("port").and_then(|v| v.as_integer()), Some(8080));
    /// assert_eq!(loaded.get("host").and_then(|v| v.as_str()), Some("env"));
    /// assert_eq!(
    ///     loaded.source_of("port"),
    ///     Some(&Source::DotenvVar { file: None, var: "APP_PORT".into(), line: 1 })
    /// );
    /// # Ok::<(), rune_config::DotenvError>(())
    /// ```
    pub fn with_dotenv(mut self, dotenv: &Dotenv, mapping: &EnvMapping) -> Self {
        let (overrides, issues) = resolve_dotenv(dotenv, mapping);
        self.push_issues(issues);
        self.push_overrides(overrides);
        self
    }

    /// Adds the `.env` file at `path`, read and parsed with `options` by
    /// [`load`](Self::load) and mapped like [`with_dotenv`](Self::with_dotenv).
    /// A missing file is an error when `required`, and skipped otherwise.
    /// Read and syntax errors are attributed to [`Source::Dotenv`].
    pub fn with_dotenv_file(
        mut self,
        path: impl Into<PathBuf>,
        required: bool,
        mapping: &EnvMapping,
        options: &DotenvOptions,
    ) -> Self {
        let path = path.into();
        self.layers.push(Layer {
            source: Source::Dotenv(path.clone()),
            input: Input::Dotenv {
                path,
                required,
                mapping: mapping.clone(),
                options: options.clone(),
            },
        });
        self
    }

    /// Adds one layer per command-line override, each attributed to
    /// [`Source::Cli`]. This is also the place for any other explicit,
    /// highest-priority overrides; the "flag" names the origin.
    pub fn with_cli(mut self, cli: &CliOverrides) -> Self {
        let (overrides, issues) = cli.parts();
        self.push_issues(issues.to_vec());
        self.push_overrides(overrides.to_vec());
        self
    }

    fn push_issues(&mut self, issues: Vec<ConfigIssue>) {
        self.layers.extend(issues.into_iter().map(|issue| Layer {
            source: issue.source.clone(),
            input: Input::Issue(issue),
        }));
    }

    fn push_overrides(&mut self, overrides: Vec<Override>) {
        self.layers.extend(overrides.into_iter().map(|o| Layer {
            source: o.source,
            input: Input::Table(nest(&o.key, o.value)),
        }));
    }

    /// Reads files, parses every layer and merges them.
    ///
    /// # Errors
    ///
    /// Every problem in every layer (unreadable or missing required files,
    /// TOML syntax errors, malformed overrides), each naming its layer and,
    /// where known, its key.
    pub fn load(&self) -> Result<LoadedConfig, ConfigErrors> {
        let mut issues = Vec::new();
        let mut parsed: Vec<(Source, Table)> = Vec::new();
        for layer in &self.layers {
            match &layer.input {
                Input::Table(table) => parsed.push((layer.source.clone(), table.clone())),
                Input::Text(text) => match parse_toml(text, &layer.source) {
                    Ok(table) => parsed.push((layer.source.clone(), table)),
                    Err(issue) => issues.push(issue),
                },
                Input::File { path, required } => {
                    match read_text(path, self.max_file_size, false) {
                        Ok(text) => match parse_toml(&text, &layer.source) {
                            Ok(table) => parsed.push((layer.source.clone(), table)),
                            Err(issue) => issues.push(issue),
                        },
                        Err(error) if error.is_not_found() && !required => {}
                        Err(error) => issues.push(ConfigIssue::new(
                            layer.source.clone(),
                            None,
                            error.to_string(),
                        )),
                    }
                }
                Input::Dotenv {
                    path,
                    required,
                    mapping,
                    options,
                } => match options.read(path) {
                    Ok(dotenv) => {
                        let (overrides, found) = resolve_dotenv(&dotenv, mapping);
                        issues.extend(found);
                        parsed.extend(
                            overrides
                                .into_iter()
                                .map(|o| (o.source, nest(&o.key, o.value))),
                        );
                    }
                    Err(error) if error.is_not_found() && !required => {}
                    Err(error) => {
                        let message = match error.line {
                            0 => error.kind.to_string(),
                            line => format!("line {line}, column {}: {}", error.column, error.kind),
                        };
                        issues.push(ConfigIssue::new(layer.source.clone(), None, message));
                    }
                },
                Input::Issue(issue) => issues.push(issue.clone()),
            }
        }
        if !issues.is_empty() {
            return Err(ConfigErrors::new(issues));
        }

        let mut loaded = LoadedConfig::default();
        for (source, table) in parsed {
            merge(
                &mut loaded.table,
                table,
                "",
                &source,
                &mut loaded.provenance,
            );
            if !loaded.sources.contains(&source) {
                loaded.sources.push(source);
            }
        }
        Ok(loaded)
    }
}

/// Maps the variables of `dotenv` through `mapping`, attributing each to
/// its file and line.
fn resolve_dotenv(
    dotenv: &Dotenv,
    mapping: &EnvMapping,
) -> (Vec<crate::overrides::Override>, Vec<ConfigIssue>) {
    let vars: Vec<(String, String)> = dotenv
        .vars()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
    let entries = dotenv.entries();
    mapping.resolve_with(&vars, |name, index| Source::DotenvVar {
        file: dotenv.path().map(Path::to_path_buf),
        var: name.to_owned(),
        line: entries.get(index).map_or(0, |e| e.line),
    })
}

/// Parses one TOML layer, reporting syntax errors with line and column.
///
/// # Errors
///
/// A [`ConfigIssue`] attributed to `source`.
pub fn parse_toml(text: &str, source: &Source) -> Result<Table, ConfigIssue> {
    text.parse::<Table>().map_err(|error| {
        let at = error
            .span()
            .map(|span| line_col(text, span.start))
            .map_or_else(String::new, |(line, col)| {
                format!(" at line {line}, column {col}")
            });
        ConfigIssue::new(
            source.clone(),
            None,
            format!("TOML syntax error{at}: {}", error.message().trim_end()),
        )
    })
}

/// 1-based line and column (in characters) of byte offset `at`.
fn line_col(text: &str, at: usize) -> (usize, usize) {
    let mut at = at.min(text.len());
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    let before = &text[..at];
    let line = before.matches('\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    (line, before[line_start..].chars().count() + 1)
}

/// Deep-merges `src` into `dst`, recording the source of every leaf.
fn merge(
    dst: &mut Table,
    src: Table,
    prefix: &str,
    source: &Source,
    provenance: &mut BTreeMap<String, Source>,
) {
    for (key, value) in src {
        let path = join(prefix, &key);
        match (dst.get_mut(&key), value) {
            (Some(Value::Table(existing)), Value::Table(incoming)) => {
                merge(existing, incoming, &path, source, provenance);
            }
            (_, value) => {
                forget(provenance, &path);
                record(&value, &path, source, provenance);
                dst.insert(key, value);
            }
        }
    }
}

/// Removes the provenance of `path` and everything under it.
fn forget(provenance: &mut BTreeMap<String, Source>, path: &str) {
    provenance.remove(path);
    let child_prefix = format!("{path}.");
    let children: Vec<String> = provenance
        .range(child_prefix.clone()..)
        .take_while(|(k, _)| k.starts_with(&child_prefix))
        .map(|(k, _)| k.clone())
        .collect();
    for child in children {
        provenance.remove(&child);
    }
}

/// Records `source` for every leaf of `value` at `path`.
fn record(value: &Value, path: &str, source: &Source, provenance: &mut BTreeMap<String, Source>) {
    if let Value::Table(table) = value {
        for (key, child) in table {
            record(child, &join(path, key), source, provenance);
        }
    } else {
        provenance.insert(path.to_owned(), source.clone());
    }
}

/// The merged configuration, with the source of every value.
///
/// `Debug` shows the same redacted view as [`report`](Self::report).
#[derive(Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct LoadedConfig {
    table: Table,
    provenance: BTreeMap<String, Source>,
    sources: Vec<Source>,
}

impl fmt::Debug for LoadedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedConfig")
            .field("values", &self.report().entries)
            .field("sources", &self.sources)
            .finish_non_exhaustive()
    }
}

impl LoadedConfig {
    /// Every final value with the layer it came from, hiding the values of
    /// secret-looking keys (see [`is_secret_key`](crate::is_secret_key)).
    ///
    /// ```
    /// use rune_config::{ConfigLoader, EnvMapping};
    ///
    /// let loaded = ConfigLoader::new()
    ///     .with_defaults_toml("[db]\nhost = \"localhost\"\npassword = \"\"")
    ///     .with_env([("APP_DB__PASSWORD", "hunter2")], &EnvMapping::new().prefix("APP_"))
    ///     .load()?;
    /// assert_eq!(
    ///     loaded.report().to_string(),
    ///     "db.host = \"localhost\"  # built-in default\n\
    ///      db.password = <redacted>  # environment variable APP_DB__PASSWORD\n",
    /// );
    /// # Ok::<(), rune_config::ConfigErrors>(())
    /// ```
    #[must_use]
    pub fn report(&self) -> ConfigReport {
        self.report_with(|_| false)
    }

    /// Like [`report`](Self::report), also hiding the values of keys for
    /// which `secret` returns `true` (it receives the dotted key).
    #[must_use]
    pub fn report_with(&self, secret: impl Fn(&str) -> bool) -> ConfigReport {
        let entries = self
            .provenance
            .iter()
            .map(|(key, source)| {
                let redacted = is_secret_key(key) || secret(key);
                let value = if redacted {
                    REDACTED.to_owned()
                } else {
                    parse_key(key)
                        .ok()
                        .and_then(|segments| lookup(&self.table, &segments))
                        .map_or_else(String::new, ToString::to_string)
                };
                ReportEntry {
                    key: key.clone(),
                    value,
                    source: source.clone(),
                    redacted,
                }
            })
            .collect();
        ConfigReport { entries }
    }

    /// The merged TOML table.
    #[must_use]
    pub const fn table(&self) -> &Table {
        &self.table
    }

    /// Consumes the configuration, returning the merged table.
    #[must_use]
    pub fn into_table(self) -> Table {
        self.table
    }

    /// The value at the dotted `key`, if set (and `key` is well-formed).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        lookup(&self.table, &parse_key(key).ok()?)
    }

    /// The layer that set the value at the dotted `key`.
    ///
    /// Provenance is tracked per leaf (any non-table value; an array is one
    /// leaf). A key inside an array resolves to the array's source; a table
    /// key has no single source and returns `None`.
    #[must_use]
    pub fn source_of(&self, key: &str) -> Option<&Source> {
        let segments = parse_key(key).ok()?;
        (1..=segments.len())
            .rev()
            .find_map(|n| self.provenance.get(&format_key(&segments[..n])))
    }

    /// Every leaf key (dotted, quoted as needed) with the layer that set it,
    /// sorted by key.
    pub fn provenance(&self) -> impl Iterator<Item = (&str, &Source)> {
        self.provenance.iter().map(|(k, s)| (k.as_str(), s))
    }

    /// The source of the leaf at (or above) `segments`, or, for a table,
    /// the one source shared by every leaf under it.
    fn attribute(&self, segments: &[String]) -> Option<&Source> {
        if let Some(source) = (1..=segments.len())
            .rev()
            .find_map(|n| self.provenance.get(&format_key(&segments[..n])))
        {
            return Some(source);
        }
        if segments.is_empty() {
            return None;
        }
        let child_prefix = format!("{}.", format_key(segments));
        let mut under = self
            .provenance
            .range(child_prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&child_prefix))
            .map(|(_, s)| s);
        let first = under.next()?;
        under.all(|s| s == first).then_some(first)
    }

    /// The layers that contributed, lowest priority first. Optional files
    /// that did not exist are absent.
    #[must_use]
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }

    /// The merged configuration as TOML text.
    ///
    /// # Errors
    ///
    /// A [`Source::Merged`] issue if the table cannot be written as TOML.
    pub fn to_toml_string(&self) -> Result<String, ConfigErrors> {
        toml::to_string(&self.table).map_err(|error| {
            ConfigIssue::new(Source::Merged, None, format!("cannot serialize: {error}")).into()
        })
    }

    /// Deserializes the merged configuration into `T`.
    ///
    /// A type error is attributed to the layer that set the offending key,
    /// so `rate_limit = "fast"` in the project file is reported against
    /// [`Source::ProjectFile`] with key `scan.rate_limit`.
    /// A problem with a whole table (a missing required field, an unknown
    /// sub-table) is attributed to the one layer that set every value in
    /// it; when several layers contributed, or the problem is at the top
    /// level, it is attributed to [`Source::Merged`] with the nearest key
    /// known.
    /// Use `#[serde(deny_unknown_fields)]` on `T` to reject unknown keys.
    ///
    /// # Errors
    ///
    /// The deserialization problem, attributed as described.
    pub fn deserialize<T: DeserializeOwned>(&self) -> Result<T, ConfigErrors> {
        let text = self.to_toml_string()?;
        toml::from_str(&text).map_err(|error| {
            let key = error
                .span()
                // An empty span marks the document root (e.g. a missing
                // top-level field): no key to blame.
                .filter(|span| !span.is_empty())
                .and_then(|span| DeTable::parse(&text).ok().map(|doc| (span, doc)))
                .and_then(|(span, doc)| locate(doc.get_ref(), &span, &[]));
            let source = key
                .as_deref()
                .and_then(|segments| self.attribute(segments))
                .cloned()
                .unwrap_or(Source::Merged);
            let key = key.filter(|k| !k.is_empty()).map(|k| format_key(&k));
            let mut message = error.message().trim_end().to_owned();
            if let Some(key) = key.as_deref().filter(|k| is_secret_key(k))
                && let Some(value) = self.get(key)
            {
                let raw = value
                    .as_str()
                    .map_or_else(|| value.to_string(), str::to_owned);
                message = scrub(message, &raw, true);
            }
            ConfigIssue::new(source, key, message).into()
        })
    }
}

/// Where every final value came from; see [`LoadedConfig::report`].
///
/// `Display` writes one `key = value  # source` line per value.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConfigReport {
    /// One entry per leaf, sorted by key.
    pub entries: Vec<ReportEntry>,
}

/// One line of a [`ConfigReport`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReportEntry {
    /// Dotted key.
    pub key: String,
    /// The value as inline TOML, or [`REDACTED`](crate::REDACTED).
    pub value: String,
    /// The layer that set it.
    pub source: Source,
    /// Whether the value was hidden.
    pub redacted: bool,
}

impl fmt::Display for ConfigReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for entry in &self.entries {
            writeln!(f, "{} = {}  # {}", entry.key, entry.value, entry.source)?;
        }
        Ok(())
    }
}

/// The deepest key whose key or value span contains the error span `at`.
///
/// Spans of tables opened by a `[header]` do not cover their body, so every
/// sub-table is searched before falling back to the current level.
fn locate(table: &DeTable<'_>, at: &Range<usize>, prefix: &[String]) -> Option<Vec<String>> {
    let mut hit = None;
    for (key, value) in table {
        let mut path = prefix.to_vec();
        path.push(key.get_ref().to_string());
        if let Some(sub) = value.get_ref().as_table()
            && let Some(found) = locate(sub, at, &path)
        {
            return Some(found);
        }
        // Arrays are provenance leaves: a hit anywhere inside one (including
        // the body of an `[[array.of.tables]]` entry) maps to the array key.
        if let Some(items) = value.get_ref().as_array()
            && items.iter().any(|item| {
                item.get_ref()
                    .as_table()
                    .is_some_and(|sub| locate(sub, at, &[]).is_some())
            })
        {
            return Some(path);
        }
        let contains = |span: Range<usize>| span.start <= at.start && at.end <= span.end;
        if hit.is_none() && (contains(key.span()) || contains(value.span())) {
            hit = Some(path);
        }
    }
    hit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> Table {
        text.parse().unwrap()
    }

    #[test]
    fn later_layers_win_and_tables_merge_deeply() {
        let loaded = ConfigLoader::new()
            .with_defaults(table("a = 1\n[t]\nx = 1\ny = 1\n"))
            .with_table(Source::Inline("one".into()), table("[t]\ny = 2\nz = 2\n"))
            .with_table(Source::Inline("two".into()), table("a = [1, 2]\n"))
            .load()
            .unwrap();
        assert_eq!(
            loaded.table(),
            &table("a = [1, 2]\n[t]\nx = 1\ny = 2\nz = 2\n")
        );
        assert_eq!(loaded.source_of("a"), Some(&Source::Inline("two".into())));
        assert_eq!(loaded.source_of("t.x"), Some(&Source::Default));
        assert_eq!(loaded.source_of("t.y"), Some(&Source::Inline("one".into())));
        assert_eq!(loaded.source_of("t"), None);
        assert_eq!(loaded.sources().len(), 3);
    }

    #[test]
    fn replacing_a_table_drops_its_old_provenance() {
        let loaded = ConfigLoader::new()
            .with_defaults(table("[t]\nx = 1\n"))
            .with_table(Source::Inline("flat".into()), table("t = 3\n"))
            .load()
            .unwrap();
        assert_eq!(loaded.provenance().count(), 1);
        assert_eq!(loaded.source_of("t"), Some(&Source::Inline("flat".into())));
        assert_eq!(
            loaded.source_of("t.x"),
            Some(&Source::Inline("flat".into()))
        );
    }

    #[test]
    fn forget_does_not_touch_siblings_sharing_a_prefix() {
        let loaded = ConfigLoader::new()
            .with_defaults(table("[a]\nx = 1\n[ab]\nx = 1\n"))
            .with_table(Source::Inline("top".into()), table("a = 0\n"))
            .load()
            .unwrap();
        assert_eq!(loaded.source_of("ab.x"), Some(&Source::Default));
    }

    #[test]
    fn syntax_errors_name_the_layer_and_line() {
        let errors = ConfigLoader::new()
            .with_toml(Source::Inline("good".into()), "a = 1")
            .with_toml(Source::Inline("bad".into()), "a = 1\nb = = 2\n")
            .load()
            .unwrap_err();
        let [issue] = errors.issues() else {
            panic!("{errors}")
        };
        assert_eq!(issue.source, Source::Inline("bad".into()));
        assert!(issue.message.contains("line 2"), "{}", issue.message);
    }

    #[test]
    fn line_col_handles_offsets_inside_multibyte_chars() {
        assert_eq!(line_col("é\nab", 1), (1, 1));
        assert_eq!(line_col("é\nab", 4), (2, 2));
        assert_eq!(line_col("x", 99), (1, 2));
    }
}
