//! Deserializing environment variables straight into a struct.

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{
    self, DeserializeOwned, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess, Visitor,
};

use crate::redact::{is_secret_key, scrub};

/// A problem turning environment variables into a value, naming the
/// variable when one is to blame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvError {
    var: Option<String>,
    key: Option<String>,
    message: String,
}

impl EnvError {
    fn new(var: Option<String>, message: impl Into<String>) -> Self {
        Self {
            var,
            key: None,
            message: message.into(),
        }
    }

    /// The environment variable at fault (for a missing field, the one
    /// that would set it).
    #[must_use]
    pub fn var(&self) -> Option<&str> {
        self.var.as_deref()
    }

    /// The dotted field path, when known (`db.port`).
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    /// What is wrong, without the variable name.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for EnvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.var, &self.key) {
            (Some(var), _) => write!(f, "environment variable {var}: {}", self.message),
            (None, Some(key)) => write!(f, "`{key}`: {}", self.message),
            (None, None) => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for EnvError {}

impl de::Error for EnvError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::new(None, msg.to_string())
    }
}

/// Deserializes `T` from the process environment, using every variable
/// (no prefix) and the default [`EnvReader`] settings.
///
/// # Errors
///
/// See [`EnvReader::from_vars`].
///
/// ```
/// # #[derive(serde::Deserialize)] struct Config { path: Option<String> }
/// let config: Config = rune_config::from_env()?;
/// # Ok::<(), rune_config::EnvError>(())
/// ```
pub fn from_env<T: DeserializeOwned>() -> Result<T, EnvError> {
    EnvReader::new().from_env()
}

/// Reads environment variables into a `serde` type.
///
/// Each variable that starts with the [prefix](Self::prefix) becomes a
/// field: the rest of its name is lower-cased and split on the
/// [separator](Self::separator) (`__` by default) into nested fields, so
/// with prefix `APP_`, `APP_DB__HOST` sets `db.host`.
///
/// Values are strings converted on demand to the type each field asks for:
///
/// - integers, floats and `char` parse from the trimmed text;
/// - `bool` accepts `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off` in any
///   case;
/// - an `Option` is `None` when the variable is unset *or empty*;
/// - a list (`Vec`, sets, tuples) is either JSON (`["a", "b"]`, when the
///   trimmed value starts with `[`) or comma-separated, with items trimmed
///   and empty items dropped, each item converted to the element type;
/// - a struct or map field may also be given whole as a JSON object
///   (`APP_DB={"host":"x"}`);
/// - an enum takes a unit variant by name, or JSON for other variants.
///
/// A field without a variable is simply absent, so `#[serde(default)]`
/// applies, and a missing required field is reported with the variable
/// that would set it. Unknown variables are ignored unless the type uses
/// `#[serde(deny_unknown_fields)]`. Values of secret-looking variables (see
/// [`is_secret_key`](crate::is_secret_key)) are kept out of error messages.
///
/// Because every leaf is text, `#[serde(flatten)]` and untagged enums only
/// work with string fields.
///
/// ```
/// use rune_config::EnvReader;
/// use serde::Deserialize;
///
/// #[derive(Debug, Deserialize)]
/// struct Config {
///     debug: bool,
///     db: Db,
///     #[serde(default)]
///     origins: Vec<String>,
///     timeout_secs: Option<u64>,
/// }
///
/// #[derive(Debug, Deserialize)]
/// struct Db {
///     host: String,
///     port: u16,
/// }
///
/// let vars = [
///     ("APP_DEBUG", "yes"),
///     ("APP_DB__HOST", "localhost"),
///     ("APP_DB__PORT", "5432"),
///     ("APP_ORIGINS", "https://a.example, https://b.example"),
///     ("UNRELATED", "ignored"),
/// ];
/// let config: Config = EnvReader::new().prefix("APP_").from_vars(vars)?;
/// assert!(config.debug);
/// assert_eq!(config.db.port, 5432);
/// assert_eq!(config.origins.len(), 2);
/// assert_eq!(config.timeout_secs, None);
///
/// let err = EnvReader::new()
///     .prefix("APP_")
///     .from_vars::<Config, _, _, _>([("APP_DEBUG", "1"), ("APP_DB__PORT", "high")])
///     .unwrap_err();
/// assert_eq!(err.var(), Some("APP_DB__PORT"));
/// assert_eq!(err.to_string(), "environment variable APP_DB__PORT: expected u16, got `high`");
/// # Ok::<(), rune_config::EnvError>(())
/// ```
#[derive(Clone, Debug)]
#[must_use]
pub struct EnvReader {
    prefix: String,
    separator: String,
    case_insensitive: bool,
}

impl Default for EnvReader {
    fn default() -> Self {
        Self {
            prefix: String::new(),
            separator: "__".to_owned(),
            case_insensitive: false,
        }
    }
}

impl EnvReader {
    /// No prefix, separator `__`, case-sensitive.
    pub fn new() -> Self {
        Self::default()
    }

    /// Only variables starting with `prefix` are used, with the prefix
    /// removed. The default empty prefix uses every variable.
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// The text between nesting levels (default `__`). An empty separator
    /// turns nesting off.
    pub fn separator(mut self, separator: impl Into<String>) -> Self {
        self.separator = separator.into();
        self
    }

    /// Matches the prefix ignoring ASCII case, and matches names to struct
    /// fields ignoring ASCII case, so `app_db__host` sets `db.host` and
    /// `APP_MAXCONN` sets a field renamed to `maxConn`. Two variables that
    /// then name the same field are an error. Off by default: the prefix
    /// must match exactly and the lower-cased name must equal the field.
    pub const fn case_insensitive(mut self, on: bool) -> Self {
        self.case_insensitive = on;
        self
    }

    /// Deserializes `T` from the process environment. Variables whose
    /// names are not UTF-8 are skipped.
    ///
    /// # Errors
    ///
    /// As [`from_vars`](Self::from_vars), plus a matching variable whose
    /// value is not UTF-8.
    pub fn from_env<T: DeserializeOwned>(&self) -> Result<T, EnvError> {
        let mut vars = Vec::new();
        for (name, value) in std::env::vars_os() {
            let Ok(name) = name.into_string() else {
                continue;
            };
            if self.strip_prefix(&name).is_none() {
                continue;
            }
            let value = value
                .into_string()
                .map_err(|_| EnvError::new(Some(name.clone()), "value is not valid UTF-8"))?;
            vars.push((name, value));
        }
        self.from_vars(vars)
    }

    /// Deserializes `T` from `vars`, such as a map from a test, the pairs of
    /// a [`Dotenv`](crate::Dotenv), or several sources chained together.
    /// When the same name appears more than once, the last value wins.
    ///
    /// # Errors
    ///
    /// An [`EnvError`] naming the variable for a value that does not
    /// convert, a name that leaves an empty segment (`APP_A____B`), a name
    /// used both as a value and as a group (`APP_DB` and `APP_DB__HOST`),
    /// or a missing required field.
    pub fn from_vars<T, I, K, V>(&self, vars: I) -> Result<T, EnvError>
    where
        T: DeserializeOwned,
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut root = BTreeMap::new();
        for (name, value) in vars {
            let name = name.as_ref();
            let Some(rest) = self.strip_prefix(name) else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            self.insert(&mut root, name, rest, value.as_ref())?;
        }
        T::deserialize(MapDe {
            map: root,
            path: Vec::new(),
            reader: self,
        })
    }

    fn strip_prefix<'n>(&self, name: &'n str) -> Option<&'n str> {
        if self.case_insensitive {
            let head = name.get(..self.prefix.len())?;
            head.eq_ignore_ascii_case(&self.prefix)
                .then(|| &name[self.prefix.len()..])
        } else {
            name.strip_prefix(&self.prefix)
        }
    }

    fn insert(
        &self,
        root: &mut BTreeMap<String, Node>,
        name: &str,
        rest: &str,
        value: &str,
    ) -> Result<(), EnvError> {
        let segments: Vec<String> = if self.separator.is_empty() {
            vec![rest.to_ascii_lowercase()]
        } else {
            rest.split(self.separator.as_str())
                .map(str::to_ascii_lowercase)
                .collect()
        };
        if segments.iter().any(String::is_empty) {
            return Err(EnvError::new(
                Some(name.to_owned()),
                format!(
                    "cannot derive a field name (empty part between `{}`)",
                    self.separator
                ),
            ));
        }
        let Some((last, parents)) = segments.split_last() else {
            return Ok(());
        };
        let mut map = root;
        for segment in parents {
            let node = map
                .entry(segment.clone())
                .or_insert_with(|| Node::Map(BTreeMap::new()));
            map = match node {
                Node::Map(inner) => inner,
                Node::Leaf { var, .. } => return Err(conflict(var, name)),
            };
        }
        match map.get(last) {
            Some(Node::Map(inner)) => {
                let other = first_var(inner).unwrap_or_default();
                Err(conflict(&other, name))
            }
            Some(Node::Leaf { var, .. }) if var != name => Err(EnvError::new(
                Some(name.to_owned()),
                format!("sets the same field as {var}"),
            )),
            _ => {
                map.insert(
                    last.clone(),
                    Node::Leaf {
                        var: name.to_owned(),
                        raw: value.to_owned(),
                    },
                );
                Ok(())
            }
        }
    }

    /// The variable name that would set the field at `path`.
    fn var_for(&self, path: &[String]) -> String {
        let mut name = self.prefix.clone();
        let sep = if self.separator.is_empty() {
            "_"
        } else {
            &self.separator
        };
        for (i, segment) in path.iter().enumerate() {
            if i > 0 {
                name.push_str(sep);
            }
            name.push_str(&segment.to_ascii_uppercase());
        }
        name
    }
}

fn conflict(a: &str, b: &str) -> EnvError {
    EnvError::new(
        Some(b.to_owned()),
        format!("conflicts with {a}: one names a value, the other a group of fields"),
    )
}

fn first_var(map: &BTreeMap<String, Node>) -> Option<String> {
    map.values().find_map(|node| match node {
        Node::Leaf { var, .. } => Some(var.clone()),
        Node::Map(inner) => first_var(inner),
    })
}

#[derive(Debug)]
enum Node {
    Leaf { var: String, raw: String },
    Map(BTreeMap<String, Self>),
}

/// A group of variables, deserialized as a map or struct.
struct MapDe<'r> {
    map: BTreeMap<String, Node>,
    path: Vec<String>,
    reader: &'r EnvReader,
}

impl MapDe<'_> {
    fn visit<'de, V: Visitor<'de>>(
        self,
        visitor: V,
        fields: Option<&'static [&'static str]>,
    ) -> Result<V::Value, EnvError> {
        let path = self.path.clone();
        let reader = self.reader;
        let mut entries: Vec<(String, String, Node)> = Vec::with_capacity(self.map.len());
        for (key, node) in self.map {
            let field = fields
                .and_then(|fields| {
                    fields.iter().find(|f| {
                        if reader.case_insensitive {
                            f.eq_ignore_ascii_case(&key)
                        } else {
                            **f == key
                        }
                    })
                })
                .map_or_else(|| key.clone(), |f| (*f).to_owned());
            entries.push((field, key, node));
        }
        visitor
            .visit_map(Entries {
                iter: entries.into_iter(),
                pending: None,
                path: &path,
                reader,
            })
            .map_err(|error| attach(error, &path, reader))
    }
}

/// Fills in the variable or key of an error raised by a struct or map.
fn attach(mut error: EnvError, path: &[String], reader: &EnvReader) -> EnvError {
    if error.var.is_some() || error.key.is_some() {
        return error;
    }
    if let Some(field) = error
        .message
        .strip_prefix("missing field `")
        .and_then(|rest| rest.strip_suffix('`'))
    {
        let mut full = path.to_vec();
        full.push(field.to_owned());
        error.var = Some(reader.var_for(&full));
        error.message = format!("not set (required by `{}`)", full.join("."));
        return error;
    }
    if !path.is_empty() {
        error.key = Some(path.join("."));
    }
    error
}

struct Entries<'a, 'r> {
    iter: std::vec::IntoIter<(String, String, Node)>,
    pending: Option<(String, Node)>,
    path: &'a [String],
    reader: &'r EnvReader,
}

impl<'de> MapAccess<'de> for Entries<'_, '_> {
    type Error = EnvError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, EnvError> {
        let Some((field, key, node)) = self.iter.next() else {
            return Ok(None);
        };
        let value = seed.deserialize(field.into_deserializer())?;
        self.pending = Some((key, node));
        Ok(Some(value))
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, EnvError> {
        let Some((key, node)) = self.pending.take() else {
            return Err(EnvError::new(None, "value requested before key"));
        };
        let mut path = self.path.to_vec();
        path.push(key);
        match node {
            Node::Leaf { var, raw } => seed.deserialize(LeafDe {
                var: &var,
                raw: &raw,
            }),
            Node::Map(map) => seed.deserialize(MapDe {
                map,
                path,
                reader: self.reader,
            }),
        }
    }
}

impl<'de> de::Deserializer<'de> for MapDe<'_> {
    type Error = EnvError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        self.visit(visitor, None)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, EnvError> {
        self.visit(visitor, Some(fields))
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        visitor.visit_some(self)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, EnvError> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        visitor.visit_unit()
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple tuple_struct map enum identifier
    }
}

/// One variable's value.
struct LeafDe<'a> {
    var: &'a str,
    raw: &'a str,
}

impl LeafDe<'_> {
    fn secret(&self) -> bool {
        is_secret_key(self.var)
    }

    fn error(&self, message: impl Into<String>) -> EnvError {
        EnvError::new(
            Some(self.var.to_owned()),
            scrub(message.into(), self.raw, self.secret()),
        )
    }

    /// Adds the variable to errors raised by visitors.
    fn wrap<T>(&self, result: Result<T, EnvError>) -> Result<T, EnvError> {
        result.map_err(|mut error| {
            if error.var.is_none() {
                error.var = Some(self.var.to_owned());
                error.message = scrub(error.message, self.raw, self.secret());
            }
            error
        })
    }

    fn expected(&self, what: &str) -> EnvError {
        if self.secret() {
            self.error(format!("expected {what}"))
        } else {
            self.error(format!("expected {what}, got `{}`", self.raw))
        }
    }

    /// Parses the value as JSON and hands it to `call`.
    fn json<'de, V: Visitor<'de>>(
        &self,
        visitor: V,
        call: impl FnOnce(serde_json::Value, V) -> Result<V::Value, serde_json::Error>,
    ) -> Result<V::Value, EnvError> {
        serde_json::from_str::<serde_json::Value>(self.raw)
            .and_then(|value| call(value, visitor))
            .map_err(|error| self.error(format!("invalid JSON: {error}")))
    }

    fn parse<T: std::str::FromStr>(&self, what: &str) -> Result<T, EnvError> {
        self.raw.trim().parse().map_err(|_| self.expected(what))
    }

    fn is_json(&self, open: char) -> bool {
        self.raw.trim_start().starts_with(open)
    }
}

macro_rules! parse_number {
    ($($method:ident => $visit:ident: $ty:ty),* $(,)?) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
            let n: $ty = self.parse(stringify!($ty))?;
            self.wrap(visitor.$visit(n))
        }
    )*};
}

impl<'de> de::Deserializer<'de> for LeafDe<'_> {
    type Error = EnvError;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        self.wrap(visitor.visit_str(self.raw))
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        let text = self.raw.trim();
        let truthy = ["true", "1", "yes", "on"];
        let falsy = ["false", "0", "no", "off"];
        let value = if truthy.iter().any(|t| text.eq_ignore_ascii_case(t)) {
            true
        } else if falsy.iter().any(|t| text.eq_ignore_ascii_case(t)) {
            false
        } else {
            return Err(self.expected("true or false"));
        };
        self.wrap(visitor.visit_bool(value))
    }

    parse_number! {
        deserialize_i8 => visit_i8: i8,
        deserialize_i16 => visit_i16: i16,
        deserialize_i32 => visit_i32: i32,
        deserialize_i64 => visit_i64: i64,
        deserialize_i128 => visit_i128: i128,
        deserialize_u8 => visit_u8: u8,
        deserialize_u16 => visit_u16: u16,
        deserialize_u32 => visit_u32: u32,
        deserialize_u64 => visit_u64: u64,
        deserialize_u128 => visit_u128: u128,
        deserialize_f32 => visit_f32: f32,
        deserialize_f64 => visit_f64: f64,
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        let mut chars = self.raw.chars();
        match (chars.next(), chars.next()) {
            (Some(c), None) => self.wrap(visitor.visit_char(c)),
            _ => Err(self.expected("a single character")),
        }
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        self.wrap(visitor.visit_str(self.raw))
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        self.wrap(visitor.visit_string(self.raw.to_owned()))
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        self.wrap(visitor.visit_bytes(self.raw.as_bytes()))
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        self.wrap(visitor.visit_byte_buf(self.raw.as_bytes().to_vec()))
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        if self.raw.trim().is_empty() {
            self.wrap(visitor.visit_none())
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        self.wrap(visitor.visit_unit())
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, EnvError> {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, EnvError> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        if self.is_json('[') {
            return self.json(visitor, |de, v| de::Deserializer::deserialize_seq(de, v));
        }
        #[allow(clippy::needless_collect, reason = "the count feeds size_hint")]
        let items: Vec<&str> = self
            .raw
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .collect();
        let var = self.var;
        let result = visitor.visit_seq(Items {
            var,
            items: items.into_iter(),
        });
        self.wrap(result)
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, EnvError> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, EnvError> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        if self.is_json('{') {
            return self.json(visitor, |de, v| de::Deserializer::deserialize_map(de, v));
        }
        Err(self.error(
            "expected a group of fields: set them as separate variables or as a JSON object",
        ))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, EnvError> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, EnvError> {
        if self.is_json('{') || self.is_json('"') {
            return self.json(visitor, |de, v| {
                de::Deserializer::deserialize_enum(de, name, variants, v)
            });
        }
        let variant: de::value::StrDeserializer<'_, EnvError> = self.raw.trim().into_deserializer();
        self.wrap(visitor.visit_enum(variant))
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, EnvError> {
        self.wrap(visitor.visit_unit())
    }
}

/// The items of a comma-separated list.
struct Items<'a> {
    var: &'a str,
    items: std::vec::IntoIter<&'a str>,
}

impl<'de> SeqAccess<'de> for Items<'_> {
    type Error = EnvError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, EnvError> {
        match self.items.next() {
            None => Ok(None),
            Some(raw) => seed.deserialize(LeafDe { var: self.var, raw }).map(Some),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.items.len())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};

    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Config {
        name: String,
        port: u16,
        #[serde(default)]
        debug: bool,
        db: Db,
        #[serde(default)]
        tags: Vec<String>,
        level: Option<Level>,
        ratio: Option<f64>,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Db {
        host: String,
        #[serde(default)]
        ports: Vec<u16>,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(rename_all = "lowercase")]
    enum Level {
        Debug,
        Info,
    }

    fn read<T: DeserializeOwned>(reader: &EnvReader, vars: &[(&str, &str)]) -> Result<T, EnvError> {
        reader.from_vars(vars.iter().copied())
    }

    fn app() -> EnvReader {
        EnvReader::new().prefix("APP_")
    }

    #[test]
    fn reads_nested_lists_options_and_enums() {
        let config: Config = read(
            &app(),
            &[
                ("APP_NAME", "007"),
                ("APP_PORT", " 8080 "),
                ("APP_DEBUG", "ON"),
                ("APP_DB__HOST", "db"),
                ("APP_DB__PORTS", "[1, 2]"),
                ("APP_TAGS", "a, b,,c"),
                ("APP_LEVEL", "info"),
                ("APP_RATIO", ""),
                ("OTHER", "x"),
            ],
        )
        .unwrap();
        assert_eq!(
            config,
            Config {
                name: "007".into(),
                port: 8080,
                debug: true,
                db: Db {
                    host: "db".into(),
                    ports: vec![1, 2],
                },
                tags: vec!["a".into(), "b".into(), "c".into()],
                level: Some(Level::Info),
                ratio: None,
            }
        );
    }

    #[test]
    fn errors_name_the_variable() {
        let base = [("APP_NAME", "x"), ("APP_PORT", "1"), ("APP_DB__HOST", "h")];
        let with = |extra: (&'static str, &'static str)| {
            let mut vars = base.to_vec();
            vars.push(extra);
            read::<Config>(&app(), &vars).unwrap_err()
        };
        let e = with(("APP_PORT", "99999"));
        assert_eq!(
            e.to_string(),
            "environment variable APP_PORT: expected u16, got `99999`"
        );
        let e = with(("APP_DB__PORTS", "1,x"));
        assert_eq!(e.var(), Some("APP_DB__PORTS"));
        let e = with(("APP_DB__PORTS", "[1,"));
        assert!(e.message().starts_with("invalid JSON"), "{e}");
        let e = with(("APP_LEVEL", "loud"));
        assert_eq!(e.var(), Some("APP_LEVEL"));
        assert!(e.message().contains("unknown variant"), "{e}");
        let e = with(("APP_DEBUG", "maybe"));
        assert_eq!(
            e.to_string(),
            "environment variable APP_DEBUG: expected true or false, got `maybe`"
        );
    }

    #[test]
    fn missing_fields_suggest_the_variable() {
        let e = read::<Config>(
            &app(),
            &[("APP_NAME", "x"), ("APP_PORT", "1"), ("APP_DB__PORTS", "1")],
        )
        .unwrap_err();
        assert_eq!(e.var(), Some("APP_DB__HOST"));
        assert_eq!(
            e.to_string(),
            "environment variable APP_DB__HOST: not set (required by `db.host`)"
        );
        let e = read::<Config>(&app(), &[]).unwrap_err();
        assert_eq!(e.var(), Some("APP_NAME"));
    }

    #[test]
    fn structural_conflicts() {
        let e = read::<Config>(&app(), &[("APP_DB", "x"), ("APP_DB__HOST", "h")]).unwrap_err();
        assert_eq!(e.var(), Some("APP_DB__HOST"));
        let e = read::<Config>(&app(), &[("APP_DB__HOST", "h"), ("APP_DB", "x")]).unwrap_err();
        assert_eq!(e.var(), Some("APP_DB"));
        let e = read::<Config>(&app(), &[("APP_A____B", "x")]).unwrap_err();
        assert_eq!(e.var(), Some("APP_A____B"));
    }

    #[test]
    fn last_duplicate_wins() {
        let v: HashMap<String, String> = read(&app(), &[("APP_X", "1"), ("APP_X", "2")]).unwrap();
        assert_eq!(v["x"], "2");
    }

    #[test]
    fn case_insensitive_matching() {
        #[derive(Debug, Deserialize)]
        struct C {
            #[serde(rename = "maxConn")]
            max_conn: u32,
        }
        assert!(read::<C>(&app(), &[("APP_MAXCONN", "3")]).is_err());
        let ci = app().case_insensitive(true);
        assert_eq!(read::<C>(&ci, &[("app_maxconn", "3")]).unwrap().max_conn, 3);
        let e = read::<C>(&ci, &[("APP_MAXCONN", "3"), ("app_maxconn", "4")]).unwrap_err();
        assert_eq!(e.var(), Some("app_maxconn"));
    }

    #[test]
    fn json_objects_maps_and_sets() {
        let c: Config = read(
            &app(),
            &[
                ("APP_NAME", "n"),
                ("APP_PORT", "1"),
                ("APP_DB", r#"{"host":"j","ports":[5]}"#),
            ],
        )
        .unwrap();
        assert_eq!(c.db.ports, [5]);
        let s: HashMap<String, BTreeSet<u8>> = read(&EnvReader::new(), &[("X", "3,1,3")]).unwrap();
        assert_eq!(s["x"].iter().copied().collect::<Vec<_>>(), [1, 3]);
    }

    #[test]
    fn custom_separator_and_no_nesting() {
        let c: HashMap<String, HashMap<String, String>> =
            read(&app().separator("."), &[("APP_A.B", "1")]).unwrap();
        assert_eq!(c["a"]["b"], "1");
        let flat: HashMap<String, String> =
            read(&app().separator(""), &[("APP_A__B", "1")]).unwrap();
        assert_eq!(flat["a__b"], "1");
    }

    #[test]
    fn secrets_stay_out_of_errors() {
        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct S {
            api_token: u32,
            mode: Level,
        }
        let e = read::<S>(
            &app(),
            &[("APP_API_TOKEN", "hunter2hunter2"), ("APP_MODE", "info")],
        )
        .unwrap_err();
        assert!(!e.to_string().contains("hunter2"), "{e}");
        let e = read::<S>(&app(), &[("APP_API_TOKEN", "1"), ("APP_MODE", "loud")]).unwrap_err();
        assert_eq!(e.var(), Some("APP_MODE"));
    }
}
