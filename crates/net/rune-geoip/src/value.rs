//! [`Value`]: a decoded MMDB data-section value.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

use crate::Error;
use crate::decode::Decoder;

/// A value from an MMDB data section ([spec, "Output Data
/// Section"](https://maxmind.github.io/`MaxMind`-DB/#output-data-section)).
///
/// Each variant is one of the format's data types. Pointers are resolved
/// while decoding, so they never appear here. `Display` renders the value
/// as JSON (bytes as an array of numbers, non-finite floats as `null`).
///
/// ```
/// use std::collections::BTreeMap;
/// use rune_geoip::Value;
///
/// let value = Value::Map(BTreeMap::from([
///     ("iso_code".to_owned(), Value::from("NZ")),
///     ("geoname_id".to_owned(), Value::Uint32(2_186_224)),
/// ]));
/// let bytes = value.encode()?;
/// assert_eq!(Value::decode(&bytes)?, value);
/// assert_eq!(value.get("iso_code").and_then(Value::as_str), Some("NZ"));
/// assert_eq!(value.to_string(), r#"{"geoname_id":2186224,"iso_code":"NZ"}"#);
/// # Ok::<(), rune_geoip::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Value {
    /// UTF-8 string (type 2).
    String(String),
    /// IEEE 754 double (type 3).
    Double(f64),
    /// Raw bytes (type 4).
    Bytes(Vec<u8>),
    /// Unsigned 16-bit integer (type 5).
    Uint16(u16),
    /// Unsigned 32-bit integer (type 6).
    Uint32(u32),
    /// Map with string keys (type 7).
    Map(BTreeMap<String, Self>),
    /// Signed 32-bit integer (type 8).
    Int32(i32),
    /// Unsigned 64-bit integer (type 9).
    Uint64(u64),
    /// Unsigned 128-bit integer (type 10).
    Uint128(u128),
    /// Array (type 11).
    Array(Vec<Self>),
    /// Boolean (type 14).
    Bool(bool),
    /// IEEE 754 float (type 15).
    Float(f32),
}

impl Value {
    /// Decodes the value at the start of `bytes`. Pointers are resolved
    /// relative to the start of `bytes`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidData`] when the bytes are not a valid encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Decoder::new(bytes).decode(0)
    }

    /// Encodes the value in the MMDB data-section format (no pointers).
    ///
    /// # Errors
    ///
    /// [`Error::Build`] when a string, byte string, map or array is longer
    /// than the format allows (16 843 036 entries or bytes).
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        crate::encode::encode(self, &mut out)?;
        Ok(out)
    }

    /// The map entry under `key`, when this is a map.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        self.as_map()?.get(key)
    }

    /// Follows a path of map keys and array indexes (`["subdivisions", "0",
    /// "iso_code"]`).
    #[must_use]
    pub fn path(&self, path: &[&str]) -> Option<&Self> {
        path.iter().try_fold(self, |value, segment| match value {
            Self::Map(map) => map.get(*segment),
            Self::Array(items) => items.get(segment.parse::<usize>().ok()?),
            _ => None,
        })
    }

    /// The string, when this is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The value as a `u64`, when it is a non-negative integer that fits.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Self::Uint16(n) => Some(n.into()),
            Self::Uint32(n) => Some(n.into()),
            Self::Uint64(n) => Some(n),
            Self::Uint128(n) => u64::try_from(n).ok(),
            Self::Int32(n) => u64::try_from(n).ok(),
            _ => None,
        }
    }

    /// The value as an `f64`, when it is a double or a float.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match *self {
            Self::Double(n) => Some(n),
            Self::Float(n) => Some(n.into()),
            _ => None,
        }
    }

    /// The boolean, when this is a boolean.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match *self {
            Self::Bool(b) => Some(b),
            _ => None,
        }
    }

    /// The map, when this is a map.
    #[must_use]
    pub const fn as_map(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Map(map) => Some(map),
            _ => None,
        }
    }

    /// The items, when this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Self::Uint32(n)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<f64> for Value {
    fn from(n: f64) -> Self {
        Self::Double(n)
    }
}

impl From<BTreeMap<String, Self>> for Value {
    fn from(map: BTreeMap<String, Self>) -> Self {
        Self::Map(map)
    }
}

impl From<Vec<Self>> for Value {
    fn from(items: Vec<Self>) -> Self {
        Self::Array(items)
    }
}

fn write_json_str(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    f.write_char('"')?;
    for c in s.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            c if u32::from(c) < 0x20 => write!(f, "\\u{:04x}", u32::from(c))?,
            c => f.write_char(c)?,
        }
    }
    f.write_char('"')
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(s) => write_json_str(f, s),
            Self::Double(n) if n.is_finite() => write!(f, "{n}"),
            Self::Float(n) if n.is_finite() => write!(f, "{n}"),
            Self::Double(_) | Self::Float(_) => f.write_str("null"),
            Self::Bytes(bytes) => {
                f.write_char('[')?;
                for (i, b) in bytes.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    write!(f, "{b}")?;
                }
                f.write_char(']')
            }
            Self::Uint16(n) => write!(f, "{n}"),
            Self::Uint32(n) => write!(f, "{n}"),
            Self::Int32(n) => write!(f, "{n}"),
            Self::Uint64(n) => write!(f, "{n}"),
            Self::Uint128(n) => write!(f, "{n}"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Map(map) => {
                f.write_char('{')?;
                for (i, (key, value)) in map.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    write_json_str(f, key)?;
                    write!(f, ":{value}")?;
                }
                f.write_char('}')
            }
            Self::Array(items) => {
                f.write_char('[')?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    write!(f, "{item}")?;
                }
                f.write_char(']')
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_walks_maps_and_arrays() {
        let value = Value::Map(BTreeMap::from([(
            "subdivisions".to_owned(),
            Value::Array(vec![Value::Map(BTreeMap::from([(
                "iso_code".to_owned(),
                Value::from("ENG"),
            )]))]),
        )]));
        assert_eq!(
            value
                .path(&["subdivisions", "0", "iso_code"])
                .and_then(Value::as_str),
            Some("ENG")
        );
        assert_eq!(value.path(&["subdivisions", "1"]), None);
        assert_eq!(value.path(&["subdivisions", "x"]), None);
        assert_eq!(value.path(&[]), Some(&value));
    }

    #[test]
    fn numeric_accessors_widen() {
        assert_eq!(Value::Uint16(7).as_u64(), Some(7));
        assert_eq!(Value::Int32(-1).as_u64(), None);
        assert_eq!(Value::Uint128(u128::MAX).as_u64(), None);
        assert_eq!(Value::Float(1.5).as_f64(), Some(1.5));
        assert_eq!(Value::from("x").as_u64(), None);
    }

    #[test]
    fn displays_as_json() {
        let value = Value::Array(vec![
            Value::from("a\"b\\\n\u{1}"),
            Value::Bytes(vec![1, 2]),
            Value::Double(f64::NAN),
            Value::Bool(true),
            Value::Int32(-5),
        ]);
        assert_eq!(
            value.to_string(),
            r#"["a\"b\\\n\u0001",[1,2],null,true,-5]"#
        );
    }
}
