//! `serde` support for [`SecretRef`] (string or one-key table form).
//!
//! Error messages never echo the offending value: a misplaced secret in a
//! config file must not end up in the error report.

use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SecretRef;

const SCHEMES: &[&str] = &["env", "file", "cmd", "keychain", "vault"];

impl Serialize for SecretRef {
    /// Serializes as the `scheme:location` string, or as
    /// `{ cmd = [program, args…] }` when a command has no string form.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Command { program, args } if !self.has_string_form() => {
                let argv: Vec<&String> = std::iter::once(program).chain(args).collect();
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("cmd", &argv)?;
                map.end()
            }
            _ => serializer.collect_str(self),
        }
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    /// Accepts `"scheme:location"` or a table with exactly one key out of
    /// `env`, `file`, `cmd`, `keychain` and `vault`, whose value is the
    /// location string (for `cmd`, also an array `[program, args…]`).
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(RefVisitor)
    }
}

/// Rejects a value of the wrong type by naming the type only.
macro_rules! reject_by_kind {
    ($($method:ident: $ty:ty => $kind:literal),* $(,)?) => {$(
        fn $method<E: de::Error>(self, _value: $ty) -> Result<Self::Value, E> {
            Err(E::custom(format_args!("expected {}, found {}", Expecting(&self), $kind)))
        }
    )*};
}

/// Adapts a visitor's `expecting` for use in `format_args!`.
struct Expecting<'a, V>(&'a V);

impl<'de, V: Visitor<'de>> fmt::Display for Expecting<'_, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.expecting(f)
    }
}

struct RefVisitor;

impl<'de> Visitor<'de> for RefVisitor {
    type Value = SecretRef;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a secret reference (`env:VAR`, `file:/path`, `cmd:program args` or a table such as `{ cmd = [\"program\", \"arg\"] }`)")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<SecretRef, E> {
        text.parse().map_err(E::custom)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<SecretRef, A::Error> {
        let Some(scheme) = map.next_key::<String>()? else {
            return Err(de::Error::custom(
                "empty secret reference table; expected one of `env`, `file`, `cmd`, `keychain`, `vault`",
            ));
        };
        if !SCHEMES.contains(&scheme.as_str()) {
            // Name the allowed keys, not the given one: it may be a secret.
            return Err(de::Error::custom(format_args!(
                "unknown secret reference scheme; expected one of `{}`",
                SCHEMES.join("`, `")
            )));
        }
        let location = map.next_value::<Location>()?;
        if map.next_key::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(
                "a secret reference table must have exactly one key",
            ));
        }
        match location {
            Location::Text(text) => SecretRef::from_parts(&scheme, &text),
            Location::Argv(argv) if scheme == "cmd" => SecretRef::command(argv),
            Location::Argv(_) => {
                return Err(de::Error::custom(format_args!(
                    "`{scheme}` takes a string; only `cmd` accepts an array"
                )));
            }
        }
        .map_err(de::Error::custom)
    }

    reject_by_kind! {
        visit_bool: bool => "a boolean",
        visit_i64: i64 => "an integer",
        visit_u64: u64 => "an integer",
        visit_i128: i128 => "an integer",
        visit_u128: u128 => "an integer",
        visit_f64: f64 => "a float",
        visit_bytes: &[u8] => "bytes",
    }

    fn visit_seq<A: SeqAccess<'de>>(self, _seq: A) -> Result<SecretRef, A::Error> {
        Err(de::Error::custom(format_args!(
            "expected {}, found an array",
            Expecting(&self)
        )))
    }
}

/// The value under a table key: a string, or (for `cmd`) an argv array.
enum Location {
    Text(String),
    Argv(Vec<String>),
}

impl<'de> Deserialize<'de> for Location {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(LocationVisitor)
    }
}

struct LocationVisitor;

impl<'de> Visitor<'de> for LocationVisitor {
    type Value = Location;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string, or for `cmd` an array of strings")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<Location, E> {
        Ok(Location::Text(text.to_owned()))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Location, A::Error> {
        let mut argv = Vec::new();
        while let Some(word) = seq.next_element::<Word>()? {
            argv.push(word.0);
        }
        Ok(Location::Argv(argv))
    }

    fn visit_map<A: MapAccess<'de>>(self, _map: A) -> Result<Location, A::Error> {
        Err(de::Error::custom(format_args!(
            "expected {}, found a table",
            Expecting(&self)
        )))
    }

    reject_by_kind! {
        visit_bool: bool => "a boolean",
        visit_i64: i64 => "an integer",
        visit_u64: u64 => "an integer",
        visit_i128: i128 => "an integer",
        visit_u128: u128 => "an integer",
        visit_f64: f64 => "a float",
        visit_bytes: &[u8] => "bytes",
    }
}

/// One `cmd` array element: a string, rejected by kind otherwise.
struct Word(String);

impl<'de> Deserialize<'de> for Word {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(WordVisitor)
    }
}

struct WordVisitor;

impl<'de> Visitor<'de> for WordVisitor {
    type Value = Word;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a command argument string")
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<Word, E> {
        Ok(Word(text.to_owned()))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, _seq: A) -> Result<Word, A::Error> {
        Err(de::Error::custom(format_args!(
            "expected {}, found an array",
            Expecting(&self)
        )))
    }

    fn visit_map<A: MapAccess<'de>>(self, _map: A) -> Result<Word, A::Error> {
        Err(de::Error::custom(format_args!(
            "expected {}, found a table",
            Expecting(&self)
        )))
    }

    reject_by_kind! {
        visit_bool: bool => "a boolean",
        visit_i64: i64 => "an integer",
        visit_u64: u64 => "an integer",
        visit_i128: i128 => "an integer",
        visit_u128: u128 => "an integer",
        visit_f64: f64 => "a float",
        visit_bytes: &[u8] => "bytes",
    }
}
