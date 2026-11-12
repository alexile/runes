//! Forgiving field deserializers for real-world HAR files.
//!
//! Exporters disagree on details the specification leaves no room for:
//! `null` where a string or object belongs, numbers written as strings,
//! fractional sizes, `0`/`1` for booleans. Every helper here accepts those
//! spellings and maps `null` to the field's "absent" value. A value of a
//! wholly different shape (an object where a number belongs) is still an
//! error, which skips the one entry that holds it.

use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer, Serializer};
use serde_json::Value;

/// Largest integer an `f64` represents exactly (2^53).
const EXACT_F64_INT: f64 = 9_007_199_254_740_992.0;

fn number_from_text(text: &str) -> Option<f64> {
    text.trim()
        .parse::<f64>()
        .ok()
        .filter(|number| number.is_finite())
}

fn number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => number_from_text(text),
        _ => None,
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "float-to-int casts saturate, and the value is finite and rounded"
)]
fn integer(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_f64().map(|float| float.round() as i64)),
        Value::String(text) => {
            let text = text.trim();
            text.parse::<i64>()
                .ok()
                .or_else(|| number_from_text(text).map(|float| float.round() as i64))
        }
        _ => None,
    }
}

fn unexpected<E: serde::de::Error>(value: &Value, expected: &str) -> E {
    E::custom(format!("expected {expected}, found {value}"))
}

/// A string; `null` reads as empty and numbers or booleans as their text.
pub fn string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    match Value::deserialize(deserializer)? {
        Value::String(text) => Ok(text),
        Value::Null => Ok(String::new()),
        Value::Number(number) => Ok(number.to_string()),
        Value::Bool(flag) => Ok(flag.to_string()),
        other => Err(unexpected(&other, "a string")),
    }
}

/// An optional string; `null` reads as `None`.
pub fn opt_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    match Value::deserialize(deserializer)? {
        Value::String(text) => Ok(Some(text)),
        Value::Null => Ok(None),
        Value::Number(number) => Ok(Some(number.to_string())),
        Value::Bool(flag) => Ok(Some(flag.to_string())),
        other => Err(unexpected(&other, "a string")),
    }
}

/// An optional integer; floats round, numeric strings parse, `null` and
/// non-numeric strings read as `None`.
pub fn opt_int<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i64>, D::Error> {
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Null | Value::String(_) | Value::Number(_) => Ok(integer(&value)),
        other => Err(unexpected(&other, "a number")),
    }
}

/// An integer that HAR marks unknown with `-1`; `null` reads as `-1`.
pub fn int_or_unknown<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    opt_int(deserializer).map(|number| number.unwrap_or(-1))
}

/// An integer whose absence reads as `0`.
pub fn int_or_zero<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    opt_int(deserializer).map(Option::unwrap_or_default)
}

/// An optional number; numeric strings parse, `null` and non-numeric
/// strings read as `None`.
pub fn opt_number<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<f64>, D::Error> {
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::Null | Value::String(_) | Value::Number(_) => Ok(number(&value)),
        other => Err(unexpected(&other, "a number")),
    }
}

/// A number whose absence reads as `0`.
pub fn number_or_zero<'de, D: Deserializer<'de>>(deserializer: D) -> Result<f64, D::Error> {
    opt_number(deserializer).map(Option::unwrap_or_default)
}

/// An optional boolean; also `"true"`/`"false"` and `0`/`1`.
pub fn opt_bool<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<bool>, D::Error> {
    match Value::deserialize(deserializer)? {
        Value::Bool(flag) => Ok(Some(flag)),
        Value::Null => Ok(None),
        Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Ok(Some(true)),
            "false" | "0" | "no" => Ok(Some(false)),
            _ => Ok(None),
        },
        Value::Number(number) => Ok(number.as_f64().map(|float| float != 0.0)),
        other => Err(unexpected(&other, "a boolean")),
    }
}

/// A list; `null` reads as empty.
pub fn list<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    match Value::deserialize(deserializer)? {
        Value::Null => Ok(Vec::new()),
        value @ Value::Array(_) => serde_json::from_value(value).map_err(D::Error::custom),
        other => Err(unexpected(&other, "an array")),
    }
}

/// A struct; `null` reads as its default.
pub fn or_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned + Default,
{
    match Value::deserialize(deserializer)? {
        Value::Null => Ok(T::default()),
        value => serde_json::from_value(value).map_err(D::Error::custom),
    }
}

/// An optional struct; `null` reads as `None`.
pub fn opt_struct<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    match Value::deserialize(deserializer)? {
        Value::Null => Ok(None),
        value => serde_json::from_value(value)
            .map(Some)
            .map_err(D::Error::custom),
    }
}

/// Writes whole numbers without a fraction (`42`, not `42.0`).
#[expect(
    clippy::cast_possible_truncation,
    reason = "only whole numbers within the exact f64 integer range are cast"
)]
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's serialize_with passes fields by reference"
)]
pub fn write_number<S: Serializer>(number: &f64, serializer: S) -> Result<S::Ok, S::Error> {
    if number.fract() == 0.0 && number.abs() <= EXACT_F64_INT {
        serializer.serialize_i64(*number as i64)
    } else {
        serializer.serialize_f64(*number)
    }
}

/// [`write_number`] for an optional number.
#[expect(
    clippy::ref_option,
    reason = "serde's serialize_with passes fields by reference"
)]
pub fn write_opt_number<S: Serializer>(
    number: &Option<f64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match number {
        Some(number) => write_number(number, serializer),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Debug, Default, Deserialize, PartialEq)]
    #[serde(default)]
    struct Probe {
        #[serde(deserialize_with = "super::string")]
        text: String,
        #[serde(deserialize_with = "super::opt_string")]
        maybe: Option<String>,
        #[serde(deserialize_with = "super::int_or_unknown")]
        size: i64,
        #[serde(deserialize_with = "super::opt_number")]
        time: Option<f64>,
        #[serde(deserialize_with = "super::opt_bool")]
        flag: Option<bool>,
        #[serde(deserialize_with = "super::list")]
        items: Vec<u8>,
    }

    fn probe(value: serde_json::Value) -> Probe {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn nulls_read_as_absent() {
        let parsed = probe(json!({
            "text": null, "maybe": null, "size": null, "time": null,
            "flag": null, "items": null
        }));
        assert_eq!(parsed.text, "");
        assert_eq!(parsed.maybe, None);
        assert_eq!(parsed.size, -1);
        assert_eq!(parsed.time, None);
        assert_eq!(parsed.flag, None);
        assert_eq!(parsed.items, Vec::<u8>::new());
    }

    #[test]
    fn alternative_spellings() {
        let parsed = probe(json!({
            "text": 12, "maybe": true, "size": "15", "time": "4.5",
            "flag": "TRUE", "items": [1, 2]
        }));
        assert_eq!(parsed.text, "12");
        assert_eq!(parsed.maybe.as_deref(), Some("true"));
        assert_eq!(parsed.size, 15);
        assert_eq!(parsed.time, Some(4.5));
        assert_eq!(parsed.flag, Some(true));
        assert_eq!(parsed.items, vec![1, 2]);
        assert_eq!(probe(json!({"size": 2.6})).size, 3);
        assert_eq!(probe(json!({"size": "n/a"})).size, -1);
        assert_eq!(probe(json!({"size": 1e300})).size, i64::MAX);
        assert_eq!(probe(json!({"flag": 0})).flag, Some(false));
    }

    #[test]
    fn wrong_shapes_are_errors() {
        for value in [
            json!({"text": {}}),
            json!({"size": []}),
            json!({"items": "x"}),
            json!({"flag": [true]}),
        ] {
            assert!(serde_json::from_value::<Probe>(value).is_err());
        }
    }

    #[test]
    fn whole_numbers_write_without_fraction() {
        let write = |number: f64| {
            let mut out = Vec::new();
            super::write_number(&number, &mut serde_json::Serializer::new(&mut out)).unwrap();
            String::from_utf8(out).unwrap()
        };
        assert_eq!(write(42.0), "42");
        assert_eq!(write(-1.0), "-1");
        assert_eq!(write(0.5), "0.5");
        assert_eq!(write(1e300), "1e+300");
    }
}
