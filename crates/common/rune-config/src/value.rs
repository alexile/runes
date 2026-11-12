//! Turning raw strings from the environment or the command line into
//! typed TOML values.

use toml::Value;

/// How a raw string (an environment variable or a `key=value` flag) is
/// turned into a TOML value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ValueKind {
    /// Guess: `true`/`false` become booleans, decimal integers become
    /// integers, decimal numbers with a `.` or exponent become floats, and
    /// anything else stays a string. Use an explicit kind when a string
    /// field may hold something that looks like a number (`1.0`, `007`).
    #[default]
    Auto,
    /// Always a string, unchanged.
    String,
    /// A 64-bit signed integer (`_` separators allowed, surrounding
    /// whitespace ignored).
    Integer,
    /// A finite decimal number (`3`, `2.5`, `1e3`), as a float.
    Float,
    /// `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off` (ASCII case-insensitive).
    Boolean,
    /// A comma-separated list of strings. Items are trimmed and empty items
    /// dropped, so the empty string is an empty list.
    StringList,
}

impl ValueKind {
    /// Converts `raw` to a value of this kind.
    ///
    /// # Errors
    ///
    /// A message such as `expected an integer` when `raw` does not fit.
    pub fn parse(self, raw: &str) -> Result<Value, String> {
        match self {
            Self::Auto => Ok(auto(raw)),
            Self::String => Ok(Value::String(raw.to_owned())),
            Self::Integer => integer(raw.trim())
                .map(Value::Integer)
                .ok_or_else(|| format!("expected an integer, got `{raw}`")),
            Self::Float => float(raw.trim())
                .map(Value::Float)
                .ok_or_else(|| format!("expected a number, got `{raw}`")),
            Self::Boolean => boolean(raw.trim())
                .map(Value::Boolean)
                .ok_or_else(|| format!("expected true or false, got `{raw}`")),
            Self::StringList => Ok(Value::Array(
                raw.split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(|item| Value::String(item.to_owned()))
                    .collect(),
            )),
        }
    }
}

fn auto(raw: &str) -> Value {
    match raw {
        "true" => return Value::Boolean(true),
        "false" => return Value::Boolean(false),
        _ => {}
    }
    if let Some(i) = integer(raw) {
        return Value::Integer(i);
    }
    if raw.contains(['.', 'e', 'E'])
        && let Some(f) = float(raw)
    {
        return Value::Float(f);
    }
    Value::String(raw.to_owned())
}

/// Decimal integer with optional sign and `_` separators between digits.
fn integer(raw: &str) -> Option<i64> {
    let digits = raw.strip_prefix(['+', '-']).unwrap_or(raw);
    let well_formed = digits.starts_with(|c: char| c.is_ascii_digit())
        && digits.ends_with(|c: char| c.is_ascii_digit())
        && !digits.contains("__")
        && digits.bytes().all(|b| b.is_ascii_digit() || b == b'_');
    if !well_formed {
        return None;
    }
    raw.replace('_', "").parse().ok()
}

/// Finite decimal float; rejects `inf`, `nan` and hex forms.
fn float(raw: &str) -> Option<f64> {
    let plain = raw
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'));
    if !plain || !raw.bytes().any(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse::<f64>().ok().filter(|f| f.is_finite())
}

fn boolean(raw: &str) -> Option<bool> {
    const TRUE: [&str; 4] = ["true", "1", "yes", "on"];
    const FALSE: [&str; 4] = ["false", "0", "no", "off"];
    if TRUE.iter().any(|t| raw.eq_ignore_ascii_case(t)) {
        Some(true)
    } else if FALSE.iter().any(|f| raw.eq_ignore_ascii_case(f)) {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_guesses_scalars() {
        assert_eq!(ValueKind::Auto.parse("true"), Ok(Value::Boolean(true)));
        assert_eq!(ValueKind::Auto.parse("-12"), Ok(Value::Integer(-12)));
        assert_eq!(ValueKind::Auto.parse("1_000"), Ok(Value::Integer(1000)));
        assert_eq!(ValueKind::Auto.parse("2.5"), Ok(Value::Float(2.5)));
        assert_eq!(ValueKind::Auto.parse("1e3"), Ok(Value::Float(1000.0)));
        for text in [
            "hello", "inf", "nan", "1.2.3", "TRUE", "", "_1", "1__0", "e",
        ] {
            assert_eq!(
                ValueKind::Auto.parse(text),
                Ok(Value::String(text.to_owned())),
                "{text:?}"
            );
        }
    }

    #[test]
    fn explicit_kinds_check_their_input() {
        assert_eq!(
            ValueKind::String.parse("42"),
            Ok(Value::String("42".into()))
        );
        assert_eq!(ValueKind::Integer.parse(" 42 "), Ok(Value::Integer(42)));
        assert!(ValueKind::Integer.parse("4.2").is_err());
        assert!(ValueKind::Integer.parse("99999999999999999999").is_err());
        assert_eq!(ValueKind::Float.parse("3"), Ok(Value::Float(3.0)));
        assert!(ValueKind::Float.parse("inf").is_err());
        assert_eq!(ValueKind::Boolean.parse("Yes"), Ok(Value::Boolean(true)));
        assert_eq!(ValueKind::Boolean.parse("off"), Ok(Value::Boolean(false)));
        assert!(ValueKind::Boolean.parse("maybe").is_err());
        assert_eq!(
            ValueKind::StringList.parse(" a, b ,,c "),
            Ok(Value::Array(vec!["a".into(), "b".into(), "c".into()]))
        );
        assert_eq!(ValueKind::StringList.parse(""), Ok(Value::Array(vec![])));
    }
}
