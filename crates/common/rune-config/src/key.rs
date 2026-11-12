//! Dotted key paths (`scan.rate_limit`, `servers."eu.west".host`).

use std::fmt::Write as _;

use toml::{Table, Value};

/// Whether `segment` can be written as a TOML bare key.
fn is_bare(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Formats one key segment, quoting it when it is not a bare key.
fn push_segment(out: &mut String, segment: &str) {
    if is_bare(segment) {
        out.push_str(segment);
        return;
    }
    out.push('"');
    for c in segment.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Appends `segment` to the dotted path `prefix`.
pub fn join(prefix: &str, segment: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + segment.len() + 1);
    out.push_str(prefix);
    if !prefix.is_empty() {
        out.push('.');
    }
    push_segment(&mut out, segment);
    out
}

/// Formats key segments as a dotted path, quoting segments as TOML does.
#[must_use]
pub fn format_key<S: AsRef<str>>(segments: &[S]) -> String {
    segments
        .iter()
        .fold(String::new(), |acc, segment| join(&acc, segment.as_ref()))
}

/// Parses a dotted key path such as `a.b` or `servers."eu.west".host`.
///
/// Segments are TOML bare keys (`A-Z a-z 0-9 - _`) or basic strings in
/// double quotes with the escapes `\"`, `\\`, `\n`, `\t`, `\r` and
/// `\uXXXX`. Whitespace
/// around a segment is ignored.
///
/// # Errors
///
/// A message describing the first problem, for an empty path, an empty or
/// invalid segment, or an unterminated quote.
pub fn parse_key(path: &str) -> Result<Vec<String>, String> {
    let mut segments = Vec::new();
    let mut chars = path.chars().peekable();
    loop {
        while chars.next_if(|c| *c == ' ' || *c == '\t').is_some() {}
        let mut segment = String::new();
        if chars.next_if_eq(&'"').is_some() {
            loop {
                match chars.next() {
                    None => return Err(format!("unterminated quote in key `{path}`")),
                    Some('"') => break,
                    Some('\\') => match chars.next() {
                        Some('"') => segment.push('"'),
                        Some('\\') => segment.push('\\'),
                        Some('n') => segment.push('\n'),
                        Some('t') => segment.push('\t'),
                        Some('r') => segment.push('\r'),
                        Some('u') => {
                            let hex: String = chars.by_ref().take(4).collect();
                            let c = u32::from_str_radix(&hex, 16)
                                .ok()
                                .filter(|_| hex.len() == 4)
                                .and_then(char::from_u32)
                                .ok_or_else(|| format!("invalid \\u escape in key `{path}`"))?;
                            segment.push(c);
                        }
                        _ => return Err(format!("unsupported escape in key `{path}`")),
                    },
                    Some(c) => segment.push(c),
                }
            }
        } else {
            while let Some(c) =
                chars.next_if(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            {
                segment.push(c);
            }
            if segment.is_empty() {
                return Err(format!("empty or invalid segment in key `{path}`"));
            }
        }
        segments.push(segment);
        while chars.next_if(|c| *c == ' ' || *c == '\t').is_some() {}
        match chars.next() {
            None => return Ok(segments),
            Some('.') => {}
            Some(c) => return Err(format!("unexpected `{c}` in key `{path}`")),
        }
    }
}

/// Builds `{ a = { b = value } }` from `["a", "b"]` and `value`.
pub fn nest(segments: &[String], value: Value) -> Table {
    let mut current = value;
    for segment in segments.iter().skip(1).rev() {
        let mut table = Table::new();
        table.insert(segment.clone(), current);
        current = Value::Table(table);
    }
    let mut root = Table::new();
    if let Some(first) = segments.first() {
        root.insert(first.clone(), current);
    }
    root
}

/// Looks up `segments` in `table`.
pub fn lookup<'a, S: AsRef<str>>(table: &'a Table, segments: &[S]) -> Option<&'a Value> {
    let (first, rest) = segments.split_first()?;
    let mut value = table.get(first.as_ref())?;
    for segment in rest {
        value = value.as_table()?.get(segment.as_ref())?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_and_quoted_segments() {
        assert_eq!(parse_key("a.b-c.d_e").unwrap(), ["a", "b-c", "d_e"]);
        assert_eq!(
            parse_key(r#"servers."eu.west" . host"#).unwrap(),
            ["servers", "eu.west", "host"]
        );
        assert_eq!(parse_key(r#""a\"b""#).unwrap(), ["a\"b"]);
    }

    #[test]
    fn rejects_bad_keys() {
        for bad in [
            "", ".", "a.", ".a", "a..b", "a b", r#""open"#, "a=b", r#""\q""#,
        ] {
            assert!(parse_key(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn formats_with_quotes_only_when_needed() {
        assert_eq!(format_key(&["a", "b"]), "a.b");
        assert_eq!(format_key(&["a", "b.c", ""]), r#"a."b.c"."""#);
        assert_eq!(format_key(&["new\nline"]), r#""new\nline""#);
    }

    #[test]
    fn nest_and_lookup_agree() {
        let segments = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        let table = nest(&segments, Value::Integer(7));
        assert_eq!(lookup(&table, &segments), Some(&Value::Integer(7)));
        assert!(lookup(&table, &["a", "x"]).is_none());
        assert!(lookup::<&str>(&table, &[]).is_none());
    }
}
