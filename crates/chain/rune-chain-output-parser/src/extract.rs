//! Lenient extraction of a JSON value from free-form model output.
//!
//! Weaker and local models rarely return bare JSON. They wrap it in prose
//! ("Sure! Here is the result: …"), put it in a Markdown fence, leave trailing
//! commas, or stop mid-object when they hit a token limit. [`extract_json`]
//! tries, in order:
//!
//! 1. the whole (trimmed) text;
//! 2. the contents of each Markdown code fence;
//! 3. each balanced `{…}` / `[…]` span in the text, leftmost first;
//! 4. the text from the first `{` / `[` to the end, with unterminated strings,
//!    arrays and objects closed (truncated output).
//!
//! Each candidate is also retried with trailing commas removed. The first
//! candidate that parses as JSON wins. Nothing here interprets the value:
//! validation is the schema's job.
//!
//! Inputs above [`MAX_INPUT_BYTES`] and containers nested deeper than
//! [`MAX_NESTING`] are rejected, and the scan is iterative (no recursion),
//! so adversarial output cannot exhaust the stack or burn unbounded CPU.

use serde_json::Value;

/// Upper bound, in bytes, on the text the extractors and parsers in this
/// crate look at (4 MiB, the same as
/// [`rune_chain_core::MAX_JSON_OUTPUT_BYTES`]). Larger inputs are rejected.
pub const MAX_INPUT_BYTES: usize = rune_chain_core::MAX_JSON_OUTPUT_BYTES;

/// Upper bound on the nesting of JSON containers the repair code will
/// rebuild (matches `serde_json`'s own recursion limit).
pub const MAX_NESTING: usize = 128;

/// How many balanced-span start positions to try before giving up. Bounds the
/// work on adversarial input (the scan per start is linear).
const MAX_SPAN_STARTS: usize = 32;

/// Extract the most plausible JSON value from `text`.
///
/// Tries, in order: the whole trimmed text; the contents of each Markdown
/// code fence; each balanced `{…}` / `[…]` span, leftmost first; and finally
/// the text from the first `{` / `[` with unterminated strings, arrays and
/// objects closed (output cut off by a token limit). Each candidate is also
/// retried with trailing commas removed, and the first that parses wins.
/// Returns `None` when none does, or when `text` is longer than
/// [`MAX_INPUT_BYTES`].
///
/// # Example
///
/// ```rust
/// use rune_chain_output_parser::extract_json;
/// use serde_json::json;
///
/// let text = "Sure! Here you go:\n{\"name\": \"Ada\", \"tags\": [\"math\",],}\nAnything else?";
/// assert_eq!(extract_json(text), Some(json!({"name": "Ada", "tags": ["math"]})));
///
/// // Output cut off by a token limit.
/// assert_eq!(extract_json(r#"{"items": [1, 2"#), Some(json!({"items": [1, 2]})));
/// ```
#[must_use]
pub fn extract_json(text: &str) -> Option<Value> {
    if text.len() > MAX_INPUT_BYTES {
        return None;
    }
    let trimmed = text.trim();
    if let Some(v) = try_parse(trimmed) {
        return Some(v);
    }
    for block in fenced_blocks(trimmed) {
        if let Some(v) = try_parse(block) {
            return Some(v);
        }
    }
    let starts = trimmed
        .char_indices()
        .filter(|&(_, c)| c == '{' || c == '[')
        .map(|(i, _)| i)
        .take(MAX_SPAN_STARTS);
    for start in starts {
        if let Some(end) = balanced_end(&trimmed[start..])
            && let Some(v) = try_parse(&trimmed[start..start + end])
        {
            return Some(v);
        }
    }
    let start = trimmed.find(['{', '['])?;
    let closed = close_truncated(&trimmed[start..])?;
    try_parse(&closed)
}

/// Parse `s` as-is, then with trailing commas removed.
fn try_parse(s: &str) -> Option<Value> {
    if s.is_empty() {
        return None;
    }
    if let Ok(v) = serde_json::from_str(s) {
        return Some(v);
    }
    let fixed = remove_trailing_commas(s);
    if fixed.len() == s.len() {
        return None;
    }
    serde_json::from_str(&fixed).ok()
}

/// The contents of each ```` ``` ```` fence in `text`, skipping the info string
/// (e.g. `json`) on the opening line. An unclosed final fence runs to the end.
fn fenced_blocks(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("```") {
        let after = &rest[open + 3..];
        let body_start = after.find('\n').map_or(after.len(), |i| i + 1);
        let info = &after[..body_start];
        // A fence whose "info string" contains a brace is inline JSON
        // (```{"a":1}```), not a language tag.
        let body = if info.contains(['{', '[']) {
            after
        } else {
            &after[body_start..]
        };
        if let Some(close) = body.find("```") {
            out.push(body[..close].trim());
            rest = &body[close + 3..];
        } else {
            out.push(body.trim());
            break;
        }
    }
    out
}

/// Byte length of the balanced JSON container that starts at `s[0]`
/// (which must be `{` or `[`), honouring strings and escapes.
fn balanced_end(s: &str) -> Option<usize> {
    let mut stack: Vec<u8> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for (i, b) in s.bytes().enumerate() {
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' if stack.len() >= MAX_NESTING => return None,
            b'{' => stack.push(b'}'),
            b'[' => stack.push(b']'),
            b'}' | b']' => {
                if stack.pop() != Some(b) {
                    return None;
                }
                if stack.is_empty() {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Drop every `,` that is followed (after whitespace) by `}` or `]`, outside
/// strings.
pub fn remove_trailing_commas(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_string = false;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if in_string {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
        } else if c == '"' {
            in_string = true;
        } else if c == ',' {
            let next = s[i + 1..].trim_start().chars().next();
            if matches!(next, Some('}' | ']')) {
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// Close whatever `s` left open: an unterminated string, then each open array
/// and object, innermost first. A dangling `,` or `:` before the closers is
/// dropped. Returns `None` when `s` has mismatched closers or nothing is open.
fn close_truncated(s: &str) -> Option<String> {
    let mut stack: Vec<char> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for c in s.chars() {
        if in_string {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' | '[' if stack.len() >= MAX_NESTING => return None,
            '{' => stack.push('}'),
            '[' => stack.push(']'),
            '}' | ']' if stack.pop() != Some(c) => return None,
            _ => {}
        }
    }
    if stack.is_empty() && !in_string {
        return None;
    }
    let mut out = s.to_owned();
    if in_string {
        if escaped {
            out.pop();
        }
        out.push('"');
    }
    let kept = out.trim_end().trim_end_matches([',', ':']).len();
    out.truncate(kept);
    out.extend(stack.iter().rev());
    Some(out)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn plain_json() {
        assert_eq!(extract_json(" {\"a\": 1} "), Some(json!({"a": 1})));
        assert_eq!(extract_json("42"), Some(json!(42)));
        assert_eq!(extract_json("\"s\""), Some(json!("s")));
    }

    #[test]
    fn fenced() {
        assert_eq!(
            extract_json("Here:\n```json\n{\"a\": 1}\n```\nDone."),
            Some(json!({"a": 1}))
        );
        assert_eq!(extract_json("```\n[1,2]\n```"), Some(json!([1, 2])));
        assert_eq!(extract_json("```{\"a\":1}```"), Some(json!({"a": 1})));
        assert_eq!(extract_json("```json\n{\"a\": 1}"), Some(json!({"a": 1})));
    }

    #[test]
    fn embedded_in_prose() {
        assert_eq!(
            extract_json("The answer is {\"a\": \"}{\"} as requested."),
            Some(json!({"a": "}{"}))
        );
        // A non-JSON brace span first, then the real one.
        assert_eq!(
            extract_json("use {curly} braces: {\"ok\": true}"),
            Some(json!({"ok": true}))
        );
    }

    #[test]
    fn trailing_commas() {
        assert_eq!(
            extract_json("{\"a\": [1, 2, ], \"b\": \"x,]\",}"),
            Some(json!({"a": [1, 2], "b": "x,]"}))
        );
    }

    #[test]
    fn truncated() {
        assert_eq!(
            extract_json("{\"a\": {\"b\": [1, 2,"),
            Some(json!({"a": {"b": [1, 2]}}))
        );
        assert_eq!(
            extract_json("{\"a\": \"unterminat"),
            Some(json!({"a": "unterminat"}))
        );
        assert_eq!(extract_json("{\"a\": \"x\\"), Some(json!({"a": "x"})));
    }

    #[test]
    fn nothing_found() {
        assert_eq!(extract_json(""), None);
        assert_eq!(extract_json("no json here"), None);
        assert_eq!(extract_json("{ not: json }"), None);
        assert_eq!(extract_json("]"), None);
        assert_eq!(extract_json("{\"a\": 1]"), None);
    }

    #[test]
    fn caps() {
        let deep = "[".repeat(MAX_NESTING + 1);
        assert_eq!(extract_json(&deep), None);
        let ok = format!("{}{}", "[".repeat(10), "]".repeat(10));
        assert!(extract_json(&ok).is_some());
        let huge = format!("{{\"a\": \"{}\"}}", "x".repeat(MAX_INPUT_BYTES));
        assert_eq!(extract_json(&huge), None);
    }

    #[test]
    fn escaped_quotes_inside_strings() {
        assert_eq!(
            extract_json(r#"x {"q": "say \"}\" now"} y"#),
            Some(json!({"q": "say \"}\" now"}))
        );
    }
}
