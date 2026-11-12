//! Reading pre-request scripts as data.
//!
//! Scripts are never executed. What can be read without running them is a
//! variable assignment whose key and value are both literals, such as
//! `pm.environment.set("token", "abc")`: the value is applied to the scope
//! the script runs in. An assignment of a computed value is reported, and
//! the variable stays as it was.

use crate::vars::Target;

/// The assignment functions recognised, and the scope each one writes.
const SETTERS: [(&str, Target); 6] = [
    ("pm.globals.set", Target::Global),
    ("pm.collectionVariables.set", Target::Collection),
    ("pm.environment.set", Target::Environment),
    ("pm.variables.set", Target::Local),
    ("postman.setGlobalVariable", Target::Global),
    ("postman.setEnvironmentVariable", Target::Environment),
];

/// A literal assignment found in a script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub target: Target,
    pub key: String,
    pub value: String,
}

/// What a script assigns: literal assignments, and the keys (or `?`) of
/// assignments whose value is computed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assignments {
    pub literal: Vec<Assignment>,
    pub computed: Vec<String>,
}

/// Replaces comments with spaces, leaving string contents alone, so that a
/// commented-out assignment is not read.
fn strip_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        if let Some(open) = quote {
            out.push(c);
            if c == '\\' {
                if let Some(escaped) = chars.next() {
                    out.push(escaped);
                }
            } else if c == open {
                quote = None;
            }
            continue;
        }
        match (c, chars.peek()) {
            ('/', Some('/')) => {
                for skipped in chars.by_ref() {
                    if skipped == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut previous = ' ';
                for skipped in chars.by_ref() {
                    if previous == '*' && skipped == '/' {
                        break;
                    }
                    previous = skipped;
                }
                out.push(' ');
            }
            ('"' | '\'' | '`', _) => {
                quote = Some(c);
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// A cursor over script text.
struct Cursor<'a> {
    rest: &'a str,
}

impl Cursor<'_> {
    fn skip_space(&mut self) {
        self.rest = self.rest.trim_start();
    }

    fn eat(&mut self, c: char) -> bool {
        self.skip_space();
        match self.rest.strip_prefix(c) {
            Some(rest) => {
                self.rest = rest;
                true
            }
            None => false,
        }
    }

    /// A JavaScript string literal without interpolation.
    fn string(&mut self) -> Option<String> {
        self.skip_space();
        let mut chars = self.rest.char_indices();
        let (_, quote) = chars.next()?;
        if !matches!(quote, '"' | '\'' | '`') {
            return None;
        }
        let mut out = String::new();
        while let Some((index, c)) = chars.next() {
            match c {
                '\\' => {
                    let (_, escaped) = chars.next()?;
                    match escaped {
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        '0' => out.push('\0'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'v' => out.push('\u{b}'),
                        'u' => {
                            let mut code = 0_u32;
                            for _ in 0..4 {
                                let (_, digit) = chars.next()?;
                                code = code * 16 + digit.to_digit(16)?;
                            }
                            out.push(char::from_u32(code)?);
                        }
                        '\n' => {}
                        other => out.push(other),
                    }
                }
                '$' if quote == '`' && self.rest[index..].starts_with("${") => return None,
                '\n' if quote != '`' => return None,
                c if c == quote => {
                    self.rest = &self.rest[index + c.len_utf8()..];
                    return Some(out);
                }
                c => out.push(c),
            }
        }
        None
    }

    /// A literal value: a string, a number, `true`, `false` or `null`
    /// (which Postman stores as text).
    fn literal(&mut self) -> Option<String> {
        self.skip_space();
        if let Some(text) = self.string() {
            return Some(text);
        }
        let end = self
            .rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_')))
            .unwrap_or(self.rest.len());
        let word = &self.rest[..end];
        let literal = matches!(word, "true" | "false" | "null")
            || (word.starts_with(|c: char| c.is_ascii_digit() || matches!(c, '-' | '+' | '.'))
                && word.parse::<f64>().is_ok());
        if literal {
            self.rest = &self.rest[end..];
            Some(word.to_owned())
        } else {
            None
        }
    }
}

/// Finds the variable assignments in a script.
pub fn assignments(source: &str) -> Assignments {
    let source = strip_comments(source);
    let mut found = Assignments::default();
    let mut position = 0;
    while position < source.len() {
        let next = SETTERS
            .iter()
            .filter_map(|(name, target)| {
                source[position..]
                    .find(name)
                    .map(|offset| (position + offset, *name, *target))
            })
            .min_by_key(|(start, _, _)| *start);
        let Some((start, name, target)) = next else {
            break;
        };
        position = start + name.len();
        let preceded = source[..start]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || matches!(c, '_' | '$' | '.'));
        if preceded {
            continue;
        }
        let mut cursor = Cursor {
            rest: &source[position..],
        };
        if !cursor.eat('(') {
            continue;
        }
        let Some(key) = cursor.string() else {
            found.computed.push("?".to_owned());
            continue;
        };
        let value = if cursor.eat(',') {
            cursor.literal()
        } else {
            None
        };
        match value {
            Some(value) if cursor.eat(')') => {
                found.literal.push(Assignment { target, key, value });
            }
            _ => found.computed.push(key),
        }
        position = source.len() - cursor.rest.len();
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn literal(source: &str) -> Vec<(Target, String, String)> {
        assignments(source)
            .literal
            .into_iter()
            .map(|found| (found.target, found.key, found.value))
            .collect()
    }

    #[test]
    fn reads_literal_assignments() {
        let script = r#"
            pm.environment.set("token", "abc");
            pm.collectionVariables.set('page', 2);
            pm.variables.set(`flag`, true);
            pm.globals.set("escaped", "a\"bA\n");
            postman.setEnvironmentVariable("legacy", "yes");
        "#;
        assert_eq!(
            literal(script),
            [
                (Target::Environment, "token".into(), "abc".into()),
                (Target::Collection, "page".into(), "2".into()),
                (Target::Local, "flag".into(), "true".into()),
                (Target::Global, "escaped".into(), "a\"bA\n".into()),
                (Target::Environment, "legacy".into(), "yes".into()),
            ]
        );
    }

    #[test]
    fn reports_computed_values() {
        let script = r#"
            pm.environment.set("ts", Date.now());
            pm.environment.set("sig", `${a}b`);
            pm.environment.set(name, "x");
            pm.environment.set("id", "1" + suffix);
        "#;
        let found = assignments(script);
        assert_eq!(found.literal.len(), 0);
        assert_eq!(found.computed, ["ts", "sig", "?", "id"]);
    }

    #[test]
    fn ignores_comments_and_lookalikes() {
        let script = r#"
            // pm.environment.set("a", "1");
            /* pm.environment.set("b", "2"); */
            my.pm.environment.set("c", "3");
            const s = "// not a comment"; pm.environment.set("d", "4");
        "#;
        assert_eq!(
            literal(script),
            [(Target::Environment, "d".into(), "4".into())]
        );
    }

    #[test]
    fn tolerates_truncated_scripts() {
        for script in [
            "pm.environment.set(",
            "pm.environment.set(\"a",
            "pm.environment.set(\"a\", \"b",
            "pm.globals.set(\"\\u12",
        ] {
            let _ = assignments(script);
        }
    }
}
