//! The `tag=value; tag=value` list shared by DKIM, DMARC, MTA-STS, TLS-RPT
//! and BIMI (RFC 6376 §3.2).

use crate::error::{Error, RecordKind};

/// One `tag=value` pair, whitespace around both trimmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

/// Whitespace allowed around tags and values (`WSP` and folding `CRLF`).
pub const fn is_fws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// Parses a tag list. Empty segments (`;;`, a trailing `;`) are skipped.
/// Tag names are ASCII letters, digits and `_`, starting with a letter;
/// values are printable ASCII and whitespace, without `;`.
///
/// With `fold_case`, duplicates are detected ignoring ASCII case (the
/// caller then matches names case-insensitively too).
pub fn parse(input: &str, record: RecordKind, fold_case: bool) -> Result<Vec<Tag<'_>>, Error> {
    let mut tags: Vec<Tag<'_>> = Vec::new();
    for segment in input.split(';') {
        let segment = segment.trim_matches(is_fws);
        if segment.is_empty() {
            continue;
        }
        let Some((name, value)) = segment.split_once('=') else {
            return Err(Error::syntax(record, segment, "tag without `=`"));
        };
        let name = name.trim_matches(is_fws);
        let value = value.trim_matches(is_fws);
        let mut chars = name.chars();
        let valid_name = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid_name {
            return Err(Error::syntax(record, segment, "invalid tag name"));
        }
        if !value.chars().all(|c| is_fws(c) || ('!'..='~').contains(&c)) {
            return Err(Error::syntax(
                record,
                segment,
                "invalid character in tag value",
            ));
        }
        let duplicate = tags.iter().any(|tag| {
            if fold_case {
                tag.name.eq_ignore_ascii_case(name)
            } else {
                tag.name == name
            }
        });
        if duplicate {
            return Err(Error::DuplicateTag {
                record,
                tag: crate::error::truncate(name),
            });
        }
        tags.push(Tag { name, value });
    }
    Ok(tags)
}

/// Splits a value list on `sep`, trimming whitespace around each item.
pub fn list(value: &str, sep: char) -> impl Iterator<Item = &str> {
    value.split(sep).map(|item| item.trim_matches(is_fws))
}

/// `value` with all folding whitespace removed (base64 in DKIM `p=`).
pub fn strip_fws(value: &str) -> String {
    value.chars().filter(|&c| !is_fws(c)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_trims() {
        let tags = parse(" v = DKIM1 ;k=rsa;\r\n\tp=AB CD ;", RecordKind::Dkim, false).unwrap();
        assert_eq!(
            tags,
            vec![
                Tag {
                    name: "v",
                    value: "DKIM1"
                },
                Tag {
                    name: "k",
                    value: "rsa"
                },
                Tag {
                    name: "p",
                    value: "AB CD"
                },
            ]
        );
    }

    #[test]
    fn rejects_duplicates_and_bad_names() {
        assert!(matches!(
            parse("a=1; a=2", RecordKind::Dkim, false),
            Err(Error::DuplicateTag { .. })
        ));
        assert!(parse("a=1; A=2", RecordKind::Dkim, false).is_ok());
        assert!(parse("a=1; A=2", RecordKind::Dmarc, true).is_err());
        assert!(parse("1a=1", RecordKind::Dkim, false).is_err());
        assert!(parse("novalue", RecordKind::Dkim, false).is_err());
        assert!(parse("a=\u{e9}", RecordKind::Dkim, false).is_err());
        assert_eq!(parse("", RecordKind::Dkim, false).unwrap(), vec![]);
    }
}
