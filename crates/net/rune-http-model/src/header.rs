//! Header fields and helpers over ordered header lists.
//!
//! Headers are a plain `Vec<HeaderEntry>` in wire order. Duplicates are
//! kept (`Set-Cookie` repeats), names keep their original case and are
//! compared case-insensitively ([RFC 9110 §5.1]). Nothing is validated:
//! security tooling must be able to record and replay malformed fields.
//!
//! [RFC 9110 §5.1]: https://www.rfc-editor.org/rfc/rfc9110#section-5.1

/// A single HTTP header as a name/value pair.
///
/// Names are matched case-insensitively on lookup; the original case is kept.
/// Neither the name nor the value is validated or normalised.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct HeaderEntry {
    /// Header field name, case preserved.
    pub name: String,
    /// Header field value.
    pub value: String,
}

impl HeaderEntry {
    /// Creates a header from a name and a value.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Whether this header is called `name`, ignoring ASCII case.
    #[must_use]
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

impl From<(String, String)> for HeaderEntry {
    fn from((name, value): (String, String)) -> Self {
        Self { name, value }
    }
}

impl From<(&str, &str)> for HeaderEntry {
    fn from((name, value): (&str, &str)) -> Self {
        Self::new(name, value)
    }
}

impl From<HeaderEntry> for (String, String) {
    fn from(entry: HeaderEntry) -> Self {
        (entry.name, entry.value)
    }
}

/// Returns the value of the first header called `name`, ignoring case.
#[must_use]
pub fn header_value<'a>(headers: &'a [HeaderEntry], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.is(name))
        .map(|header| header.value.as_str())
}

/// Returns the values of every header called `name`, ignoring case, in order.
pub fn header_values<'a>(
    headers: &'a [HeaderEntry],
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |header| header.is(name))
        .map(|header| header.value.as_str())
}

/// Whether any header is called `name`, ignoring case.
#[must_use]
pub fn has_header(headers: &[HeaderEntry], name: &str) -> bool {
    headers.iter().any(|header| header.is(name))
}

/// Sets `name` to the single value `value`.
///
/// The first header called `name` (ignoring case) keeps its position and its
/// name's case and takes the new value; later duplicates are removed. When
/// none exists, the header is appended.
pub fn set_header(headers: &mut Vec<HeaderEntry>, name: &str, value: impl Into<String>) {
    let value = value.into();
    match headers.iter().position(|header| header.is(name)) {
        Some(first) => {
            let mut index = 0;
            headers.retain(|header| {
                let keep = index <= first || !header.is(name);
                index += 1;
                keep
            });
            if let Some(header) = headers.get_mut(first) {
                header.value = value;
            }
        }
        None => headers.push(HeaderEntry::new(name, value)),
    }
}

/// Removes every header called `name`, ignoring case, and returns how many
/// were removed.
pub fn remove_header(headers: &mut Vec<HeaderEntry>, name: &str) -> usize {
    let before = headers.len();
    headers.retain(|header| !header.is(name));
    before - headers.len()
}

/// Builds a header list from name/value pairs, keeping their order.
pub fn headers_from_pairs<I, K, V>(pairs: I) -> Vec<HeaderEntry>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    pairs
        .into_iter()
        .map(|(name, value)| HeaderEntry::new(name, value))
        .collect()
}

/// Converts a header list into owned name/value pairs, keeping their order.
#[must_use]
pub fn headers_to_pairs(headers: &[HeaderEntry]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|header| (header.name.clone(), header.value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_case_insensitive_and_ordered() {
        let headers = headers_from_pairs([
            ("Set-Cookie", "a=1"),
            ("content-type", "text/plain"),
            ("SET-COOKIE", "b=2"),
        ]);
        assert_eq!(header_value(&headers, "Content-Type"), Some("text/plain"));
        assert_eq!(
            header_values(&headers, "set-cookie").collect::<Vec<_>>(),
            vec!["a=1", "b=2"]
        );
        assert_eq!(header_value(&headers, "missing"), None);
        assert!(has_header(&headers, "CONTENT-TYPE"));
        assert!(!has_header(&headers, "accept"));
        assert_eq!(headers_to_pairs(&headers)[0].1, "a=1");
    }

    #[test]
    fn conversions() {
        let pair: (String, String) = HeaderEntry::new("A", "b").into();
        assert_eq!(HeaderEntry::from(pair), HeaderEntry::new("A", "b"));
        assert_eq!(HeaderEntry::from(("A", "b")), HeaderEntry::new("A", "b"));
    }

    #[test]
    fn set_header_replaces_first_and_drops_duplicates() {
        let mut headers = headers_from_pairs([
            ("Accept", "*/*"),
            ("X-Token", "one"),
            ("Host", "h"),
            ("x-token", "two"),
        ]);
        set_header(&mut headers, "X-TOKEN", "new");
        assert_eq!(
            headers,
            headers_from_pairs([("Accept", "*/*"), ("X-Token", "new"), ("Host", "h")])
        );
        set_header(&mut headers, "Cookie", "c=1");
        assert_eq!(headers.last(), Some(&HeaderEntry::new("Cookie", "c=1")));
    }

    #[test]
    fn remove_header_counts() {
        let mut headers = headers_from_pairs([("A", "1"), ("b", "2"), ("a", "3")]);
        assert_eq!(remove_header(&mut headers, "a"), 2);
        assert_eq!(remove_header(&mut headers, "a"), 0);
        assert_eq!(headers, headers_from_pairs([("b", "2")]));
    }
}
