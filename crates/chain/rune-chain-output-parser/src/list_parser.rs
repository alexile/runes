use rune_chain_core::ChainError;

use crate::OutputParser;

/// Split LLM text output into a `Vec<String>` on a configurable delimiter.
///
/// Empty items after splitting are discarded. Each item is trimmed of leading
/// and trailing whitespace.
///
/// # Example
///
/// ```rust
/// use rune_chain_output_parser::{OutputParser, ListOutputParser};
///
/// // Newline-delimited (default)
/// let p = ListOutputParser::new();
/// let items = p.parse("apple\nbanana\ncherry").unwrap();
/// assert_eq!(items, vec!["apple", "banana", "cherry"]);
///
/// // Comma-delimited
/// let p2 = ListOutputParser::with_delimiter(",");
/// let items2 = p2.parse("red, green, blue").unwrap();
/// assert_eq!(items2, vec!["red", "green", "blue"]);
/// ```
pub struct ListOutputParser {
    delimiter: String,
}

impl ListOutputParser {
    /// Create a parser that splits on newlines (`"\n"`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            delimiter: "\n".to_string(),
        }
    }

    /// Create a parser that splits on the given delimiter.
    pub fn with_delimiter(delimiter: impl Into<String>) -> Self {
        Self {
            delimiter: delimiter.into(),
        }
    }
}

impl Default for ListOutputParser {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputParser<Vec<String>> for ListOutputParser {
    fn parse(&self, text: &str) -> Result<Vec<String>, ChainError> {
        let items = text
            .split(&self.delimiter)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Ok(items)
    }

    fn format_instructions(&self) -> Option<String> {
        let delim_name = match self.delimiter.as_str() {
            "\n" => "newline-separated",
            "," => "comma-separated",
            ";" => "semicolon-separated",
            d => return Some(format!("Return a list of items separated by `{d}`.")),
        };
        Some(format!(
            "Return a {delim_name} list of items, with no additional text."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_newline() {
        let p = ListOutputParser::new();
        let items = p.parse("a\nb\nc").unwrap();
        assert_eq!(items, vec!["a", "b", "c"]);
    }

    #[test]
    fn trims_items() {
        let p = ListOutputParser::new();
        let items = p.parse("  a  \n  b  ").unwrap();
        assert_eq!(items, vec!["a", "b"]);
    }

    #[test]
    fn drops_empty_items() {
        let p = ListOutputParser::new();
        let items = p.parse("a\n\nb").unwrap();
        assert_eq!(items, vec!["a", "b"]);
    }

    #[test]
    fn comma_delimiter() {
        let p = ListOutputParser::with_delimiter(",");
        let items = p.parse("x, y, z").unwrap();
        assert_eq!(items, vec!["x", "y", "z"]);
    }
}
