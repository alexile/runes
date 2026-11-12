use rune_chain_core::ChainError;

use crate::OutputParser;

/// Identity parser — returns the text as a trimmed `String`.
///
/// # Example
///
/// ```rust
/// use rune_chain_output_parser::{OutputParser, StringOutputParser};
///
/// let p = StringOutputParser;
/// assert_eq!(p.parse("  hello  ").unwrap(), "hello");
/// ```
pub struct StringOutputParser;

impl OutputParser<String> for StringOutputParser {
    fn parse(&self, text: &str) -> Result<String, ChainError> {
        Ok(text.trim().to_string())
    }

    fn format_instructions(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_whitespace() {
        let p = StringOutputParser;
        assert_eq!(p.parse("  hello world  ").unwrap(), "hello world");
    }

    #[test]
    fn empty_returns_empty() {
        let p = StringOutputParser;
        assert_eq!(p.parse("").unwrap(), "");
    }
}
