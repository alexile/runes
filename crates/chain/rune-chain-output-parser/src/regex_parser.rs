use regex::Regex;
use rune_chain_core::ChainError;

use crate::OutputParser;

/// Extract the first capture group of a regex pattern from LLM output.
///
/// If the pattern has no capture groups, returns the entire match.
/// Returns [`ChainError::ParseError`] if the pattern does not match.
///
/// # Example
///
/// ```rust
/// use rune_chain_output_parser::{OutputParser, RegexOutputParser};
///
/// // Extract a number from text
/// let p = RegexOutputParser::new(r"(\d+)").unwrap();
/// assert_eq!(p.parse("The answer is 42 items").unwrap(), "42");
///
/// // Extract an email address
/// let p2 = RegexOutputParser::new(r"[\w.+-]+@[\w-]+\.\w+").unwrap();
/// assert_eq!(p2.parse("Contact: alice@example.com for details").unwrap(), "alice@example.com");
/// ```
pub struct RegexOutputParser {
    regex: Regex,
}

impl RegexOutputParser {
    /// Create a parser with the given regex pattern.
    ///
    /// Returns an error if the pattern is invalid.
    pub fn new(pattern: &str) -> Result<Self, ChainError> {
        Regex::new(pattern)
            .map(|regex| Self { regex })
            .map_err(|e| ChainError::ParseError(format!("invalid regex: {e}")))
    }
}

impl OutputParser<String> for RegexOutputParser {
    fn parse(&self, text: &str) -> Result<String, ChainError> {
        let caps = self
            .regex
            .captures(text)
            .ok_or_else(|| ChainError::ParseError(format!("pattern did not match: {text:?}")))?;

        // Use capture group 1 if it exists, otherwise the full match (group 0).
        let matched = caps
            .get(1)
            .or_else(|| caps.get(0))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();

        Ok(matched)
    }

    fn format_instructions(&self) -> Option<String> {
        Some(format!(
            "Your response must match the pattern: {}",
            self.regex.as_str()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_capture_group() {
        let p = RegexOutputParser::new(r"answer is (\d+)").unwrap();
        assert_eq!(p.parse("The answer is 42 things").unwrap(), "42");
    }

    #[test]
    fn falls_back_to_full_match() {
        let p = RegexOutputParser::new(r"\d+").unwrap();
        assert_eq!(p.parse("there are 7 items").unwrap(), "7");
    }

    #[test]
    fn returns_error_on_no_match() {
        let p = RegexOutputParser::new(r"\d+").unwrap();
        assert!(p.parse("no numbers here").is_err());
    }

    #[test]
    fn invalid_pattern_returns_error() {
        assert!(RegexOutputParser::new(r"[invalid").is_err());
    }
}
