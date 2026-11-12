use rune_chain_core::ChainError;

use crate::OutputParser;

/// Parse the first number (integer or float) found in LLM output as `f64`.
///
/// # Example
///
/// ```rust
/// use rune_chain_output_parser::{OutputParser, NumberOutputParser};
///
/// let p = NumberOutputParser;
/// assert_eq!(p.parse("The answer is 42").unwrap(), 42.0);
/// assert_eq!(p.parse("3.14 radians").unwrap(), 3.14);
/// assert_eq!(p.parse("  -7  ").unwrap(), -7.0);
/// ```
pub struct NumberOutputParser;

impl OutputParser<f64> for NumberOutputParser {
    fn parse(&self, text: &str) -> Result<f64, ChainError> {
        // Scan for a token that looks like a number (with optional sign and decimal point).
        for token in text.split_whitespace() {
            let cleaned: String = token
                .chars()
                .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == '+')
                .collect();
            if let Ok(n) = cleaned.parse::<f64>() {
                return Ok(n);
            }
        }
        Err(ChainError::ParseError(format!(
            "no number found in: {text:?}"
        )))
    }

    fn format_instructions(&self) -> Option<String> {
        Some("Respond with a single number only, no units or extra text.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_integer() {
        assert_eq!(NumberOutputParser.parse("answer: 42").unwrap(), 42.0);
    }

    #[test]
    fn extracts_float() {
        assert!((NumberOutputParser.parse("1.23456").unwrap() - 1.23456).abs() < 1e-5);
    }

    #[test]
    fn extracts_negative() {
        assert_eq!(
            NumberOutputParser
                .parse("temperature is -5 degrees")
                .unwrap(),
            -5.0
        );
    }

    #[test]
    fn returns_error_when_absent() {
        assert!(NumberOutputParser.parse("no numbers here at all").is_err());
    }
}
