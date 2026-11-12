use rune_chain_core::ChainError;

use crate::OutputParser;

/// Parse LLM output as a boolean.
///
/// Recognises (case-insensitive): `yes`, `true`, `1`, `on` → `true`;
/// `no`, `false`, `0`, `off` → `false`.
///
/// # Example
///
/// ```rust
/// use rune_chain_output_parser::{OutputParser, BoolOutputParser};
///
/// let p = BoolOutputParser;
/// assert_eq!(p.parse("Yes").unwrap(), true);
/// assert_eq!(p.parse("no").unwrap(), false);
/// assert_eq!(p.parse("TRUE").unwrap(), true);
/// ```
pub struct BoolOutputParser;

impl OutputParser<bool> for BoolOutputParser {
    fn parse(&self, text: &str) -> Result<bool, ChainError> {
        match text.trim().to_lowercase().as_str() {
            "yes" | "true" | "1" | "on" => Ok(true),
            "no" | "false" | "0" | "off" => Ok(false),
            other => Err(ChainError::ParseError(format!(
                "expected yes/no/true/false, got: {other:?}"
            ))),
        }
    }

    fn format_instructions(&self) -> Option<String> {
        Some("Respond with only 'yes' or 'no'.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_true_variants() {
        let p = BoolOutputParser;
        assert!(p.parse("yes").unwrap());
        assert!(p.parse("YES").unwrap());
        assert!(p.parse("true").unwrap());
        assert!(p.parse("True").unwrap());
        assert!(p.parse("1").unwrap());
        assert!(p.parse("on").unwrap());
    }

    #[test]
    fn parses_false_variants() {
        let p = BoolOutputParser;
        assert!(!p.parse("no").unwrap());
        assert!(!p.parse("NO").unwrap());
        assert!(!p.parse("false").unwrap());
        assert!(!p.parse("False").unwrap());
        assert!(!p.parse("0").unwrap());
        assert!(!p.parse("off").unwrap());
    }

    #[test]
    fn rejects_unknown() {
        let p = BoolOutputParser;
        assert!(p.parse("maybe").is_err());
        assert!(p.parse("sure").is_err());
    }
}
