use std::fmt;

use rune_chain_core::ChainError;

/// Detailed error produced by the `try_*` methods of this crate.
///
/// The [`PromptTemplate`](crate::PromptTemplate) trait returns
/// [`ChainError`]; every `TemplateError` converts into one with `?` (missing
/// variables become [`ChainError::MissingVariable`], invalid placeholder
/// values [`ChainError::ParseError`], everything else
/// [`ChainError::Other`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TemplateError {
    /// The template string is malformed (only reported by strict
    /// constructors such as [`StringTemplate::try_new`](crate::StringTemplate::try_new)).
    Syntax {
        /// Byte offset in the template where the problem starts.
        position: usize,
        /// What is wrong.
        message: String,
    },
    /// Variables the template needs but the arguments do not supply, in
    /// order of first appearance.
    MissingVariables(Vec<String>),
    /// The declared input variables do not match the template.
    DeclarationMismatch {
        /// Variables the template uses but that were not declared.
        undeclared: Vec<String>,
        /// Declared variables the template never uses.
        unused: Vec<String>,
    },
    /// A few-shot example does not supply every variable of the example
    /// template.
    InvalidExample {
        /// Index of the offending example.
        index: usize,
        /// Variables it is missing.
        missing: Vec<String>,
    },
    /// A messages placeholder received a value that is not an array of
    /// messages.
    InvalidPlaceholderValue {
        /// The placeholder variable name.
        name: String,
        /// Why the value was rejected.
        reason: String,
    },
    /// The rendered prompt exceeds the configured maximum length.
    TooLong {
        /// Rendered length in bytes.
        len: usize,
        /// Configured limit in bytes.
        max: usize,
    },
}

fn list(names: &[String]) -> String {
    names.join(", ")
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { position, message } => {
                write!(f, "template syntax error at byte {position}: {message}")
            }
            Self::MissingVariables(names) => {
                write!(f, "missing prompt variables: {}", list(names))
            }
            Self::DeclarationMismatch { undeclared, unused } => {
                write!(f, "declared input variables do not match the template")?;
                if !undeclared.is_empty() {
                    write!(f, "; used but not declared: {}", list(undeclared))?;
                }
                if !unused.is_empty() {
                    write!(f, "; declared but not used: {}", list(unused))?;
                }
                Ok(())
            }
            Self::InvalidExample { index, missing } => write!(
                f,
                "few-shot example {index} is missing variables: {}",
                list(missing)
            ),
            Self::InvalidPlaceholderValue { name, reason } => {
                write!(
                    f,
                    "invalid value for messages placeholder `{name}`: {reason}"
                )
            }
            Self::TooLong { len, max } => write!(
                f,
                "rendered prompt is {len} bytes, exceeding the {max}-byte limit"
            ),
        }
    }
}

impl std::error::Error for TemplateError {}

impl From<TemplateError> for ChainError {
    fn from(err: TemplateError) -> Self {
        match err {
            TemplateError::MissingVariables(names) => Self::MissingVariable(list(&names)),
            TemplateError::InvalidPlaceholderValue { .. } => Self::ParseError(err.to_string()),
            other => Self::Other(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_lists_names() {
        let e = TemplateError::DeclarationMismatch {
            undeclared: vec!["a".into(), "b".into()],
            unused: vec!["c".into()],
        };
        assert_eq!(
            e.to_string(),
            "declared input variables do not match the template; used but not declared: a, b; declared but not used: c"
        );
    }

    #[test]
    fn converts_to_chain_error() {
        let e: ChainError = TemplateError::MissingVariables(vec!["x".into(), "y".into()]).into();
        assert!(matches!(e, ChainError::MissingVariable(v) if v == "x, y"));
        let e: ChainError = TemplateError::TooLong { len: 5, max: 4 }.into();
        assert!(matches!(e, ChainError::Other(_)));
    }
}
