//! The crate's error type.

/// Why a schema or document could not be read.
///
/// Problems inside a readable schema (references to undefined types,
/// duplicate definitions, missing root types, executable definitions mixed
/// into SDL) are not errors: they become
/// [`GraphQlSpec::warnings`](crate::GraphQlSpec::warnings) and the import
/// goes on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GraphQlError {
    /// The text is not valid GraphQL.
    #[error("syntax error at {line}:{column}: {message}")]
    Syntax {
        /// 1-based line.
        line: usize,
        /// 1-based column, in characters.
        column: usize,
        /// What went wrong.
        message: String,
    },
    /// The input looks like JSON but is not valid JSON.
    #[error("invalid JSON: {0}")]
    Json(String),
    /// The JSON is not an introspection result (no `__schema`).
    #[error("not a GraphQL introspection result: {0}")]
    NotIntrospection(String),
    /// The input is not UTF-8.
    #[error("input is not UTF-8")]
    NotUtf8,
    /// The input exceeds the size or nesting limits.
    #[error("input too large: {0}")]
    TooLarge(String),
}

impl GraphQlError {
    /// A stable, machine-readable kind an agent can branch on.
    ///
    /// ```
    /// use rune_graphql::parse_sdl;
    ///
    /// let error = parse_sdl("type Query {").unwrap_err();
    /// assert_eq!(error.code(), "syntax_error");
    /// ```
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Syntax { .. } => "syntax_error",
            Self::Json(_) => "json_error",
            Self::NotIntrospection(_) => "not_introspection",
            Self::NotUtf8 => "not_utf8",
            Self::TooLarge(_) => "too_large",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_distinct() {
        let errors = [
            GraphQlError::Syntax {
                line: 1,
                column: 2,
                message: String::from("x"),
            },
            GraphQlError::Json(String::new()),
            GraphQlError::NotIntrospection(String::new()),
            GraphQlError::NotUtf8,
            GraphQlError::TooLarge(String::new()),
        ];
        let mut codes: Vec<_> = errors.iter().map(GraphQlError::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len());
        assert_eq!(errors[0].to_string(), "syntax error at 1:2: x");
    }
}
