//! The crate's error type.

/// Why a document could not be imported.
///
/// Problems inside a valid document (dangling or external `$ref`s, unknown
/// security schemes, relative server URLs) are not errors: they become
/// [`ApiSpec::warnings`](crate::ApiSpec::warnings) and the import goes on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OpenApiError {
    /// The input is not valid JSON or YAML.
    #[error("invalid document: {0}")]
    Parse(String),
    /// The input parsed, but has no `openapi` or `swagger` version field.
    #[error("not an OpenAPI or Swagger document: {0}")]
    NotOpenApi(String),
    /// The document declares a version this crate does not read.
    #[error("unsupported specification version `{0}`")]
    UnsupportedVersion(String),
    /// The input is YAML, but the `yaml` feature is off.
    #[error("YAML input needs the `yaml` feature")]
    YamlDisabled,
    /// The input exceeds the size, nesting or node limits.
    #[error("document too large: {0}")]
    TooLarge(String),
}

impl OpenApiError {
    /// A stable, machine-readable kind an agent can branch on.
    ///
    /// ```
    /// use rune_openapi::{Options, parse};
    ///
    /// let error = parse(br#"{"info": {}}"#, &Options::default()).unwrap_err();
    /// assert_eq!(error.code(), "not_openapi");
    /// ```
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Parse(_) => "parse_error",
            Self::NotOpenApi(_) => "not_openapi",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::YamlDisabled => "yaml_disabled",
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
            OpenApiError::Parse(String::new()),
            OpenApiError::NotOpenApi(String::new()),
            OpenApiError::UnsupportedVersion(String::new()),
            OpenApiError::YamlDisabled,
            OpenApiError::TooLarge(String::new()),
        ];
        let mut codes: Vec<_> = errors.iter().map(OpenApiError::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len());
        assert_eq!(
            OpenApiError::UnsupportedVersion("4.0".into()).to_string(),
            "unsupported specification version `4.0`"
        );
    }
}
