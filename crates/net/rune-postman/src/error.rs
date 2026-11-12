//! The crate's error type.

/// Why a collection or environment could not be read at all.
///
/// Problems confined to one item (a request with a malformed field, an auth
/// type that needs a live signature, …) are not errors: the item is skipped
/// or imported as far as possible, and a [`Warning`](crate::Warning) says
/// what happened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PostmanError {
    /// The input is not valid JSON.
    #[error("invalid JSON: {0}")]
    Json(String),
    /// The input is JSON but not a Postman v2.0 / v2.1 collection.
    #[error("not a Postman collection: {0}")]
    NotCollection(&'static str),
    /// The input is JSON but not a Postman environment or globals export.
    #[error("not a Postman environment: {0}")]
    NotEnvironment(&'static str),
}

impl PostmanError {
    /// A stable, machine-readable kind an agent can branch on.
    ///
    /// ```
    /// let error = rune_postman::read(b"[]", &Default::default()).unwrap_err();
    /// assert_eq!(error.code(), "not_collection");
    /// ```
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Json(_) => "invalid_json",
            Self::NotCollection(_) => "not_collection",
            Self::NotEnvironment(_) => "not_environment",
        }
    }
}
