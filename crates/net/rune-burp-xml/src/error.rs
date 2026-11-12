//! The crate's error type.

/// Why an export could not be read at all.
///
/// Problems confined to one item (bad base64, a request that is not HTTP)
/// are not errors: the item is skipped with a [`Warning`](crate::Warning).
/// Malformed XML after the first item stops reading with a warning, and
/// the items read so far are kept.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BurpError {
    /// The input is not well-formed XML before its root element.
    #[error("invalid XML: {0}")]
    Xml(String),
    /// The input is XML but not a Burp items or issues export.
    #[error("not a Burp export: {0}")]
    NotBurp(&'static str),
}

impl BurpError {
    /// A stable, machine-readable kind an agent can branch on.
    ///
    /// ```
    /// let error = rune_burp_xml::read(b"<html/>", &Default::default()).unwrap_err();
    /// assert_eq!(error.code(), "not_burp");
    /// ```
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Xml(_) => "invalid_xml",
            Self::NotBurp(_) => "not_burp",
        }
    }
}
