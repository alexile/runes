//! The crate's error type.

/// Why a document could not be imported.
///
/// Problems inside a readable WSDL (unresolved references, non-SOAP
/// bindings, imports that are not fetched, recursive or oversized schemas)
/// are not errors: they become
/// [`WsdlSpec::warnings`](crate::WsdlSpec::warnings) and the import goes on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WsdlError {
    /// The input is not well-formed XML.
    #[error("invalid XML: {0}")]
    Xml(String),
    /// The input is not UTF-8.
    #[error("input is not UTF-8")]
    NotUtf8,
    /// The XML root is neither WSDL 1.1 `definitions` nor WSDL 2.0
    /// `description`.
    #[error("not a WSDL document: {0}")]
    NotWsdl(String),
    /// The input exceeds the size, nesting or element limits.
    #[error("document too large: {0}")]
    TooLarge(String),
}

impl WsdlError {
    /// A stable, machine-readable kind an agent can branch on.
    ///
    /// ```
    /// use rune_wsdl::{Options, parse};
    ///
    /// let error = parse(b"<html/>", &Options::default()).unwrap_err();
    /// assert_eq!(error.code(), "not_wsdl");
    /// ```
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Xml(_) => "xml_error",
            Self::NotUtf8 => "not_utf8",
            Self::NotWsdl(_) => "not_wsdl",
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
            WsdlError::Xml(String::new()),
            WsdlError::NotUtf8,
            WsdlError::NotWsdl(String::new()),
            WsdlError::TooLarge(String::new()),
        ];
        let mut codes: Vec<_> = errors.iter().map(WsdlError::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len());
        assert_eq!(
            WsdlError::NotWsdl(String::from("root is `html`")).to_string(),
            "not a WSDL document: root is `html`"
        );
    }
}
