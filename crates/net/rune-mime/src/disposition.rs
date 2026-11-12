//! `Content-Disposition` ([RFC 6266], and [RFC 7578 §4.2] for form data).
//!
//! [RFC 6266]: https://www.rfc-editor.org/rfc/rfc6266
//! [RFC 7578 §4.2]: https://www.rfc-editor.org/rfc/rfc7578#section-4.2

use std::fmt;
use std::str::FromStr;

use crate::MimeError;
use crate::params::{Cursor, Param, checked_token, find_param, write_params};

/// A parsed `Content-Disposition`: `disposition-type *( ";" parameter )`.
///
/// ```
/// use rune_mime::ContentDisposition;
///
/// let cd: ContentDisposition =
///     "form-data; name=\"avatar\"; filename*=UTF-8''%E2%82%AC.png".parse().unwrap();
/// assert!(cd.is_form_data());
/// assert_eq!(cd.name(), Some("avatar"));
/// assert_eq!(cd.filename(), Some("€.png"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentDisposition {
    kind: String,
    /// Parameters in the order they appeared.
    pub params: Vec<Param>,
}

impl ContentDisposition {
    /// A disposition of the given type (`inline`, `attachment`,
    /// `form-data`), lowercased.
    ///
    /// # Errors
    ///
    /// [`MimeError::InvalidValue`] if `kind` is not a token.
    pub fn new(kind: &str) -> Result<Self, MimeError> {
        Ok(Self {
            kind: checked_token("disposition type", kind)?,
            params: Vec::new(),
        })
    }

    /// `form-data; name="…"`, the disposition of a form field.
    ///
    /// # Errors
    ///
    /// Never in practice; the signature matches the other constructors.
    pub fn form_data(name: &str) -> Result<Self, MimeError> {
        Self::new("form-data")?.with_param("name", name)
    }

    /// Parses a `Content-Disposition` value, with the same tolerance as
    /// [`MediaType::parse`](crate::MediaType::parse).
    ///
    /// # Errors
    ///
    /// [`MimeError::Empty`], [`MimeError::Syntax`] or
    /// [`MimeError::InvalidExtValue`].
    pub fn parse(text: &str) -> Result<Self, MimeError> {
        let text = text.trim_matches([' ', '\t']);
        if text.is_empty() {
            return Err(MimeError::Empty);
        }
        let mut cursor = Cursor::new(text);
        let kind = cursor
            .required_token("a disposition type")?
            .to_ascii_lowercase();
        let params = cursor.params()?;
        Ok(Self { kind, params })
    }

    /// Adds a parameter.
    ///
    /// # Errors
    ///
    /// [`MimeError::InvalidValue`] if `name` is not a valid parameter name (see [`Param::new`]).
    pub fn with_param(mut self, name: &str, value: impl Into<String>) -> Result<Self, MimeError> {
        self.params.push(Param::new(name, value)?);
        Ok(self)
    }

    /// The disposition type, lowercase.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// `true` for `form-data`.
    #[must_use]
    pub fn is_form_data(&self) -> bool {
        self.kind == "form-data"
    }

    /// `true` for `attachment`.
    #[must_use]
    pub fn is_attachment(&self) -> bool {
        self.kind == "attachment"
    }

    /// A parameter value by case-insensitive name; `name*` wins over `name`.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        find_param(&self.params, name)
    }

    /// The `name` parameter (the form field name).
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.param("name")
    }

    /// The file name: `filename*` if present, else `filename`.
    ///
    /// The value is returned as sent. It may contain path separators or
    /// `..`; callers that store files must sanitise it.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.param("filename")
    }
}

impl fmt::Display for ContentDisposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.kind)?;
        write_params(f, &self.params)
    }
}

impl FromStr for ContentDisposition {
    type Err = MimeError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6266_examples() {
        let cd = ContentDisposition::parse("Attachment; filename=example.html").unwrap();
        assert!(cd.is_attachment());
        assert_eq!(cd.filename(), Some("example.html"));

        let cd = ContentDisposition::parse("INLINE; FILENAME= \"an example.html\"").unwrap();
        assert_eq!(cd.kind(), "inline");
        assert_eq!(cd.filename(), Some("an example.html"));

        let cd =
            ContentDisposition::parse("attachment; filename*= UTF-8''%e2%82%ac%20rates").unwrap();
        assert_eq!(cd.filename(), Some("€ rates"));

        let cd = ContentDisposition::parse(
            "attachment; filename=\"EURO rates\"; filename*=utf-8''%e2%82%ac%20rates",
        )
        .unwrap();
        assert_eq!(cd.filename(), Some("€ rates"));
    }

    #[test]
    fn form_data_round_trip() {
        let cd = ContentDisposition::form_data("a b")
            .unwrap()
            .with_param("filename", "x.txt")
            .unwrap();
        assert_eq!(cd.to_string(), "form-data; name=\"a b\"; filename=x.txt");
        assert_eq!(ContentDisposition::parse(&cd.to_string()).unwrap(), cd);
    }
}
