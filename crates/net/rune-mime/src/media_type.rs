//! `Content-Type` media types ([RFC 9110 §8.3.1], [RFC 2045 §5.1]).
//!
//! [RFC 9110 §8.3.1]: https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1
//! [RFC 2045 §5.1]: https://www.rfc-editor.org/rfc/rfc2045#section-5.1

use std::fmt;
use std::str::FromStr;

use crate::params::{Cursor, Param, checked_token, find_param, write_params};
use crate::{Charset, MimeError};

/// A parsed media type: `type "/" subtype *( ";" parameter )`.
///
/// Type, subtype and parameter names are case-insensitive, so they are
/// stored in ASCII lowercase; parameter values keep their case and their
/// order (duplicates included, so differential tooling can see them).
/// `Display` writes the canonical form, which parses back to an equal value.
///
/// ```
/// use rune_mime::MediaType;
///
/// let mt: MediaType = "Text/HTML; Charset=\"UTF-8\"".parse().unwrap();
/// assert_eq!(mt.essence(), "text/html");
/// assert_eq!(mt.param("charset"), Some("UTF-8"));
/// assert_eq!(mt.to_string(), "text/html; charset=UTF-8");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MediaType {
    type_: String,
    subtype: String,
    /// Parameters in the order they appeared.
    pub params: Vec<Param>,
}

impl MediaType {
    /// A media type without parameters. Both parts must be tokens; they are
    /// lowercased.
    ///
    /// # Errors
    ///
    /// [`MimeError::InvalidValue`] if either part is not a token.
    pub fn new(type_: &str, subtype: &str) -> Result<Self, MimeError> {
        Ok(Self {
            type_: checked_token("media type", type_)?,
            subtype: checked_token("media subtype", subtype)?,
            params: Vec::new(),
        })
    }

    /// Parses a `Content-Type` value.
    ///
    /// Leading and trailing whitespace, empty parameters (`;;`) and
    /// whitespace around `=` are tolerated; anything else outside the
    /// grammar is an error.
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
        let type_ = cursor.required_token("a media type")?.to_ascii_lowercase();
        if !cursor.eat(b'/') {
            return Err(cursor.error("`/` after the media type"));
        }
        let subtype = cursor
            .required_token("a media subtype")?
            .to_ascii_lowercase();
        let params = cursor.params()?;
        Ok(Self {
            type_,
            subtype,
            params,
        })
    }

    /// Adds a parameter (replacing nothing; see [`set_param`](Self::set_param)).
    ///
    /// # Errors
    ///
    /// [`MimeError::InvalidValue`] if `name` is not a valid parameter name (see [`Param::new`]).
    pub fn with_param(mut self, name: &str, value: impl Into<String>) -> Result<Self, MimeError> {
        self.params.push(Param::new(name, value)?);
        Ok(self)
    }

    /// Sets a parameter, removing every existing one of the same name.
    ///
    /// # Errors
    ///
    /// [`MimeError::InvalidValue`] if `name` is not a valid parameter name (see [`Param::new`]).
    pub fn set_param(&mut self, name: &str, value: impl Into<String>) -> Result<(), MimeError> {
        let param = Param::new(name, value)?;
        self.params.retain(|p| p.name != param.name);
        self.params.push(param);
        Ok(())
    }

    /// The top-level type, lowercase (`text`).
    #[must_use]
    pub fn type_(&self) -> &str {
        &self.type_
    }

    /// The subtype, lowercase (`html`, `vnd.api+json`).
    #[must_use]
    pub fn subtype(&self) -> &str {
        &self.subtype
    }

    /// The structured-syntax suffix of [RFC 6838 §4.2.8], if any: `json` for
    /// `application/vnd.api+json`.
    ///
    /// [RFC 6838 §4.2.8]: https://www.rfc-editor.org/rfc/rfc6838#section-4.2.8
    #[must_use]
    pub fn suffix(&self) -> Option<&str> {
        self.subtype
            .rsplit_once('+')
            .map(|(_, suffix)| suffix)
            .filter(|suffix| !suffix.is_empty())
    }

    /// `type/subtype` without parameters, lowercase.
    #[must_use]
    pub fn essence(&self) -> String {
        format!("{}/{}", self.type_, self.subtype)
    }

    /// `true` if the essence is `type_/subtype` (case-insensitive).
    #[must_use]
    pub fn is(&self, type_: &str, subtype: &str) -> bool {
        self.type_.eq_ignore_ascii_case(type_) && self.subtype.eq_ignore_ascii_case(subtype)
    }

    /// A parameter value by case-insensitive name. An extended (`name*`)
    /// parameter wins over a plain one; otherwise the first occurrence.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        find_param(&self.params, name)
    }

    /// The `charset` parameter, as a [`Charset`].
    #[must_use]
    pub fn charset(&self) -> Option<Charset> {
        self.param("charset").map(Charset::from_label)
    }

    /// The `boundary` parameter.
    #[must_use]
    pub fn boundary(&self) -> Option<&str> {
        self.param("boundary")
    }

    /// `true` for `multipart/*`.
    #[must_use]
    pub fn is_multipart(&self) -> bool {
        self.type_ == "multipart"
    }

    /// `true` for `multipart/form-data` ([RFC 7578]).
    ///
    /// [RFC 7578]: https://www.rfc-editor.org/rfc/rfc7578
    #[must_use]
    pub fn is_form_data(&self) -> bool {
        self.is("multipart", "form-data")
    }

    /// `true` for `application/json` and any `+json` suffix.
    #[must_use]
    pub fn is_json(&self) -> bool {
        self.is("application", "json") || self.suffix() == Some("json")
    }

    /// `true` for `application/xml`, `text/xml` and any `+xml` suffix.
    #[must_use]
    pub fn is_xml(&self) -> bool {
        self.is("application", "xml") || self.is("text", "xml") || self.suffix() == Some("xml")
    }

    /// `true` for `application/x-www-form-urlencoded`.
    #[must_use]
    pub fn is_form_urlencoded(&self) -> bool {
        self.is("application", "x-www-form-urlencoded")
    }

    /// `true` if the body is meant to be read as text: `text/*`, JSON, XML,
    /// `application/javascript`, `application/ecmascript` and URL-encoded
    /// forms.
    #[must_use]
    pub fn is_textual(&self) -> bool {
        self.type_ == "text"
            || self.is_json()
            || self.is_xml()
            || self.is_form_urlencoded()
            || self.is("application", "javascript")
            || self.is("application", "ecmascript")
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.type_, self.subtype)?;
        write_params(f, &self.params)
    }
}

impl FromStr for MediaType {
    type Err = MimeError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc_examples() {
        // RFC 9110 §8.3.1: these are all equivalent.
        let forms = [
            "text/html;charset=utf-8",
            "text/html;charset=UTF-8",
            "Text/HTML;Charset=\"utf-8\"",
            "text/html; charset=\"utf-8\"",
        ];
        for form in forms {
            let mt = MediaType::parse(form).unwrap();
            assert_eq!(mt.essence(), "text/html", "{form}");
            assert_eq!(mt.charset(), Some(Charset::Utf8), "{form}");
        }
    }

    #[test]
    fn suffix_and_predicates() {
        let mt = MediaType::parse("application/vnd.api+json").unwrap();
        assert_eq!(mt.suffix(), Some("json"));
        assert!(mt.is_json() && mt.is_textual() && !mt.is_xml());
        assert!(MediaType::parse("image/svg+xml").unwrap().is_xml());
        assert!(!MediaType::parse("image/png").unwrap().is_textual());
        assert_eq!(MediaType::parse("a/b+").unwrap().suffix(), None);
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "  ",
            "text",
            "text/",
            "/html",
            "text/html junk",
            "te xt/html",
        ] {
            assert!(MediaType::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn set_param_replaces() {
        let mut mt = MediaType::new("Text", "Plain")
            .unwrap()
            .with_param("charset", "latin1")
            .unwrap();
        mt.set_param("Charset", "utf-8").unwrap();
        assert_eq!(mt.to_string(), "text/plain; charset=utf-8");
        assert!(MediaType::new("te xt", "plain").is_err());
    }
}
