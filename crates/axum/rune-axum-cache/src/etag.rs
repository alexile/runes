//! Entity tags and entity-tag lists ([RFC 9110 §8.8.3], §13.1.1-2).
//!
//! [RFC 9110 §8.8.3]: https://www.rfc-editor.org/rfc/rfc9110#section-8.8.3

use std::fmt;
use std::str::FromStr;

use http::HeaderValue;
use sha2::{Digest, Sha256};

use crate::Error;

/// An HTTP entity tag: an opaque validator, strong or weak.
///
/// Tags are restricted to visible ASCII other than `"` (the `etagc` rule
/// without `obs-text`), so every tag renders to a valid header value.
///
/// # Examples
///
/// ```rust
/// use rune_axum_cache::EntityTag;
///
/// let strong = EntityTag::strong("v1")?;
/// let weak: EntityTag = r#"W/"v1""#.parse()?;
/// assert_eq!(strong.to_string(), r#""v1""#);
/// assert!(strong.weak_eq(&weak));
/// assert!(!strong.strong_eq(&weak));
///
/// // A content hash makes a stable strong tag.
/// let tag = EntityTag::from_content(b"hello");
/// assert!(!tag.is_weak());
/// assert_eq!(tag, EntityTag::from_content(b"hello"));
/// # Ok::<(), rune_axum_cache::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EntityTag {
    weak: bool,
    tag: String,
}

impl EntityTag {
    /// Creates a strong tag from its opaque value (without quotes).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEntityTag`] if `tag` contains `"`, whitespace,
    /// control or non-ASCII characters.
    pub fn strong(tag: impl Into<String>) -> Result<Self, Error> {
        Self::new(false, tag.into())
    }

    /// Creates a weak tag from its opaque value (without quotes).
    ///
    /// # Errors
    ///
    /// As for [`EntityTag::strong`].
    pub fn weak(tag: impl Into<String>) -> Result<Self, Error> {
        Self::new(true, tag.into())
    }

    fn new(weak: bool, tag: String) -> Result<Self, Error> {
        if tag.bytes().all(is_etagc) {
            Ok(Self { weak, tag })
        } else {
            Err(Error::InvalidEntityTag)
        }
    }

    /// A strong tag derived from the representation bytes: the first 128
    /// bits of their SHA-256 digest, in lowercase hex.
    ///
    /// Stable across processes and releases, so caches keep validating
    /// after a restart or a deploy that does not change the content.
    #[must_use]
    pub fn from_content(content: &[u8]) -> Self {
        let digest = Sha256::digest(content);
        let mut tag = String::with_capacity(32);
        for byte in &digest[..16] {
            tag.push(char::from(HEX[usize::from(byte >> 4)]));
            tag.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Self { weak: false, tag }
    }

    /// Parses a single `entity-tag` such as `"abc"` or `W/"abc"`.
    /// Surrounding whitespace is ignored.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEntityTag`] when the text is not exactly one tag.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let b = text.trim_matches([' ', '\t']).as_bytes();
        match parse_tag(b) {
            Some((tag, [])) => Ok(tag),
            _ => Err(Error::InvalidEntityTag),
        }
    }

    /// Whether this is a weak tag (`W/"…"`).
    #[must_use]
    pub const fn is_weak(&self) -> bool {
        self.weak
    }

    /// The opaque value, without quotes or weakness prefix.
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Strong comparison: both tags are strong and their values match.
    /// Used by `If-Match`.
    #[must_use]
    pub fn strong_eq(&self, other: &Self) -> bool {
        !self.weak && !other.weak && self.tag == other.tag
    }

    /// Weak comparison: the values match, whatever their weakness. Used by
    /// `If-None-Match`.
    #[must_use]
    pub fn weak_eq(&self, other: &Self) -> bool {
        self.tag == other.tag
    }

    /// The tag as a header value, for `ETag`.
    #[must_use]
    pub fn to_header_value(&self) -> HeaderValue {
        crate::ascii_header_value(&self.to_string())
    }
}

impl FromStr for EntityTag {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for EntityTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.weak {
            f.write_str("W/")?;
        }
        write!(f, "\"{}\"", self.tag)
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

const fn is_etagc(c: u8) -> bool {
    c == 0x21 || matches!(c, 0x23..=0x7e)
}

/// Parses one tag at the start of `b`, returning it and the rest.
fn parse_tag(b: &[u8]) -> Option<(EntityTag, &[u8])> {
    let (weak, b) = b.strip_prefix(b"W/").map_or((false, b), |r| (true, r));
    let b = b.strip_prefix(b"\"")?;
    let end = b.iter().position(|&c| c == b'"')?;
    let (value, rest) = (&b[..end], &b[end + 1..]);
    if !value.iter().copied().all(is_etagc) {
        return None;
    }
    let tag = String::from_utf8(value.to_vec()).ok()?;
    Some((EntityTag { weak, tag }, rest))
}

/// The value of an `If-Match` or `If-None-Match` field: `*` or a list of
/// entity tags.
///
/// # Examples
///
/// ```rust
/// use rune_axum_cache::{EntityTag, EntityTagList};
///
/// let list = EntityTagList::parse(r#""a", W/"b" , "c""#)?;
/// let b = EntityTag::strong("b")?;
/// assert!(list.matches_weak(&b));
/// assert!(!list.matches_strong(&b));
/// assert!(EntityTagList::parse("*")?.matches_strong(&b));
/// # Ok::<(), rune_axum_cache::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntityTagList {
    /// `*`: matches any current representation.
    Any,
    /// One or more explicit tags.
    Tags(Vec<EntityTag>),
}

impl EntityTagList {
    /// Parses a field value. Empty list elements (`"a", , "b"`) are
    /// skipped, as the list syntax of RFC 9110 §5.6.1 requires.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEntityTag`] when the value is empty, mixes `*` with
    /// tags, or contains anything that is not an entity tag.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let trimmed = text.trim_matches([' ', '\t']);
        if trimmed == "*" {
            return Ok(Self::Any);
        }
        let mut tags = Vec::new();
        let mut b = trimmed.as_bytes();
        loop {
            b = skip_separators(b);
            if b.is_empty() {
                break;
            }
            let (tag, rest) = parse_tag(b).ok_or(Error::InvalidEntityTag)?;
            tags.push(tag);
            let rest = skip_ows(rest);
            if !(rest.is_empty() || rest.starts_with(b",")) {
                return Err(Error::InvalidEntityTag);
            }
            b = rest;
        }
        if tags.is_empty() {
            Err(Error::InvalidEntityTag)
        } else {
            Ok(Self::Tags(tags))
        }
    }

    /// Parses every line of a (possibly repeated) header as one list.
    ///
    /// # Errors
    ///
    /// As for [`EntityTagList::parse`], or when a line is not valid text.
    pub fn from_header_values<'a>(
        values: impl IntoIterator<Item = &'a HeaderValue>,
    ) -> Result<Self, Error> {
        let mut joined = String::new();
        for value in values {
            let text = value.to_str().map_err(|_| Error::InvalidEntityTag)?;
            if !joined.is_empty() {
                joined.push_str(", ");
            }
            joined.push_str(text);
        }
        Self::parse(&joined)
    }

    /// Whether `tag` matches by strong comparison (`If-Match`).
    #[must_use]
    pub fn matches_strong(&self, tag: &EntityTag) -> bool {
        match self {
            Self::Any => true,
            Self::Tags(tags) => tags.iter().any(|t| t.strong_eq(tag)),
        }
    }

    /// Whether `tag` matches by weak comparison (`If-None-Match`).
    #[must_use]
    pub fn matches_weak(&self, tag: &EntityTag) -> bool {
        match self {
            Self::Any => true,
            Self::Tags(tags) => tags.iter().any(|t| t.weak_eq(tag)),
        }
    }
}

impl FromStr for EntityTagList {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for EntityTagList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Tags(tags) => {
                for (i, tag) in tags.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{tag}")?;
                }
                Ok(())
            }
        }
    }
}

fn skip_ows(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|&&c| c == b' ' || c == b'\t').count();
    &b[n..]
}

fn skip_separators(b: &[u8]) -> &[u8] {
    let n = b
        .iter()
        .take_while(|&&c| c == b' ' || c == b'\t' || c == b',')
        .count();
    &b[n..]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(tag: &str) -> EntityTag {
        EntityTag::strong(tag).unwrap()
    }

    fn w(tag: &str) -> EntityTag {
        EntityTag::weak(tag).unwrap()
    }

    #[test]
    fn comparison_table_from_rfc_9110() {
        // RFC 9110 §8.8.3.2.
        assert!(!w("1").strong_eq(&w("1")));
        assert!(w("1").weak_eq(&w("1")));
        assert!(!w("1").strong_eq(&w("2")));
        assert!(!w("1").weak_eq(&w("2")));
        assert!(!w("1").strong_eq(&s("1")));
        assert!(w("1").weak_eq(&s("1")));
        assert!(s("1").strong_eq(&s("1")));
        assert!(s("1").weak_eq(&s("1")));
    }

    #[test]
    fn parses_single_tags() {
        assert_eq!(EntityTag::parse(r#""xyzzy""#), Ok(s("xyzzy")));
        assert_eq!(EntityTag::parse(r#" W/"xyzzy" "#), Ok(w("xyzzy")));
        assert_eq!(EntityTag::parse(r#""""#), Ok(s("")));
        for bad in [
            "xyzzy",
            r#""xyz"zy""#,
            r#""xyz zy""#,
            r#"w/"x""#,
            r#"W/ "x""#,
            r#""x"#,
            r#""x" "y""#,
            "\"caf\u{e9}\"",
        ] {
            assert_eq!(EntityTag::parse(bad), Err(Error::InvalidEntityTag), "{bad}");
        }
    }

    #[test]
    fn constructors_validate() {
        assert!(EntityTag::strong("a\"b").is_err());
        assert!(EntityTag::weak("a b").is_err());
        assert!(EntityTag::strong("!#$%&'()*+,-./~").is_ok());
    }

    #[test]
    fn display_round_trips() {
        for tag in [s("abc"), w("abc"), s("")] {
            assert_eq!(EntityTag::parse(&tag.to_string()), Ok(tag.clone()));
            assert_eq!(tag.to_header_value(), tag.to_string().as_str());
        }
    }

    #[test]
    fn content_tag_is_sha256_prefix() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a3...
        assert_eq!(
            EntityTag::from_content(b"abc").to_string(),
            r#""ba7816bf8f01cfea414140de5dae2223""#
        );
    }

    #[test]
    fn parses_lists() {
        assert_eq!(EntityTagList::parse(" * "), Ok(EntityTagList::Any));
        assert_eq!(
            EntityTagList::parse(r#""a",W/"b" ,, "c","#),
            Ok(EntityTagList::Tags(vec![s("a"), w("b"), s("c")]))
        );
        // Commas are legal inside a tag.
        assert_eq!(
            EntityTagList::parse(r#""a,b""#),
            Ok(EntityTagList::Tags(vec![s("a,b")]))
        );
        for bad in ["", " , ", r#"*, "a""#, r#""a" "b""#, r#""a", b"#, "**"] {
            assert_eq!(
                EntityTagList::parse(bad),
                Err(Error::InvalidEntityTag),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn joins_repeated_header_lines() {
        let values = [
            HeaderValue::from_static(r#""a""#),
            HeaderValue::from_static(r#"W/"b""#),
        ];
        let list = EntityTagList::from_header_values(&values).unwrap();
        assert_eq!(list.to_string(), r#""a", W/"b""#);
        let bad = [HeaderValue::from_bytes(b"\"\xff\"").unwrap()];
        assert!(EntityTagList::from_header_values(&bad).is_err());
        assert!(EntityTagList::from_header_values(&[]).is_err());
    }
}
