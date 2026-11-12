//! Parameterised transforms: framing, match/replace, XOR, Unicode case.
//!
//! These take arguments, so they are not in the built-in registry; build
//! them directly and chain or register them.

use std::str;

use crate::{Category, Error, Transform};

/// Prepend fixed bytes. Decoding strips them and fails when the input does
/// not start with them.
///
/// ```
/// use rune_transform::{PrefixTransform, Transform};
///
/// let prefix = PrefixTransform::new("Bearer ");
/// assert_eq!(prefix.encode(b"abc")?, b"Bearer abc");
/// assert_eq!(prefix.decode(b"Bearer abc")?, b"abc");
/// assert!(prefix.decode(b"Basic abc").is_err());
/// # Ok::<(), rune_transform::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixTransform {
    /// Bytes prepended on encode.
    prefix: Vec<u8>,
}

impl PrefixTransform {
    /// Prepend `prefix`.
    #[must_use]
    pub fn new(prefix: impl Into<Vec<u8>>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// The bytes prepended on encode.
    #[must_use]
    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }
}

impl Transform for PrefixTransform {
    fn id(&self) -> &'static str {
        "prefix"
    }

    fn description(&self) -> &'static str {
        "Prepend a fixed string"
    }

    fn category(&self) -> Category {
        Category::Framing
    }

    fn is_reversible(&self) -> bool {
        true
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(self.prefix.len() + input.len());
        out.extend_from_slice(&self.prefix);
        out.extend_from_slice(input);
        Ok(out)
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        input
            .strip_prefix(self.prefix.as_slice())
            .map(<[u8]>::to_vec)
            .ok_or_else(|| Error::malformed(self.id(), "input does not start with the prefix"))
    }
}

/// Append fixed bytes. Decoding strips them and fails when the input does
/// not end with them.
///
/// ```
/// use rune_transform::{SuffixTransform, Transform};
///
/// let suffix = SuffixTransform::new("--");
/// assert_eq!(suffix.encode(b"1' OR 1=1")?, b"1' OR 1=1--");
/// assert_eq!(suffix.decode(b"x--")?, b"x");
/// # Ok::<(), rune_transform::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuffixTransform {
    /// Bytes appended on encode.
    suffix: Vec<u8>,
}

impl SuffixTransform {
    /// Append `suffix`.
    #[must_use]
    pub fn new(suffix: impl Into<Vec<u8>>) -> Self {
        Self {
            suffix: suffix.into(),
        }
    }

    /// The bytes appended on encode.
    #[must_use]
    pub fn suffix(&self) -> &[u8] {
        &self.suffix
    }
}

impl Transform for SuffixTransform {
    fn id(&self) -> &'static str {
        "suffix"
    }

    fn description(&self) -> &'static str {
        "Append a fixed string"
    }

    fn category(&self) -> Category {
        Category::Framing
    }

    fn is_reversible(&self) -> bool {
        true
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(input.len() + self.suffix.len());
        out.extend_from_slice(input);
        out.extend_from_slice(&self.suffix);
        Ok(out)
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        input
            .strip_suffix(self.suffix.as_slice())
            .map(<[u8]>::to_vec)
            .ok_or_else(|| Error::malformed(self.id(), "input does not end with the suffix"))
    }
}

/// Replace every non-overlapping occurrence of one byte string with
/// another, scanning left to right. An empty pattern leaves the input
/// unchanged. One-way.
///
/// ```
/// use rune_transform::{MatchReplaceTransform, Transform};
///
/// let spaces = MatchReplaceTransform::new(" ", "/**/");
/// assert_eq!(spaces.encode(b"UNION SELECT 1")?, b"UNION/**/SELECT/**/1");
/// # Ok::<(), rune_transform::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchReplaceTransform {
    /// Bytes searched for.
    from: Vec<u8>,
    /// Replacement bytes.
    to: Vec<u8>,
}

impl MatchReplaceTransform {
    /// Replace `from` with `to`.
    #[must_use]
    pub fn new(from: impl Into<Vec<u8>>, to: impl Into<Vec<u8>>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
        }
    }

    /// The bytes searched for.
    #[must_use]
    pub fn pattern(&self) -> &[u8] {
        &self.from
    }

    /// The replacement bytes.
    #[must_use]
    pub fn replacement(&self) -> &[u8] {
        &self.to
    }
}

impl Transform for MatchReplaceTransform {
    fn id(&self) -> &'static str {
        "match_replace"
    }

    fn description(&self) -> &'static str {
        "Replace every occurrence of a byte string"
    }

    fn category(&self) -> Category {
        Category::Text
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let needle = self.from.as_slice();
        if needle.is_empty() {
            return Ok(input.to_vec());
        }
        let mut out = Vec::with_capacity(input.len());
        let mut rest = input;
        while let Some((&first, tail)) = rest.split_first() {
            if let Some(after) = rest.strip_prefix(needle) {
                out.extend_from_slice(&self.to);
                rest = after;
            } else {
                out.push(first);
                rest = tail;
            }
        }
        Ok(out)
    }
}

/// XOR every byte with a repeating key, using `rune-xor`. Self-inverse; an
/// empty key leaves the input unchanged.
///
/// ```
/// use rune_transform::{Transform, XorTransform};
///
/// let xor = XorTransform::new("K");
/// assert_eq!(xor.encode(b"\x0b")?, b"@");
/// assert_eq!(xor.decode(&xor.encode(b"secret")?)?, b"secret");
/// # Ok::<(), rune_transform::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorTransform {
    /// Repeating key.
    key: Vec<u8>,
}

impl XorTransform {
    /// XOR with the repeating `key`.
    #[must_use]
    pub fn new(key: impl Into<Vec<u8>>) -> Self {
        Self { key: key.into() }
    }

    /// The repeating key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl Transform for XorTransform {
    fn id(&self) -> &'static str {
        "xor"
    }

    fn description(&self) -> &'static str {
        "XOR with a repeating key"
    }

    fn category(&self) -> Category {
        Category::Cipher
    }

    fn is_reversible(&self) -> bool {
        true
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        if self.key.is_empty() {
            return Ok(input.to_vec());
        }
        Ok(rune_xor::xor(input, &self.key))
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        self.encode(input)
    }
}

/// Full Unicode uppercase of UTF-8 text (the built-in `upper_case` only
/// touches ASCII). One-way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnicodeUpperCaseTransform;

impl Transform for UnicodeUpperCaseTransform {
    fn id(&self) -> &'static str {
        "unicode_upper_case"
    }

    fn description(&self) -> &'static str {
        "Uppercase UTF-8 text (full Unicode case mapping)"
    }

    fn category(&self) -> Category {
        Category::Text
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let text = str::from_utf8(input).map_err(|_| Error::not_utf8(self.id()))?;
        Ok(text.to_uppercase().into_bytes())
    }
}

/// Full Unicode lowercase of UTF-8 text (the built-in `lower_case` only
/// touches ASCII). One-way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnicodeLowerCaseTransform;

impl Transform for UnicodeLowerCaseTransform {
    fn id(&self) -> &'static str {
        "unicode_lower_case"
    }

    fn description(&self) -> &'static str {
        "Lowercase UTF-8 text (full Unicode case mapping)"
    }

    fn category(&self) -> Category {
        Category::Text
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let text = str::from_utf8(input).map_err(|_| Error::not_utf8(self.id()))?;
        Ok(text.to_lowercase().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::TransformChain;

    #[test]
    fn prefix_suffix_round_trip_and_reject() {
        let prefix = PrefixTransform::new("pre-");
        let suffix = SuffixTransform::new("-suf");
        assert_eq!(prefix.prefix(), b"pre-");
        assert_eq!(suffix.suffix(), b"-suf");
        let chain = TransformChain::new(vec![
            Arc::new(prefix.clone()) as Arc<dyn Transform>,
            Arc::new(suffix.clone()),
        ]);
        assert_eq!(chain.encode(b"body").ok(), Some(b"pre-body-suf".to_vec()));
        assert_eq!(chain.decode(b"pre-body-suf").ok(), Some(b"body".to_vec()));
        assert_eq!(
            prefix.decode(b"body").err().map(|e| e.code()),
            Some("transform.malformed")
        );
        assert!(suffix.decode(b"body").is_err());
    }

    #[test]
    fn match_replace_replaces_all_and_is_one_way() {
        let replace = MatchReplaceTransform::new("ab", "X");
        assert_eq!(replace.pattern(), b"ab");
        assert_eq!(replace.replacement(), b"X");
        assert_eq!(replace.encode(b"abcabab-a").ok(), Some(b"XcXX-a".to_vec()));
        assert_eq!(replace.encode(b"").ok(), Some(Vec::new()));
        assert_eq!(
            MatchReplaceTransform::new("", "X").encode(b"abc").ok(),
            Some(b"abc".to_vec())
        );
        assert_eq!(
            MatchReplaceTransform::new("aa", "a").encode(b"aaaaa").ok(),
            Some(b"aaa".to_vec())
        );
        assert!(!replace.is_reversible());
        assert!(replace.decode(b"X").is_err());
    }

    #[test]
    fn xor_is_self_inverse() {
        let xor = XorTransform::new(*b"KEY");
        assert_eq!(xor.key(), b"KEY");
        let ct = xor.encode(b"Attack at dawn").ok().unwrap_or_default();
        assert_eq!(ct, rune_xor::xor(b"Attack at dawn", b"KEY"));
        assert_eq!(xor.decode(&ct).ok(), Some(b"Attack at dawn".to_vec()));
        assert_eq!(
            XorTransform::new(Vec::new()).encode(b"x").ok(),
            Some(b"x".to_vec())
        );
    }

    #[test]
    fn unicode_case_transforms_fold_non_ascii() {
        assert_eq!(
            UnicodeUpperCaseTransform.encode("straße é".as_bytes()).ok(),
            Some("STRASSE É".as_bytes().to_vec())
        );
        assert_eq!(
            UnicodeLowerCaseTransform.encode("ÉA".as_bytes()).ok(),
            Some("éa".as_bytes().to_vec())
        );
        assert_eq!(
            UnicodeUpperCaseTransform.encode(&[0xff]).err(),
            Some(Error::not_utf8("unicode_upper_case"))
        );
        assert!(UnicodeLowerCaseTransform.encode(&[0xff]).is_err());
        assert!(UnicodeLowerCaseTransform.decode(b"a").is_err());
    }
}
