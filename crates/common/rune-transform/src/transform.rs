//! The [`Transform`] trait and the building blocks shared by every transform.

use std::fmt;
use std::sync::Arc;

use crate::Error;

/// The broad family a transform belongs to.
///
/// Used to group transforms in listings and to let callers pick, say, every
/// encoding for payload evasion without naming them one by one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Category {
    /// Text encodings of bytes: base64, base32, hex, URL, HTML entities.
    Encoding,
    /// Backslash and percent escape sequences (`\xHH`, `\uHHHH`, `%uHHHH`).
    Escape,
    /// Numeric renderings of bytes (binary digits, decimal values).
    Numeric,
    /// Compression formats (gzip, zlib, raw deflate).
    Compression,
    /// Classical ciphers and self-inverse byte shuffles (ROT13, XOR, …).
    Cipher,
    /// Cryptographic digests.
    Hash,
    /// Lossy text rewrites (case folding, leetspeak, match/replace).
    Text,
    /// Framing: fixed prefixes and suffixes.
    Framing,
    /// Structured decoders (JWT) and anything else.
    Other,
}

impl Category {
    /// Lowercase name of the category, such as `"encoding"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Encoding => "encoding",
            Self::Escape => "escape",
            Self::Numeric => "numeric",
            Self::Compression => "compression",
            Self::Cipher => "cipher",
            Self::Hash => "hash",
            Self::Text => "text",
            Self::Framing => "framing",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// A named byte-to-byte operation, optionally reversible.
///
/// `encode` is the forward operation and always exists. Reversible
/// transforms also implement `decode` and return `true` from
/// [`is_reversible`](Transform::is_reversible); one-way transforms (hashes,
/// case folding) keep the default `decode`, which fails with
/// [`Error::NotReversible`].
///
/// Implement it to add a transform of your own, then
/// [`register`](crate::TransformRegistry::register) it or put it in a
/// [`TransformChain`](crate::TransformChain).
///
/// ```
/// use rune_transform::{Category, Error, Transform, TransformRegistry};
///
/// /// Doubles every byte; `decode` keeps every other one.
/// #[derive(Debug)]
/// struct Stutter;
///
/// impl Transform for Stutter {
///     fn id(&self) -> &str { "stutter" }
///     fn description(&self) -> &str { "Repeat every byte twice" }
///     fn category(&self) -> Category { Category::Other }
///     fn is_reversible(&self) -> bool { true }
///     fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
///         Ok(input.iter().flat_map(|&b| [b, b]).collect())
///     }
///     fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
///         if input.len() % 2 != 0 {
///             return Err(Error::malformed(self.id(), "odd length"));
///         }
///         Ok(input.iter().step_by(2).copied().collect())
///     }
/// }
///
/// let mut registry = TransformRegistry::builtin();
/// registry.register(Stutter)?;
/// let chain = registry.parse_chain("stutter | hex")?;
/// assert_eq!(chain.encode(b"ab")?, b"61616262");
/// assert_eq!(chain.decode(b"61616262")?, b"ab");
/// # Ok::<(), Error>(())
/// ```
pub trait Transform: Send + Sync + fmt::Debug {
    /// Stable, unique identifier: lowercase ASCII letters, digits and `_`.
    fn id(&self) -> &str;

    /// Short human-readable description of what the transform does.
    fn description(&self) -> &str;

    /// The family this transform belongs to.
    fn category(&self) -> Category {
        Category::Other
    }

    /// Whether [`decode`](Transform::decode) reverses
    /// [`encode`](Transform::encode).
    fn is_reversible(&self) -> bool {
        false
    }

    /// Apply the forward transform.
    ///
    /// # Errors
    /// Returns an [`Error`] when the input is not acceptable to this
    /// transform, for example non-UTF-8 bytes where text is required.
    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error>;

    /// Reverse the transform.
    ///
    /// # Errors
    /// Returns [`Error::NotReversible`] for a one-way transform, and another
    /// [`Error`] when `input` is not valid output of this transform.
    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let _ = input;
        Err(Error::not_reversible(self.id()))
    }
}

impl<T: Transform + ?Sized> Transform for Arc<T> {
    fn id(&self) -> &str {
        (**self).id()
    }

    fn description(&self) -> &str {
        (**self).description()
    }

    fn category(&self) -> Category {
        (**self).category()
    }

    fn is_reversible(&self) -> bool {
        (**self).is_reversible()
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        (**self).encode(input)
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        (**self).decode(input)
    }
}

impl<T: Transform + ?Sized> Transform for Box<T> {
    fn id(&self) -> &str {
        (**self).id()
    }

    fn description(&self) -> &str {
        (**self).description()
    }

    fn category(&self) -> Category {
        (**self).category()
    }

    fn is_reversible(&self) -> bool {
        (**self).is_reversible()
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        (**self).encode(input)
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        (**self).decode(input)
    }
}

/// A reversible transform run backwards: its `encode` is the inner
/// transform's `decode`, and the other way round.
///
/// Its id is the inner id with `:decode` appended, the same spelling
/// [`TransformRegistry::resolve`](crate::TransformRegistry::resolve) accepts.
///
/// ```
/// use rune_transform::{Inverse, Transform, TransformRegistry};
///
/// let registry = TransformRegistry::builtin();
/// let unhex = Inverse::new(registry.get("hex").expect("built in"))?;
/// assert_eq!(unhex.id(), "hex:decode");
/// assert_eq!(unhex.encode(b"6869")?, b"hi");
/// assert!(Inverse::new(registry.get("md5").expect("built in")).is_err());
/// # Ok::<(), rune_transform::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Inverse {
    /// The transform being inverted.
    inner: Arc<dyn Transform>,
    /// `<inner id>:decode`.
    id: String,
}

impl Inverse {
    /// Invert `inner`.
    ///
    /// # Errors
    /// Returns [`Error::NotReversible`] when `inner` is one-way.
    pub fn new(inner: Arc<dyn Transform>) -> Result<Self, Error> {
        if !inner.is_reversible() {
            return Err(Error::not_reversible(inner.id()));
        }
        let id = format!("{}:decode", inner.id());
        Ok(Self { inner, id })
    }

    /// The transform being inverted.
    #[must_use]
    pub fn inner(&self) -> &Arc<dyn Transform> {
        &self.inner
    }
}

impl Transform for Inverse {
    fn id(&self) -> &str {
        &self.id
    }

    fn description(&self) -> &str {
        self.inner.description()
    }

    fn category(&self) -> Category {
        self.inner.category()
    }

    fn is_reversible(&self) -> bool {
        true
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.decode(input)
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner.encode(input)
    }
}

/// Why a built-in step function rejected its input; [`FnTransform`] adds
/// the transform id to turn it into an [`Error`].
#[derive(Debug)]
pub enum Fault {
    /// Malformed input, with a reason.
    Malformed(String),
    /// Text was required and the input is not UTF-8.
    NotUtf8,
}

impl Fault {
    /// A [`Fault::Malformed`] from anything printable.
    pub fn malformed(reason: impl fmt::Display) -> Self {
        Self::Malformed(reason.to_string())
    }

    /// Attach the transform id.
    fn into_error(self, id: &str) -> Error {
        match self {
            Self::Malformed(reason) => Error::malformed(id, reason),
            Self::NotUtf8 => Error::not_utf8(id),
        }
    }
}

impl From<std::str::Utf8Error> for Fault {
    fn from(_: std::str::Utf8Error) -> Self {
        Self::NotUtf8
    }
}

/// Signature of a built-in encode or decode step.
pub type StepFn = fn(&[u8]) -> Result<Vec<u8>, Fault>;

/// A built-in transform made of a pair of free functions.
pub struct FnTransform {
    /// Stable identifier.
    pub id: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Family.
    pub category: Category,
    /// Forward operation.
    pub encode: StepFn,
    /// Reverse operation, or `None` when one-way.
    pub decode: Option<StepFn>,
}

impl fmt::Debug for FnTransform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FnTransform")
            .field("id", &self.id)
            .field("category", &self.category)
            .field("reversible", &self.decode.is_some())
            .finish_non_exhaustive()
    }
}

impl Transform for FnTransform {
    fn id(&self) -> &str {
        self.id
    }

    fn description(&self) -> &str {
        self.description
    }

    fn category(&self) -> Category {
        self.category
    }

    fn is_reversible(&self) -> bool {
        self.decode.is_some()
    }

    fn encode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        (self.encode)(input).map_err(|fault| fault.into_error(self.id))
    }

    fn decode(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let decode = self.decode.ok_or_else(|| Error::not_reversible(self.id))?;
        decode(input).map_err(|fault| fault.into_error(self.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unnecessary_wraps, reason = "matches the StepFn signature")]
    fn upper(input: &[u8]) -> Result<Vec<u8>, Fault> {
        Ok(input.to_ascii_uppercase())
    }

    fn text_only(input: &[u8]) -> Result<Vec<u8>, Fault> {
        Ok(std::str::from_utf8(input)?.as_bytes().to_vec())
    }

    #[test]
    fn fn_transform_maps_faults_and_one_way_decode() {
        let one_way = FnTransform {
            id: "up",
            description: "upper",
            category: Category::Text,
            encode: upper,
            decode: None,
        };
        assert!(!one_way.is_reversible());
        assert_eq!(one_way.encode(b"ab").ok(), Some(b"AB".to_vec()));
        assert_eq!(
            one_way.decode(b"AB").err().map(|e| e.code()),
            Some("transform.not_reversible")
        );

        let text = FnTransform {
            id: "text",
            description: "text",
            category: Category::Other,
            encode: text_only,
            decode: Some(text_only),
        };
        assert_eq!(text.encode(&[0xff]).err(), Some(Error::not_utf8("text")));
    }

    #[test]
    fn inverse_swaps_directions_and_wrappers_delegate() {
        let inner: Arc<dyn Transform> = Arc::new(FnTransform {
            id: "up",
            description: "upper",
            category: Category::Text,
            encode: upper,
            decode: Some(upper),
        });
        let inverse = Inverse::new(Arc::clone(&inner)).ok();
        let inverse = inverse.as_ref();
        assert_eq!(inverse.map(Transform::id), Some("up:decode"));
        assert_eq!(inverse.map(Transform::category), Some(Category::Text));
        assert_eq!(inverse.map(|t| t.inner().id()), Some("up"));

        let boxed: Box<dyn Transform> = Box::new(Arc::clone(&inner));
        assert_eq!(boxed.id(), "up");
        assert_eq!(boxed.description(), "upper");
        assert!(boxed.is_reversible());
        assert_eq!(boxed.decode(b"x").ok(), Some(b"X".to_vec()));
        assert_eq!(Category::Hash.to_string(), "hash");
    }
}
