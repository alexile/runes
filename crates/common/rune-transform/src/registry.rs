//! Name-based lookup of transforms.

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use crate::{Category, Error, Inverse, Transform, TransformChain};

/// Longest accepted transform id, in bytes.
const MAX_ID_LEN: usize = 64;

/// Which way to run a transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Direction {
    /// The forward operation ([`Transform::encode`]).
    #[default]
    Encode,
    /// The reverse operation ([`Transform::decode`]).
    Decode,
}

impl Direction {
    /// `"encode"` or `"decode"`, the suffix used in chain specs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Encode => "encode",
            Self::Decode => "decode",
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl FromStr for Direction {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        match text {
            "encode" => Ok(Self::Encode),
            "decode" => Ok(Self::Decode),
            _ => Err(Error::InvalidSpec {
                spec: text.to_owned(),
                reason: "direction must be `encode` or `decode`",
            }),
        }
    }
}

/// A set of transforms, looked up by id.
///
/// [`TransformRegistry::builtin`] returns every built-in transform;
/// [`TransformRegistry::new`] starts empty. Either can be extended with
/// [`register`](Self::register). Cloning is cheap: transforms are shared.
///
/// Steps are named by a *spec*: a transform id, optionally followed by
/// `:encode` (the default) or `:decode` to run it backwards, as in
/// `base64:decode`.
///
/// ```
/// use rune_transform::{Category, TransformRegistry};
///
/// let registry = TransformRegistry::builtin();
/// assert!(registry.len() > 40);
/// assert!(registry.contains("gzip"));
/// assert_eq!(registry.get("sha1").map(|t| t.category()), Some(Category::Hash));
///
/// let chain = registry.parse_chain("base64:decode, hex")?;
/// assert_eq!(chain.encode(b"aGk=")?, b"6869");
/// # Ok::<(), rune_transform::Error>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct TransformRegistry {
    /// Transforms in registration order.
    order: Vec<Arc<dyn Transform>>,
    /// Position of each id in `order`.
    index: HashMap<String, usize>,
}

impl TransformRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry holding every built-in transform.
    ///
    /// Building it allocates the table; keep one around rather than calling
    /// this per value.
    #[must_use]
    pub fn builtin() -> Self {
        let mut registry = Self::new();
        for transform in crate::builtin::all() {
            let id = transform.id().to_owned();
            registry.index.insert(id, registry.order.len());
            registry.order.push(transform);
        }
        registry
    }

    /// Add a transform.
    ///
    /// # Errors
    /// Returns [`Error::InvalidSpec`] when the id is not lowercase ASCII
    /// letters, digits and `_` (at most 64 bytes), or
    /// [`Error::DuplicateId`] when the id is already taken.
    pub fn register<T: Transform + 'static>(&mut self, transform: T) -> Result<(), Error> {
        self.register_arc(Arc::new(transform))
    }

    /// Add a shared transform. See [`register`](Self::register).
    ///
    /// # Errors
    /// As for [`register`](Self::register).
    pub fn register_arc(&mut self, transform: Arc<dyn Transform>) -> Result<(), Error> {
        let id = transform.id();
        validate_id(id)?;
        if self.index.contains_key(id) {
            return Err(Error::DuplicateId { id: id.to_owned() });
        }
        self.index.insert(id.to_owned(), self.order.len());
        self.order.push(transform);
        Ok(())
    }

    /// The transform registered as `id`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<Arc<dyn Transform>> {
        self.index
            .get(id)
            .and_then(|&position| self.order.get(position))
            .map(Arc::clone)
    }

    /// Whether `id` is registered.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.index.contains_key(id)
    }

    /// Every registered id, in registration order.
    pub fn ids(&self) -> impl Iterator<Item = &str> + '_ {
        self.order.iter().map(Transform::id)
    }

    /// Every registered transform, in registration order.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn Transform>> + '_ {
        self.order.iter()
    }

    /// The registered transforms of one category, in registration order.
    pub fn by_category(&self, category: Category) -> impl Iterator<Item = &Arc<dyn Transform>> {
        self.order
            .iter()
            .filter(move |transform| transform.category() == category)
    }

    /// Number of registered transforms.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether nothing is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Look up a step spec (`id`, `id:encode` or `id:decode`).
    ///
    /// A `:decode` spec yields an [`Inverse`] of the transform.
    ///
    /// # Errors
    /// Returns [`Error::InvalidSpec`] for a malformed spec,
    /// [`Error::UnknownTransform`] for an unregistered id, or
    /// [`Error::NotReversible`] for `:decode` on a one-way transform.
    pub fn resolve(&self, spec: &str) -> Result<Arc<dyn Transform>, Error> {
        let (id, direction) = match spec.split_once(':') {
            Some((id, direction)) => (id, direction.parse()?),
            None => (spec, Direction::Encode),
        };
        let transform = self.lookup(id)?;
        match direction {
            Direction::Encode => Ok(transform),
            Direction::Decode => Ok(Arc::new(Inverse::new(transform)?)),
        }
    }

    /// Build a chain from step specs, in encode order.
    ///
    /// # Errors
    /// Returns the first error from [`resolve`](Self::resolve).
    pub fn chain<S: AsRef<str>>(&self, specs: &[S]) -> Result<TransformChain, Error> {
        specs
            .iter()
            .map(|spec| self.resolve(spec.as_ref()))
            .collect()
    }

    /// Build a chain from one string of step specs separated by `|`, `,`
    /// or whitespace, such as `"base64:decode | gzip:decode"`.
    ///
    /// An empty string gives an empty chain.
    ///
    /// # Errors
    /// Returns the first error from [`resolve`](Self::resolve).
    pub fn parse_chain(&self, specs: &str) -> Result<TransformChain, Error> {
        specs
            .split(|ch: char| ch == '|' || ch == ',' || ch.is_whitespace())
            .filter(|spec| !spec.is_empty())
            .map(|spec| self.resolve(spec))
            .collect()
    }

    /// Run the transform `id` in `direction`.
    ///
    /// # Errors
    /// Returns [`Error::UnknownTransform`] for an unregistered id, or the
    /// transform's own error.
    pub fn apply(&self, id: &str, direction: Direction, input: &[u8]) -> Result<Vec<u8>, Error> {
        let transform = self.lookup(id)?;
        match direction {
            Direction::Encode => transform.encode(input),
            Direction::Decode => transform.decode(input),
        }
    }

    /// Encode `input` with the transform `id`.
    ///
    /// # Errors
    /// As for [`apply`](Self::apply).
    pub fn encode(&self, id: &str, input: &[u8]) -> Result<Vec<u8>, Error> {
        self.apply(id, Direction::Encode, input)
    }

    /// Decode `input` with the transform `id`.
    ///
    /// # Errors
    /// As for [`apply`](Self::apply); one-way transforms fail with
    /// [`Error::NotReversible`].
    pub fn decode(&self, id: &str, input: &[u8]) -> Result<Vec<u8>, Error> {
        self.apply(id, Direction::Decode, input)
    }

    /// [`get`](Self::get), or [`Error::UnknownTransform`].
    fn lookup(&self, id: &str) -> Result<Arc<dyn Transform>, Error> {
        self.get(id)
            .ok_or_else(|| Error::UnknownTransform { id: id.to_owned() })
    }
}

/// Check that `id` is a well-formed transform id.
fn validate_id(id: &str) -> Result<(), Error> {
    let reason = if id.is_empty() {
        "id is empty"
    } else if id.len() > MAX_ID_LEN {
        "id is longer than 64 bytes"
    } else if !id
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        "id may only contain lowercase ASCII letters, digits and `_`"
    } else {
        return Ok(());
    };
    Err(Error::InvalidSpec {
        spec: id.to_owned(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrefixTransform;
    use std::collections::HashSet;

    #[test]
    fn builtin_ids_are_valid_and_unique() {
        let registry = TransformRegistry::builtin();
        assert!(registry.len() >= 40, "only {} transforms", registry.len());
        let unique: HashSet<&str> = registry.ids().collect();
        assert_eq!(unique.len(), registry.len());
        for id in registry.ids() {
            assert!(validate_id(id).is_ok(), "{id}");
            assert!(registry.contains(id));
        }
        assert!(registry.by_category(Category::Hash).count() >= 6);
        assert!(!registry.is_empty());
        assert!(TransformRegistry::new().is_empty());
    }

    #[test]
    fn register_rejects_duplicates_and_bad_ids() {
        let mut registry = TransformRegistry::builtin();
        assert_eq!(
            registry.register(PrefixTransform::new("x")).ok(),
            Some(()),
            "prefix is not built in"
        );
        assert_eq!(
            registry
                .register(PrefixTransform::new("y"))
                .err()
                .map(|e| e.code()),
            Some("transform.duplicate_id")
        );
        for bad in ["", "Base64", "a:b", "a b", &"x".repeat(65)] {
            assert_eq!(
                validate_id(bad).err().map(|e| e.code()),
                Some("transform.invalid_spec"),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn resolve_specs() {
        let registry = TransformRegistry::builtin();
        assert_eq!(
            registry
                .resolve("hex:encode")
                .ok()
                .map(|t| t.id().to_owned()),
            Some("hex".to_owned())
        );
        assert_eq!(
            registry
                .resolve("hex:decode")
                .ok()
                .map(|t| t.id().to_owned()),
            Some("hex:decode".to_owned())
        );
        assert_eq!(
            registry.resolve("hex:sideways").err().map(|e| e.code()),
            Some("transform.invalid_spec")
        );
        assert_eq!(
            registry.resolve("md5:decode").err(),
            Some(Error::not_reversible("md5"))
        );
        assert_eq!(
            registry.chain(&["base64", "nope"]).err().map(|e| e.code()),
            Some("transform.unknown_transform")
        );
        let chain = registry.parse_chain("  hex|base64 ,url  ").ok();
        assert_eq!(
            chain.map(|c| c.ids().map(str::to_owned).collect::<Vec<_>>()),
            Some(vec![
                "hex".to_owned(),
                "base64".to_owned(),
                "url".to_owned()
            ])
        );
        assert_eq!(registry.parse_chain("").ok().map(|c| c.len()), Some(0));
        assert_eq!(Direction::Decode.to_string(), "decode");
        assert_eq!("encode".parse::<Direction>().ok(), Some(Direction::Encode));
    }

    #[test]
    fn apply_by_id() {
        let registry = TransformRegistry::builtin();
        assert_eq!(registry.encode("hex", b"hi").ok(), Some(b"6869".to_vec()));
        assert_eq!(
            registry.apply("hex", Direction::Decode, b"6869").ok(),
            Some(b"hi".to_vec())
        );
        assert_eq!(
            registry.decode("sha1", b"x").err().map(|e| e.code()),
            Some("transform.not_reversible")
        );
        assert_eq!(
            registry.encode("nope", b"x").err().map(|e| e.code()),
            Some("transform.unknown_transform")
        );
    }
}
