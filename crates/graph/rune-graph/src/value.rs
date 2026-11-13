use std::fmt;

/// A property value stored on a node or edge.
///
/// `Value` covers the full set of JSON-compatible scalar types plus lists,
/// making it suitable as a general-purpose property bag for graph nodes and
/// edges. The `From` impls let you use Rust literals directly via [`props!`](crate::props).
///
/// # Example
///
/// ```rust
/// use rune_graph::Value;
///
/// let v: Value = "hello".into();
/// assert_eq!(v, Value::Str("hello".to_string()));
///
/// let n: Value = 42_i64.into();
/// assert_eq!(n, Value::Int(42));
/// ```
///
/// With the `persist` feature `Value` implements `serde::Serialize` and
/// `serde::Deserialize` using serde's externally tagged enum layout
/// (`{"Int": 3}` in JSON). Decoding refuses lists nested deeper than
/// [`Value::MAX_DEPTH`], so a hostile snapshot cannot exhaust the stack.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Explicit null / missing value.
    Null,
    /// Boolean.
    Bool(bool),
    /// 64-bit signed integer.
    Int(i64),
    /// 64-bit float.
    Float(f64),
    /// UTF-8 string.
    Str(String),
    /// Ordered list of values (heterogeneous).
    List(Vec<Self>),
}

impl Value {
    /// Deepest list nesting accepted when decoding a `Value`.
    pub const MAX_DEPTH: usize = 128;

    /// Whether decoding this value would fail the [`Value::MAX_DEPTH`] check.
    #[cfg(feature = "wal")]
    pub(crate) fn too_deep(&self) -> bool {
        fn deeper(v: &Value, depth: usize) -> bool {
            depth > Value::MAX_DEPTH
                || matches!(v, Value::List(items) if items.iter().any(|x| deeper(x, depth + 1)))
        }
        deeper(self, 0)
    }

    /// Borrow the string if this is a [`Value::Str`].
    ///
    /// ```rust
    /// use rune_graph::Value;
    /// assert_eq!(Value::from("a").as_str(), Some("a"));
    /// assert_eq!(Value::Int(1).as_str(), None);
    /// ```
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Return the integer if this is a [`Value::Int`].
    ///
    /// ```rust
    /// use rune_graph::Value;
    /// assert_eq!(Value::Int(7).as_int(), Some(7));
    /// ```
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// Return a numeric value as `f64` (`Int` is converted, `Float` returned as is).
    ///
    /// ```rust
    /// use rune_graph::Value;
    /// assert_eq!(Value::Int(2).as_f64(), Some(2.0));
    /// assert_eq!(Value::Float(0.5).as_f64(), Some(0.5));
    /// assert_eq!(Value::Null.as_f64(), None);
    /// ```
    #[allow(
        clippy::cast_precision_loss,
        reason = "integers above 2^53 lose precision, which is acceptable for a numeric view"
    )]
    #[must_use]
    pub const fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Int(n) => Some(*n as f64),
            Self::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Return the boolean if this is a [`Value::Bool`].
    ///
    /// ```rust
    /// use rune_graph::Value;
    /// assert_eq!(Value::Bool(true).as_bool(), Some(true));
    /// ```
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// `true` for [`Value::Null`].
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Float(x) => write!(f, "{x}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::List(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
        }
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Self::Int(i64::from(v))
    }
}

impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Self::Int(i64::from(v))
    }
}

impl From<usize> for Value {
    #[allow(
        clippy::cast_possible_wrap,
        reason = "values are masked or range-limited first; truncation is the intended encoding"
    )]
    fn from(v: usize) -> Self {
        Self::Int(v as i64)
    }
}

impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Self::Float(v)
    }
}

impl From<f32> for Value {
    fn from(v: f32) -> Self {
        Self::Float(f64::from(v))
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Self::Str(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Self::Str(v.to_string())
    }
}

impl From<Vec<Self>> for Value {
    fn from(v: Vec<Self>) -> Self {
        Self::List(v)
    }
}

impl From<Option<Self>> for Value {
    fn from(v: Option<Self>) -> Self {
        v.unwrap_or(Self::Null)
    }
}

#[cfg(feature = "persist")]
mod serde_impl {
    use std::fmt;

    use serde::de::{self, DeserializeSeed, EnumAccess, SeqAccess, VariantAccess, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::Value;

    const NAME: &str = "Value";
    const VARIANTS: &[&str] = &["Null", "Bool", "Int", "Float", "Str", "List"];

    impl Serialize for Value {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            match self {
                Self::Null => s.serialize_unit_variant(NAME, 0, "Null"),
                Self::Bool(b) => s.serialize_newtype_variant(NAME, 1, "Bool", b),
                Self::Int(n) => s.serialize_newtype_variant(NAME, 2, "Int", n),
                Self::Float(x) => s.serialize_newtype_variant(NAME, 3, "Float", x),
                Self::Str(v) => s.serialize_newtype_variant(NAME, 4, "Str", v),
                Self::List(v) => s.serialize_newtype_variant(NAME, 5, "List", v),
            }
        }
    }

    impl<'de> Deserialize<'de> for Value {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            ValueSeed { depth: 0 }.deserialize(d)
        }
    }

    #[derive(Clone, Copy)]
    struct ValueSeed {
        depth: usize,
    }

    impl<'de> DeserializeSeed<'de> for ValueSeed {
        type Value = Value;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
            if self.depth > Value::MAX_DEPTH {
                return Err(de::Error::custom("value lists nested too deeply"));
            }
            d.deserialize_enum(NAME, VARIANTS, self)
        }
    }

    enum Tag {
        Null,
        Bool,
        Int,
        Float,
        Str,
        List,
    }

    impl<'de> Deserialize<'de> for Tag {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct TagVisitor;
            impl Visitor<'_> for TagVisitor {
                type Value = Tag;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a Value variant")
                }
                fn visit_u64<E: de::Error>(self, v: u64) -> Result<Tag, E> {
                    match v {
                        0 => Ok(Tag::Null),
                        1 => Ok(Tag::Bool),
                        2 => Ok(Tag::Int),
                        3 => Ok(Tag::Float),
                        4 => Ok(Tag::Str),
                        5 => Ok(Tag::List),
                        _ => Err(E::invalid_value(de::Unexpected::Unsigned(v), &self)),
                    }
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Tag, E> {
                    match v {
                        "Null" => Ok(Tag::Null),
                        "Bool" => Ok(Tag::Bool),
                        "Int" => Ok(Tag::Int),
                        "Float" => Ok(Tag::Float),
                        "Str" => Ok(Tag::Str),
                        "List" => Ok(Tag::List),
                        _ => Err(E::unknown_variant(v, VARIANTS)),
                    }
                }
            }
            d.deserialize_identifier(TagVisitor)
        }
    }

    impl<'de> Visitor<'de> for ValueSeed {
        type Value = Value;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a Value")
        }
        fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Value, A::Error> {
            let (tag, variant) = data.variant::<Tag>()?;
            match tag {
                Tag::Null => variant.unit_variant().map(|()| Value::Null),
                Tag::Bool => variant.newtype_variant().map(Value::Bool),
                Tag::Int => variant.newtype_variant().map(Value::Int),
                Tag::Float => variant.newtype_variant().map(Value::Float),
                Tag::Str => variant.newtype_variant().map(Value::Str),
                Tag::List => variant
                    .newtype_variant_seed(ListSeed {
                        depth: self.depth + 1,
                    })
                    .map(Value::List),
            }
        }
    }

    struct ListSeed {
        depth: usize,
    }

    impl<'de> DeserializeSeed<'de> for ListSeed {
        type Value = Vec<Value>;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Vec<Value>, D::Error> {
            d.deserialize_seq(self)
        }
    }

    impl<'de> Visitor<'de> for ListSeed {
        type Value = Vec<Value>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a list of values")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<Value>, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1024));
            while let Some(v) = seq.next_element_seed(ValueSeed { depth: self.depth })? {
                out.push(v);
            }
            Ok(out)
        }
    }
}
