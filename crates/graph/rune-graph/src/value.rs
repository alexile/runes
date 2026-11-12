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
#[cfg_attr(feature = "persist", derive(serde::Serialize, serde::Deserialize))]
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
