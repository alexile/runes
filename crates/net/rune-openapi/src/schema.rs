//! The normalized schema model and example generation.

use serde_json::{Map, Value};

/// Deepest schema nesting [`Schema::example_value`] walks.
const MAX_EXAMPLE_DEPTH: usize = 32;

/// The declared (or inferred) type of a schema.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum SchemaType {
    /// Text. Swagger 2.0 `file` parameters are strings with format `binary`.
    String,
    /// A whole number.
    Integer,
    /// Any number.
    Number,
    /// `true` or `false`.
    Boolean,
    /// A list.
    Array,
    /// A nested object.
    Object,
    /// Not declared and not inferable.
    #[default]
    Unknown,
}

impl SchemaType {
    /// The type of a concrete JSON value (`null` is [`SchemaType::Unknown`]).
    ///
    /// ```
    /// use rune_openapi::SchemaType;
    ///
    /// assert_eq!(SchemaType::of(&serde_json::json!(1.5)), SchemaType::Number);
    /// assert_eq!(SchemaType::of(&serde_json::json!(7)), SchemaType::Integer);
    /// ```
    #[must_use]
    pub fn of(value: &Value) -> Self {
        match value {
            Value::String(_) => Self::String,
            Value::Number(number) => {
                if number.is_f64() {
                    Self::Number
                } else {
                    Self::Integer
                }
            }
            Value::Bool(_) => Self::Boolean,
            Value::Array(_) => Self::Array,
            Value::Object(_) => Self::Object,
            Value::Null => Self::Unknown,
        }
    }

    /// Whether this is a scalar type (string, integer, number or boolean).
    #[must_use]
    pub const fn is_scalar(self) -> bool {
        matches!(
            self,
            Self::String | Self::Integer | Self::Number | Self::Boolean
        )
    }
}

/// How example values are chosen for generated requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ExampleStrategy {
    /// Use `example`, `examples`, `x-example` and `default` from the
    /// document first, then synthesize from the type.
    #[default]
    PreferExamples,
    /// Ignore document examples and defaults; synthesize every value from
    /// type, format, bounds and `enum`.
    TypeDefaults,
}

/// A schema with `$ref`s resolved, `allOf` merged and `oneOf`/`anyOf`
/// kept as [`variants`](Self::variants).
///
/// Every `OpenAPI` version normalizes to this shape: 3.1 type arrays
/// (`["string", "null"]`) set [`nullable`](Self::nullable), numeric
/// `exclusiveMinimum` becomes [`minimum`](Self::minimum) plus
/// [`exclusive_minimum`](Self::exclusive_minimum), `const` becomes a single
/// [`enum_values`](Self::enum_values) entry and Swagger 2.0 parameter
/// objects become schemas of their own.
///
/// Recursive references and very large schemas are cut off: the node that
/// was not expanded has [`truncated`](Self::truncated) set.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(default))]
#[non_exhaustive]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors the JSON Schema boolean keywords"
)]
pub struct Schema {
    /// Declared or inferred type.
    pub kind: SchemaType,
    /// Component name when the schema came from a `$ref` (`Pet` for
    /// `#/components/schemas/Pet`).
    pub name: Option<String>,
    /// Declared format, such as `int64`, `date-time`, `uuid` or `binary`.
    pub format: Option<String>,
    /// Whether `null` is allowed.
    pub nullable: bool,
    /// Allowed values (`enum`, or `const` as a single entry).
    pub enum_values: Vec<Value>,
    /// The declared `default`.
    pub default: Option<Value>,
    /// The declared `example` (or first of `examples`).
    pub example: Option<Value>,
    /// Lower bound for numbers.
    pub minimum: Option<f64>,
    /// Upper bound for numbers.
    pub maximum: Option<f64>,
    /// Whether [`minimum`](Self::minimum) itself is excluded.
    pub exclusive_minimum: bool,
    /// Whether [`maximum`](Self::maximum) itself is excluded.
    pub exclusive_maximum: bool,
    /// Minimum string length.
    pub min_length: Option<u64>,
    /// Maximum string length.
    pub max_length: Option<u64>,
    /// Regular expression strings must match (ECMA-262 dialect).
    pub pattern: Option<String>,
    /// Sent by the server only; generated requests leave it out.
    pub read_only: bool,
    /// Sent by the client only.
    pub write_only: bool,
    /// Object properties, in map order (sorted by name unless `serde_json`'s
    /// `preserve_order` feature is on).
    pub properties: Vec<Property>,
    /// Array item schema.
    pub items: Option<Box<Self>>,
    /// `oneOf` / `anyOf` alternatives.
    pub variants: Vec<Self>,
    /// Children were not expanded: a recursive `$ref`, or a depth or size
    /// limit was hit.
    pub truncated: bool,
}

/// A named object property.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct Property {
    /// Property name.
    pub name: String,
    /// Whether the parent object lists it in `required`.
    pub required: bool,
    /// The property's schema.
    pub schema: Schema,
}

impl Schema {
    /// A schema of the given type and nothing else.
    #[must_use]
    pub fn new(kind: SchemaType) -> Self {
        Self {
            kind,
            ..Self::default()
        }
    }

    /// The schema that describes this value's structure: itself, or its
    /// first [`variant`](Self::variants) when it declares no type,
    /// properties or items of its own.
    #[must_use]
    pub fn shape(&self) -> &Self {
        let mut current = self;
        for _ in 0..MAX_EXAMPLE_DEPTH {
            let bare = matches!(current.kind, SchemaType::Unknown | SchemaType::Object)
                && current.properties.is_empty()
                && current.items.is_none();
            match current.variants.first() {
                Some(first) if bare => current = first,
                _ => break,
            }
        }
        current
    }

    /// The property called `name`, looking through [`shape`](Self::shape).
    #[must_use]
    pub fn property(&self, name: &str) -> Option<&Property> {
        self.properties
            .iter()
            .chain(self.shape().properties.iter())
            .find(|property| property.name == name)
    }

    /// The item schema, looking through [`shape`](Self::shape).
    #[must_use]
    pub fn item_schema(&self) -> Option<&Self> {
        self.items
            .as_deref()
            .or_else(|| self.shape().items.as_deref())
    }

    /// Whether string values are raw bytes (`format: binary` or `base64`).
    #[must_use]
    pub fn is_binary(&self) -> bool {
        matches!(self.format.as_deref(), Some("binary" | "base64"))
    }

    /// An example value that satisfies the schema.
    ///
    /// With [`ExampleStrategy::PreferExamples`], declared `example` and
    /// `default` values win. Otherwise the first `enum` value is used, then
    /// a value synthesized from the type, format and bounds. Objects leave
    /// out read-only properties and optional recursive ones; arrays hold
    /// one item.
    ///
    /// ```
    /// use rune_openapi::{ExampleStrategy, Schema, SchemaType};
    ///
    /// let mut id = Schema::new(SchemaType::Integer);
    /// id.minimum = Some(10.0);
    /// assert_eq!(id.example_value(ExampleStrategy::TypeDefaults), 10);
    ///
    /// let mut when = Schema::new(SchemaType::String);
    /// when.format = Some("date".into());
    /// assert_eq!(when.example_value(ExampleStrategy::TypeDefaults), "2024-01-01");
    /// ```
    #[must_use]
    pub fn example_value(&self, strategy: ExampleStrategy) -> Value {
        self.example_at(strategy, 0)
    }

    fn example_at(&self, strategy: ExampleStrategy, depth: usize) -> Value {
        if strategy == ExampleStrategy::PreferExamples
            && let Some(example) = self.example.as_ref().or(self.default.as_ref())
        {
            return example.clone();
        }
        if let Some(value) = self.enum_values.iter().find(|value| !value.is_null()) {
            return value.clone();
        }
        if self.is_cut_off() {
            return Value::Object(Map::new());
        }
        let shape = self.shape();
        if !std::ptr::eq(shape, self) && depth < MAX_EXAMPLE_DEPTH {
            return shape.example_at(strategy, depth + 1);
        }
        match self.kind {
            SchemaType::Object => {
                let mut object = Map::new();
                if depth < MAX_EXAMPLE_DEPTH {
                    for property in &self.properties {
                        if property.schema.read_only
                            || (property.schema.is_cut_off() && !property.required)
                        {
                            continue;
                        }
                        object.insert(
                            property.name.clone(),
                            property.schema.example_at(strategy, depth + 1),
                        );
                    }
                }
                Value::Object(object)
            }
            SchemaType::Array => {
                let mut items = Vec::new();
                if depth < MAX_EXAMPLE_DEPTH
                    && let Some(item) = &self.items
                    && !(item.truncated && item.kind == SchemaType::Unknown)
                {
                    items.push(item.example_at(strategy, depth + 1));
                }
                Value::Array(items)
            }
            _ => self.synthesize(),
        }
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "example bounds are small numbers; saturating casts are fine"
    )]
    fn synthesize(&self) -> Value {
        match self.kind {
            SchemaType::Integer => {
                let mut value = self.minimum.map_or(1.0, f64::ceil);
                if self.exclusive_minimum
                    && let Some(minimum) = self.minimum
                    && value <= minimum
                {
                    value = minimum.floor() + 1.0;
                }
                if let Some(maximum) = self.maximum {
                    let mut ceiling = maximum.floor();
                    if self.exclusive_maximum && ceiling >= maximum {
                        ceiling -= 1.0;
                    }
                    value = value.min(ceiling);
                }
                Value::from(value as i64)
            }
            SchemaType::Number => {
                let mut value = self.minimum.unwrap_or(1.5);
                if self.exclusive_minimum && self.minimum.is_some() {
                    value += 1.0;
                }
                if let Some(maximum) = self.maximum {
                    let ceiling = if self.exclusive_maximum {
                        maximum - 0.5
                    } else {
                        maximum
                    };
                    value = value.min(ceiling);
                }
                serde_json::Number::from_f64(value).map_or_else(|| Value::from(1), Value::Number)
            }
            SchemaType::Boolean => Value::Bool(true),
            SchemaType::Array => Value::Array(Vec::new()),
            SchemaType::Object => Value::Object(Map::new()),
            SchemaType::String | SchemaType::Unknown => {
                let base = match self.format.as_deref().unwrap_or_default() {
                    "date-time" => "2024-01-01T00:00:00Z",
                    "date" => "2024-01-01",
                    "time" => "00:00:00",
                    "duration" => "P1D",
                    "uuid" => "00000000-0000-4000-8000-000000000000",
                    "email" | "idn-email" => "user@example.test",
                    "uri" | "url" | "iri" | "uri-reference" | "iri-reference" => {
                        "https://example.test/"
                    }
                    "hostname" | "idn-hostname" => "example.test",
                    "ipv4" => "192.0.2.1",
                    "ipv6" => "2001:db8::1",
                    "byte" | "base64" => "c3RyaW5n",
                    "binary" => "binary",
                    "password" => "password",
                    "int32" | "int64" => "1",
                    _ => "string",
                };
                let mut text = base.to_owned();
                let min_length = self.min_length.unwrap_or(0).min(1024) as usize;
                while text.chars().count() < min_length {
                    text.push('x');
                }
                if let Some(max_length) = self.max_length {
                    text = text.chars().take(max_length.min(1024) as usize).collect();
                }
                Value::String(text)
            }
        }
    }

    /// A truncated node with nothing known about it (a recursive `$ref`).
    fn is_cut_off(&self) -> bool {
        self.truncated && self.kind == SchemaType::Unknown && self.variants.is_empty()
    }

    /// Folds an `allOf` part into this schema: unset fields are taken from
    /// `other`, properties are appended and `required` flags are unioned.
    pub(crate) fn absorb(&mut self, other: Self) {
        if self.kind == SchemaType::Unknown {
            self.kind = other.kind;
        }
        fill(&mut self.format, other.format);
        fill(&mut self.default, other.default);
        fill(&mut self.example, other.example);
        fill(&mut self.minimum, other.minimum);
        fill(&mut self.maximum, other.maximum);
        fill(&mut self.min_length, other.min_length);
        fill(&mut self.max_length, other.max_length);
        fill(&mut self.pattern, other.pattern);
        if self.enum_values.is_empty() {
            self.enum_values = other.enum_values;
        }
        self.exclusive_minimum |= other.exclusive_minimum;
        self.exclusive_maximum |= other.exclusive_maximum;
        self.read_only |= other.read_only;
        self.write_only |= other.write_only;
        self.truncated |= other.truncated;
        for property in other.properties {
            if let Some(existing) = self
                .properties
                .iter_mut()
                .find(|existing| existing.name == property.name)
            {
                existing.required |= property.required;
            } else {
                self.properties.push(property);
            }
        }
        if self.items.is_none() {
            self.items = other.items;
        }
        self.variants.extend(other.variants);
    }
}

fn fill<T>(slot: &mut Option<T>, value: Option<T>) {
    if slot.is_none() {
        *slot = value;
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn string(format: &str) -> Schema {
        let mut schema = Schema::new(SchemaType::String);
        schema.format = Some(format.to_owned());
        schema
    }

    #[test]
    fn integer_bounds() {
        let mut schema = Schema::new(SchemaType::Integer);
        assert_eq!(schema.example_value(ExampleStrategy::TypeDefaults), 1);
        schema.minimum = Some(0.0);
        schema.exclusive_minimum = true;
        assert_eq!(schema.example_value(ExampleStrategy::TypeDefaults), 1);
        schema.minimum = Some(5.0);
        schema.maximum = Some(3.0);
        assert_eq!(schema.example_value(ExampleStrategy::TypeDefaults), 3);
        schema.maximum = Some(5.0);
        schema.exclusive_minimum = false;
        schema.exclusive_maximum = true;
        assert_eq!(schema.example_value(ExampleStrategy::TypeDefaults), 4);
    }

    #[test]
    fn number_bounds() {
        let mut schema = Schema::new(SchemaType::Number);
        assert_eq!(schema.example_value(ExampleStrategy::TypeDefaults), 1.5);
        schema.minimum = Some(2.5);
        schema.exclusive_minimum = true;
        assert_eq!(schema.example_value(ExampleStrategy::TypeDefaults), 3.5);
    }

    #[test]
    fn string_formats_and_lengths() {
        assert_eq!(
            string("uuid").example_value(ExampleStrategy::TypeDefaults),
            "00000000-0000-4000-8000-000000000000"
        );
        let mut short = string("");
        short.max_length = Some(3);
        assert_eq!(short.example_value(ExampleStrategy::TypeDefaults), "str");
        let mut long = string("");
        long.min_length = Some(8);
        assert_eq!(
            long.example_value(ExampleStrategy::TypeDefaults),
            "stringxx"
        );
    }

    #[test]
    fn examples_enum_and_strategy() {
        let mut schema = string("");
        schema.example = Some(json!("ex"));
        schema.enum_values = vec![Value::Null, json!("a")];
        assert_eq!(schema.example_value(ExampleStrategy::PreferExamples), "ex");
        assert_eq!(schema.example_value(ExampleStrategy::TypeDefaults), "a");
    }

    #[test]
    fn objects_skip_read_only_and_use_variants() {
        let mut id = Schema::new(SchemaType::Integer);
        id.read_only = true;
        let mut object = Schema::new(SchemaType::Object);
        object.properties = vec![
            Property {
                name: "id".into(),
                required: true,
                schema: id,
            },
            Property {
                name: "tags".into(),
                required: false,
                schema: Schema {
                    kind: SchemaType::Array,
                    items: Some(Box::new(Schema::new(SchemaType::Boolean))),
                    ..Schema::default()
                },
            },
        ];
        assert_eq!(
            object.example_value(ExampleStrategy::TypeDefaults),
            json!({"tags": [true]})
        );
        let either = Schema {
            variants: vec![object.clone(), Schema::new(SchemaType::Integer)],
            ..Schema::default()
        };
        assert_eq!(either.shape(), &object);
        assert!(either.property("tags").is_some());
        assert_eq!(
            either.example_value(ExampleStrategy::TypeDefaults),
            json!({"tags": [true]})
        );
    }

    #[test]
    fn absorb_merges() {
        let mut base = Schema::new(SchemaType::Object);
        base.properties.push(Property {
            name: "a".into(),
            required: false,
            schema: Schema::default(),
        });
        let mut part = Schema::new(SchemaType::String);
        part.format = Some("x".into());
        part.properties.push(Property {
            name: "a".into(),
            required: true,
            schema: Schema::default(),
        });
        part.properties.push(Property {
            name: "b".into(),
            required: false,
            schema: Schema::default(),
        });
        base.absorb(part);
        assert_eq!(base.kind, SchemaType::Object);
        assert_eq!(base.format.as_deref(), Some("x"));
        assert_eq!(base.properties.len(), 2);
        assert!(base.properties[0].required);
    }

    #[test]
    fn value_types() {
        assert_eq!(SchemaType::of(&json!("x")), SchemaType::String);
        assert_eq!(SchemaType::of(&json!(true)), SchemaType::Boolean);
        assert_eq!(SchemaType::of(&json!([])), SchemaType::Array);
        assert_eq!(SchemaType::of(&json!({})), SchemaType::Object);
        assert_eq!(SchemaType::of(&Value::Null), SchemaType::Unknown);
        assert!(SchemaType::Integer.is_scalar());
        assert!(!SchemaType::Object.is_scalar());
    }
}
