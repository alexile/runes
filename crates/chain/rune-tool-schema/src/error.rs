//! The crate's error type.

/// Why a descriptor, name, category, schema or tool definition was
/// rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The tool name breaks the MCP naming rules (1 to 128 characters from
    /// `A-Z a-z 0-9 _ - .`).
    #[error("invalid tool name {name:?}: {reason}")]
    InvalidName {
        /// The rejected name.
        name: String,
        /// Which rule it breaks.
        reason: &'static str,
    },
    /// The category is not a `snake_case` identifier of at most 64 bytes.
    #[error(
        "invalid tool category {0:?}: expected 1-64 bytes of [a-z0-9_], starting with a letter"
    )]
    InvalidCategory(String),
    /// The description is empty or only whitespace.
    #[error("tool {0:?} has an empty description")]
    EmptyDescription(String),
    /// A schema is not a JSON object whose `type` is `"object"`, as MCP
    /// requires for `inputSchema` and `outputSchema`.
    #[error("tool {tool:?}: {field} must be a JSON Schema object with \"type\": \"object\"")]
    SchemaNotObject {
        /// The tool the schema belongs to.
        tool: String,
        /// `inputSchema` or `outputSchema`.
        field: &'static str,
    },
    /// A schema cannot be compiled for argument checking.
    #[error("invalid schema at {pointer:?}: {reason}")]
    InvalidSchema {
        /// JSON Pointer to the problem inside the schema.
        pointer: String,
        /// What is wrong.
        reason: String,
    },
    /// The input schema uses a keyword the target provider rejects and
    /// that cannot be rewritten; see [`Dialect::lint`](crate::Dialect::lint).
    #[error("tool {tool:?}: {dialect} cannot accept the schema at {pointer:?}: {reason}")]
    UnsupportedSchema {
        /// The tool the schema belongs to.
        tool: String,
        /// The target dialect.
        dialect: &'static str,
        /// JSON Pointer to the keyword.
        pointer: String,
        /// Why.
        reason: String,
    },
    /// Model-facing text contains an invisible or bidirectional character
    /// (see [`is_hidden_char`](crate::is_hidden_char)).
    #[error("tool {tool:?}: hidden character U+{:04X} in {location}", u32::from(*character))]
    HiddenCharacter {
        /// The tool concerned.
        tool: String,
        /// `title`, `description`, `tags`, or a JSON Pointer into the
        /// input schema prefixed with `inputSchema`.
        location: String,
        /// The character found.
        character: char,
    },
    /// The description is longer than the cap in force.
    #[error("tool {tool:?}: description is {chars} characters, more than the {max} allowed")]
    DescriptionTooLong {
        /// The tool concerned.
        tool: String,
        /// Its length in characters.
        chars: usize,
        /// The cap.
        max: usize,
    },
    /// The `_meta` entry this crate writes could not be read back.
    #[error("tool {tool:?}: malformed `_meta` entry {key:?}: {reason}")]
    InvalidMeta {
        /// The tool the entry belongs to.
        tool: String,
        /// The `_meta` key.
        key: &'static str,
        /// The deserialization error.
        reason: String,
    },
}
