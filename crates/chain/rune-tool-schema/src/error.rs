//! The crate's error type.

/// Why a descriptor, name, category or MCP tool definition was rejected.
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
