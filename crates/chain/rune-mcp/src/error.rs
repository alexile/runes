//! The crate's error type.

use std::time::Duration;

use crate::sanitize::clean_text;

/// A boxed error from rmcp or the transport underneath it.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Longest server-supplied error message kept in [`Error::Protocol`].
const MAX_PEER_MESSAGE: usize = 1024;

/// Why an MCP server or client operation failed.
///
/// A tool that runs and fails is not an error at this level: it comes back
/// as a [`ToolOutput`](crate::ToolOutput) with
/// [`is_error`](crate::ToolOutput::is_error) set, as MCP prescribes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A tool descriptor was rejected (registration, export or import).
    #[error(transparent)]
    Descriptor(#[from] rune_tool_schema::Error),
    /// A tool, resource, prompt or server namespace is already registered.
    #[error("{kind} {name:?} is already registered")]
    Duplicate {
        /// `"tool"`, `"resource"`, `"prompt"` or `"server"`.
        kind: &'static str,
        /// The duplicated name or URI.
        name: String,
    },
    /// No tool with this name is known (not registered, not listed by the
    /// remote server, or hidden by the policy or allowlist).
    #[error("unknown tool {0:?}")]
    UnknownTool(String),
    /// No resource with this URI is registered.
    #[error("unknown resource {0:?}")]
    UnknownResource(String),
    /// No prompt with this name is known.
    #[error("unknown prompt {0:?}")]
    UnknownPrompt(String),
    /// No server is registered under this namespace in an
    /// [`McpToolset`](crate::McpToolset).
    #[error("unknown server namespace {0:?}")]
    UnknownServer(String),
    /// The policy refused the call.
    #[error("tool {tool:?} denied by policy: {reason}")]
    Denied {
        /// The tool that was called.
        tool: String,
        /// The policy's reason.
        reason: String,
    },
    /// A definition from the server broke a rule or a limit (name, schema,
    /// list size). Only returned in [strict](crate::ClientOptions::strict)
    /// mode; otherwise the definition is skipped and reported by
    /// [`McpClient::rejected`](crate::McpClient::rejected).
    #[error("server definition {name:?} rejected: {reason}")]
    Rejected {
        /// The tool, resource or prompt name.
        name: String,
        /// The rule it broke.
        reason: String,
    },
    /// The server changed a tool's definition after the
    /// [`RemoteTool`](crate::RemoteTool) was created (a "rug pull"); list
    /// the tools again and review them before calling.
    #[error("the definition of tool {0:?} changed on the server; list tools again")]
    DefinitionChanged(String),
    /// A server namespace breaks the naming rules
    /// ([`validate_namespace`](crate::sanitize::validate_namespace)).
    #[error("invalid server namespace {namespace:?}: {reason}")]
    InvalidNamespace {
        /// The namespace.
        namespace: String,
        /// The rule it broke.
        reason: &'static str,
    },
    /// A transport configuration was refused, such as plain HTTP to a
    /// remote host or an empty program name.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// A request took longer than its timeout. The server is told to
    /// cancel it where the protocol allows.
    #[error("{operation} timed out after {after:?}")]
    Timeout {
        /// What timed out (`"tools/call"`, `"initialize"`, …).
        operation: &'static str,
        /// The timeout that expired.
        after: Duration,
    },
    /// A resource or prompt from the server is larger than
    /// [`max_result_bytes`](crate::ClientOptions::max_result_bytes).
    #[error("{what} exceeds the {limit}-byte limit")]
    TooLarge {
        /// What was too large.
        what: &'static str,
        /// The limit in bytes.
        limit: usize,
    },
    /// The MCP session could not be set up (transport failure or a failed
    /// `initialize` handshake).
    #[error("MCP initialization failed: {0}")]
    Initialize(#[source] BoxError),
    /// The peer answered a request with a JSON-RPC error. The message is
    /// the peer's, cleaned of hidden characters and cut to 1 KiB.
    #[error("MCP error {code}: {message}")]
    Protocol {
        /// JSON-RPC error code.
        code: i32,
        /// Error message.
        message: String,
    },
    /// The transport failed, closed, or the peer sent an unexpected reply.
    #[error("MCP transport error: {0}")]
    Transport(#[source] BoxError),
    /// A value could not be converted between this crate's types and the
    /// MCP wire types.
    #[error("cannot convert {what}: {reason}")]
    Convert {
        /// What was being converted.
        what: &'static str,
        /// The underlying error.
        reason: String,
    },
    /// An operation on one server of an [`McpToolset`](crate::McpToolset)
    /// failed.
    #[error("server {namespace:?}: {source}")]
    Server {
        /// The server's namespace.
        namespace: String,
        /// What went wrong.
        #[source]
        source: Box<Self>,
    },
}

impl From<rmcp::ServiceError> for Error {
    fn from(err: rmcp::ServiceError) -> Self {
        match err {
            rmcp::ServiceError::McpError(data) => Self::Protocol {
                code: data.code.0,
                message: clean_text(&data.message, MAX_PEER_MESSAGE),
            },
            other => Self::Transport(Box::new(other)),
        }
    }
}
