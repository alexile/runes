//! Hardened MCP client and server for rune tools, built on [rmcp] and
//! [`rune_tool_schema`].
//!
//! - [`McpServer`] serves tools described by a [`ToolDescriptor`] and run by
//!   a [`ToolHandler`], plus resources and prompts. Arguments are checked
//!   against the tool's input schema before the handler runs, handlers run
//!   isolated (a panic becomes a fixed error message), and an optional call
//!   timeout bounds them.
//! - [`McpClient`] consumes an external MCP server's tools, resources and
//!   prompts, treating everything it sends as untrusted: definitions are
//!   validated, descriptions stripped of invisible characters and capped,
//!   duplicate names dropped, safety claims ignored unless
//!   [`ServerTrust::Trusted`], every request time-limited, and results
//!   capped. [`RemoteTool`] makes each tool a handler (to proxy) and, with
//!   the `chain` feature, a `rune_chain_core::Tool` whose results are
//!   fenced as untrusted data ([`sanitize::fence`]).
//! - [`McpToolset`] joins several servers into one tool set, exposing each
//!   tool as `<namespace>__<tool>` so servers cannot collide with or shadow
//!   each other.
//! - A [`ToolPolicy`] on either side, and a per-server allowlist on the
//!   client, decide which tools are listed and which calls run.
//! - Arguments are checked on both sides with
//!   [`rune_tool_schema::Validator`] (JSON Pointer errors, local `$ref`,
//!   bounded depth, size and work; see [`schema_limits`]), compiled once
//!   per tool when it is registered or listed.
//! - [`McpToolset::export_tools`] and [`McpClient::export_tools`] turn the
//!   gathered tools into `OpenAI` (plain or strict), Anthropic or Gemini
//!   tool definitions, listing every schema keyword that had to be removed
//!   or rewritten ([`DialectExport`]).
//!
//! Transports are rmcp's: any `AsyncRead + AsyncWrite` stream (in-process
//! `tokio::io::duplex`, sockets, pipes) out of the box; stdio, and local
//! servers spawned without a shell and with a cleared environment
//! ([`StdioServer`]), with the `stdio` feature; a Streamable HTTP endpoint
//! with `http-server`; a Streamable HTTP client configuration that insists
//! on HTTPS and redacts credentials (`HttpClientConfig`) with
//! `http-client`. The `chain` feature bridges `rune_chain_core::Tool` in
//! both directions.
//!
//! Protocol: [Model Context Protocol][spec] (tools, resources, prompts,
//! list-changed notifications).
//!
//! [rmcp]: https://docs.rs/rmcp
//! [spec]: https://modelcontextprotocol.io/specification/2025-11-25/server
//!
//! # Example
//!
//! A rune tool served over MCP and called by a client, in memory:
//!
//! ```
//! use rune_mcp::{tool_fn, ClientOptions, McpClient, McpServer, ServerTrust, ToolError, ToolOutput};
//! use rune_tool_schema::{single_input_schema, ToolDescriptor, ToolHints};
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let upper = ToolDescriptor::new("upper", "Upper-case the input.")
//!     .with_hints(ToolHints::PURE)
//!     .with_input_schema(single_input_schema("Text"));
//! let server = McpServer::new("demo", "0.1.0").tool(
//!     upper,
//!     tool_fn(|args| async move {
//!         let input = args.get("input").and_then(|v| v.as_str()).ok_or(ToolError::new("no input"))?;
//!         Ok(ToolOutput::text(input.to_uppercase()))
//!     }),
//! )?;
//!
//! let (server_io, client_io) = tokio::io::duplex(64 * 1024);
//! // The session lives as long as the `RunningServer`; keep it in a task.
//! tokio::spawn(async move { server.serve(server_io).await?.waiting().await });
//! let client = McpClient::connect(
//!     client_io,
//!     ClientOptions::default().with_trust(ServerTrust::Trusted),
//! )
//! .await?;
//!
//! let tools = client.list_tools().await?;
//! assert_eq!(tools[0].name, "upper");
//!
//! let args = serde_json::json!({"input": "hello"}).as_object().unwrap().clone();
//! let out = client.call_tool("upper", args).await?;
//! assert_eq!(out.text_content(), "HELLO");
//! client.close().await?;
//! # Ok::<(), rune_mcp::Error>(())
//! # })?;
//! # Ok::<(), rune_mcp::Error>(())
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "chain")]
mod chain;
mod client;
mod convert;
mod error;
mod export;
mod handler;
#[cfg(feature = "http-client")]
mod http;
mod output;
mod policy;
mod resource;
pub mod sanitize;
mod schema;
mod server;
#[cfg(feature = "stdio")]
mod stdio;
mod toolset;

#[cfg(feature = "chain")]
pub use chain::{ChainTool, chain_input};
pub use client::{
    ClientOptions, DEFAULT_CALL_TIMEOUT, DEFAULT_MAX_DESCRIPTION_BYTES, DEFAULT_MAX_LIST_ITEMS,
    DEFAULT_MAX_RESULT_BYTES, DEFAULT_MAX_SCHEMA_BYTES, DEFAULT_REQUEST_TIMEOUT, ListChanges,
    McpClient, Rejection, RemoteTool, ServerInfo,
};
pub use convert::{ServerTrust, mcp_to_tool, tool_to_mcp};
pub use error::{BoxError, Error};
pub use export::{DialectExport, ExportWarning, export_tools};
pub use handler::{FnHandler, ToolHandler, tool_fn};
#[cfg(feature = "http-client")]
pub use http::HttpClientConfig;
pub use output::{Content, ToolError, ToolOutput};
pub use policy::{
    AllOf, AllowAll, AllowNames, Decision, DenyNames, MaxSafety, Side, ToolCall, ToolPolicy,
};
pub use resource::{
    FnSource, PromptArgument, PromptHandler, PromptInfo, PromptMessage, PromptResult, PromptRole,
    ResourceBody, ResourceContent, ResourceHandler, ResourceInfo, prompt_fn, resource_fn,
};
pub use schema::{MAX_SCHEMA_DEPTH, MAX_VALIDATION_STEPS, schema_limits};
pub use server::{McpServer, RunningServer};
#[cfg(feature = "stdio")]
pub use stdio::StdioServer;
pub use toolset::McpToolset;

/// The rmcp version this crate is built on, re-exported for transports and
/// wire types.
pub use rmcp;
pub use rune_tool_schema;
pub use rune_tool_schema::{Dialect, ExportOptions, ToolDescriptor};
