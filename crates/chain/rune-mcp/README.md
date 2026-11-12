# rune-mcp

> Hardened MCP client and server on rmcp: rune tools, resources and prompts, namespaced multi-server tool sets, policy, caps and fencing

[![crates.io](https://img.shields.io/crates/v/rune-mcp)](https://crates.io/crates/rune-mcp)
[![docs.rs](https://img.shields.io/docsrs/rune-mcp)](https://docs.rs/rune-mcp)
[![license](https://img.shields.io/crates/l/rune-mcp)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [Model Context Protocol](https://modelcontextprotocol.io/specification/2025-11-25/server)
client and server for tools described with
[`rune-tool-schema`](../rune-tool-schema), built on the official Rust SDK,
[rmcp](https://docs.rs/rmcp) 3.9. It bridges MCP to
[`rune-chain-core`](../rune-chain-core) agents in both directions.

MCP tool servers are a prime prompt-injection and data-exfiltration
vector, so the client treats everything a server sends as untrusted, and
the server checks everything a client sends before a handler sees it.

## What it does

- **`McpServer`** serves `ToolDescriptor` + `ToolHandler` pairs, plus
  resources (`resources/list`, `resources/read`) and prompts
  (`prompts/list`, `prompts/get`).
- **`McpClient`** consumes any MCP server: tools come back as
  `ToolDescriptor`s, calls as `ToolOutput`s; resources and prompts as
  `ResourceInfo` / `ResourceContent` and `PromptInfo` / `PromptResult`.
- **`McpToolset`** joins several servers into one tool set, exposing each
  tool as `<namespace>__<tool>`.
- **`RemoteTool`** turns a remote tool back into a handler (to proxy or
  aggregate) and, with the `chain` feature, into a `rune_chain_core::Tool`.
- **`ToolPolicy`**, on both sides, decides which tools are listed and which
  calls run: `AllowAll`, `MaxSafety`, `AllowNames`, `DenyNames`, `AllOf`,
  or any `Fn(&ToolCall) -> Decision` closure.

## Security model

Client side (consuming servers):

| Threat | Defence | Default |
| --- | --- | --- |
| Tool shadowing / name collisions across servers | `McpToolset` namespaces every tool as `<ns>__<tool>`; namespaces cannot contain `__` | on |
| Duplicate name inside one server | both copies dropped (or listing fails when `strict`) | on |
| Malformed definitions | MCP name rules, object schemas, schema ≤ 64 KiB and ≤ 32 levels | on |
| Tool poisoning in descriptions | invisible / bidi / Unicode-tag characters stripped, descriptions capped at 1 KiB | on |
| "Rug pull" (definition changes after review) | a `RemoteTool` refuses calls once the server's definition differs (`Error::DefinitionChanged`) | on |
| Unwanted tools | `with_allowed_tools([...])` per server, plus `ToolPolicy` | off / allow all |
| Self-declared "read-only" tools | safety claims ignored unless `ServerTrust::Trusted` | untrusted |
| Hanging servers | `call_timeout` 60 s (server is sent a cancellation), `request_timeout` 30 s incl. `initialize` | on |
| Huge results | tool results capped at 128 KiB (`ToolOutput::truncated`); resources and prompts above it fail with `Error::TooLarge` | on |
| Prompt injection in results | chain-tool results wrapped in an `<mcp_result server=… tool=…>` fence that the content cannot close; put `sanitize::FENCE_NOTICE` in the system prompt | on |
| Oversized listings | at most 256 tools / resources / prompts per listing | on |
| Secrets leaking to stdio servers | `StdioServer`: no shell, **cleared environment** plus only the variables you pass, stderr discarded, killed on drop | on |
| Credentials over plain HTTP | `HttpClientConfig`: `https://` unless loopback, no `user:pass@` URLs; token and header values `[REDACTED]` in `Debug` | on |

Server side (serving tools): arguments are validated against the tool's
input schema before the handler runs (`validate_arguments`: types, required,
`additionalProperties: false`, enums, bounds, nested objects and arrays);
handlers run in their own task, so a panic becomes the fixed message "the
tool failed with an internal error"; `with_call_timeout` bounds them;
`ChainTool` hides `ExecutionFailed`/`Other` messages ("tool execution
failed") unless `with_error_detail(true)`. Unknown names are echoed only
cleaned and cut.

## Transports

| Transport | Server | Client | Feature |
| --- | --- | --- | --- |
| Any `AsyncRead + AsyncWrite` stream | `McpServer::serve(stream)` | `McpClient::connect(stream, opts)` | (none) |
| stdio / child process | `McpServer::serve_stdio()` | `McpClient::spawn(&StdioServer, opts)` | `stdio` |
| Streamable HTTP | `McpServer::into_http_service(config)` | `McpClient::connect_http(client, &HttpClientConfig, opts)` | `http-server` / `http-client` |

`into_http_service` returns a `tower` service to mount in axum
(`Router::new().nest_service("/mcp", service)`) or hyper. By default it
accepts only loopback `Host` headers; widen `allowed_hosts` in the config
for a public deployment, and put authentication in the router.

`http-client` brings no HTTP stack: pass any rmcp `StreamableHttpClient`,
for example `reqwest::Client` with rmcp's
`transport-streamable-http-client-reqwest` feature enabled in your own
manifest.

## Installation

```toml
[dependencies]
rune-mcp = { version = "0.1", features = ["stdio", "chain"] }
```

## Usage

Serve a tool and call it, in memory:

```rust
use rune_mcp::{tool_fn, ClientOptions, McpClient, McpServer, MaxSafety, ToolError, ToolOutput};
use rune_tool_schema::{single_input_schema, SafetyLevel, ToolDescriptor, ToolHints};

#[tokio::main]
async fn main() -> Result<(), rune_mcp::Error> {
    let server = McpServer::new("demo", "0.1.0")
        .with_policy(MaxSafety(SafetyLevel::Active))
        .tool(
            ToolDescriptor::new("upper", "Upper-case the input.")
                .with_hints(ToolHints::PURE)
                .with_input_schema(single_input_schema("Text")),
            tool_fn(|args| async move {
                let input = args.get("input").and_then(|v| v.as_str()).ok_or(ToolError::new("no input"))?;
                Ok(ToolOutput::text(input.to_uppercase()))
            }),
        )?;
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move { server.serve(server_io).await?.waiting().await });

    let client = McpClient::connect(client_io, ClientOptions::default()).await?;
    let args = serde_json::json!({"input": "hello"}).as_object().cloned().unwrap_or_default();
    assert_eq!(client.call_tool("upper", args).await?.text_content(), "HELLO");
    Ok(())
}
```

Several external servers as one namespaced tool set for an agent
(`stdio` and `chain` features):

```rust,no_run
use std::time::Duration;
use rune_mcp::{ClientOptions, McpClient, McpToolset, StdioServer};

async fn tools() -> Result<Vec<rune_mcp::RemoteTool>, rune_mcp::Error> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let fetch = StdioServer::new("uvx").arg("mcp-server-fetch").env("PATH", &path);
    let git = StdioServer::new("uvx").args(["mcp-server-git", "--repository", "."]).env("PATH", &path);

    let options = ClientOptions::default().with_call_timeout(Duration::from_secs(20));
    let toolset = McpToolset::new()
        .with_server("fetch", McpClient::spawn(&fetch, options.clone()).await?)?
        .with_server(
            "git",
            McpClient::spawn(&git, options.with_allowed_tools(["git_status", "git_log"])).await?,
        )?;
    // `fetch__fetch`, `git__git_status`, `git__git_log`: each implements
    // `rune_chain_core::Tool` and returns fenced, capped results.
    toolset.remote_tools().await
}
```

Watch for `notifications/tools/list_changed` with `client.subscribe()` and
list again when it fires; tools that changed must be reviewed again.

## Migration from the unreleased 0.1 development API

- `McpClient::connect_child_process(Command, …)` → `McpClient::spawn(&StdioServer, …)`
  (the environment is now cleared; pass the variables the server needs).
- `Error::DuplicateTool(name)` → `Error::Duplicate { kind: "tool", name }`;
  a malformed definition in strict mode is `Error::Rejected`, not
  `Error::Descriptor`.
- `ChainTool(tool)` → `ChainTool::new(tool)`; error messages other than
  invalid input are hidden unless `with_error_detail(true)`.
- `RemoteTool` as a chain tool returns fenced output; turn it off with
  `ClientOptions::with_fence_results(false)`.
- The server validates arguments against the input schema, so handlers no
  longer see arguments that break it.

## License

MIT
