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
- **`export_tools`** (also `McpToolset::export_tools` and
  `McpClient::export_tools`) turns the gathered tools into OpenAI (plain
  or strict), Anthropic or Gemini tool definitions, with a warning for
  every schema keyword that had to be removed or rewritten.

Schema validation, hidden-character rules and provider dialects come from
[`rune-tool-schema`](../rune-tool-schema); this crate adds the MCP
policies on top (size caps, allowlists, namespaces, fencing).

## Security model

Client side (consuming servers):

| Threat | Defence | Default |
| --- | --- | --- |
| Tool shadowing / name collisions across servers | `McpToolset` namespaces every tool as `<ns>__<tool>`; namespaces cannot contain `__` | on |
| Duplicate name inside one server | both copies dropped (or listing fails when `strict`) | on |
| Malformed definitions | MCP name rules, object schemas, schema ≤ 64 KiB and ≤ 32 levels, input schema must compile (well-typed keywords, only local `$ref`s, usable `pattern`s) | on |
| Hostile schemas (`$ref` cycles, `anyOf` explosions) | argument checks stop at 200 000 steps or 128 subschema levels and refuse the call ("too complex to check within the limits"); values deeper than 32 levels or over 10 000 nodes refused up front | on |
| Tool poisoning in descriptions | invisible / bidi / Unicode-tag characters stripped from descriptions, titles, tags and schema annotations, descriptions capped at 1 KiB; tools with such characters in property names or `enum` values rejected | on |
| Arguments that do not fit the schema | checked against the listed input schema before the call is sent; an `isError` result names each violation by JSON Pointer | on |
| "Rug pull" (definition changes after review) | a `RemoteTool` refuses calls once the server's definition differs (`Error::DefinitionChanged`) | on |
| Unwanted tools | `with_allowed_tools([...])` per server, plus `ToolPolicy` | off / allow all |
| Self-declared "read-only" tools | safety claims ignored unless `ServerTrust::Trusted` | untrusted |
| Hanging servers | `call_timeout` 60 s (server is sent a cancellation), `request_timeout` 30 s incl. `initialize` | on |
| Huge results | tool results capped at 128 KiB (`ToolOutput::truncated`); resources and prompts above it fail with `Error::TooLarge` | on |
| Prompt injection in results | chain-tool results wrapped in an `<mcp_result server=… tool=…>` fence that the content cannot close; put `sanitize::FENCE_NOTICE` in the system prompt | on |
| Oversized listings | at most 256 tools / resources / prompts per listing | on |
| Secrets leaking to stdio servers | `StdioServer`: no shell, **cleared environment** plus only the variables you pass, stderr discarded, killed on drop | on |
| Credentials over plain HTTP | `HttpClientConfig`: `https://` unless loopback, no `user:pass@` URLs; token and header values `[REDACTED]` in `Debug` | on |

Server side (serving tools): each tool's input schema is compiled into a
`rune_tool_schema::Validator` at registration (a schema that does not
compile is refused), and arguments are checked against it before the
handler runs (types, required, `additionalProperties: false`, enums,
`const`, bounds, `pattern`, `multipleOf`, combinators, local `$ref`,
nested objects and arrays), within the same limits as the client;
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
manifest. Build that client with redirects turned off
(`reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())`):
a stock `reqwest::Client` follows redirects to other hosts, and to plain
`http://`, and only strips `Authorization` and cookies on the way, so
headers added with `HttpClientConfig::with_header` (an API key, say) would
be sent to wherever the server redirects.

## Installation

```toml
[dependencies]
rune-mcp = { version = "0.2", features = ["stdio", "chain"] }
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

### Exporting tools for a model provider

Hand the gathered tools to a model API in its own format. Every keyword
the provider would reject or ignore is removed or rewritten and reported,
and tools the provider cannot take (a `.` in the name for OpenAI, a
schema it rejects outright) are skipped with a reason:

```rust,no_run
use rune_mcp::{Dialect, ExportOptions, McpToolset};

async fn openai_tools(toolset: &McpToolset) -> Result<Vec<serde_json::Value>, rune_mcp::Error> {
    let export = toolset
        .export_tools(Dialect::OpenAiStrict, &ExportOptions::default())
        .await?;
    for warning in &export.warnings {
        // e.g. "docs__search: /properties/q/maxLength: ... (maxLength, removed)"
        eprintln!("schema change: {warning}");
    }
    for skipped in &export.skipped {
        eprintln!("not exported: {}: {}", skipped.name, skipped.reason);
    }
    Ok(export.definitions())
}
```

Calls still go through `toolset.call_tool(name, args)`, and arguments are
checked against the server's original schema, so a constraint removed for
the provider is still enforced. With `Dialect::OpenAiStrict`, optional
properties come back as `null`; run
`rune_tool_schema::drop_optional_nulls(&tool.input_schema, &mut args)`
first.

## Migrating from 0.1

- `rune_mcp::validate_arguments(schema, args)` is gone. Use
  `rune_tool_schema::Validator::new(schema)?.validate(&args)` (or
  `ToolDescriptor::validate_arguments`), which returns `Violations` with a
  JSON Pointer per problem; `rune_mcp::schema_limits()` gives the limits
  this crate uses.
- Invalid-argument results now list every violation, one per line, in
  `rune-tool-schema`'s wording (`/port: less than the minimum 1` instead of
  `/port: below the minimum`). Match on `is_error`, not on the text.
- `McpServer::tool` / `add_tool` refuse an input schema that does not
  compile (`Error::Descriptor(rune_tool_schema::Error::InvalidSchema { .. })`):
  a `$ref` outside the document, a `pattern` the `regex` crate cannot
  build (look-around, backreferences), a keyword with a value of the wrong
  type.
- The client rejects listed tools for the same reasons, and for hidden
  characters in property names or `enum` values. They show up in
  `McpClient::rejected()` (or fail the listing when strict).
- The client checks arguments before sending a call; invalid ones come
  back as an `isError` result and never reach the server.
- `sanitize::strip_hidden` is now `rune_tool_schema::strip_hidden`
  re-exported: it returns `Cow<str>`, removes a wider set of characters
  (variation selectors, Hangul fillers, Mongolian vowel separator and
  others) and turns U+2028/U+2029 into `\n`. `sanitize::clean_text` still
  returns `String`.

## Migrating from the unreleased 0.1 development API

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
