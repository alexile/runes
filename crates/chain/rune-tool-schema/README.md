# rune-tool-schema

> MCP-shaped tool descriptor: name, description, JSON-schema input, safety level and category

[![crates.io](https://img.shields.io/crates/v/rune-tool-schema)](https://crates.io/crates/rune-tool-schema)
[![docs.rs](https://img.shields.io/docsrs/rune-tool-schema)](https://docs.rs/rune-tool-schema)
[![license](https://img.shields.io/crates/l/rune-tool-schema)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

One description of an LLM-callable tool, shared by `rune-chain` tools, other
tool catalogs and MCP servers and clients. Plain data, no I/O.

- **`ToolDescriptor`**: name, title, description, input JSON Schema,
  optional output JSON Schema, `SafetyLevel`, `ToolHints`, `ToolCategory`,
  tags and version.
- **`SafetyLevel`** (`passive` < `active` < `intrusive`), ordered so a
  policy can compare levels directly.
- **`ToolHints`**: `read_only`, `destructive`, `idempotent`, `open_world`,
  one-to-one with MCP tool annotations. `ToolHints::PURE` for local
  computations, `ToolHints::MCP_DEFAULT` for what MCP assumes when a hint is
  missing.
- **`ToolCategory`**: an open set of `snake_case` names, with constants for
  the common ones.
- **`McpTool`**: the MCP `Tool` definition as `tools/list` returns it.
  `ToolDescriptor::to_mcp` validates (name rules, non-empty description,
  object-typed schemas) and exports; `McpTool::to_descriptor` imports a tool
  listed by an external server, using MCP defaults for missing annotations.
  Category, tags, safety and version travel in `_meta["runes/tool"]`, so an
  export round-trips losslessly. Unknown fields (`icons`, `execution`, ...)
  are preserved.

Field names and defaults follow the
[MCP specification, Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

## Installation

```toml
[dependencies]
rune-tool-schema = "0.1"
# Generate schemas from Rust types:
rune-tool-schema = { version = "0.1", features = ["schemars"] }
```

## Usage

```rust
use rune_tool_schema::{single_input_schema, McpTool, ToolCategory, ToolDescriptor, ToolHints};

let tool = ToolDescriptor::new("hex_encode", "Hex-encode a UTF-8 string.")
    .with_category(ToolCategory::ENCODING)
    .with_hints(ToolHints::PURE)
    .with_input_schema(single_input_schema("Text to encode"));

let mcp: McpTool = tool.to_mcp().unwrap();
let json = serde_json::to_string(&mcp).unwrap();
let back: McpTool = serde_json::from_str(&json).unwrap();
assert_eq!(back.to_descriptor().unwrap(), tool);
```

With the `schemars` feature, schemas come from types:

```rust,ignore
#[derive(schemars::JsonSchema)]
struct ScanArgs { host: String, ports: Option<Vec<u16>> }

let tool = ToolDescriptor::new("scan", "Scan a host.").with_input_type::<ScanArgs>();
```

## Trust

Annotations and `_meta` on a tool listed by an external MCP server are the
server's own claims. An unannotated tool imports as `intrusive`, but a
policy for untrusted servers should not rely on any claimed level.

## License

MIT
