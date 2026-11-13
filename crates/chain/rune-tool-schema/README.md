# rune-tool-schema

> Tool definitions for LLM function calling: MCP descriptor, OpenAI/Anthropic/Gemini export with schema lint, argument validation and text hygiene

[![crates.io](https://img.shields.io/crates/v/rune-tool-schema)](https://crates.io/crates/rune-tool-schema)
[![docs.rs](https://img.shields.io/docsrs/rune-tool-schema)](https://docs.rs/rune-tool-schema)
[![license](https://img.shields.io/crates/l/rune-tool-schema)](LICENSE)

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

- **Provider dialects**: `ToolDescriptor::export(Dialect::…)` emits the
  definition OpenAI (plain or `strict` structured outputs), Anthropic
  (`input_schema`) or Gemini (OpenAPI-subset `FunctionDeclaration`)
  expects. The schema is rewritten into the provider's subset (strict mode:
  every property required, optional ones made nullable,
  `additionalProperties: false`; Gemini: `$ref`s inlined, upper-case types,
  `nullable`), and every change comes back as a `SchemaFinding` with a JSON
  Pointer. `Dialect::lint` reports which keywords a provider rejects or
  ignores without exporting, and names are checked against each provider's
  rules.
- **Argument validation**: `Validator` checks what a model sends back
  against the input schema (types, `required`, `enum`, `const`, numeric and
  length bounds, `pattern`, `items`, nested objects, `additionalProperties`,
  `anyOf`/`oneOf`/`allOf`, local `$ref`) and reports every violation with a
  JSON Pointer, e.g. `/days: greater than the maximum 14`. Depth, size and
  work are bounded by `Limits`; patterns run on the linear-time `regex`
  engine with a size cap. `ToolDescriptor::parse_arguments::<T>()`
  validates and deserializes in one step; `drop_optional_nulls` undoes the
  strict-mode nulls first.
- **Text hygiene**: tool text is a prompt-injection surface. `strip_hidden`
  removes zero-width, bidi-override, tag and variation-selector characters;
  `ToolDescriptor::check_hygiene` refuses them (and over-long descriptions),
  `ToolDescriptor::sanitized` cleans them. Export sanitizes and caps the
  description (`MAX_DESCRIPTION_CHARS`, 4096 by default).

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

Export for a provider and check what the model sends back:

```rust
use rune_tool_schema::{Dialect, ToolDescriptor};
use serde_json::json;

let tool = ToolDescriptor::new("get_weather", "Current weather for a city.")
    .with_input_schema(json!({
        "type": "object",
        "properties": {
            "city": { "type": "string", "minLength": 1 },
            "days": { "type": "integer", "minimum": 1, "maximum": 14 }
        },
        "required": ["city"]
    }));

let openai = tool.export(Dialect::OpenAiStrict).unwrap();
// minLength is outside strict mode's subset: removed and reported.
assert_eq!(openai.findings[0].pointer, "/properties/city/minLength");
let anthropic = tool.export(Dialect::Anthropic).unwrap();
assert!(anthropic.definition["input_schema"].is_object());

let err = tool.validate_arguments(&json!({ "days": 30 })).unwrap_err();
assert_eq!(
    err.to_string(),
    "invalid arguments:\n/city: missing required property\n/days: greater than the maximum 14"
);
```

With the `schemars` feature, schemas come from types:

```rust,ignore
#[derive(schemars::JsonSchema, serde::Deserialize)]
struct ScanArgs { host: String, ports: Option<Vec<u16>> }

let tool = ToolDescriptor::new("scan", "Scan a host.").with_input_type::<ScanArgs>();
let args: ScanArgs = tool.parse_arguments(&model_arguments)?;
```

Provider rules follow their public documentation and change over time;
treat findings as guidance and keep the original schema as the source of
truth (validate returned arguments against it, since removed constraints
are no longer seen by the model).

## Trust

Annotations and `_meta` on a tool listed by an external MCP server are the
server's own claims. An unannotated tool imports as `intrusive`, but a
policy for untrusted servers should not rely on any claimed level.

## License

MIT
