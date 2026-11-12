# rune-chain-tools

> Standard LLM-callable tool implementations for rune-chain: encoding, hashing, analysis, and cipher utilities.

[![crates.io](https://img.shields.io/crates/v/rune-chain-tools)](https://crates.io/crates/rune-chain-tools)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-tools)](https://docs.rs/rune-chain-tools)
[![license](https://img.shields.io/crates/l/rune-chain-tools)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-chain-tools` provides LLM-callable wrappers over the `rune-*` utility crates. Each function takes and returns `String` values so they can be trivially wired into tool-call schemas for any `rune-chain-agent` or custom agent loop.

| Module | Tools |
|--------|-------|
| `encoding` | `hex_encode`, `hex_decode`, `base64_encode`, `base64_decode` |
| `hashing` | `sha256` |
| `analysis` | `entropy_score`, `extract_strings`, `extract_strings_from_hex` |
| `cipher` | `caesar_brute`, `xor_brute` |

## Safety

Every tool is a pure, in-memory computation. None of them reads files, starts processes or opens network connections,
so they need no path jail, host allowlist or approval step.

- **Arguments.** Each tool accepts free text (ReAct) or the function-calling form `{"input": "<text>"}`.
  It advertises a closed schema with only `input`, so `rune-chain-agent` can validate calls before they run.
  JSON objects of any other shape are rejected.
- **Size caps.** Input is limited to 1 MiB (`input::MAX_INPUT_BYTES`).
  `caesar_brute` takes at most 16 KiB, because its output is 26 times its input.
  `xor_brute` takes at most 64 KiB of hex, because it tries all 256 keys.
- **Errors.** Invalid input returns `ToolError::InvalidInput`. It never panics or returns an `"error: ..."` string as a success.

## Installation

```toml
[dependencies]
rune-chain-tools = "0.2"
```

## Usage

```rust
use rune_chain_tools::{encoding, hashing, analysis, cipher};

// Encoding
let hex = encoding::hex_encode("hello");
assert_eq!(hex, "68656c6c6f");

let decoded = encoding::hex_decode(&hex).unwrap();
assert_eq!(decoded, "hello");

let b64 = encoding::base64_encode("hello");
assert_eq!(b64, "aGVsbG8=");

// Hashing
let digest = hashing::sha256("hello");
assert_eq!(digest.len(), 64);

// Analysis
let score = analysis::entropy_score("hello world");
println!("entropy: {score:.4} bits/byte");

let strings = analysis::extract_strings("hello\x00world\x01embedded");
println!("strings: {:?}", strings);

// Cipher brute-force
let candidates = cipher::caesar_brute("khoor");
// candidates[0] contains "hello" (shift 3)

let candidates = cipher::xor_brute(&encoding::hex_encode(
    &String::from_utf8(rune_xor::xor_single(b"hello world", 0x42)).unwrap()
));
// candidates[0] contains "hello world"
```

### Tool descriptors and MCP

Every tool describes itself as a [`rune-tool-schema`](../rune-tool-schema)
`ToolDescriptor` (category, safety level, behaviour hints, input schema),
which exports to an MCP tool definition:

```rust
use rune_chain_tools::describe::{Describe, descriptors};
use rune_chain_tools::Sha256;

let mcp = Sha256.descriptor().to_mcp().unwrap();
assert_eq!(mcp.name, "sha256");
let all = descriptors(); // one per tool, for a catalog or `tools/list`
assert_eq!(all.len(), 10);
```

## Migrating from 0.1

- The `Tool` wrappers now unwrap `{"input": "..."}` arguments.
  Before, `hex_encode` called through native function calling encoded the whole JSON text.
  As a result, free-text input that is itself a JSON object must now be wrapped as `{"input": "<json>"}`.
- Each wrapper's `Tool::schema` is now closed (`additionalProperties: false`) and declares `maxLength`.
- Inputs above the size caps are rejected.
- `XorBrute` now returns `ToolError::InvalidInput` for invalid hex, instead of a successful `"error: invalid hex input"`.
- The free functions (`encoding::*`, `cipher::*`, and so on) are unchanged.

## License

MIT
