//! Standard LLM-callable tool implementations for the `rune-chain` framework.
//!
//! Each function in this crate is designed to be called by an LLM agent as a
//! tool. Functions take and return `String` values so they can be serialised
//! into JSON tool-call schemas without friction.
//!
//! Tool functions are grouped by category:
//!
//! | Module | Tools |
//! |--------|-------|
//! | [`encoding`] | hex, base64 encode/decode |
//! | [`hashing`] | SHA-256 |
//! | [`analysis`] | entropy score, extract printable strings |
//! | [`cipher`] | Caesar brute-force, single-byte XOR brute-force |
//!
//! # Features
//!
//! - **Encoding**: `hex_encode`, `hex_decode`, `base64_encode`, `base64_decode`
//! - **Hashing**: `sha256`
//! - **Analysis**: `entropy_score`, `extract_strings`
//! - **Cipher**: `caesar_brute`, `xor_brute`
//!
//! # Safety
//!
//! Every tool is a pure, bounded, in-memory computation: none reads files,
//! spawns processes or opens connections, so none needs a path jail, host
//! allowlist or approval step. Inputs are capped ([`input::MAX_INPUT_BYTES`],
//! lower for the brute-force ciphers whose cost or output grows with input),
//! and invalid input is a [`ToolError`](rune_chain_core::ToolError), never a
//! panic or an `"error: ..."` success string.
//!
//! Every tool also describes itself as a `rune-tool-schema`
//! [`ToolDescriptor`](rune_tool_schema::ToolDescriptor), for MCP export and
//! tool catalogs: see [`describe`].
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_tools::{encoding, hashing, analysis};
//!
//! let hex = encoding::hex_encode("hello");
//! assert_eq!(hex, "68656c6c6f");
//!
//! let decoded = encoding::hex_decode(&hex).unwrap();
//! assert_eq!(decoded, "hello");
//!
//! let digest = hashing::sha256("hello");
//! assert_eq!(digest.len(), 64);
//!
//! let score = analysis::entropy_score("hello world");
//! assert!(score > 0.0 && score < 8.0);
//! ```

/// Text analysis tools.
pub mod analysis;
/// Classical cipher tools.
pub mod cipher;
pub mod describe;
/// Encoding and decoding tools.
pub mod encoding;
/// Hashing tools.
pub mod hashing;
pub mod input;
#[cfg(test)]
mod tests;
pub mod tools;

pub use tools::{
    Base64Decode, Base64Encode, CaesarBrute, EntropyScore, ExtractStrings, ExtractStringsFromHex,
    HexDecode, HexEncode, Sha256, XorBrute,
};
