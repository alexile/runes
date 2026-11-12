//! [`Tool`] trait wrappers for all `rune-chain-tools` functions.
//!
//! Every wrapper accepts free text or `{"input": "<text>"}` (see
//! [`tool_input`]), rejects oversized input, and advertises a closed
//! single-`input` schema so agents can validate calls before running them.
//! All of them are pure, in-memory computations: none touches the
//! filesystem, a shell or the network.
//!
//! Each struct in this module wraps a single tool function and implements the
//! async [`Tool`] trait so it can be registered with an
//! [`AgentExecutor`](https://docs.rs/rune-chain-agent) or
//! [`FunctionCallingAgent`](https://docs.rs/rune-chain-agent).
//!
//! # Usage
//!
//! ```rust,no_run
//! use rune_chain_tools::tools::{HexEncode, Sha256, EntropyScore};
//! // register with an agent:
//! // AgentExecutor::new(llm)
//! //     .tool(HexEncode)
//! //     .tool(Sha256)
//! //     .tool(EntropyScore)
//! ```

use async_trait::async_trait;
use rune_chain_core::{Tool, ToolError};

use crate::input::{
    MAX_CAESAR_INPUT_BYTES, MAX_INPUT_BYTES, MAX_XOR_INPUT_BYTES, input_schema, tool_input,
};

// ── Encoding ─────────────────────────────────────────────────────────────────

/// Hex-encode UTF-8 text to a lowercase hex string.
pub struct HexEncode;

#[async_trait]
impl Tool for HexEncode {
    fn name(&self) -> &'static str {
        "hex_encode"
    }
    fn description(&self) -> &'static str {
        "Hex-encodes a UTF-8 string to lowercase hexadecimal."
    }
    fn schema(&self) -> serde_json::Value {
        input_schema("UTF-8 text to hex-encode.", MAX_INPUT_BYTES)
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let input = tool_input(input, MAX_INPUT_BYTES)?;
        let input = input.as_ref();
        Ok(crate::encoding::hex_encode(input))
    }
}

/// Decode a lowercase hex string back to UTF-8 text.
pub struct HexDecode;

#[async_trait]
impl Tool for HexDecode {
    fn name(&self) -> &'static str {
        "hex_decode"
    }
    fn description(&self) -> &'static str {
        "Decodes a hexadecimal string back to UTF-8 text."
    }
    fn schema(&self) -> serde_json::Value {
        input_schema("Hexadecimal string to decode.", MAX_INPUT_BYTES)
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let input = tool_input(input, MAX_INPUT_BYTES)?;
        let input = input.as_ref();
        crate::encoding::hex_decode(input).map_err(ToolError::InvalidInput)
    }
}

/// Base64-encode UTF-8 text using the standard alphabet.
pub struct Base64Encode;

#[async_trait]
impl Tool for Base64Encode {
    fn name(&self) -> &'static str {
        "base64_encode"
    }
    fn description(&self) -> &'static str {
        "Base64-encodes a UTF-8 string using the standard alphabet."
    }
    fn schema(&self) -> serde_json::Value {
        input_schema("UTF-8 text to base64-encode.", MAX_INPUT_BYTES)
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let input = tool_input(input, MAX_INPUT_BYTES)?;
        let input = input.as_ref();
        Ok(crate::encoding::base64_encode(input))
    }
}

/// Decode a base64 string back to UTF-8 text.
pub struct Base64Decode;

#[async_trait]
impl Tool for Base64Decode {
    fn name(&self) -> &'static str {
        "base64_decode"
    }
    fn description(&self) -> &'static str {
        "Decodes a base64 string back to UTF-8 text."
    }
    fn schema(&self) -> serde_json::Value {
        input_schema("Base64 string to decode.", MAX_INPUT_BYTES)
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let input = tool_input(input, MAX_INPUT_BYTES)?;
        let input = input.as_ref();
        crate::encoding::base64_decode(input).map_err(ToolError::InvalidInput)
    }
}

// ── Hashing ───────────────────────────────────────────────────────────────────

/// Compute the SHA-256 hash of text.
pub struct Sha256;

#[async_trait]
impl Tool for Sha256 {
    fn name(&self) -> &'static str {
        "sha256"
    }
    fn description(&self) -> &'static str {
        "Computes the SHA-256 hash of a UTF-8 string and returns lowercase hex."
    }
    fn schema(&self) -> serde_json::Value {
        input_schema("UTF-8 text to hash.", MAX_INPUT_BYTES)
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let input = tool_input(input, MAX_INPUT_BYTES)?;
        let input = input.as_ref();
        Ok(crate::hashing::sha256(input))
    }
}

// ── Analysis ──────────────────────────────────────────────────────────────────

/// Compute the Shannon entropy score of text.
pub struct EntropyScore;

#[async_trait]
impl Tool for EntropyScore {
    fn name(&self) -> &'static str {
        "entropy_score"
    }
    fn description(&self) -> &'static str {
        "Computes the Shannon entropy (0.0–8.0 bits/byte) of the input. \
         Values above ~7.2 suggest encrypted or compressed data."
    }
    fn schema(&self) -> serde_json::Value {
        input_schema("Text to score.", MAX_INPUT_BYTES)
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let input = tool_input(input, MAX_INPUT_BYTES)?;
        let input = input.as_ref();
        Ok(crate::analysis::entropy_score(input).to_string())
    }
}

/// Extract printable ASCII strings from input text.
pub struct ExtractStrings;

#[async_trait]
impl Tool for ExtractStrings {
    fn name(&self) -> &'static str {
        "extract_strings"
    }
    fn description(&self) -> &'static str {
        "Extracts printable ASCII strings (≥4 chars) from the input. \
         Returns one string per line."
    }
    fn schema(&self) -> serde_json::Value {
        input_schema("Text to scan for printable strings.", MAX_INPUT_BYTES)
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let input = tool_input(input, MAX_INPUT_BYTES)?;
        let input = input.as_ref();
        let strings = crate::analysis::extract_strings(input);
        Ok(strings.join("\n"))
    }
}

/// Extract printable ASCII strings from a hex-encoded binary blob.
pub struct ExtractStringsFromHex;

#[async_trait]
impl Tool for ExtractStringsFromHex {
    fn name(&self) -> &'static str {
        "extract_strings_from_hex"
    }
    fn description(&self) -> &'static str {
        "Extracts printable ASCII strings from a hex-encoded binary blob. \
         Returns one string per line."
    }
    fn schema(&self) -> serde_json::Value {
        input_schema("Hex-encoded binary blob.", MAX_INPUT_BYTES)
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let input = tool_input(input, MAX_INPUT_BYTES)?;
        let input = input.as_ref();
        let bytes = rune_hex::decode(input)
            .map_err(|_| ToolError::InvalidInput("error: invalid hex input".to_owned()))?;
        Ok(rune_strings::extract_default(&bytes).join("\n"))
    }
}

// ── Cipher ────────────────────────────────────────────────────────────────────

/// Brute-force all 26 Caesar cipher shifts of the input.
pub struct CaesarBrute;

#[async_trait]
impl Tool for CaesarBrute {
    fn name(&self) -> &'static str {
        "caesar_brute"
    }
    fn description(&self) -> &'static str {
        "Brute-forces all 26 Caesar cipher shifts of the input text and \
         returns all candidates, one per line."
    }
    fn schema(&self) -> serde_json::Value {
        input_schema("Caesar-ciphered text.", MAX_CAESAR_INPUT_BYTES)
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let input = tool_input(input, MAX_CAESAR_INPUT_BYTES)?;
        let input = input.as_ref();
        let results = crate::cipher::caesar_brute(input);
        Ok(results.join("\n"))
    }
}

/// Brute-force single-byte XOR decryption of hex-encoded ciphertext.
pub struct XorBrute;

#[async_trait]
impl Tool for XorBrute {
    fn name(&self) -> &'static str {
        "xor_brute"
    }
    fn description(&self) -> &'static str {
        "Brute-forces single-byte XOR decryption on hex-encoded ciphertext. \
         Returns the top candidates sorted by printability score."
    }
    fn schema(&self) -> serde_json::Value {
        input_schema("Hex-encoded ciphertext.", MAX_XOR_INPUT_BYTES)
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let input = tool_input(input, MAX_XOR_INPUT_BYTES)?;
        let input = input.as_ref();
        if rune_hex::decode(input).is_err() {
            return Err(ToolError::InvalidInput(
                "error: invalid hex input".to_owned(),
            ));
        }
        Ok(crate::cipher::xor_brute(input).join("\n"))
    }
}
