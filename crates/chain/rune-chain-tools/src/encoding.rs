/// Hex-encode `input` bytes (UTF-8 text) to a lowercase hex string.
///
/// # Example
///
/// ```rust
/// use rune_chain_tools::encoding::hex_encode;
///
/// assert_eq!(hex_encode("hello"), "68656c6c6f");
/// ```
#[must_use]
pub fn hex_encode(input: &str) -> String {
    rune_hex::encode(input.as_bytes())
}

/// Decode a hex string back to UTF-8 text.
///
/// Returns an error message string if the input is not valid hex or the decoded
/// bytes are not valid UTF-8.
///
/// # Example
///
/// ```rust
/// use rune_chain_tools::encoding::hex_decode;
///
/// assert_eq!(hex_decode("68656c6c6f").unwrap(), "hello");
/// assert!(hex_decode("zz").is_err());
/// ```
pub fn hex_decode(input: &str) -> Result<String, String> {
    let bytes = rune_hex::decode(input).map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

/// Base64-encode `input` bytes (UTF-8 text) using the standard alphabet.
///
/// # Example
///
/// ```rust
/// use rune_chain_tools::encoding::base64_encode;
///
/// assert_eq!(base64_encode("hello"), "aGVsbG8=");
/// ```
#[must_use]
pub fn base64_encode(input: &str) -> String {
    rune_base64::encode(input.as_bytes())
}

/// Decode a base64 string (standard or URL-safe alphabet) back to UTF-8 text.
///
/// Returns an error message string if the input is not valid base64 or not
/// valid UTF-8.
///
/// # Example
///
/// ```rust
/// use rune_chain_tools::encoding::base64_decode;
///
/// assert_eq!(base64_decode("aGVsbG8=").unwrap(), "hello");
/// ```
pub fn base64_decode(input: &str) -> Result<String, String> {
    let bytes = rune_base64::decode(input).map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}
