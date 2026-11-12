/// Compute the Shannon entropy of `input` text (0.0 – 8.0 bits per byte).
///
/// Higher values indicate more randomness. Values above ~7.2 typically signal
/// encrypted or compressed data.
///
/// # Example
///
/// ```rust
/// use rune_chain_tools::analysis::entropy_score;
///
/// let score = entropy_score("aaaaaaa");
/// assert_eq!(score, 0.0);
///
/// let score = entropy_score("hello world");
/// assert!(score > 2.0 && score < 8.0);
/// ```
#[must_use]
pub fn entropy_score(input: &str) -> f64 {
    rune_entropy::entropy(input.as_bytes())
}

/// Extract printable ASCII strings of at least 4 characters from binary-encoded hex.
///
/// `hex_input` must be a lowercase hex string (e.g. from [`crate::encoding::hex_encode`]).
/// Returns a list of extracted strings, one per line. Useful for analysing unknown
/// binary blobs without needing filesystem access.
///
/// # Example
///
/// ```rust
/// use rune_chain_tools::analysis::extract_strings_from_hex;
///
/// let hex = rune_chain_tools::encoding::hex_encode("hello\x00\x01world");
/// let strings = extract_strings_from_hex(&hex);
/// assert!(strings.iter().any(|s| s.contains("hello")));
/// ```
#[must_use]
pub fn extract_strings_from_hex(hex_input: &str) -> Vec<String> {
    let Ok(bytes) = rune_hex::decode(hex_input) else {
        return vec!["error: invalid hex input".to_string()];
    };
    rune_strings::extract_default(&bytes)
}

/// Extract printable ASCII strings of at least 4 characters from `input` text.
///
/// Treats the text as raw bytes. Useful for finding embedded strings in
/// base64-decoded or otherwise opaque content.
///
/// # Example
///
/// ```rust
/// use rune_chain_tools::analysis::extract_strings;
///
/// let strings = extract_strings("hello\x00world\x01foo");
/// assert!(strings.iter().any(|s| s == "hello"));
/// assert!(strings.iter().any(|s| s == "world"));
/// ```
#[must_use]
pub fn extract_strings(input: &str) -> Vec<String> {
    rune_strings::extract_default(input.as_bytes())
}
