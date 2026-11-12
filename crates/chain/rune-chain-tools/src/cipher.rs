/// Try all 25 Caesar shifts on `ciphertext` and return candidates as `"shift: plaintext"` lines.
///
/// # Example
///
/// ```rust
/// use rune_chain_tools::cipher::caesar_brute;
///
/// let results = caesar_brute("khoor");
/// assert!(results.iter().any(|s| s.contains("hello")));
/// ```
#[must_use]
pub fn caesar_brute(ciphertext: &str) -> Vec<String> {
    rune_caesar::brute_force(ciphertext)
        .into_iter()
        .map(|(shift, plaintext)| format!("{shift:2}: {plaintext}"))
        .collect()
}

/// Try all 256 single-byte XOR keys on the hex-encoded `ciphertext` and return
/// the top candidates sorted by English-language score.
///
/// Returns lines formatted as `"key=0xNN score=N.NNN plaintext"`.
/// The most likely key is first.
///
/// # Example
///
/// ```rust
/// use rune_chain_tools::cipher::xor_brute;
///
/// // "hello" XOR'd with key 0x42 = hex bytes
/// let ciphertext_hex = rune_chain_tools::encoding::hex_encode(
///     &String::from_utf8(rune_xor::xor_single(b"hello world", 0x42)).unwrap()
/// );
/// let results = xor_brute(&ciphertext_hex);
/// assert!(!results.is_empty());
/// ```
#[must_use]
pub fn xor_brute(ciphertext_hex: &str) -> Vec<String> {
    let Ok(bytes) = rune_hex::decode(ciphertext_hex) else {
        return vec!["error: invalid hex input".to_string()];
    };
    rune_xor::brute_force(&bytes)
        .into_iter()
        .take(5)
        .map(|c| {
            format!(
                "key=0x{:02X} score={:.3} {}",
                c.key,
                c.score,
                String::from_utf8_lossy(&c.plaintext)
            )
        })
        .collect()
}
