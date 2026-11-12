/// Compute the SHA-256 hash of `input` (UTF-8 text) and return as lowercase hex.
///
/// # Example
///
/// ```rust
/// use rune_chain_tools::hashing::sha256;
///
/// let digest = sha256("hello");
/// assert_eq!(digest.len(), 64);
/// assert_eq!(
///     digest,
///     "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
/// );
/// ```
#[must_use]
pub fn sha256(input: &str) -> String {
    rune_sha256::hash_bytes(input.as_bytes())
}
