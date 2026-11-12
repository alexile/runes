//! The crate's error type.

/// Why a hostname, an allowlist pattern or a certificate name was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is empty, or is only the root `.`.
    #[error("empty hostname")]
    Empty,
    /// The name is longer than 253 bytes (without its trailing dot).
    #[error("hostname is {len} bytes, more than the limit of 253")]
    TooLong {
        /// Length in bytes, without the trailing dot.
        len: usize,
    },
    /// Two dots in a row, or a leading dot.
    #[error("hostname has an empty label")]
    EmptyLabel,
    /// A label is longer than 63 bytes.
    #[error("label is {len} bytes, more than the limit of 63")]
    LabelTooLong {
        /// Length of the label in bytes.
        len: usize,
    },
    /// A character outside letters, digits, `-` and `_` (and `*` in patterns).
    ///
    /// Internationalized names must be converted to A-labels (`xn--…`) first.
    #[error("invalid character {ch:?} at byte {index}")]
    InvalidChar {
        /// The offending character.
        ch: char,
        /// Its byte offset in the input.
        index: usize,
    },
    /// The right-most label is all digits, so the name looks like an IPv4
    /// address rather than a hostname (RFC 3696 §2).
    #[error("right-most label is numeric: an IP address is not a hostname")]
    NumericTld,
    /// `*` appears inside a label (`f*o.example.com`) instead of being the
    /// whole label.
    #[error("a wildcard must be a whole label")]
    PartialWildcard,
    /// The right-most label of a pattern is a wildcard, so the pattern is not
    /// anchored to any domain (`*`, `example.*`).
    #[error("the right-most label of a pattern must not be a wildcard")]
    UnanchoredWildcard,
    /// A certificate name has a wildcard that is not the single left-most
    /// label (RFC 6125 §6.4.3, RFC 9525 §6.3).
    #[error("a certificate wildcard must be the single left-most label")]
    MisplacedWildcard,
    /// A certificate wildcard covers fewer than two labels (`*.com`).
    #[error("a certificate wildcard must be followed by at least two labels")]
    WildcardTooBroad,
    /// A certificate wildcard covers a public suffix (`*.co.uk`), so it
    /// would match names registered by unrelated parties. Only returned by
    /// the Public Suffix List checks of the `psl` feature.
    #[error("a certificate wildcard must not cover a public suffix")]
    PublicSuffixWildcard,
}
