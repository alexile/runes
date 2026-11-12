//! The crate's error type.

/// Why a host name, or a rule of a list, was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is empty, or is only the root `.`.
    #[error("empty domain name")]
    Empty,
    /// The name is longer than 253 characters (without its trailing dot).
    #[error("domain name is {len} characters, more than the limit of 253")]
    TooLong {
        /// Length in characters, without the trailing dot.
        len: usize,
    },
    /// A leading dot, or two dots in a row.
    #[error("domain name has an empty label")]
    EmptyLabel,
    /// A label is longer than 63 characters.
    #[error("label is {len} characters, more than the limit of 63")]
    LabelTooLong {
        /// Length of the label in characters.
        len: usize,
    },
    /// An ASCII character other than letters, digits, `-` and `_`, or a
    /// non-ASCII whitespace or control character.
    #[error("invalid character {ch:?} at byte {index}")]
    InvalidChar {
        /// The offending character.
        ch: char,
        /// Its byte offset in the input.
        index: usize,
    },
    /// The right-most label is all digits: the name looks like an IPv4
    /// address, which has no public suffix (RFC 3696 §2).
    #[error("right-most label is numeric: an IP address has no public suffix")]
    NumericTld,
    /// An `xn--` label is not valid Punycode (RFC 3492).
    #[error("label {label:?} is not valid Punycode")]
    InvalidPunycode {
        /// The A-label, lowercased.
        label: String,
    },
    /// A rule of a list is malformed.
    #[error("line {line}: invalid rule {rule:?}: {reason}")]
    InvalidRule {
        /// 1-based line number in the list.
        line: usize,
        /// The rule as written.
        rule: String,
        /// What is wrong with it.
        reason: Box<Self>,
    },
    /// A wildcard that is not the whole left-most label of a rule
    /// (`a.*.example`, `f*.example`), an exception rule with a wildcard, or
    /// a rule that is only `*`.
    #[error("a wildcard must be the whole left-most label of a normal rule")]
    MisplacedWildcard,
    /// An exception rule with a single label (`!example`), which would leave
    /// an empty public suffix.
    #[error("an exception rule needs at least two labels")]
    ExceptionTooShort,
}
