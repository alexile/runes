//! The crate's error type.

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Punycode input contains a character that is not a basic code point
    /// (RFC 3492 section 5): it is not ASCII.
    #[error("Punycode input contains the non-ASCII character {0:?}")]
    PunycodeNonBasic(char),
    /// Punycode input contains a character that is not a base-36 digit
    /// after the last delimiter.
    #[error("Punycode input contains the invalid digit {0:?}")]
    PunycodeInvalidDigit(char),
    /// Punycode input ends in the middle of a variable-length integer.
    #[error("Punycode input ends in the middle of a delta")]
    PunycodeTruncated,
    /// Punycode arithmetic overflowed (RFC 3492 section 6.4).
    #[error("Punycode arithmetic overflow")]
    PunycodeOverflow,
    /// Punycode input decodes to a value that is a basic (ASCII) code point
    /// or not a Unicode scalar value (RFC 3492 section 6.2).
    #[error("Punycode input decodes to the invalid code point {0:#X}")]
    PunycodeInvalidCodePoint(u32),
    /// The Unicode side of a Punycode conversion, the input of `encode` or
    /// the output of `decode`, is longer than
    /// [`punycode::MAX_LEN`](crate::punycode::MAX_LEN) characters.
    #[error("Punycode text of {len} characters exceeds the limit of {max}")]
    PunycodeTooLong {
        /// Length in characters, as far as it was counted.
        len: usize,
        /// The limit.
        max: usize,
    },
    /// UTS #46 processing rejected the domain name: a disallowed code point,
    /// a bad Punycode label, a hyphen, bidi or joiner rule violation, or a
    /// code point denied by the chosen [`AsciiRules`](crate::AsciiRules).
    #[error("domain name is not valid under UTS #46 processing")]
    Uts46,
    /// The domain name contains a code point that UTS #46 accepts but
    /// IDNA2008 (RFC 5892) does not (`NV8` or `XV8`), and
    /// [`Options::idna2008`](crate::Options::idna2008) is set.
    #[error("U+{:04X} is not valid under IDNA2008", u32::from(*.0))]
    NotIdna2008(char),
    /// A label of the ASCII form is empty (`VerifyDnsLength`).
    #[error("label {index} of the domain name is empty")]
    EmptyLabel {
        /// Zero-based index of the label.
        index: usize,
    },
    /// A label of the ASCII form is longer than 63 octets (`VerifyDnsLength`).
    #[error("label {index} is {len} octets long, more than 63")]
    LabelTooLong {
        /// Zero-based index of the label.
        index: usize,
        /// Length of the label in octets.
        len: usize,
    },
    /// The ASCII form is longer than 253 octets, not counting a trailing
    /// dot (`VerifyDnsLength`).
    #[error("domain name is {len} octets long, more than 253")]
    DomainTooLong {
        /// Length of the domain name in octets.
        len: usize,
    },
}
