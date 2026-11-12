use core::fmt;

/// Everything that can go wrong while encoding or decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HexError {
    /// The input holds an odd number of hex digits, so the last byte is
    /// missing its low half.
    OddLength,
    /// `byte` at `offset` (counted from the start of the input, prefix and
    /// separators included) is not a hex digit, or is a separator that splits
    /// the two digits of a byte.
    InvalidByte {
        /// The offending input byte. For non-ASCII text this is the first
        /// byte of the UTF-8 sequence.
        byte: u8,
        /// Its position in the input.
        offset: usize,
    },
    /// The input contains at least one byte that is not a hex digit.
    ///
    /// Returned by the [`ct`](crate::ct) functions, which do not reveal where
    /// the problem is.
    Invalid,
    /// The output buffer is too short.
    BufferTooSmall {
        /// Bytes the operation needs.
        needed: usize,
        /// Bytes the buffer has.
        available: usize,
    },
    /// The input decodes to a different number of bytes than required.
    WrongLength {
        /// Bytes required.
        expected: usize,
        /// Bytes the input holds.
        actual: usize,
    },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::OddLength => f.write_str("odd number of hex digits"),
            Self::InvalidByte { byte, offset } if byte.is_ascii_graphic() || byte == b' ' => {
                write!(
                    f,
                    "invalid hex character {:?} at offset {offset}",
                    char::from(byte)
                )
            }
            Self::InvalidByte { byte, offset } => {
                write!(
                    f,
                    "invalid hex character (byte 0x{byte:02x}) at offset {offset}"
                )
            }
            Self::Invalid => f.write_str("invalid hex character"),
            Self::BufferTooSmall { needed, available } => write!(
                f,
                "output buffer too small: need {needed} bytes, have {available}"
            ),
            Self::WrongLength { expected, actual } => {
                write!(f, "expected {expected} bytes of hex, got {actual}")
            }
        }
    }
}

impl core::error::Error for HexError {}

#[cfg(feature = "std")]
impl From<HexError> for std::io::Error {
    fn from(err: HexError) -> Self {
        Self::new(std::io::ErrorKind::InvalidData, err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages() {
        let cases = [
            (HexError::OddLength, "odd number of hex digits"),
            (
                HexError::InvalidByte {
                    byte: b'z',
                    offset: 3,
                },
                "invalid hex character 'z' at offset 3",
            ),
            (
                HexError::InvalidByte {
                    byte: b'\n',
                    offset: 0,
                },
                "invalid hex character (byte 0x0a) at offset 0",
            ),
            (
                HexError::InvalidByte {
                    byte: 0xc3,
                    offset: 9,
                },
                "invalid hex character (byte 0xc3) at offset 9",
            ),
            (HexError::Invalid, "invalid hex character"),
            (
                HexError::BufferTooSmall {
                    needed: 4,
                    available: 2,
                },
                "output buffer too small: need 4 bytes, have 2",
            ),
            (
                HexError::WrongLength {
                    expected: 32,
                    actual: 20,
                },
                "expected 32 bytes of hex, got 20",
            ),
        ];
        for (err, msg) in cases {
            assert_eq!(err.to_string(), msg);
        }
    }
}
