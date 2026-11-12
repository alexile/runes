//! [`SecretValue`]: a resolved secret that never prints itself.

use std::fmt;

use subtle::ConstantTimeEq;

/// The placeholder printed in place of a secret.
pub const REDACTED: &str = "<redacted>";

/// A resolved secret.
///
/// `Debug`, `Display` and (with the `serde` feature) `Serialize` all print
/// [`REDACTED`] instead of the value, so a `SecretValue` inside a config
/// struct, an error or a log line never leaks. Read the value explicitly
/// with [`expose`](Self::expose) at the point of use.
///
/// Equality is constant-time in the contents. With the `zeroize` feature
/// the buffer is wiped when the value is dropped.
///
/// ```
/// use rune_secret_ref::SecretValue;
///
/// let token = SecretValue::new("hunter2");
/// assert_eq!(format!("{token:?} {token}"), "SecretValue(<redacted>) <redacted>");
/// assert_eq!(token.expose(), "hunter2");
/// ```
#[derive(Clone)]
pub struct SecretValue(String);

impl SecretValue {
    /// Wraps a secret.
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The secret's plain value. Call it where the secret is used (an
    /// HTTP header, a login), never to log or display it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretValue {
    fn from(secret: String) -> Self {
        Self(secret)
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue({REDACTED})")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl PartialEq for SecretValue {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for SecretValue {}

#[cfg(feature = "serde")]
impl serde::Serialize for SecretValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

#[cfg(feature = "zeroize")]
impl Drop for SecretValue {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SecretValue {}

/// Wipes a scratch buffer that held secret bytes (a no-op without the
/// `zeroize` feature).
pub fn wipe(buffer: &mut Vec<u8>) {
    #[cfg(feature = "zeroize")]
    zeroize::Zeroize::zeroize(buffer);
    #[cfg(not(feature = "zeroize"))]
    buffer.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-Value_42";

    #[test]
    fn never_prints_its_contents() {
        let value = SecretValue::new(SECRET);
        for text in [
            format!("{value}"),
            format!("{value:?}"),
            format!("{value:#?}"),
            format!("{value:>40}"),
            format!("{:?}", Some(&value)),
            format!("{:?}", [&value]),
        ] {
            assert!(!text.contains(SECRET), "{text}");
            assert!(text.contains(REDACTED), "{text}");
        }
    }

    #[test]
    fn compares_by_contents() {
        assert_eq!(SecretValue::new("a"), SecretValue::from("a".to_owned()));
        assert_ne!(SecretValue::new("a"), SecretValue::new("b"));
        assert_ne!(SecretValue::new("a"), SecretValue::new("ab"));
    }

    #[test]
    fn wipe_empties_the_buffer() {
        let mut buffer = SECRET.as_bytes().to_vec();
        wipe(&mut buffer);
        assert_eq!(buffer, Vec::<u8>::new());
    }
}
