//! Basic ([RFC 7617]) and Bearer ([RFC 6750]) credentials, and a
//! constant-time comparison helper.
//!
//! [RFC 7617]: https://www.rfc-editor.org/rfc/rfc7617
//! [RFC 6750]: https://www.rfc-editor.org/rfc/rfc6750

use std::fmt;

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;

use crate::challenge::is_token68;
use crate::{AuthError, Challenge};

/// Compares two byte strings in time that depends on neither their content
/// nor their lengths: both are hashed with SHA-256 and the digests are
/// compared in constant time.
///
/// ```
/// use rune_http_auth::constant_time_eq;
///
/// assert!(constant_time_eq(b"hunter2", b"hunter2"));
/// assert!(!constant_time_eq(b"hunter2", b"hunter3"));
/// assert!(!constant_time_eq(b"", b"x"));
/// ```
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let a = Sha256::digest(a);
    let b = Sha256::digest(b);
    a.as_slice().ct_eq(b.as_slice()).into()
}

/// Basic credentials: a user-id and a password ([RFC 7617]), encoded as
/// UTF-8.
///
/// ```
/// use rune_http_auth::BasicCredentials;
///
/// // RFC 7617 §2.
/// let creds = BasicCredentials::new("Aladdin", "open sesame").unwrap();
/// assert_eq!(creds.to_string(), "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
/// let back = BasicCredentials::parse("basic  QWxhZGRpbjpvcGVuIHNlc2FtZQ==").unwrap();
/// assert_eq!(back, creds);
/// assert!(creds.verify("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="));
/// ```
///
/// [RFC 7617]: https://www.rfc-editor.org/rfc/rfc7617
#[derive(Clone, PartialEq, Eq)]
pub struct BasicCredentials {
    /// The user-id. Never contains a colon.
    pub username: String,
    /// The password. May contain colons.
    pub password: String,
}

impl fmt::Debug for BasicCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl BasicCredentials {
    /// Credentials for `username` and `password`.
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidValue`] if the user-id contains a colon, or
    /// either value contains a control character (RFC 7617 §2).
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, AuthError> {
        let username = username.into();
        let password = password.into();
        if username.contains(':') || username.chars().any(char::is_control) {
            return Err(AuthError::InvalidValue {
                what: "Basic user-id",
            });
        }
        if password.chars().any(char::is_control) {
            return Err(AuthError::InvalidValue {
                what: "Basic password",
            });
        }
        Ok(Self { username, password })
    }

    /// Parses an `Authorization: Basic …` value. The user-id runs up to the
    /// first colon; control characters are accepted, so captured traffic
    /// can be inspected as sent.
    ///
    /// # Errors
    ///
    /// [`AuthError::WrongScheme`], [`AuthError::Base64`],
    /// [`AuthError::InvalidUtf8`], a syntax error, or
    /// [`AuthError::InvalidValue`] when the decoded text has no colon.
    pub fn parse(header: &str) -> Result<Self, AuthError> {
        let challenge = Challenge::parse(header)?;
        if !challenge.is_scheme("Basic") {
            return Err(AuthError::WrongScheme {
                expected: "Basic",
                found: challenge.scheme,
            });
        }
        let token = challenge.token68.ok_or(AuthError::Base64)?;
        let bytes = rune_base64::decode(&token).map_err(|_| AuthError::Base64)?;
        let text = String::from_utf8(bytes).map_err(|_| AuthError::InvalidUtf8)?;
        let (username, password) = text.split_once(':').ok_or(AuthError::InvalidValue {
            what: "Basic credentials",
        })?;
        Ok(Self {
            username: username.to_owned(),
            password: password.to_owned(),
        })
    }

    /// `true` if `header` carries exactly these credentials. The user-id
    /// and password are both compared with [`constant_time_eq`], and both
    /// comparisons always run.
    #[must_use]
    pub fn verify(&self, header: &str) -> bool {
        let Ok(other) = Self::parse(header) else {
            return false;
        };
        let user = constant_time_eq(self.username.as_bytes(), other.username.as_bytes());
        let pass = constant_time_eq(self.password.as_bytes(), other.password.as_bytes());
        user & pass
    }
}

impl fmt::Display for BasicCredentials {
    /// The `Authorization` header value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = format!("{}:{}", self.username, self.password);
        write!(f, "Basic {}", rune_base64::encode(raw.as_bytes()))
    }
}

/// The `Authorization` value for a Bearer token: `Bearer <token>`.
///
/// ```
/// use rune_http_auth::{bearer, parse_bearer};
///
/// let header = bearer("mF_9.B5f-4.1JqM").unwrap();
/// assert_eq!(header, "Bearer mF_9.B5f-4.1JqM");
/// assert_eq!(parse_bearer(&header).unwrap(), "mF_9.B5f-4.1JqM");
/// assert!(bearer("has space").is_err());
/// ```
///
/// # Errors
///
/// [`AuthError::InvalidValue`] if the token is not an RFC 6750
/// `b64token`.
pub fn bearer(token: &str) -> Result<String, AuthError> {
    if is_token68(token) {
        Ok(format!("Bearer {token}"))
    } else {
        Err(AuthError::InvalidValue {
            what: "Bearer token",
        })
    }
}

/// Extracts the token from an `Authorization: Bearer …` value.
///
/// # Errors
///
/// [`AuthError::WrongScheme`], a syntax error, or
/// [`AuthError::InvalidValue`] when there is no token.
pub fn parse_bearer(header: &str) -> Result<String, AuthError> {
    let challenge = Challenge::parse(header)?;
    if !challenge.is_scheme("Bearer") {
        return Err(AuthError::WrongScheme {
            expected: "Bearer",
            found: challenge.scheme,
        });
    }
    challenge.token68.ok_or(AuthError::InvalidValue {
        what: "Bearer token",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7617_utf8_example() {
        // RFC 7617 §2.1: user "test", password "123£".
        let creds = BasicCredentials::new("test", "123\u{a3}").unwrap();
        assert_eq!(creds.to_string(), "Basic dGVzdDoxMjPCow==");
    }

    #[test]
    fn rejects() {
        assert!(BasicCredentials::new("a:b", "c").is_err());
        assert!(BasicCredentials::new("a", "c\n").is_err());
        assert!(matches!(
            BasicCredentials::parse("Bearer abc"),
            Err(AuthError::WrongScheme { .. })
        ));
        assert_eq!(BasicCredentials::parse("Basic a"), Err(AuthError::Base64));
        assert_eq!(BasicCredentials::parse("Basic"), Err(AuthError::Base64));
        // "nocolon"
        assert!(BasicCredentials::parse("Basic bm9jb2xvbg==").is_err());
        assert!(BasicCredentials::parse("Basic /w==").is_err());
        assert!(parse_bearer("Basic abc").is_err());
        assert!(parse_bearer("Bearer").is_err());
    }

    #[test]
    fn password_may_hold_colons() {
        let creds = BasicCredentials::new("u", "p:a:ss").unwrap();
        assert_eq!(BasicCredentials::parse(&creds.to_string()).unwrap(), creds);
        assert!(!creds.verify("Basic dTpw"));
        assert!(!creds.verify("garbage"));
        assert!(!format!("{creds:?}").contains("p:a:ss"));
    }
}
