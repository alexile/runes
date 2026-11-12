//! Decode and inspect JWT claims without signature verification.
//!
//! A JWT in JWS Compact Serialization ([RFC 7515 §7.1], [RFC 7519 §3]) has
//! three dot-separated base64url sections: `header.payload.signature`. This
//! crate decodes the header and the payload as JSON — useful for debugging,
//! CTF challenges, and security research where you need to see what a token
//! contains.
//!
//! # This crate does NOT verify signatures
//!
//! Nothing here checks the signature, the `alg`, the expiry or any other
//! claim. A token that decodes successfully may be forged, expired, or
//! signed with `alg: none`. Never use this crate to grant access based on
//! token contents; use a JWT library that verifies signatures for that.
//!
//! # Untrusted input
//!
//! Every function accepts arbitrary text and returns a [`JwtError`] instead
//! of panicking. Memory use is linear in the token length, and JSON nesting
//! is bounded by `serde_json`'s recursion limit.
//!
//! # Strictness
//!
//! - The token must have exactly three dot-separated sections. Five-section
//!   JWE tokens ([RFC 7516]) are rejected.
//! - Sections use the base64url alphabet (`A–Z a–z 0–9 - _`). Trailing `=`
//!   padding is tolerated, any other `=` is not.
//! - The header and the claims set must be JSON objects ([RFC 7515 §4],
//!   [RFC 7519 §7.2]). For a JWS whose payload is not JSON, use
//!   [`decode_raw`]. Duplicate member names keep the last value.
//!
//! # Features
//!
//! - [`decode`] — decode the header and claims and validate the signature
//!   encoding.
//! - [`decode_raw`] — base64url-decode all three sections to bytes.
//! - [`header`] — decode only the header.
//! - [`claims`] — decode only the claims set.
//! - [`algorithm`] — extract the `alg` header parameter.
//! - [`subject`] — extract the `sub` claim.
//! - [`expiry`] — extract the `exp` claim as a Unix timestamp.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_jwt::{algorithm, claims, expiry};
//!
//! // The example JWT from RFC 7519 §3.1.
//! let token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.\
//!              eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.\
//!              dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
//!
//! assert_eq!(algorithm(token)?, "HS256");
//! assert_eq!(claims(token)?["iss"], "joe");
//! assert_eq!(expiry(token)?, Some(1_300_819_380));
//! # Ok::<(), rune_jwt::JwtError>(())
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-jwt <token>
//! ```
//!
//! [RFC 7515 §4]: https://www.rfc-editor.org/rfc/rfc7515#section-4
//! [RFC 7515 §7.1]: https://www.rfc-editor.org/rfc/rfc7515#section-7.1
//! [RFC 7516]: https://www.rfc-editor.org/rfc/rfc7516
//! [RFC 7519 §3]: https://www.rfc-editor.org/rfc/rfc7519#section-3
//! [RFC 7519 §7.2]: https://www.rfc-editor.org/rfc/rfc7519#section-7.2

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;

use serde_json::Value;

/// A section of a compact JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Section {
    /// The JOSE header (first section).
    Header,
    /// The payload / claims set (second section).
    Payload,
    /// The signature (third section).
    Signature,
}

impl fmt::Display for Section {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Header => "header",
            Self::Payload => "payload",
            Self::Signature => "signature",
        })
    }
}

/// Error returned when a token cannot be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JwtError {
    /// The token does not have exactly three dot-separated sections.
    #[error("token must have exactly three dot-separated sections, found {found}")]
    Sections {
        /// Number of sections found.
        found: usize,
    },
    /// A section is not valid base64url.
    #[error("{section}: invalid base64url: {reason}")]
    Base64 {
        /// The offending section.
        section: Section,
        /// What is wrong with the encoding.
        reason: String,
    },
    /// The header or payload is not valid JSON.
    #[error("{section}: invalid JSON: {reason}")]
    Json {
        /// The offending section.
        section: Section,
        /// The JSON parser's message.
        reason: String,
    },
    /// The header or payload is valid JSON but not a JSON object.
    #[error("{section}: expected a JSON object")]
    NotObject {
        /// The offending section.
        section: Section,
    },
    /// A required header parameter is absent.
    #[error("{section}: missing '{name}'")]
    Missing {
        /// The section that should contain the member.
        section: Section,
        /// The member name.
        name: &'static str,
    },
    /// A header parameter or claim has the wrong JSON type or range.
    #[error("{section}: '{name}' must be {expected}")]
    InvalidMember {
        /// The section that contains the member.
        section: Section,
        /// The member name.
        name: &'static str,
        /// Description of the expected value.
        expected: &'static str,
    },
}

/// A decoded JWT: header and claims as JSON, signature still encoded.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct DecodedJwt {
    /// Decoded JOSE header (always a JSON object).
    pub header: Value,
    /// Decoded claims set (always a JSON object).
    pub payload: Value,
    /// The signature section exactly as it appeared in the token (base64url,
    /// already checked to decode; empty for an unsecured JWT).
    pub signature: String,
}

/// The three sections of a compact JWS, base64url-decoded to bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RawJwt {
    /// Header bytes (the JOSE header JSON text).
    pub header: Vec<u8>,
    /// Payload bytes (JSON for a JWT, arbitrary for a JWS).
    pub payload: Vec<u8>,
    /// Signature bytes (empty for an unsecured JWT).
    pub signature: Vec<u8>,
}

/// Decodes the header and claims of a JWT without verifying the signature.
///
/// The signature section is checked to be valid base64url but is not
/// verified.
///
/// # Errors
///
/// Returns [`JwtError`] if the token does not have three sections, a
/// section is not base64url, or the header or payload is not a JSON object.
///
/// # Examples
///
/// ```rust
/// use rune_jwt::decode;
///
/// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
///              eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
///              SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
///
/// let decoded = decode(token)?;
/// assert_eq!(decoded.header["alg"], "HS256");
/// assert_eq!(decoded.payload["sub"], "1234567890");
/// # Ok::<(), rune_jwt::JwtError>(())
/// ```
pub fn decode(token: &str) -> Result<DecodedJwt, JwtError> {
    let [header, payload, signature] = split(token)?;
    let header = decode_object(header, Section::Header)?;
    let payload = decode_object(payload, Section::Payload)?;
    base64url_decode(signature).map_err(|reason| JwtError::Base64 {
        section: Section::Signature,
        reason,
    })?;
    Ok(DecodedJwt {
        header,
        payload,
        signature: signature.to_owned(),
    })
}

/// Base64url-decodes all three sections of a compact JWS to bytes.
///
/// Unlike [`decode`], the header and payload are not parsed as JSON, so this
/// also works for a JWS whose payload is not a JSON claims set.
///
/// # Errors
///
/// Returns [`JwtError`] if the token does not have three sections or a
/// section is not base64url.
///
/// # Examples
///
/// ```rust
/// use rune_jwt::decode_raw;
///
/// // RFC 8037 §A.4: an Ed25519 JWS over a plain-text payload.
/// let token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.\
///              hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
/// let raw = decode_raw(token)?;
/// assert_eq!(raw.payload, b"Example of Ed25519 signing");
/// assert_eq!(raw.signature.len(), 64);
/// # Ok::<(), rune_jwt::JwtError>(())
/// ```
pub fn decode_raw(token: &str) -> Result<RawJwt, JwtError> {
    let [header, payload, signature] = split(token)?;
    let section_bytes = |text: &str, section| {
        base64url_decode(text).map_err(|reason| JwtError::Base64 { section, reason })
    };
    Ok(RawJwt {
        header: section_bytes(header, Section::Header)?,
        payload: section_bytes(payload, Section::Payload)?,
        signature: section_bytes(signature, Section::Signature)?,
    })
}

/// Decodes only the header of a JWT as a JSON object.
///
/// The token must still have three sections; the other two are not decoded.
///
/// # Errors
///
/// Returns [`JwtError`] if the token does not have three sections or the
/// header is not a base64url-encoded JSON object.
///
/// # Examples
///
/// ```rust
/// use rune_jwt::header;
///
/// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig";
/// assert_eq!(header(token)?["typ"], "JWT");
/// # Ok::<(), rune_jwt::JwtError>(())
/// ```
pub fn header(token: &str) -> Result<Value, JwtError> {
    let [header, _, _] = split(token)?;
    decode_object(header, Section::Header)
}

/// Decodes only the payload (claims set) of a JWT as a JSON object.
///
/// The token must still have three sections; the other two are not decoded.
///
/// # Errors
///
/// Returns [`JwtError`] if the token does not have three sections or the
/// payload is not a base64url-encoded JSON object.
///
/// # Examples
///
/// ```rust
/// use rune_jwt::claims;
///
/// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
///              eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
///              SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
/// assert_eq!(claims(token)?["name"], "John Doe");
/// # Ok::<(), rune_jwt::JwtError>(())
/// ```
pub fn claims(token: &str) -> Result<Value, JwtError> {
    let [_, payload, _] = split(token)?;
    decode_object(payload, Section::Payload)
}

/// Extracts the `alg` header parameter.
///
/// # Errors
///
/// Returns [`JwtError`] if the header cannot be decoded, has no `alg`, or
/// `alg` is not a string.
///
/// # Examples
///
/// ```rust
/// use rune_jwt::algorithm;
///
/// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig";
/// assert_eq!(algorithm(token)?, "HS256");
/// # Ok::<(), rune_jwt::JwtError>(())
/// ```
pub fn algorithm(token: &str) -> Result<String, JwtError> {
    match header(token)?.get("alg") {
        None => Err(JwtError::Missing {
            section: Section::Header,
            name: "alg",
        }),
        Some(Value::String(alg)) => Ok(alg.clone()),
        Some(_) => Err(JwtError::InvalidMember {
            section: Section::Header,
            name: "alg",
            expected: "a string",
        }),
    }
}

/// Extracts the `sub` (subject) claim.
///
/// Returns `Ok(None)` if the claim is absent.
///
/// # Errors
///
/// Returns [`JwtError`] if the payload cannot be decoded or `sub` is present
/// but not a string ([RFC 7519 §4.1.2]).
///
/// [RFC 7519 §4.1.2]: https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2
///
/// # Examples
///
/// ```rust
/// use rune_jwt::subject;
///
/// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.sig";
/// assert_eq!(subject(token)?, Some("user123".to_owned()));
/// # Ok::<(), rune_jwt::JwtError>(())
/// ```
pub fn subject(token: &str) -> Result<Option<String>, JwtError> {
    match claims(token)?.get("sub") {
        None => Ok(None),
        Some(Value::String(sub)) => Ok(Some(sub.clone())),
        Some(_) => Err(JwtError::InvalidMember {
            section: Section::Payload,
            name: "sub",
            expected: "a string",
        }),
    }
}

/// Extracts the `exp` (expiration time) claim as whole seconds since the
/// Unix epoch.
///
/// `exp` is a `NumericDate` ([RFC 7519 §2]), which may have a fractional
/// part; it is truncated to whole seconds. Returns `Ok(None)` if the claim
/// is absent. The expiry is reported, not checked.
///
/// [RFC 7519 §2]: https://www.rfc-editor.org/rfc/rfc7519#section-2
///
/// # Errors
///
/// Returns [`JwtError`] if the payload cannot be decoded or `exp` is present
/// but not a non-negative number that fits in a `u64`.
///
/// # Examples
///
/// ```rust
/// use rune_jwt::expiry;
///
/// let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDAwMDAwMDB9.sig";
/// assert_eq!(expiry(token)?, Some(1_700_000_000));
/// # Ok::<(), rune_jwt::JwtError>(())
/// ```
pub fn expiry(token: &str) -> Result<Option<u64>, JwtError> {
    let invalid = JwtError::InvalidMember {
        section: Section::Payload,
        name: "exp",
        expected: "a non-negative NumericDate",
    };
    match claims(token)?.get("exp") {
        None => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .or_else(|| number.as_f64().and_then(whole_seconds))
            .map(Some)
            .ok_or(invalid),
        Some(_) => Err(invalid),
    }
}

/// Truncates a non-negative finite `NumericDate` to whole seconds.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is checked to be finite and within 0..2^64 first"
)]
fn whole_seconds(seconds: f64) -> Option<u64> {
    // 2^64 as f64; every finite f64 below it truncates into u64 exactly.
    const LIMIT: f64 = 18_446_744_073_709_551_616.0;
    (seconds.is_finite() && (0.0..LIMIT).contains(&seconds)).then(|| seconds.trunc() as u64)
}

/// Splits a compact token into exactly three sections.
fn split(token: &str) -> Result<[&str; 3], JwtError> {
    let mut parts = token.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(header), Some(payload), Some(signature), None) => Ok([header, payload, signature]),
        _ => Err(JwtError::Sections {
            found: token.split('.').count(),
        }),
    }
}

fn decode_object(text: &str, section: Section) -> Result<Value, JwtError> {
    let bytes = base64url_decode(text).map_err(|reason| JwtError::Base64 { section, reason })?;
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(object @ Value::Object(_)) => Ok(object),
        Ok(_) => Err(JwtError::NotObject { section }),
        Err(error) => Err(JwtError::Json {
            section,
            reason: error.to_string(),
        }),
    }
}

/// Decodes unpadded base64url (RFC 4648 §5), tolerating trailing `=`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "the value is masked to its low byte first"
)]
fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    let data = input.trim_end_matches('=');
    let padding = input.len() - data.len();
    if padding > 2 {
        return Err("too much '=' padding".into());
    }
    if data.len() % 4 == 1 {
        return Err(format!("invalid length {}", data.len()));
    }
    let mut output = Vec::with_capacity(data.len() / 4 * 3 + 2);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for (index, ch) in data.char_indices() {
        let value = sextet(ch).ok_or_else(|| format!("invalid character {ch:?} at {index}"))?;
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(output)
}

fn sextet(ch: char) -> Option<u8> {
    let byte = u8::try_from(ch).ok()?;
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                          eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
                          SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    /// `{"alg":"none"}`
    const NONE_HEADER: &str = "eyJhbGciOiJub25lIn0";

    fn b64(bytes: &[u8]) -> String {
        rune_base64::encode_url_no_pad(bytes)
    }

    fn token(header: &str, payload: &str) -> String {
        format!("{}.{}.", b64(header.as_bytes()), b64(payload.as_bytes()))
    }

    #[test]
    fn decode_header_alg() {
        let decoded = decode(SAMPLE).unwrap();
        assert_eq!(decoded.header["alg"], "HS256");
        assert_eq!(decoded.header["typ"], "JWT");
    }

    #[test]
    fn decode_payload_claims() {
        let decoded = decode(SAMPLE).unwrap();
        assert_eq!(decoded.payload["sub"], "1234567890");
        assert_eq!(decoded.payload["name"], "John Doe");
        assert_eq!(decoded.payload["iat"], 1_516_239_022_u64);
    }

    #[test]
    fn helpers() {
        assert_eq!(algorithm(SAMPLE).unwrap(), "HS256");
        assert_eq!(claims(SAMPLE).unwrap()["name"], "John Doe");
        assert_eq!(subject(SAMPLE).unwrap(), Some("1234567890".to_owned()));
        assert_eq!(expiry(SAMPLE).unwrap(), None);
    }

    #[test]
    fn error_on_missing_parts() {
        assert_eq!(
            decode("only.two").unwrap_err(),
            JwtError::Sections { found: 2 }
        );
        assert_eq!(
            decode("just_one").unwrap_err(),
            JwtError::Sections { found: 1 }
        );
        assert_eq!(decode("").unwrap_err(), JwtError::Sections { found: 1 });
    }

    #[test]
    fn error_on_bad_base64() {
        assert!(matches!(
            decode("!!!.!!!.!!!").unwrap_err(),
            JwtError::Base64 {
                section: Section::Header,
                ..
            }
        ));
    }

    // Regression: `decode` used `splitn(3, '.')`, so a four- or
    // five-section token (e.g. a JWE) was accepted and the extra sections
    // were folded into the "signature".
    #[test]
    fn regression_extra_sections_rejected() {
        let four = format!("{SAMPLE}.extra");
        assert_eq!(decode(&four).unwrap_err(), JwtError::Sections { found: 4 });
        assert_eq!(
            decode("a.b.c.d.e").unwrap_err(),
            JwtError::Sections { found: 5 }
        );
        assert!(header(&four).is_err());
        assert!(claims(&four).is_err());
        assert!(decode_raw(&four).is_err());
    }

    // Regression: `header` read the first section of any string, so a
    // bare base64url blob with no dots "decoded" while `decode` rejected it.
    #[test]
    fn regression_header_and_claims_require_three_sections() {
        assert_eq!(
            header(NONE_HEADER).unwrap_err(),
            JwtError::Sections { found: 1 }
        );
        assert_eq!(
            claims(&format!("{NONE_HEADER}.e30")).unwrap_err(),
            JwtError::Sections { found: 2 }
        );
    }

    // Regression: the decoder mapped '=' to the value 0 anywhere in a
    // section, so padding in the middle of the data was silently accepted.
    #[test]
    fn regression_interior_padding_rejected() {
        assert!(base64url_decode("e3=0").is_err());
        assert!(decode(&format!("{NONE_HEADER}.e3=0.")).is_err());
        assert!(base64url_decode("e30===").is_err());
        // Trailing padding is tolerated.
        assert_eq!(base64url_decode("e30=").unwrap(), b"{}");
        assert_eq!(base64url_decode("ZQ==").unwrap(), b"e");
    }

    // Regression: '+' and '/' (the standard alphabet) were accepted
    // although JWS sections are base64url.
    #[test]
    fn regression_standard_alphabet_rejected() {
        assert!(base64url_decode("ab+/").is_err());
        assert_eq!(base64url_decode("ab-_").unwrap(), [0x69, 0xbf, 0xbf]);
    }

    // Regression: the signature section was returned without being
    // checked, so `decode` accepted garbage there.
    #[test]
    fn regression_signature_must_be_base64url() {
        let bad = format!("{NONE_HEADER}.e30.not a signature!");
        assert!(matches!(
            decode(&bad).unwrap_err(),
            JwtError::Base64 {
                section: Section::Signature,
                ..
            }
        ));
        assert!(decode(&format!("{NONE_HEADER}.e30.A")).is_err());
    }

    // Regression: a header or payload that was valid JSON but not an
    // object (e.g. `[]`, `"x"`, `1`) was accepted.
    #[test]
    fn regression_non_object_rejected() {
        for json in ["[]", "\"x\"", "1", "null", "true"] {
            assert_eq!(
                decode(&token(json, "{}")).unwrap_err(),
                JwtError::NotObject {
                    section: Section::Header
                }
            );
            assert_eq!(
                decode(&token(r#"{"alg":"none"}"#, json)).unwrap_err(),
                JwtError::NotObject {
                    section: Section::Payload
                }
            );
        }
    }

    // Regression: `expiry` used `as_u64`, so a fractional NumericDate
    // (RFC 7519 §2 allows one) was reported as an absent claim.
    #[test]
    fn regression_fractional_exp() {
        let t = token(r#"{"alg":"none"}"#, r#"{"exp":1300819380.75}"#);
        assert_eq!(expiry(&t).unwrap(), Some(1_300_819_380));
    }

    // Regression: a present but ill-typed `exp` or `sub` was
    // indistinguishable from an absent one.
    #[test]
    fn regression_ill_typed_claims_are_errors() {
        for exp in ["\"soon\"", "-1", "1e300", "true", "null"] {
            let t = token(r#"{"alg":"none"}"#, &format!(r#"{{"exp":{exp}}}"#));
            assert!(
                matches!(expiry(&t), Err(JwtError::InvalidMember { name: "exp", .. })),
                "exp {exp}"
            );
        }
        let t = token(r#"{"alg":"none"}"#, r#"{"sub":42}"#);
        assert!(matches!(
            subject(&t),
            Err(JwtError::InvalidMember { name: "sub", .. })
        ));
        let t = token(r#"{"alg":7}"#, "{}");
        assert!(matches!(
            algorithm(&t),
            Err(JwtError::InvalidMember { name: "alg", .. })
        ));
        let t = token(r#"{"typ":"JWT"}"#, "{}");
        assert_eq!(
            algorithm(&t).unwrap_err(),
            JwtError::Missing {
                section: Section::Header,
                name: "alg"
            }
        );
    }

    #[test]
    fn whole_seconds_bounds() {
        assert_eq!(whole_seconds(0.0), Some(0));
        assert_eq!(whole_seconds(1.9), Some(1));
        assert_eq!(whole_seconds(-0.5), None);
        assert_eq!(whole_seconds(f64::NAN), None);
        assert_eq!(whole_seconds(f64::INFINITY), None);
        assert_eq!(whole_seconds(18_446_744_073_709_551_616.0), None);
        assert_eq!(
            whole_seconds(18_446_744_073_709_549_568.0),
            Some(18_446_744_073_709_549_568)
        );
    }

    #[test]
    fn invalid_utf8_payload_is_json_error() {
        let t = format!("{NONE_HEADER}.{}.", b64(&[0x7b, 0xff, 0x7d]));
        assert!(matches!(
            decode(&t).unwrap_err(),
            JwtError::Json {
                section: Section::Payload,
                ..
            }
        ));
    }

    #[test]
    fn non_ascii_input_does_not_panic() {
        for t in ["é.é.é", "\u{1F600}..", "eyJ\u{0301}.e30.", "..", "...."] {
            assert!(decode(t).is_err(), "{t}");
            assert!(decode_raw(t).is_err() || t == "..", "{t}");
        }
        assert_eq!(
            decode_raw("..").unwrap(),
            RawJwt {
                header: vec![],
                payload: vec![],
                signature: vec![],
            }
        );
    }

    #[test]
    fn deeply_nested_payload_is_an_error_not_a_stack_overflow() {
        let depth = 100_000;
        let json = format!("{{\"a\":{}{}}}", "[".repeat(depth), "]".repeat(depth));
        let err = decode(&token(r#"{"alg":"none"}"#, &json)).unwrap_err();
        assert!(matches!(
            err,
            JwtError::Json {
                section: Section::Payload,
                ..
            }
        ));
    }

    #[test]
    fn oversized_token_decodes_linearly() {
        let big = "x".repeat(4 << 20);
        let t = token(r#"{"alg":"none"}"#, &format!(r#"{{"blob":"{big}"}}"#));
        assert_eq!(
            claims(&t).unwrap()["blob"].as_str().map(str::len),
            Some(big.len())
        );
        let dots = ".".repeat(1 << 20);
        assert_eq!(
            decode(&dots).unwrap_err(),
            JwtError::Sections {
                found: (1 << 20) + 1
            }
        );
    }

    #[test]
    fn error_messages_name_the_section() {
        let err = decode(&format!("{NONE_HEADER}.!.")).unwrap_err();
        assert!(
            err.to_string().starts_with("payload: invalid base64url"),
            "{err}"
        );
    }
}
