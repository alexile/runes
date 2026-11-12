//! Verification keys and where they come from.

use std::{fmt, future::Future, pin::Pin, sync::Arc};

use jsonwebtoken::{
    Algorithm, DecodingKey,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, KeyOperations, PublicKeyUse},
};

/// Boxed, `Send` future returned by [`KeySource::resolve`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Error building a [`VerifyKey`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The algorithm does not fit the key type (for example `HS256` for an
    /// RSA key).
    #[error("algorithm {alg:?} cannot be used with a {key_type} key")]
    AlgorithmMismatch {
        /// The requested algorithm.
        alg: Algorithm,
        /// The key type, e.g. `"RSA"`.
        key_type: &'static str,
    },
    /// The JWK has no `alg` and one cannot be inferred (symmetric keys).
    #[error("JWK has no `alg` and none can be inferred for this key type")]
    MissingAlgorithm,
    /// The JWK is marked for encryption, or its `key_ops` exclude `verify`.
    #[error("JWK is not a signature verification key")]
    NotForSigning,
    /// The key type, curve or algorithm is not supported.
    #[error("unsupported key: {0}")]
    Unsupported(String),
    /// The key material could not be parsed.
    #[error("invalid key: {0}")]
    Invalid(String),
}

/// Error looking up the key for a token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LookupError {
    /// The token has no `kid` and the source holds more than one key.
    #[error("token has no `kid` but several keys are configured")]
    KidRequired,
    /// No key matches the token's `kid`.
    #[error("no key matches the token's `kid`")]
    UnknownKid,
    /// The keys could not be loaded (network error, bad JWKS, ...).
    #[error("keys unavailable: {0}")]
    Unavailable(String),
}

/// A key that verifies signatures with exactly one algorithm.
///
/// The algorithm is pinned when the key is built, and a token whose header
/// names any other `alg` is rejected before the signature is checked. That
/// is what stops algorithm confusion: an RSA public key can never be used as
/// an HMAC secret, and `alg: none` is never accepted.
///
/// # Examples
///
/// ```rust
/// use rune_axum_jwt::VerifyKey;
///
/// let key = VerifyKey::hs256(b"a long, random shared secret").with_kid("v1");
/// assert_eq!(key.kid(), Some("v1"));
/// ```
#[derive(Clone)]
pub struct VerifyKey {
    kid: Option<String>,
    alg: Algorithm,
    key: DecodingKey,
}

impl fmt::Debug for VerifyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyKey")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

/// The key type an algorithm needs. `None` for algorithms this crate does
/// not know, which are then never accepted.
const fn key_type(alg: Algorithm) -> Option<&'static str> {
    Some(match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => "HMAC",
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => "RSA",
        Algorithm::ES256 | Algorithm::ES384 => "EC",
        Algorithm::EdDSA => "OKP",
        _ => return None,
    })
}

fn expect_type(alg: Algorithm, want: &'static str) -> Result<(), KeyError> {
    match key_type(alg) {
        Some(have) if have == want => Ok(()),
        Some(_) => Err(KeyError::AlgorithmMismatch {
            alg,
            key_type: want,
        }),
        None => Err(KeyError::Unsupported(format!("algorithm {alg:?}"))),
    }
}

fn invalid(err: &jsonwebtoken::errors::Error) -> KeyError {
    KeyError::Invalid(err.to_string())
}

impl VerifyKey {
    /// HMAC key for `HS256`, `HS384` or `HS512`.
    ///
    /// # Errors
    ///
    /// [`KeyError::AlgorithmMismatch`] if `alg` is not an HMAC algorithm.
    pub fn hmac(alg: Algorithm, secret: &[u8]) -> Result<Self, KeyError> {
        expect_type(alg, "HMAC")?;
        Ok(Self::new(alg, DecodingKey::from_secret(secret)))
    }

    /// HMAC-SHA-256 key.
    #[must_use]
    pub fn hs256(secret: &[u8]) -> Self {
        Self::new(Algorithm::HS256, DecodingKey::from_secret(secret))
    }

    /// HMAC-SHA-384 key.
    #[must_use]
    pub fn hs384(secret: &[u8]) -> Self {
        Self::new(Algorithm::HS384, DecodingKey::from_secret(secret))
    }

    /// HMAC-SHA-512 key.
    #[must_use]
    pub fn hs512(secret: &[u8]) -> Self {
        Self::new(Algorithm::HS512, DecodingKey::from_secret(secret))
    }

    /// RSA public key in PEM (PKCS#1 or SPKI) for `RS*` or `PS*`.
    ///
    /// # Errors
    ///
    /// [`KeyError::AlgorithmMismatch`] for a non-RSA algorithm,
    /// [`KeyError::Invalid`] if the PEM does not parse.
    pub fn rsa_pem(alg: Algorithm, pem: &[u8]) -> Result<Self, KeyError> {
        expect_type(alg, "RSA")?;
        let key = DecodingKey::from_rsa_pem(pem).map_err(|e| invalid(&e))?;
        Ok(Self::new(alg, key))
    }

    /// RSA public key from base64url modulus `n` and exponent `e`.
    ///
    /// # Errors
    ///
    /// As for [`VerifyKey::rsa_pem`].
    pub fn rsa_components(alg: Algorithm, n: &str, e: &str) -> Result<Self, KeyError> {
        expect_type(alg, "RSA")?;
        let key = DecodingKey::from_rsa_components(n, e).map_err(|e| invalid(&e))?;
        Ok(Self::new(alg, key))
    }

    /// ECDSA public key in PEM (SPKI) for `ES256` (P-256) or `ES384` (P-384).
    ///
    /// # Errors
    ///
    /// [`KeyError::AlgorithmMismatch`] for a non-ECDSA algorithm,
    /// [`KeyError::Invalid`] if the PEM does not parse.
    pub fn ec_pem(alg: Algorithm, pem: &[u8]) -> Result<Self, KeyError> {
        expect_type(alg, "EC")?;
        let key = DecodingKey::from_ec_pem(pem).map_err(|e| invalid(&e))?;
        Ok(Self::new(alg, key))
    }

    /// Ed25519 public key in PEM (SPKI), verified as `EdDSA`.
    ///
    /// # Errors
    ///
    /// [`KeyError::Invalid`] if the PEM does not parse.
    pub fn ed_pem(pem: &[u8]) -> Result<Self, KeyError> {
        let key = DecodingKey::from_ed_pem(pem).map_err(|e| invalid(&e))?;
        Ok(Self::new(Algorithm::EdDSA, key))
    }

    /// Builds a key from a JWK.
    ///
    /// The algorithm is the JWK's `alg` when present. Without one it is
    /// inferred: `RS256` for RSA, `ES256`/`ES384` from the EC curve, `EdDSA`
    /// for Ed25519. Symmetric (`oct`) keys must carry an `alg`. Keys marked
    /// `use: "enc"`, or whose `key_ops` lack `verify`, are refused.
    ///
    /// # Errors
    ///
    /// Any [`KeyError`] variant, see above.
    pub fn from_jwk(jwk: &Jwk) -> Result<Self, KeyError> {
        if matches!(jwk.common.public_key_use, Some(PublicKeyUse::Encryption)) {
            return Err(KeyError::NotForSigning);
        }
        if let Some(ops) = &jwk.common.key_operations
            && !ops.iter().any(|op| matches!(op, KeyOperations::Verify))
        {
            return Err(KeyError::NotForSigning);
        }
        let declared = jwk.common.key_algorithm.map(signing_alg).transpose()?;
        let alg = match &jwk.algorithm {
            AlgorithmParameters::RSA(_) => declared.unwrap_or(Algorithm::RS256),
            AlgorithmParameters::EllipticCurve(params) => {
                let natural = match params.curve {
                    EllipticCurve::P256 => Algorithm::ES256,
                    EllipticCurve::P384 => Algorithm::ES384,
                    ref other => return Err(KeyError::Unsupported(format!("EC curve {other:?}"))),
                };
                declared.unwrap_or(natural)
            }
            AlgorithmParameters::OctetKeyPair(params) => {
                if params.curve != EllipticCurve::Ed25519 {
                    return Err(KeyError::Unsupported(format!(
                        "OKP curve {:?}",
                        params.curve
                    )));
                }
                declared.unwrap_or(Algorithm::EdDSA)
            }
            AlgorithmParameters::OctetKey(_) => declared.ok_or(KeyError::MissingAlgorithm)?,
            _ => return Err(KeyError::Unsupported("key type".into())),
        };
        let want = match &jwk.algorithm {
            AlgorithmParameters::RSA(_) => "RSA",
            AlgorithmParameters::EllipticCurve(_) => "EC",
            AlgorithmParameters::OctetKeyPair(_) => "OKP",
            AlgorithmParameters::OctetKey(_) => "HMAC",
            _ => return Err(KeyError::Unsupported("key type".into())),
        };
        expect_type(alg, want)?;
        if let AlgorithmParameters::EllipticCurve(params) = &jwk.algorithm {
            let fits = matches!(
                (alg, &params.curve),
                (Algorithm::ES256, EllipticCurve::P256) | (Algorithm::ES384, EllipticCurve::P384)
            );
            if !fits {
                return Err(KeyError::AlgorithmMismatch {
                    alg,
                    key_type: "EC",
                });
            }
        }
        let key = DecodingKey::from_jwk(jwk).map_err(|e| invalid(&e))?;
        Ok(Self {
            kid: jwk.common.key_id.clone(),
            alg,
            key,
        })
    }

    const fn new(alg: Algorithm, key: DecodingKey) -> Self {
        Self {
            kid: None,
            alg,
            key,
        }
    }

    /// Sets the key id matched against the token's `kid` header.
    #[must_use]
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// The key id, if any.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The one algorithm this key verifies.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.alg
    }

    /// Whether this is a symmetric (HMAC) key.
    #[must_use]
    pub const fn is_symmetric(&self) -> bool {
        matches!(
            self.alg,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        )
    }

    pub(crate) const fn decoding_key(&self) -> &DecodingKey {
        &self.key
    }
}

fn signing_alg(alg: KeyAlgorithm) -> Result<Algorithm, KeyError> {
    Ok(match alg {
        KeyAlgorithm::HS256 => Algorithm::HS256,
        KeyAlgorithm::HS384 => Algorithm::HS384,
        KeyAlgorithm::HS512 => Algorithm::HS512,
        KeyAlgorithm::ES256 => Algorithm::ES256,
        KeyAlgorithm::ES384 => Algorithm::ES384,
        KeyAlgorithm::RS256 => Algorithm::RS256,
        KeyAlgorithm::RS384 => Algorithm::RS384,
        KeyAlgorithm::RS512 => Algorithm::RS512,
        KeyAlgorithm::PS256 => Algorithm::PS256,
        KeyAlgorithm::PS384 => Algorithm::PS384,
        KeyAlgorithm::PS512 => Algorithm::PS512,
        KeyAlgorithm::EdDSA => Algorithm::EdDSA,
        KeyAlgorithm::RSA1_5 | KeyAlgorithm::RSA_OAEP | KeyAlgorithm::RSA_OAEP_256 => {
            return Err(KeyError::NotForSigning);
        }
        other => return Err(KeyError::Unsupported(format!("JWK algorithm {other:?}"))),
    })
}

/// Parses a JWKS document, keeping only usable signature keys.
///
/// Keys that fail to parse, are for encryption, or use an unsupported curve
/// are skipped rather than failing the whole set, so one exotic key in an
/// identity provider's JWKS does not lock everyone out. With
/// `allow_symmetric = false`, `oct` keys are skipped too.
pub fn keys_from_jwks(json: &[u8], allow_symmetric: bool) -> Result<Vec<Arc<VerifyKey>>, String> {
    #[derive(serde::Deserialize)]
    struct RawSet {
        keys: Vec<serde_json::Value>,
    }
    let set: RawSet = serde_json::from_slice(json).map_err(|e| e.to_string())?;
    let keys = set
        .keys
        .into_iter()
        .filter_map(|raw| serde_json::from_value::<Jwk>(raw).ok())
        .filter_map(|jwk| VerifyKey::from_jwk(&jwk).ok())
        .filter(|key| allow_symmetric || !key.is_symmetric())
        .map(Arc::new)
        .collect();
    Ok(keys)
}

/// Picks the key for a token's `kid` from a key list.
///
/// With a `kid`, the key with that id wins; a lone key without an id also
/// matches. Without a `kid`, there must be exactly one key.
#[allow(clippy::option_if_let_else, reason = "a match reads clearer here")]
pub fn pick(keys: &[Arc<VerifyKey>], kid: Option<&str>) -> Result<Arc<VerifyKey>, LookupError> {
    match kid {
        Some(kid) => keys
            .iter()
            .find(|k| k.kid.as_deref() == Some(kid))
            .or_else(|| match keys {
                [only] if only.kid.is_none() => Some(only),
                _ => None,
            })
            .cloned()
            .ok_or(LookupError::UnknownKid),
        None => match keys {
            [only] => Ok(Arc::clone(only)),
            [] => Err(LookupError::UnknownKid),
            _ => Err(LookupError::KidRequired),
        },
    }
}

/// Where verification keys come from.
///
/// Implement this to plug in a custom store (a secrets manager, a database).
/// [`StaticKeys`] and, with the `jwks` feature, `JwksSource` are provided.
pub trait KeySource: Send + Sync + 'static {
    /// Returns the key for a token whose header carries `kid`.
    ///
    /// Must return [`LookupError::KidRequired`] when `kid` is `None` and more
    /// than one key could apply.
    fn resolve<'a>(
        &'a self,
        kid: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Arc<VerifyKey>, LookupError>>;
}

/// A fixed set of keys.
///
/// # Examples
///
/// ```rust
/// use rune_axum_jwt::{JwtConfig, StaticKeys, VerifyKey};
///
/// let keys = StaticKeys::new([
///     VerifyKey::hs256(b"old secret").with_kid("2025"),
///     VerifyKey::hs256(b"new secret").with_kid("2026"),
/// ]);
/// let config = JwtConfig::new(keys);
/// ```
#[derive(Debug, Clone, Default)]
pub struct StaticKeys {
    keys: Vec<Arc<VerifyKey>>,
}

impl StaticKeys {
    /// A key set from the given keys.
    pub fn new(keys: impl IntoIterator<Item = VerifyKey>) -> Self {
        Self {
            keys: keys.into_iter().map(Arc::new).collect(),
        }
    }

    /// Parses a JWKS JSON document (`{"keys": [...]}`).
    ///
    /// Unusable entries (encryption keys, unsupported curves) are skipped.
    /// `oct` keys are kept only when they carry an `alg`.
    ///
    /// # Errors
    ///
    /// [`KeyError::Invalid`] if the JSON does not parse or no usable key is
    /// left.
    pub fn from_jwks_json(json: &str) -> Result<Self, KeyError> {
        let keys = keys_from_jwks(json.as_bytes(), true).map_err(KeyError::Invalid)?;
        if keys.is_empty() {
            return Err(KeyError::Invalid("no usable keys in JWKS".into()));
        }
        Ok(Self { keys })
    }

    /// Adds a key.
    #[must_use]
    pub fn with(mut self, key: VerifyKey) -> Self {
        self.keys.push(Arc::new(key));
        self
    }

    /// The keys in the set.
    pub fn keys(&self) -> impl Iterator<Item = &VerifyKey> {
        self.keys.iter().map(AsRef::as_ref)
    }
}

impl KeySource for StaticKeys {
    fn resolve<'a>(
        &'a self,
        kid: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Arc<VerifyKey>, LookupError>> {
        let picked = pick(&self.keys, kid);
        Box::pin(async move { picked })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(kid: Option<&str>) -> Arc<VerifyKey> {
        let key = VerifyKey::hs256(b"x");
        Arc::new(match kid {
            Some(kid) => key.with_kid(kid),
            None => key,
        })
    }

    #[test]
    fn pick_rules() {
        assert!(pick(&[k(None)], None).is_ok());
        assert!(pick(&[k(None)], Some("a")).is_ok());
        assert_eq!(pick(&[], None).unwrap_err(), LookupError::UnknownKid);
        assert_eq!(
            pick(&[k(Some("a")), k(Some("b"))], None).unwrap_err(),
            LookupError::KidRequired
        );
        assert_eq!(
            pick(&[k(Some("a")), k(Some("b"))], Some("b"))
                .unwrap()
                .kid(),
            Some("b")
        );
        assert_eq!(
            pick(&[k(Some("a"))], Some("c")).unwrap_err(),
            LookupError::UnknownKid
        );
    }

    #[test]
    fn hmac_rejects_asymmetric_alg() {
        assert!(matches!(
            VerifyKey::hmac(Algorithm::RS256, b"x"),
            Err(KeyError::AlgorithmMismatch { .. })
        ));
        assert!(matches!(
            VerifyKey::rsa_pem(Algorithm::HS256, b"x"),
            Err(KeyError::AlgorithmMismatch { .. })
        ));
    }

    #[test]
    fn jwks_skips_unusable_keys() {
        let json = br#"{"keys":[
            {"kty":"EC","crv":"P-521","x":"AA","y":"AA","kid":"p521"},
            {"kty":"RSA","use":"enc","n":"AQAB","e":"AQAB","kid":"enc"},
            {"kty":"oct","k":"c2VjcmV0","alg":"HS256","kid":"oct"},
            {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"ed"},
            {"kty":"weird"}
        ]}"#;
        let remote = keys_from_jwks(json, false).unwrap();
        assert_eq!(remote.len(), 1);
        assert_eq!(remote[0].kid(), Some("ed"));
        assert_eq!(remote[0].algorithm(), Algorithm::EdDSA);
        let local = keys_from_jwks(json, true).unwrap();
        assert_eq!(local.len(), 2);
    }

    #[test]
    fn jwk_alg_must_fit_key_type() {
        let jwk: Jwk = serde_json::from_str(
            r#"{"kty":"OKP","crv":"Ed25519","alg":"HS256","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
        )
        .unwrap();
        assert!(matches!(
            VerifyKey::from_jwk(&jwk),
            Err(KeyError::AlgorithmMismatch { .. })
        ));
        let jwk: Jwk = serde_json::from_str(r#"{"kty":"oct","k":"c2VjcmV0"}"#).unwrap();
        assert_eq!(
            VerifyKey::from_jwk(&jwk).unwrap_err(),
            KeyError::MissingAlgorithm
        );
    }
}
