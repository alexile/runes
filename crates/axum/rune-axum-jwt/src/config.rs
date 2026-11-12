//! Validation settings and the verification pipeline.

use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{Algorithm, Validation, decode, errors::ErrorKind};
use serde_json::Value;

use crate::{
    JwtRejection, VerifiedClaims,
    key::{KeySource, LookupError, StaticKeys, VerifyKey},
};

/// Default [`JwtConfig::max_token_len`]: 8 KiB.
pub const DEFAULT_MAX_TOKEN_LEN: usize = 8 * 1024;

/// How tokens are verified: where the keys come from and which claims must
/// hold.
///
/// Cheap to clone (one `Arc`). Pass it to [`JwtLayer::new`](crate::JwtLayer::new),
/// or put it in Axum state for the [`Jwt<C>`](crate::Jwt) extractor.
///
/// Always checked: signature with the key's pinned algorithm, `exp` (must be
/// present), `nbf` and `iat` when present. `exp`, `nbf` and `iat` must be
/// JSON numbers when present; any other type (a string, `null`) rejects the
/// token instead of being treated as absent. Opt in to `iss`, `aud` and more.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_axum_jwt::JwtConfig;
///
/// let config = JwtConfig::hs256(b"a long, random shared secret")
///     .issuer("https://auth.example.com")
///     .audience(&["api.example.com"])
///     .leeway(30)
///     .require_claims(["sub"])
///     .max_age(Duration::from_secs(24 * 3600));
/// ```
#[derive(Clone)]
pub struct JwtConfig {
    inner: Arc<Inner>,
}

#[derive(Clone)]
struct Inner {
    keys: Arc<dyn KeySource>,
    issuer: Option<String>,
    audience: Vec<String>,
    leeway: u64,
    max_token_len: usize,
    required: Vec<String>,
    max_age: Option<Duration>,
    roles_claim: Vec<String>,
    id: Arc<()>,
}

impl std::fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtConfig")
            .field("issuer", &self.inner.issuer)
            .field("audience", &self.inner.audience)
            .field("leeway", &self.inner.leeway)
            .field("max_token_len", &self.inner.max_token_len)
            .field("required", &self.inner.required)
            .field("max_age", &self.inner.max_age)
            .finish_non_exhaustive()
    }
}

impl JwtConfig {
    /// A config that takes keys from `keys`.
    pub fn new(keys: impl KeySource) -> Self {
        Self::from_source(Arc::new(keys))
    }

    /// Like [`JwtConfig::new`], for an already shared source.
    #[must_use]
    pub fn from_source(keys: Arc<dyn KeySource>) -> Self {
        install_crypto_provider();
        Self {
            inner: Arc::new(Inner {
                keys,
                issuer: None,
                audience: Vec::new(),
                leeway: 0,
                max_token_len: DEFAULT_MAX_TOKEN_LEN,
                required: Vec::new(),
                max_age: None,
                roles_claim: vec!["roles".to_owned()],
                id: Arc::new(()),
            }),
        }
    }

    /// A config with one HMAC-SHA-256 shared secret.
    #[must_use]
    pub fn hs256(secret: &[u8]) -> Self {
        Self::new(StaticKeys::new([VerifyKey::hs256(secret)]))
    }

    /// A config with one HMAC-SHA-384 shared secret.
    #[must_use]
    pub fn hs384(secret: &[u8]) -> Self {
        Self::new(StaticKeys::new([VerifyKey::hs384(secret)]))
    }

    /// A config with one HMAC-SHA-512 shared secret.
    #[must_use]
    pub fn hs512(secret: &[u8]) -> Self {
        Self::new(StaticKeys::new([VerifyKey::hs512(secret)]))
    }

    fn inner_mut(&mut self) -> &mut Inner {
        let inner = Arc::make_mut(&mut self.inner);
        // A changed config is a different config.
        inner.id = Arc::new(());
        inner
    }

    /// Requires `iss` to equal `iss` exactly.
    #[must_use]
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.inner_mut().issuer = Some(iss.into());
        self
    }

    /// Requires `aud` to be present and to contain one of `aud`.
    ///
    /// Without this, `aud` is not checked at all. Set it for any token that
    /// is not minted for this service alone: otherwise a token the same
    /// issuer made for another API is accepted here too.
    #[must_use]
    pub fn audience(mut self, aud: &[&str]) -> Self {
        self.inner_mut().audience = aud.iter().map(|a| (*a).to_owned()).collect();
        self
    }

    /// Clock skew, in seconds, allowed on `exp`, `nbf` and `iat`. Default 0.
    #[must_use]
    pub fn leeway(mut self, seconds: u64) -> Self {
        self.inner_mut().leeway = seconds;
        self
    }

    /// Longest accepted token, in bytes. Longer ones are rejected before
    /// any decoding. Default [`DEFAULT_MAX_TOKEN_LEN`].
    #[must_use]
    pub fn max_token_len(mut self, bytes: usize) -> Self {
        self.inner_mut().max_token_len = bytes;
        self
    }

    /// Claims that must be present (and not `null`), e.g. `sub`.
    #[must_use]
    pub fn require_claims<I, T>(mut self, claims: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.inner_mut()
            .required
            .extend(claims.into_iter().map(Into::into));
        self
    }

    /// Rejects tokens whose `iat` is older than `age`, and makes `iat`
    /// required.
    #[must_use]
    pub fn max_age(mut self, age: Duration) -> Self {
        self.inner_mut().max_age = Some(age);
        self
    }

    /// Where roles live in the claims, as a dot-separated path. Default
    /// `roles`. Keycloak uses `realm_access.roles`.
    ///
    /// The value may be an array of strings or one space-separated string.
    #[must_use]
    pub fn roles_claim(mut self, path: &str) -> Self {
        self.inner_mut().roles_claim = path.split('.').map(str::to_owned).collect();
        self
    }

    /// Whether `id` is this config's identity: nested layers reuse each
    /// other's verified claims only when they share a config.
    pub(crate) fn is(&self, id: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.inner.id, id)
    }

    /// Verifies `token` and returns its claims.
    ///
    /// This is what [`JwtLayer`](crate::JwtLayer) and [`Jwt<C>`](crate::Jwt)
    /// run; call it directly to authenticate something other than an HTTP
    /// request (a WebSocket message, a job).
    ///
    /// # Errors
    ///
    /// A [`JwtRejection`] saying what failed.
    pub async fn verify(&self, token: &str) -> Result<VerifiedClaims, JwtRejection> {
        let inner = &*self.inner;
        if token.len() > inner.max_token_len {
            return Err(JwtRejection::TooLong {
                max: inner.max_token_len,
            });
        }

        // Look at the raw header before trusting anything in it.
        let header = rune_jwt::header(token).map_err(|e| JwtRejection::Malformed(e.to_string()))?;
        let alg_name = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or_else(|| JwtRejection::UnsupportedAlgorithm(String::new()))?;
        let alg = Algorithm::from_str(alg_name)
            .map_err(|_| JwtRejection::UnsupportedAlgorithm(alg_name.to_owned()))?;
        if header.get("crit").is_some() {
            return Err(JwtRejection::CriticalHeader);
        }
        let kid = match header.get("kid") {
            None | Some(Value::Null) => None,
            Some(Value::String(kid)) => Some(kid.as_str()),
            Some(_) => return Err(JwtRejection::Malformed("kid is not a string".into())),
        };

        let key = inner.keys.resolve(kid).await.map_err(|e| match e {
            LookupError::KidRequired => JwtRejection::KidRequired,
            LookupError::UnknownKid => JwtRejection::UnknownKid,
            LookupError::Unavailable(why) => JwtRejection::KeysUnavailable(why),
        })?;
        if key.algorithm() != alg {
            return Err(JwtRejection::AlgorithmMismatch {
                token: alg_name.to_owned(),
                key: format!("{:?}", key.algorithm()),
            });
        }

        let mut validation = Validation::new(key.algorithm());
        validation.leeway = inner.leeway;
        validation.validate_nbf = true;
        let mut spec = vec!["exp"];
        if let Some(iss) = &inner.issuer {
            validation.set_issuer(&[iss]);
            spec.push("iss");
        }
        if inner.audience.is_empty() {
            validation.validate_aud = false;
        } else {
            validation.set_audience(&inner.audience);
            spec.push("aud");
        }
        validation.set_required_spec_claims(&spec);

        let data =
            decode::<Value>(token, key.decoding_key(), &validation).map_err(|e| map_error(&e))?;
        let claims = data.claims;
        let Value::Object(map) = &claims else {
            return Err(JwtRejection::InvalidClaims(
                "claims are not an object".into(),
            ));
        };

        // A date claim of the wrong type must never read as "absent": a
        // string `nbf` would otherwise skip the not-before check.
        numeric_date(map, "exp")?;
        numeric_date(map, "nbf")?;
        self.check_iat(numeric_date(map, "iat")?)?;
        for name in &inner.required {
            if map.get(name).is_none_or(Value::is_null) {
                return Err(JwtRejection::MissingClaim(name.clone()));
            }
        }

        let scopes = scopes_of(map);
        let roles = lookup(&claims, &inner.roles_claim)
            .map(string_list)
            .unwrap_or_default();
        Ok(VerifiedClaims::new(
            Arc::new(claims),
            kid.map(str::to_owned),
            key.algorithm(),
            scopes,
            roles,
            Arc::clone(&inner.id),
        ))
    }

    fn check_iat(&self, iat: Option<f64>) -> Result<(), JwtRejection> {
        let inner = &*self.inner;
        let iat = match iat {
            None if inner.max_age.is_some() => {
                return Err(JwtRejection::MissingClaim("iat".into()));
            }
            None => return Ok(()),
            Some(iat) => iat,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        #[allow(clippy::cast_precision_loss, reason = "leeway is a few seconds")]
        let leeway = inner.leeway as f64;
        if iat > now + leeway {
            return Err(JwtRejection::BadIssuedAt("issued in the future"));
        }
        if let Some(max_age) = inner.max_age
            && now - iat > max_age.as_secs_f64() + leeway
        {
            return Err(JwtRejection::BadIssuedAt("too old"));
        }
        Ok(())
    }
}

/// Reads a `NumericDate` claim strictly: absent is `None`; anything present
/// must be a finite, non-negative JSON number. `null`, strings, booleans and
/// so on are rejected rather than treated as missing.
fn numeric_date(
    map: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<f64>, JwtRejection> {
    let Some(value) = map.get(name) else {
        return Ok(None);
    };
    value
        .as_f64()
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map(Some)
        .ok_or_else(|| JwtRejection::InvalidClaims(format!("{name} is not a NumericDate")))
}

/// Makes the crypto backend picked by this crate's features the process
/// default, unless the application already installed one. Without this, a
/// build where some other crate turns on a second `jsonwebtoken` backend
/// would have no default and fail on the first verification.
fn install_crypto_provider() {
    #[cfg(feature = "rust_crypto")]
    let _ = jsonwebtoken::crypto::CryptoProvider::install_default(
        &jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER,
    );
    #[cfg(all(feature = "aws_lc_rs", not(feature = "rust_crypto")))]
    let _ = jsonwebtoken::crypto::CryptoProvider::install_default(
        &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER,
    );
}

fn map_error(err: &jsonwebtoken::errors::Error) -> JwtRejection {
    match err.kind() {
        ErrorKind::InvalidSignature => JwtRejection::InvalidSignature,
        ErrorKind::ExpiredSignature => JwtRejection::Expired,
        ErrorKind::ImmatureSignature => JwtRejection::NotYetValid,
        ErrorKind::InvalidIssuer => JwtRejection::InvalidIssuer,
        ErrorKind::InvalidAudience => JwtRejection::InvalidAudience,
        ErrorKind::MissingRequiredClaim(claim) => JwtRejection::MissingClaim(claim.clone()),
        ErrorKind::InvalidClaimFormat(claim) => {
            JwtRejection::InvalidClaims(format!("{claim} has the wrong type"))
        }
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
            JwtRejection::UnsupportedAlgorithm(String::new())
        }
        ErrorKind::Json(e) => JwtRejection::InvalidClaims(e.to_string()),
        _ => JwtRejection::Malformed(err.to_string()),
    }
}

fn lookup<'a>(value: &'a Value, path: &[String]) -> Option<&'a Value> {
    path.iter().try_fold(value, |v, seg| v.get(seg))
}

fn string_list(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => s.split_whitespace().map(str::to_owned).collect(),
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// `scope` (RFC 8693 / RFC 9068, space-separated) and `scp` (string or
/// array, as Azure AD and Okta issue it), merged.
fn scopes_of(map: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut scopes: Vec<String> = ["scope", "scp"]
        .iter()
        .filter_map(|k| map.get(*k))
        .flat_map(string_list)
        .collect();
    scopes.sort_unstable();
    scopes.dedup();
    scopes
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    const SECRET: &[u8] = b"a long, random shared secret for tests";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn sign(claims: &Value) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(SECRET),
        )
        .expect("HS256 signing works")
    }

    async fn verify(claims: &Value) -> Result<VerifiedClaims, JwtRejection> {
        JwtConfig::hs256(SECRET).verify(&sign(claims)).await
    }

    #[tokio::test]
    async fn well_typed_dates_pass() {
        let t = now();
        let claims = json!({"sub": "a", "exp": t + 600, "nbf": t - 10, "iat": t});
        assert!(verify(&claims).await.is_ok());
    }

    #[tokio::test]
    async fn future_nbf_is_rejected() {
        let claims = json!({"sub": "a", "exp": now() + 600, "nbf": 99_999_999_999_u64});
        assert_eq!(
            verify(&claims).await.unwrap_err(),
            JwtRejection::NotYetValid
        );
    }

    /// A far-future `nbf` sent as a string must not read as "no nbf" and
    /// slip past the not-before check (the jsonwebtoken claim type confusion,
    /// GHSA-h395-gr6q-cpjc). The same goes for every date claim and for any
    /// non-number type.
    #[tokio::test]
    async fn mistyped_date_claims_are_rejected() {
        let exp = now() + 600;
        let cases = [
            json!({"sub": "a", "exp": exp, "nbf": "99999999999"}),
            json!({"sub": "a", "exp": exp, "nbf": null}),
            json!({"sub": "a", "exp": exp, "nbf": true}),
            json!({"sub": "a", "exp": exp, "nbf": [1]}),
            json!({"sub": "a", "exp": exp, "nbf": {"t": 1}}),
            json!({"sub": "a", "exp": exp, "nbf": -1}),
            json!({"sub": "a", "exp": "never"}),
            json!({"sub": "a", "exp": exp.to_string()}),
            json!({"sub": "a", "exp": exp, "iat": "yesterday"}),
            json!({"sub": "a", "exp": exp, "iat": null}),
        ];
        for claims in &cases {
            let err = verify(claims).await.unwrap_err();
            assert!(
                matches!(
                    err,
                    JwtRejection::InvalidClaims(_) | JwtRejection::MissingClaim(_)
                ),
                "{claims} gave {err:?}"
            );
        }
    }

    #[test]
    fn numeric_date_is_strict() {
        let map = |v: Value| json!({ "d": v }).as_object().cloned().unwrap_or_default();
        assert_eq!(numeric_date(&map(json!(5)), "d"), Ok(Some(5.0)));
        assert_eq!(numeric_date(&map(json!(1.5)), "d"), Ok(Some(1.5)));
        assert_eq!(numeric_date(&serde_json::Map::new(), "d"), Ok(None));
        for bad in [json!("5"), json!(null), json!(-1), json!(false), json!([])] {
            assert!(numeric_date(&map(bad), "d").is_err());
        }
    }
}
