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
/// present), `nbf` and `iat` when present. Opt in to `iss`, `aud` and more.
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

        self.check_iat(map.get("iat"))?;
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

    fn check_iat(&self, iat: Option<&Value>) -> Result<(), JwtRejection> {
        let inner = &*self.inner;
        let iat = match iat {
            None | Some(Value::Null) if inner.max_age.is_some() => {
                return Err(JwtRejection::MissingClaim("iat".into()));
            }
            None | Some(Value::Null) => return Ok(()),
            Some(v) => v
                .as_f64()
                .ok_or_else(|| JwtRejection::InvalidClaims("iat is not a number".into()))?,
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

fn map_error(err: &jsonwebtoken::errors::Error) -> JwtRejection {
    match err.kind() {
        ErrorKind::InvalidSignature => JwtRejection::InvalidSignature,
        ErrorKind::ExpiredSignature => JwtRejection::Expired,
        ErrorKind::ImmatureSignature => JwtRejection::NotYetValid,
        ErrorKind::InvalidIssuer => JwtRejection::InvalidIssuer,
        ErrorKind::InvalidAudience => JwtRejection::InvalidAudience,
        ErrorKind::MissingRequiredClaim(claim) => JwtRejection::MissingClaim(claim.clone()),
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
