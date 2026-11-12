//! Keys fetched from a JWKS URL, optionally found through OIDC discovery.

use std::{
    net::IpAddr,
    sync::{Arc, PoisonError, RwLock},
    time::{Duration, Instant},
};

use reqwest::{Client, Url, header::ACCEPT, redirect};

use crate::{
    JwtConfig,
    key::{BoxFuture, KeySource, LookupError, VerifyKey, keys_from_jwks, pick},
};

/// Error fetching a JWKS or discovery document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JwksError {
    /// The URL does not parse.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    /// The URL is not `https`, and not plain `http` to a loopback host.
    #[error("URL must use https (plain http only to localhost): {0}")]
    NotHttps(String),
    /// The HTTP client could not be built.
    #[error("HTTP client: {0}")]
    Client(String),
    /// Connection or protocol error.
    #[error("request failed: {0}")]
    Transport(String),
    /// The request took longer than the configured timeout.
    #[error("request timed out")]
    Timeout,
    /// A non-2xx response (redirects are not followed).
    #[error("HTTP status {0}")]
    Status(u16),
    /// The body is larger than the configured cap.
    #[error("response larger than {0} bytes")]
    TooLarge(usize),
    /// The body is not the expected JSON.
    #[error("invalid document: {0}")]
    InvalidDocument(String),
    /// The JWKS has no key this crate can verify with.
    #[error("JWKS has no usable signature keys")]
    NoUsableKeys,
    /// The discovery document names a different issuer.
    #[error("discovery issuer {found:?} does not match {expected:?}")]
    IssuerMismatch {
        /// The issuer asked for.
        expected: String,
        /// The issuer in the document.
        found: String,
    },
}

/// Tuning for [`JwksSource`].
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_axum_jwt::JwksOptions;
///
/// let options = JwksOptions::default()
///     .refresh_interval(Duration::from_secs(600))
///     .min_refetch_interval(Duration::from_secs(60));
/// ```
#[derive(Debug, Clone)]
pub struct JwksOptions {
    refresh_interval: Duration,
    min_refetch_interval: Duration,
    timeout: Duration,
    max_response_bytes: usize,
}

impl Default for JwksOptions {
    fn default() -> Self {
        Self {
            refresh_interval: Duration::from_secs(300),
            min_refetch_interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            max_response_bytes: 256 * 1024,
        }
    }
}

impl JwksOptions {
    /// How old the cached keys may get before the next request refreshes
    /// them. Default 5 minutes.
    #[must_use]
    pub const fn refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    /// Smallest gap between two fetches, whatever triggers them. Default 30
    /// seconds.
    ///
    /// This is what stops a flood of tokens with made-up `kid`s from turning
    /// into a flood of requests to the identity provider: an unknown `kid`
    /// triggers at most one refetch per interval, and the others are
    /// rejected straight away. `Duration::ZERO` turns the limit off; do not
    /// do that in production.
    #[must_use]
    pub const fn min_refetch_interval(mut self, interval: Duration) -> Self {
        self.min_refetch_interval = interval;
        self
    }

    /// Timeout for one fetch, connect included. Default 5 seconds.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Largest accepted response body. Default 256 KiB.
    #[must_use]
    pub const fn max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }
}

#[derive(Default)]
struct Cache {
    keys: Arc<[Arc<VerifyKey>]>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
    last_error: Option<JwksError>,
}

struct Shared {
    url: Url,
    client: Client,
    options: JwksOptions,
    cache: RwLock<Cache>,
    fetching: tokio::sync::Mutex<()>,
}

/// Keys from a JWKS URL, cached and refreshed.
///
/// - Fetched lazily on first use, then refreshed when older than
///   [`JwksOptions::refresh_interval`], and when a token names a `kid` the
///   cache does not have (key rotation).
/// - Fetches are single-flight and at least
///   [`JwksOptions::min_refetch_interval`] apart.
/// - If a refresh fails, the previous keys stay in use.
/// - `https` only (plain `http` to `localhost`, `127.0.0.1` or `::1` is
///   allowed for development); redirects are not followed; bodies are capped
///   and fetches time out.
/// - Only signature keys are kept: symmetric (`oct`) keys, `use: "enc"`
///   keys and unsupported curves in the set are ignored.
///
/// Cheap to clone; clones share the cache.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_axum_jwt::{JwksSource, JwtConfig};
///
/// # fn main() -> Result<(), rune_axum_jwt::JwksError> {
/// let keys = JwksSource::new("https://auth.example.com/.well-known/jwks.json")?;
/// let config = JwtConfig::new(keys)
///     .issuer("https://auth.example.com/")
///     .audience(&["api.example.com"]);
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct JwksSource {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for JwksSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksSource")
            .field("url", &self.shared.url.as_str())
            .field("options", &self.shared.options)
            .finish_non_exhaustive()
    }
}

fn check_url(raw: &str) -> Result<Url, JwksError> {
    let url = Url::parse(raw).map_err(|e| JwksError::InvalidUrl(e.to_string()))?;
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    match url.scheme() {
        "https" if url.host().is_some() => Ok(url),
        "http" if loopback => Ok(url),
        _ => Err(JwksError::NotHttps(raw.to_owned())),
    }
}

fn client(options: &JwksOptions) -> Result<Client, JwksError> {
    Client::builder()
        .timeout(options.timeout)
        .connect_timeout(options.timeout)
        .redirect(redirect::Policy::none())
        .build()
        .map_err(|e| JwksError::Client(e.to_string()))
}

fn transport(err: &reqwest::Error) -> JwksError {
    if err.is_timeout() {
        JwksError::Timeout
    } else {
        JwksError::Transport(err.to_string())
    }
}

async fn get_capped(client: &Client, url: &Url, max: usize) -> Result<Vec<u8>, JwksError> {
    let mut response = client
        .get(url.clone())
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| transport(&e))?;
    let status = response.status();
    if !status.is_success() {
        return Err(JwksError::Status(status.as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|len| len > max as u64)
    {
        return Err(JwksError::TooLarge(max));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| transport(&e))? {
        if body.len() + chunk.len() > max {
            return Err(JwksError::TooLarge(max));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

impl JwksSource {
    /// A source for the JWKS at `url`, with default [`JwksOptions`].
    ///
    /// Nothing is fetched yet.
    ///
    /// # Errors
    ///
    /// [`JwksError::InvalidUrl`], [`JwksError::NotHttps`] or
    /// [`JwksError::Client`].
    pub fn new(url: &str) -> Result<Self, JwksError> {
        Self::with_options(url, JwksOptions::default())
    }

    /// A source for the JWKS at `url`.
    ///
    /// # Errors
    ///
    /// As for [`JwksSource::new`].
    pub fn with_options(url: &str, options: JwksOptions) -> Result<Self, JwksError> {
        let url = check_url(url)?;
        let client = client(&options)?;
        Ok(Self::build(url, client, options))
    }

    fn build(url: Url, client: Client, options: JwksOptions) -> Self {
        Self {
            shared: Arc::new(Shared {
                url,
                client,
                options,
                cache: RwLock::new(Cache::default()),
                fetching: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// Finds the JWKS through OIDC discovery.
    ///
    /// Fetches `{issuer}/.well-known/openid-configuration`, checks that its
    /// `issuer` equals `issuer` exactly (OIDC Discovery §4.3), and
    /// uses its `jwks_uri`, which must also be `https`.
    ///
    /// # Errors
    ///
    /// Any [`JwksError`] from fetching or checking the document.
    pub async fn discover(issuer: &str, options: JwksOptions) -> Result<Self, JwksError> {
        #[derive(serde::Deserialize)]
        struct Discovery {
            issuer: String,
            jwks_uri: String,
        }
        let base = issuer.trim_end_matches('/');
        let url = check_url(&format!("{base}/.well-known/openid-configuration"))?;
        let client = client(&options)?;
        let body = get_capped(&client, &url, options.max_response_bytes).await?;
        let doc: Discovery =
            serde_json::from_slice(&body).map_err(|e| JwksError::InvalidDocument(e.to_string()))?;
        if doc.issuer != issuer {
            return Err(JwksError::IssuerMismatch {
                expected: issuer.to_owned(),
                found: doc.issuer,
            });
        }
        let jwks = check_url(&doc.jwks_uri)?;
        Ok(Self::build(jwks, client, options))
    }

    /// The JWKS URL.
    #[must_use]
    pub fn url(&self) -> &str {
        self.shared.url.as_str()
    }

    /// Fetches the keys now, ignoring the refetch interval.
    ///
    /// Useful at startup to fail fast, or to warm the cache.
    ///
    /// # Errors
    ///
    /// The fetch error; the cache keeps its previous keys.
    pub async fn refresh(&self) -> Result<usize, JwksError> {
        let _guard = self.shared.fetching.lock().await;
        self.fetch_locked().await
    }

    fn snapshot(&self) -> (Arc<[Arc<VerifyKey>]>, bool) {
        let cache = self
            .shared
            .cache
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let stale = cache
            .fetched_at
            .is_none_or(|t| t.elapsed() >= self.shared.options.refresh_interval);
        (Arc::clone(&cache.keys), stale)
    }

    fn last_error(&self) -> String {
        self.shared
            .cache
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .last_error
            .as_ref()
            .map_or_else(|| JwksError::NoUsableKeys.to_string(), ToString::to_string)
    }

    /// Fetches unless another fetch happened within the minimum interval.
    async fn refresh_if_due(&self) {
        let _guard = self.shared.fetching.lock().await;
        let due = self
            .shared
            .cache
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .last_attempt
            .is_none_or(|t| t.elapsed() >= self.shared.options.min_refetch_interval);
        if due {
            // Errors are recorded in the cache and logged.
            let _ = self.fetch_locked().await;
        }
    }

    /// Fetch and store; the caller holds `fetching`.
    async fn fetch_locked(&self) -> Result<usize, JwksError> {
        let shared = &*self.shared;
        let result = get_capped(
            &shared.client,
            &shared.url,
            shared.options.max_response_bytes,
        )
        .await
        .and_then(|body| keys_from_jwks(&body, false).map_err(JwksError::InvalidDocument))
        .and_then(|keys| {
            if keys.is_empty() {
                Err(JwksError::NoUsableKeys)
            } else {
                Ok(keys)
            }
        });
        let now = Instant::now();
        if let Err(err) = &result {
            tracing::warn!(url = %shared.url, error = %err, "jwt: JWKS fetch failed");
        }
        let mut cache = shared.cache.write().unwrap_or_else(PoisonError::into_inner);
        cache.last_attempt = Some(now);
        match result {
            Ok(keys) => {
                let count = keys.len();
                cache.keys = keys.into();
                cache.fetched_at = Some(now);
                cache.last_error = None;
                drop(cache);
                Ok(count)
            }
            Err(err) => {
                cache.last_error = Some(err.clone());
                drop(cache);
                Err(err)
            }
        }
    }

    async fn resolve_inner(&self, kid: Option<&str>) -> Result<Arc<VerifyKey>, LookupError> {
        let (mut keys, stale) = self.snapshot();
        if stale {
            self.refresh_if_due().await;
            keys = self.snapshot().0;
        }
        if keys.is_empty() {
            return Err(LookupError::Unavailable(self.last_error()));
        }
        match pick(&keys, kid) {
            Err(LookupError::UnknownKid) if kid.is_some() => {
                // Maybe the keys rotated. `refresh_if_due` is throttled, so a
                // stream of bogus kids costs at most one fetch per interval.
                self.refresh_if_due().await;
                pick(&self.snapshot().0, kid)
            }
            other => other,
        }
    }
}

impl KeySource for JwksSource {
    fn resolve<'a>(
        &'a self,
        kid: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Arc<VerifyKey>, LookupError>> {
        Box::pin(self.resolve_inner(kid))
    }
}

impl JwtConfig {
    /// A config that takes keys from the JWKS at `url` (default options).
    ///
    /// # Errors
    ///
    /// As for [`JwksSource::new`].
    pub fn jwks(url: &str) -> Result<Self, JwksError> {
        JwksSource::new(url).map(Self::new)
    }

    /// A config for an OIDC issuer: keys via discovery, and `iss`
    /// pinned to `issuer`.
    ///
    /// Still set [`JwtConfig::audience`] to your API's identifier.
    ///
    /// # Errors
    ///
    /// As for [`JwksSource::discover`].
    pub async fn oidc(issuer: &str) -> Result<Self, JwksError> {
        Self::oidc_with(issuer, JwksOptions::default()).await
    }

    /// [`JwtConfig::oidc`] with custom [`JwksOptions`].
    ///
    /// # Errors
    ///
    /// As for [`JwksSource::discover`].
    pub async fn oidc_with(issuer: &str, options: JwksOptions) -> Result<Self, JwksError> {
        let source = JwksSource::discover(issuer, options).await?;
        Ok(Self::new(source).issuer(issuer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_policy() {
        assert!(check_url("https://idp.example.com/jwks").is_ok());
        assert!(check_url("http://localhost:8080/jwks").is_ok());
        assert!(check_url("http://127.0.0.1/jwks").is_ok());
        assert!(check_url("http://[::1]/jwks").is_ok());
        assert!(matches!(
            check_url("http://idp.example.com/jwks"),
            Err(JwksError::NotHttps(_))
        ));
        assert!(matches!(
            check_url("http://localhost.evil.com/jwks"),
            Err(JwksError::NotHttps(_))
        ));
        assert!(matches!(
            check_url("file:///etc/passwd"),
            Err(JwksError::NotHttps(_))
        ));
        assert!(matches!(
            check_url("not a url"),
            Err(JwksError::InvalidUrl(_))
        ));
    }
}
