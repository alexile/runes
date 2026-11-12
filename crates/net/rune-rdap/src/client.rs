//! The RDAP client (feature `client`): bootstrap, redirects, caching and
//! rate limiting over any HTTP transport.
//!
//! The transport is the caller's: implement [`Fetcher`] for your HTTP
//! client, or enable the `reqwest` feature for [`ReqwestFetcher`]. The
//! client does the rest:
//!
//! 1. loads the IANA bootstrap registry the query needs (once, then again
//!    when it expires; a stale copy is used if a refresh fails),
//! 2. picks the service's `https` base URL first, falling back to the
//!    others on transport errors,
//! 3. follows redirects (RFC 7480 §5.2) up to a limit, `http(s)` only,
//! 4. spaces requests to each host and honours `429` + `Retry-After`,
//! 5. caches objects for their `Cache-Control: max-age` (or a default).

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::bootstrap::{Bootstrap, IANA_BASE, Registry, RegistryKind};
use crate::cache::TtlCache;
use crate::ratelimit::RateLimiter;
use crate::response::{Outcome, Response, interpret};
use crate::{Error, Object, Query};

/// The media type RDAP clients ask for
/// ([RFC 7480 §4.2](https://www.rfc-editor.org/rfc/rfc7480#section-4.2)).
pub const ACCEPT: &str = "application/rdap+json";

/// An HTTP client that performs one `GET`.
///
/// Implementations send `Accept: application/rdap+json` ([`ACCEPT`]) and
/// must **not** follow redirects: the [`Client`] follows them itself, with
/// its own limit, rate limiting and scheme checks.
pub trait Fetcher {
    /// Transport errors.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Fetches `url` and returns the response as received.
    fn get(&self, url: &str) -> impl Future<Output = Result<Response, Self::Error>> + Send;
}

/// Client settings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Where the bootstrap files are fetched from (ending in `/`).
    /// Default: [`IANA_BASE`].
    pub bootstrap_base: String,
    /// How long a bootstrap file is used when the response carries no
    /// `max-age`. Default: 24 hours.
    pub bootstrap_ttl: Duration,
    /// How long an object is cached when the response carries no
    /// `max-age`. Default: one hour. `Duration::ZERO` disables caching.
    pub cache_ttl: Duration,
    /// Upper bound on any cache lifetime, including server `max-age`.
    /// Default: 24 hours.
    pub max_cache_ttl: Duration,
    /// Objects kept in the cache. Default: 1024.
    pub cache_capacity: usize,
    /// Minimum spacing between requests to one host. Default: one second.
    pub min_interval: Duration,
    /// Redirects followed per lookup. Default: 5.
    pub max_redirects: u8,
    /// Retries after a `429` answer. Default: 1.
    pub max_retries: u8,
    /// The wait after a `429` without a usable `Retry-After`. Default: 5 s.
    pub default_retry_wait: Duration,
    /// A `429` asking for a longer wait than this fails at once with
    /// [`Error::RateLimited`]. Default: 60 s.
    pub max_retry_wait: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            bootstrap_base: IANA_BASE.to_owned(),
            bootstrap_ttl: Duration::from_secs(24 * 3600),
            cache_ttl: Duration::from_secs(3600),
            max_cache_ttl: Duration::from_secs(24 * 3600),
            cache_capacity: 1024,
            min_interval: Duration::from_secs(1),
            max_redirects: 5,
            max_retries: 1,
            default_retry_wait: Duration::from_secs(5),
            max_retry_wait: Duration::from_secs(60),
        }
    }
}

impl Options {
    /// Sets [`bootstrap_base`](Self::bootstrap_base); a missing trailing
    /// `/` is added.
    #[must_use]
    pub fn with_bootstrap_base(mut self, base: impl Into<String>) -> Self {
        let mut base = base.into();
        if !base.ends_with('/') {
            base.push('/');
        }
        self.bootstrap_base = base;
        self
    }

    /// Sets [`bootstrap_ttl`](Self::bootstrap_ttl).
    #[must_use]
    pub const fn with_bootstrap_ttl(mut self, ttl: Duration) -> Self {
        self.bootstrap_ttl = ttl;
        self
    }

    /// Sets [`cache_ttl`](Self::cache_ttl).
    #[must_use]
    pub const fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Sets [`max_cache_ttl`](Self::max_cache_ttl).
    #[must_use]
    pub const fn with_max_cache_ttl(mut self, ttl: Duration) -> Self {
        self.max_cache_ttl = ttl;
        self
    }

    /// Sets [`cache_capacity`](Self::cache_capacity).
    #[must_use]
    pub const fn with_cache_capacity(mut self, entries: usize) -> Self {
        self.cache_capacity = entries;
        self
    }

    /// Sets [`min_interval`](Self::min_interval).
    #[must_use]
    pub const fn with_min_interval(mut self, interval: Duration) -> Self {
        self.min_interval = interval;
        self
    }

    /// Sets [`max_redirects`](Self::max_redirects).
    #[must_use]
    pub const fn with_max_redirects(mut self, redirects: u8) -> Self {
        self.max_redirects = redirects;
        self
    }

    /// Sets [`max_retries`](Self::max_retries).
    #[must_use]
    pub const fn with_max_retries(mut self, retries: u8) -> Self {
        self.max_retries = retries;
        self
    }

    /// Sets [`default_retry_wait`](Self::default_retry_wait).
    #[must_use]
    pub const fn with_default_retry_wait(mut self, wait: Duration) -> Self {
        self.default_retry_wait = wait;
        self
    }

    /// Sets [`max_retry_wait`](Self::max_retry_wait).
    #[must_use]
    pub const fn with_max_retry_wait(mut self, wait: Duration) -> Self {
        self.max_retry_wait = wait;
        self
    }
}

/// A successful lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Lookup {
    /// The object.
    pub object: Object,
    /// The URL first asked (the cache key).
    pub url: String,
    /// The URL that answered, after redirects.
    pub final_url: String,
    /// Whether the object came from the cache.
    pub cached: bool,
}

#[derive(Debug, Clone)]
struct Cached {
    object: Object,
    final_url: String,
}

#[derive(Debug)]
struct State {
    bootstrap: Bootstrap,
    /// Expiry per fetched registry; pinned registries have none.
    expires: HashMap<RegistryKind, Instant>,
    cache: TtlCache<Cached>,
    limiter: RateLimiter,
}

/// An RDAP client over a [`Fetcher`].
///
/// It is `Sync`: share one (e.g. in an `Arc`) so that every task uses the
/// same cache and rate limits.
#[derive(Debug)]
pub struct Client<F> {
    fetcher: F,
    options: Options,
    pinned: bool,
    state: Mutex<State>,
}

fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

impl<F: Fetcher + Sync> Client<F> {
    /// A client that fetches bootstrap files on demand.
    pub fn new(fetcher: F, options: Options) -> Self {
        let state = State {
            bootstrap: Bootstrap::new(),
            expires: HashMap::new(),
            cache: TtlCache::new(options.cache_capacity),
            limiter: RateLimiter::new(options.min_interval),
        };
        Self {
            fetcher,
            options,
            pinned: false,
            state: Mutex::new(state),
        }
    }

    /// Uses `bootstrap` and never fetches registries (for offline use, or
    /// registries cached by the caller). Queries whose registry is missing
    /// fail with [`Error::MissingRegistry`].
    #[must_use]
    pub fn with_bootstrap(mut self, bootstrap: Bootstrap) -> Self {
        self.pinned = true;
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        state.bootstrap = bootstrap;
        state.expires.clear();
        self
    }

    /// The options in use.
    pub const fn options(&self) -> &Options {
        &self.options
    }

    /// A copy of the registries loaded so far (to persist them).
    pub fn bootstrap(&self) -> Bootstrap {
        self.lock().bootstrap.clone()
    }

    /// Drops every cached object (registries are kept).
    pub fn clear_cache(&self) {
        self.lock().cache.clear();
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Parses `input` with [`Query::parse`] and looks it up.
    pub async fn lookup_str(&self, input: &str) -> Result<Lookup, Error> {
        self.lookup(&Query::parse(input)?).await
    }

    /// Looks `query` up at the server its bootstrap registry names.
    pub async fn lookup(&self, query: &Query) -> Result<Lookup, Error> {
        let kind = RegistryKind::for_query(query);
        self.ensure_registry(kind).await?;
        let urls = self.lock().bootstrap.urls(query)?;
        let mut last = None;
        for url in urls {
            match self.fetch(&url).await {
                Err(e @ Error::Transport(_)) => last = Some(e),
                other => return other,
            }
        }
        Err(last.unwrap_or_else(|| Error::NoService {
            query: query.path(),
        }))
    }

    /// Fetches the RDAP object at `url` (e.g. a `self` or `related` link),
    /// with the same redirect, cache and rate-limit handling as
    /// [`lookup`](Self::lookup).
    pub async fn fetch(&self, url: &str) -> Result<Lookup, Error> {
        if let Some(hit) = self.lock().cache.get(url, now()) {
            return Ok(Lookup {
                object: hit.object.clone(),
                url: url.to_owned(),
                final_url: hit.final_url.clone(),
                cached: true,
            });
        }
        let mut current = checked_url(url)?;
        let mut redirects = 0u8;
        let mut retries = 0u8;
        loop {
            let response = self.get(&current).await?;
            match interpret(&response) {
                Ok(Outcome::Object(object)) => {
                    let ttl = self.ttl(&response, self.options.cache_ttl);
                    self.lock().cache.insert(
                        url,
                        Cached {
                            object: object.clone(),
                            final_url: current.to_string(),
                        },
                        ttl,
                        now(),
                    );
                    return Ok(Lookup {
                        object,
                        url: url.to_owned(),
                        final_url: current.into(),
                        cached: false,
                    });
                }
                Ok(Outcome::Redirect(location)) => {
                    if redirects >= self.options.max_redirects {
                        return Err(Error::Redirect(format!(
                            "more than {} redirects",
                            self.options.max_redirects
                        )));
                    }
                    redirects += 1;
                    let next = current
                        .join(&location)
                        .map_err(|e| Error::Redirect(format!("bad Location {location:?}: {e}")))?;
                    current = checked_url(next.as_str())?;
                }
                Err(Error::RateLimited { retry_after }) => {
                    let wait = retry_after.unwrap_or(self.options.default_retry_wait);
                    if let Some(host) = current.host_str()
                        && let Some(until) = now().checked_add(wait)
                    {
                        self.lock().limiter.defer(host, until);
                    }
                    if retries >= self.options.max_retries || wait > self.options.max_retry_wait {
                        return Err(Error::RateLimited { retry_after });
                    }
                    retries += 1;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Fetches (or re-fetches) the registry of `kind` now. Does nothing
    /// for a client built [`with_bootstrap`](Self::with_bootstrap).
    pub async fn refresh_registry(&self, kind: RegistryKind) -> Result<(), Error> {
        if self.pinned {
            return Ok(());
        }
        let url = format!("{}{}", self.options.bootstrap_base, kind.file_name());
        let response = self.get(&checked_url(&url)?).await?;
        if response.status != 200 {
            return Err(Error::Server {
                status: response.status,
                error_code: None,
                title: Some(format!("fetching bootstrap {url}")),
                description: Vec::new(),
            });
        }
        let registry = Registry::parse(kind, &response.body)?;
        let ttl = self.ttl(&response, self.options.bootstrap_ttl);
        let mut state = self.lock();
        state.bootstrap.insert(registry);
        // A zero TTL still lets this lookup use the file.
        match now().checked_add(ttl) {
            Some(at) => state.expires.insert(kind, at),
            None => state.expires.remove(&kind),
        };
        drop(state);
        Ok(())
    }

    async fn ensure_registry(&self, kind: RegistryKind) -> Result<(), Error> {
        if self.pinned {
            return Ok(());
        }
        let (loaded, fresh) = {
            let state = self.lock();
            let loaded = state.bootstrap.get(kind).is_some();
            let fresh = state.expires.get(&kind).is_none_or(|at| *at > now());
            drop(state);
            (loaded, fresh)
        };
        if loaded && fresh {
            return Ok(());
        }
        match self.refresh_registry(kind).await {
            // Serve stale rather than fail when a refresh does not work.
            Err(_) if loaded => Ok(()),
            other => other,
        }
    }

    /// The cache lifetime for `response`: its `max-age`, else `default`,
    /// capped by `max_cache_ttl`.
    fn ttl(&self, response: &Response, default: Duration) -> Duration {
        response
            .max_age()
            .unwrap_or(default)
            .min(self.options.max_cache_ttl)
    }

    /// One rate-limited `GET`.
    async fn get(&self, url: &url::Url) -> Result<Response, Error> {
        let host = url.host_str().unwrap_or_default();
        let wait = self.lock().limiter.reserve(host, now());
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        self.fetcher
            .get(url.as_str())
            .await
            .map_err(|e| Error::Transport(Box::new(e)))
    }
}

fn checked_url(url: &str) -> Result<url::Url, Error> {
    let parsed =
        url::Url::parse(url).map_err(|e| Error::Redirect(format!("bad URL {url:?}: {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(Error::Redirect(format!("refusing non-HTTP(S) URL {url:?}")));
    }
    Ok(parsed)
}

#[cfg(feature = "reqwest")]
pub use self::reqwest_fetcher::ReqwestFetcher;

#[cfg(feature = "reqwest")]
mod reqwest_fetcher {
    use std::future::Future;
    use std::time::Duration;

    use super::{ACCEPT, Fetcher};
    use crate::response::{MAX_BODY_LEN, Response};

    /// A [`Fetcher`] backed by `reqwest` (feature `reqwest`). It needs a
    /// Tokio runtime.
    #[derive(Debug, Clone)]
    pub struct ReqwestFetcher {
        client: reqwest::Client,
        max_body: usize,
    }

    impl ReqwestFetcher {
        /// A client that does not follow redirects, times out after 30
        /// seconds and reads at most [`MAX_BODY_LEN`] + 1 body bytes (so an
        /// oversized body still fails to parse).
        pub fn new() -> Result<Self, reqwest::Error> {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .user_agent(concat!("rune-rdap/", env!("CARGO_PKG_VERSION")))
                .build()?;
            Ok(Self::from_client(client))
        }

        /// Wraps a client you configured. Disable redirects on it
        /// (`redirect::Policy::none()`).
        #[must_use]
        pub const fn from_client(client: reqwest::Client) -> Self {
            Self {
                client,
                max_body: MAX_BODY_LEN,
            }
        }

        /// Reads at most `bytes` + 1 body bytes.
        #[must_use]
        pub const fn with_max_body(mut self, bytes: usize) -> Self {
            self.max_body = bytes;
            self
        }
    }

    impl Fetcher for ReqwestFetcher {
        type Error = reqwest::Error;

        fn get(&self, url: &str) -> impl Future<Output = Result<Response, Self::Error>> + Send {
            let request = self.client.get(url).header(reqwest::header::ACCEPT, ACCEPT);
            let limit = self.max_body.saturating_add(1);
            async move {
                let mut response = request.send().await?;
                let status = response.status().as_u16();
                let headers = response
                    .headers()
                    .iter()
                    .map(|(n, v)| {
                        (
                            n.as_str().to_owned(),
                            String::from_utf8_lossy(v.as_bytes()).into_owned(),
                        )
                    })
                    .collect();
                let mut body = Vec::new();
                while body.len() < limit {
                    let Some(chunk) = response.chunk().await? else {
                        break;
                    };
                    let take = chunk.len().min(limit - body.len());
                    body.extend_from_slice(&chunk[..take]);
                }
                let mut out = Response::new(status, body);
                out.headers = headers;
                Ok(out)
            }
        }
    }
}
