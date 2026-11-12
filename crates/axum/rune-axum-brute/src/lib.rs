//! Account lockout middleware for Axum — blocks repeated authentication failures per client key.
//!
//! Tracks failed authentication attempts (HTTP 401/403 responses) per key and locks
//! out the key after a configurable threshold. Locked keys receive `429 Too Many Requests`
//! with a `Retry-After` header before any handler runs. A sliding window resets the
//! failure count after inactivity, so transient failures do not cause permanent lockout.
//!
//! Two integration paths are available:
//!
//! - [`BruteLayer`] — a Tower middleware that inspects response status codes automatically.
//!   Apply it as a `.layer()` on your router. Use [`BruteLayer::by_ip`] for lockout per
//!   socket peer IP, [`BruteLayer::by_client_ip`] behind trusted reverse proxies, or supply
//!   a custom key function.
//! - [`BruteGuard`] — an Axum extractor that gives handlers direct access to the store.
//!   Use this when your handler decides whether an attempt succeeded or failed (e.g., after
//!   checking a password). Requires [`Arc<dyn BruteForceStore>`] in Axum state via [`FromRef`].
//!
//! # Client IP
//!
//! IP-keyed lockout uses the **socket peer address** (`ConnectInfo<SocketAddr>`), not
//! `X-Forwarded-For`: a forged header could otherwise dodge lockout with a fresh key per
//! attempt, or lock out a victim by naming their IP. Forwarding headers are honoured only
//! from proxies listed in a [`ClientIpConfig`]. Serve the app with
//! `into_make_service_with_connect_info::<SocketAddr>()`; without it IP-keyed requests are
//! rejected with `500` rather than sharing one placeholder key.
//!
//! # Features
//!
//! - [`BruteForceStore`] trait — plug in any backend (Redis, database, in-process).
//! - [`InMemoryStore`] — in-memory implementation with sliding window, automatic lockout
//!   expiry and a bounded key map. All clones share the same counters via [`Arc`].
//! - [`BruteLayer`] — Tower layer that locks out keys triggering 401/403 and clears them on 2xx.
//! - [`BruteGuard`] — Axum extractor for handler-driven failure recording.
//!
//! # Quick Start
//!
//! ## Automatic lockout with `BruteLayer`
//!
//! ```rust,no_run
//! use std::{net::SocketAddr, sync::Arc};
//! use axum::{routing::post, Router};
//! use rune_axum_brute::{BruteLayer, InMemoryStore};
//!
//! # async fn run() -> std::io::Result<()> {
//! let store = Arc::new(InMemoryStore::new(5, 300));
//!
//! let app: Router = Router::new()
//!     .route("/login", post(|| async { "ok" }))
//!     .layer(BruteLayer::by_ip(store));
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//! axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
//! # }
//! ```
//!
//! ## Manual recording with `BruteGuard`
//!
//! ```rust
//! use std::sync::Arc;
//! use axum::{extract::FromRef, http::StatusCode, routing::post, Router};
//! use rune_axum_brute::{BruteForceStore, BruteGuard, InMemoryStore};
//!
//! #[derive(Clone)]
//! struct AppState {
//!     store: Arc<dyn BruteForceStore>,
//! }
//!
//! impl FromRef<AppState> for Arc<dyn BruteForceStore> {
//!     fn from_ref(state: &AppState) -> Self {
//!         Arc::clone(&state.store)
//!     }
//! }
//!
//! async fn login(guard: BruteGuard) -> StatusCode {
//!     if guard.is_locked("alice") {
//!         return StatusCode::TOO_MANY_REQUESTS;
//!     }
//!     let password_correct = false;
//!     if password_correct {
//!         guard.record_success("alice");
//!         StatusCode::OK
//!     } else {
//!         guard.record_failure("alice");
//!         StatusCode::UNAUTHORIZED
//!     }
//! }
//!
//! let store: Arc<dyn BruteForceStore> = Arc::new(InMemoryStore::new(5, 300));
//! let state = AppState { store };
//! let app: Router = Router::new()
//!     .route("/login", post(login))
//!     .with_state(state);
//! ```

use axum::{
    extract::{FromRef, FromRequestParts},
    response::Response,
};
use http::{Request, StatusCode, request::Parts};
use pin_project_lite::pin_project;
use rune_axum_ipfilter::client_ip::ipv6_prefix;
pub use rune_axum_ipfilter::{CidrParseError, ClientIpConfig, ProxyHeader};
use std::{
    collections::HashMap,
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{self, Poll},
    time::{Duration, Instant},
};
use tower_layer::Layer;
use tower_service::Service;

/// The pluggable interface for tracking authentication failures and lockouts.
///
/// Implement this trait to use any storage backend — in-process memory, Redis,
/// a SQL database — as the lockout store for [`BruteLayer`] and [`BruteGuard`].
/// All methods receive a `key` string that identifies the subject (IP address,
/// username, API key, etc.).
///
/// # Examples
///
/// ```rust
/// use std::sync::Arc;
/// use rune_axum_brute::{BruteForceStore, InMemoryStore};
///
/// let store: Arc<dyn BruteForceStore> = Arc::new(InMemoryStore::new(3, 60));
/// store.record_failure("alice");
/// store.record_failure("alice");
/// store.record_failure("alice");
/// assert!(store.is_locked("alice"));
/// ```
pub trait BruteForceStore: Send + Sync + 'static {
    /// Records one authentication failure for `key` and returns the updated failure count.
    ///
    /// Once the count reaches the configured threshold the key is locked out
    /// until the lockout window expires.
    fn record_failure(&self, key: &str) -> u32;

    /// Records a successful authentication for `key` and clears the failure count.
    fn record_success(&self, key: &str);

    /// Returns `true` when `key` is currently locked out.
    ///
    /// Expired lockouts are cleared lazily on the first call after expiry, so
    /// this method always reflects the current state without a background task.
    fn is_locked(&self, key: &str) -> bool;

    /// Unconditionally clears the failure count and any active lockout for `key`.
    fn reset(&self, key: &str);

    /// Returns how long `key` stays locked, if it is locked and the store knows.
    ///
    /// [`BruteLayer`] sends this as `Retry-After`. The default returns `None`, in which case
    /// no `Retry-After` header is sent.
    fn lockout_remaining(&self, key: &str) -> Option<Duration> {
        let _ = key;
        None
    }
}

struct Entry {
    failure_count: u32,
    locked_until: Option<Instant>,
    window_start: Instant,
}

impl Entry {
    fn locked_at(&self, now: Instant) -> bool {
        self.locked_until.is_some_and(|until| now < until)
    }
}

/// The default upper bound on tracked keys for [`InMemoryStore`].
pub const DEFAULT_MAX_KEYS: usize = 100_000;

/// In-memory brute-force store with sliding failure window and timed lockout.
///
/// All clones of an [`InMemoryStore`] share the same counter map via [`Arc`],
/// so counters are consistent across Tower service clones and across threads.
/// Use [`InMemoryStore::new`] for a simple threshold+lockout setup, or
/// [`InMemoryStore::with_window`] to also constrain failures to a time window.
///
/// The map is bounded by [`InMemoryStore::with_max_keys`] (default [`DEFAULT_MAX_KEYS`]).
/// When it is full, entries that are neither locked nor inside their failure window are
/// dropped first; if that is not enough, a batch (1/16 of capacity) is evicted, oldest
/// unlocked entries first and active lockouts only as a last resort (soonest-expiring
/// first). A flood of distinct keys therefore cannot exhaust memory.
///
/// # Examples
///
/// ```rust
/// use rune_axum_brute::InMemoryStore;
///
/// // Lock after 5 failures; lockout lasts 5 minutes; track at most 10 000 keys.
/// let store = InMemoryStore::new(5, 300).with_max_keys(10_000);
/// ```
#[derive(Clone)]
pub struct InMemoryStore {
    state: Arc<Mutex<HashMap<String, Entry>>>,
    max_attempts: u32,
    lockout: Duration,
    window: Duration,
    max_keys: usize,
}

impl fmt::Debug for InMemoryStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryStore")
            .field("max_attempts", &self.max_attempts)
            .field("lockout", &self.lockout)
            .field("window", &self.window)
            .field("max_keys", &self.max_keys)
            .finish_non_exhaustive()
    }
}

impl InMemoryStore {
    /// Creates a store that locks `key` after `max_attempts` failures for `lockout_secs` seconds.
    ///
    /// Failures are counted across all time (no sliding window). Use
    /// [`InMemoryStore::with_window`] if you want the failure counter to reset
    /// automatically after a period of inactivity.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_brute::InMemoryStore;
    ///
    /// let store = InMemoryStore::new(5, 300);
    /// ```
    #[must_use]
    pub fn new(max_attempts: u32, lockout_secs: u64) -> Self {
        Self::with_window(max_attempts, u64::MAX, lockout_secs)
    }

    /// Creates a store with a sliding failure window.
    ///
    /// Failure counts are reset when `window_secs` pass without a new failure
    /// for that key. If `max_attempts` failures occur within the window the key
    /// is locked for `lockout_secs`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_brute::InMemoryStore;
    ///
    /// // 5 failures within 60 s triggers a 10-minute lockout.
    /// let store = InMemoryStore::with_window(5, 60, 600);
    /// ```
    #[must_use]
    pub fn with_window(max_attempts: u32, window_secs: u64, lockout_secs: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            max_attempts,
            lockout: Duration::from_secs(lockout_secs),
            window: Duration::from_secs(window_secs),
            max_keys: DEFAULT_MAX_KEYS,
        }
    }

    /// Bounds the number of tracked keys (at least 1). Defaults to [`DEFAULT_MAX_KEYS`].
    #[must_use]
    pub fn with_max_keys(mut self, max_keys: usize) -> Self {
        self.max_keys = max_keys.max(1);
        self
    }

    /// Returns the number of keys currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Returns `true` when no key is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        // A panic while holding the lock leaves the counters usable; keep going.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn window_expired(&self, entry: &Entry, now: Instant) -> bool {
        now.saturating_duration_since(entry.window_start) >= self.window
    }

    fn make_room(&self, map: &mut HashMap<String, Entry>, now: Instant) {
        map.retain(|_, e| e.locked_at(now) || !self.window_expired(e, now));
        if map.len() < self.max_keys {
            return;
        }
        let batch = (self.max_keys / 16).max(1).min(map.len());
        // Unlocked entries (oldest window first) before locked ones (soonest expiry first).
        let mut victims: Vec<((bool, Instant), String)> = map
            .iter()
            .map(|(key, e)| {
                let rank = match e.locked_until {
                    Some(until) if now < until => (true, until),
                    _ => (false, e.window_start),
                };
                (rank, key.clone())
            })
            .collect();
        victims.select_nth_unstable_by_key(batch - 1, |(rank, _)| *rank);
        for (_, key) in victims.into_iter().take(batch) {
            map.remove(&key);
        }
    }
}

impl BruteForceStore for InMemoryStore {
    fn record_failure(&self, key: &str) -> u32 {
        let now = Instant::now();
        let mut map = self.lock();
        if !map.contains_key(key) && map.len() >= self.max_keys {
            self.make_room(&mut map, now);
        }
        let entry = map.entry(key.to_owned()).or_insert_with(|| Entry {
            failure_count: 0,
            locked_until: None,
            window_start: now,
        });

        if now.saturating_duration_since(entry.window_start) >= self.window {
            entry.failure_count = 0;
            entry.window_start = now;
        }

        entry.failure_count = entry.failure_count.saturating_add(1);

        if entry.failure_count >= self.max_attempts {
            // An absurdly long lockout that overflows `Instant` is capped at one year.
            let until = now
                .checked_add(self.lockout)
                .or_else(|| now.checked_add(Duration::from_secs(365 * 24 * 3600)))
                .unwrap_or(now);
            entry.locked_until = Some(until);
        }

        let count = entry.failure_count;
        drop(map);
        count
    }

    fn record_success(&self, key: &str) {
        self.lock().remove(key);
    }

    fn is_locked(&self, key: &str) -> bool {
        self.lockout_remaining(key).is_some()
    }

    fn reset(&self, key: &str) {
        self.lock().remove(key);
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "the guard must outlive the entry borrowed from it"
    )]
    fn lockout_remaining(&self, key: &str) -> Option<Duration> {
        let now = Instant::now();
        let mut map = self.lock();
        let entry = map.get_mut(key)?;
        match entry.locked_until {
            Some(until) if now < until => Some(until - now),
            Some(_) => {
                entry.locked_until = None;
                None
            }
            None => None,
        }
    }
}

/// Axum extractor that gives handlers direct access to the brute-force store.
///
/// Extract [`BruteGuard`] in a handler to manually record successes and
/// failures based on application-level logic (e.g., after verifying a
/// password). The guard delegates to the [`Arc<dyn BruteForceStore>`] pulled
/// from Axum state via [`FromRef`].
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use axum::{extract::FromRef, http::StatusCode};
/// use rune_axum_brute::{BruteForceStore, BruteGuard, InMemoryStore};
///
/// #[derive(Clone)]
/// struct AppState { store: Arc<dyn BruteForceStore> }
///
/// impl FromRef<AppState> for Arc<dyn BruteForceStore> {
///     fn from_ref(state: &AppState) -> Self { Arc::clone(&state.store) }
/// }
///
/// async fn login(guard: BruteGuard) -> StatusCode {
///     if guard.is_locked("alice") {
///         return StatusCode::TOO_MANY_REQUESTS;
///     }
///     guard.record_failure("alice");
///     StatusCode::UNAUTHORIZED
/// }
/// ```
pub struct BruteGuard {
    store: Arc<dyn BruteForceStore>,
}

impl BruteGuard {
    /// Returns `true` when `key` is currently locked out.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::sync::Arc;
    /// use rune_axum_brute::{BruteGuard, InMemoryStore};
    ///
    /// # fn example(guard: BruteGuard) {
    /// if guard.is_locked("alice") {
    ///     // reject the request early
    /// }
    /// # }
    /// ```
    #[must_use]
    pub fn is_locked(&self, key: &str) -> bool {
        self.store.is_locked(key)
    }

    /// Records one authentication failure for `key` and returns the updated count.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn example(guard: rune_axum_brute::BruteGuard) {
    /// let count = guard.record_failure("alice");
    /// println!("alice has {count} failures");
    /// # }
    /// ```
    #[must_use]
    pub fn record_failure(&self, key: &str) -> u32 {
        self.store.record_failure(key)
    }

    /// Records a successful authentication for `key`, clearing any failure count.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn example(guard: rune_axum_brute::BruteGuard) {
    /// guard.record_success("alice");
    /// # }
    /// ```
    pub fn record_success(&self, key: &str) {
        self.store.record_success(key);
    }

    /// Unconditionally clears the failure count and any active lockout for `key`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn example(guard: rune_axum_brute::BruteGuard) {
    /// guard.reset("alice");
    /// # }
    /// ```
    pub fn reset(&self, key: &str) {
        self.store.reset(key);
    }
}

impl<S> FromRequestParts<S> for BruteGuard
where
    S: Send + Sync,
    Arc<dyn BruteForceStore>: FromRef<S>,
{
    type Rejection = std::convert::Infallible;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait is async; this implementation happens not to await"
    )]
    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self {
            store: Arc::from_ref(state),
        })
    }
}

type KeyFn = Arc<dyn Fn(&Request<axum::body::Body>) -> Option<String> + Send + Sync>;

/// Tower [`Layer`] that automatically locks out keys triggering repeated 401/403 responses.
///
/// Extracts a key from each incoming request, checks whether the key is currently locked
/// (returning `429 Too Many Requests` with `Retry-After` if so), and after the inner service
/// responds, records failures on 401/403 or successes on 2xx. All service clones share
/// counters via the [`Arc`] inside the store.
///
/// [`BruteLayer::by_ip`] keys on the **socket peer IP** (`ConnectInfo<SocketAddr>`), never on
/// a client-supplied header, so attackers cannot rotate `X-Forwarded-For` to dodge lockout
/// or forge it to lock out a victim. Behind a reverse proxy use
/// [`BruteLayer::by_client_ip`] with the proxy listed as trusted.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use axum::{routing::post, Router};
/// use rune_axum_brute::{BruteLayer, InMemoryStore};
///
/// let store = Arc::new(InMemoryStore::new(5, 300));
///
/// let app: Router = Router::new()
///     .route("/login", post(|| async { "ok" }))
///     .layer(BruteLayer::by_ip(store));
/// ```
#[derive(Clone)]
pub struct BruteLayer {
    store: Arc<dyn BruteForceStore>,
    key_fn: KeyFn,
    missing_key_status: StatusCode,
}

impl fmt::Debug for BruteLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BruteLayer")
            .field("missing_key_status", &self.missing_key_status)
            .finish_non_exhaustive()
    }
}

impl BruteLayer {
    /// Creates a [`BruteLayer`] keyed by the socket peer IP address.
    ///
    /// Requires the server to be started with
    /// `into_make_service_with_connect_info::<SocketAddr>()`. A request without
    /// `ConnectInfo<SocketAddr>` is rejected with `500 Internal Server Error` (see
    /// [`missing_key_status`](Self::missing_key_status)); it is never keyed by a header or
    /// by a shared placeholder.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use axum::{routing::post, Router};
    /// use rune_axum_brute::{BruteLayer, InMemoryStore};
    ///
    /// let store = Arc::new(InMemoryStore::new(5, 300));
    /// let app: Router = Router::new()
    ///     .route("/login", post(|| async { "ok" }))
    ///     .layer(BruteLayer::by_ip(store));
    /// ```
    pub fn by_ip(store: Arc<dyn BruteForceStore>) -> Self {
        Self::by_client_ip(store, ClientIpConfig::new(), 128)
    }

    /// Creates a [`BruteLayer`] keyed by the client IP resolved with `client_ip`, with IPv6
    /// addresses truncated to `ipv6_prefix` bits (`128` keeps full addresses, `64` locks out
    /// a whole `/64`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::sync::Arc;
    /// use rune_axum_brute::{BruteLayer, ClientIpConfig, InMemoryStore};
    ///
    /// // Behind a load balancer in 10.0.0.0/8 that appends to X-Forwarded-For.
    /// let layer = BruteLayer::by_client_ip(
    ///     Arc::new(InMemoryStore::new(5, 300)),
    ///     ClientIpConfig::new().trust_proxy("10.0.0.0/8")?,
    ///     64,
    /// );
    /// # Ok::<(), rune_axum_brute::CidrParseError>(())
    /// ```
    pub fn by_client_ip(
        store: Arc<dyn BruteForceStore>,
        client_ip: ClientIpConfig,
        ipv6_prefix_len: u8,
    ) -> Self {
        let key_fn: KeyFn = Arc::new(move |req| {
            client_ip
                .resolve(req)
                .map(|ip| ipv6_prefix(ip, ipv6_prefix_len).to_string())
        });
        Self {
            store,
            key_fn,
            missing_key_status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Creates a [`BruteLayer`] with a custom key extraction function.
    ///
    /// The function receives the full request and must return the string key
    /// that identifies the subject for lockout purposes.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use axum::{routing::post, Router};
    /// use rune_axum_brute::{BruteLayer, InMemoryStore};
    ///
    /// let store = Arc::new(InMemoryStore::new(3, 120));
    /// let layer = BruteLayer::new(store, |req| {
    ///     req.headers()
    ///         .get("x-api-key")
    ///         .and_then(|v| v.to_str().ok())
    ///         .unwrap_or("unknown")
    ///         .to_owned()
    /// });
    ///
    /// let app: Router = Router::new()
    ///     .route("/api", post(|| async { "ok" }))
    ///     .layer(layer);
    /// ```
    pub fn new<F>(store: Arc<dyn BruteForceStore>, key_fn: F) -> Self
    where
        F: Fn(&Request<axum::body::Body>) -> String + Send + Sync + 'static,
    {
        Self {
            store,
            key_fn: Arc::new(move |req| Some(key_fn(req))),
            missing_key_status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Sets the status returned when no key can be derived (for [`by_ip`](Self::by_ip):
    /// `ConnectInfo<SocketAddr>` is missing). Defaults to `500 Internal Server Error`.
    #[must_use]
    pub const fn missing_key_status(mut self, status: StatusCode) -> Self {
        self.missing_key_status = status;
        self
    }
}

impl<S> Layer<S> for BruteLayer {
    type Service = BruteService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BruteService {
            inner,
            store: Arc::clone(&self.store),
            key_fn: Arc::clone(&self.key_fn),
            missing_key_status: self.missing_key_status,
        }
    }
}

/// Tower [`Service`] produced by [`BruteLayer`].
///
/// Checks the lockout state before forwarding requests and records outcomes
/// from response status codes after the inner service responds.
#[derive(Clone)]
pub struct BruteService<S> {
    inner: S,
    store: Arc<dyn BruteForceStore>,
    key_fn: KeyFn,
    missing_key_status: StatusCode,
}

impl<S> Service<Request<axum::body::Body>> for BruteService<S>
where
    S: Service<Request<axum::body::Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<axum::body::Body>) -> Self::Future {
        let key = (self.key_fn)(&req);
        let store = Arc::clone(&self.store);
        let missing_key_status = self.missing_key_status;
        // Take the service that was driven to readiness; leave a fresh clone behind.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let Some(key) = key else {
                return Ok(status_response(missing_key_status));
            };
            if store.is_locked(&key) {
                return Ok(locked_response(store.lockout_remaining(&key)));
            }

            let response = inner.call(req).await?;
            let status = response.status();

            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                store.record_failure(&key);
            } else if status.is_success() {
                store.record_success(&key);
            }

            Ok(response)
        })
    }
}

pin_project! {
    /// Future returned by [`BruteService`].
    pub struct BruteFuture<F> {
        #[pin]
        inner: F,
    }
}

impl<F, E> Future for BruteFuture<F>
where
    F: Future<Output = Result<Response, E>>,
{
    type Output = Result<Response, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.project().inner.poll(cx)
    }
}

fn status_response(status: StatusCode) -> Response {
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = status;
    response
}

fn locked_response(remaining: Option<Duration>) -> Response {
    let mut response = status_response(StatusCode::TOO_MANY_REQUESTS);
    if let Some(remaining) = remaining {
        let secs = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
        response
            .headers_mut()
            .insert(http::header::RETRY_AFTER, secs.max(1).into());
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, extract::ConnectInfo, routing::post};
    use http::{Request, StatusCode};
    use std::net::{IpAddr, SocketAddr};
    use tower::ServiceExt;

    fn build_with(layer: BruteLayer, status: StatusCode) -> Router {
        Router::new()
            .route(
                "/login",
                post(move || {
                    let status = status;
                    async move { status }
                }),
            )
            .layer(layer)
    }

    fn build_app(store: Arc<dyn BruteForceStore>, status: StatusCode) -> Router {
        build_with(BruteLayer::by_ip(store), status)
    }

    fn login_from(peer: Option<&str>, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder().method("POST").uri("/login");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut req = builder.body(Body::empty()).unwrap();
        if let Some(peer) = peer {
            let ip: IpAddr = peer.parse().unwrap();
            req.extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(ip, 41_000)));
        }
        req
    }

    async fn send(app: &Router, req: Request<Body>) -> http::Response<Body> {
        app.clone().oneshot(req).await.unwrap()
    }

    async fn post_login(app: Router) -> http::Response<Body> {
        send(&app, login_from(Some("10.0.0.1"), &[])).await
    }

    #[tokio::test]
    async fn failure_increments_count() {
        let store = Arc::new(InMemoryStore::new(5, 300));
        let count = store.record_failure("alice");
        assert_eq!(count, 1);
        let count = store.record_failure("alice");
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn max_attempts_triggers_lockout() {
        let store = Arc::new(InMemoryStore::new(3, 300));
        store.record_failure("alice");
        store.record_failure("alice");
        store.record_failure("alice");
        assert!(store.is_locked("alice"));
    }

    #[tokio::test]
    async fn success_clears_count() {
        let store = Arc::new(InMemoryStore::new(3, 300));
        store.record_failure("alice");
        store.record_failure("alice");
        store.record_success("alice");
        assert!(!store.is_locked("alice"));
    }

    #[tokio::test]
    async fn reset_clears_lockout() {
        let store = Arc::new(InMemoryStore::new(2, 300));
        store.record_failure("alice");
        store.record_failure("alice");
        assert!(store.is_locked("alice"));
        store.reset("alice");
        assert!(!store.is_locked("alice"));
    }

    #[tokio::test]
    async fn lockout_expires_after_duration() {
        let store = Arc::new(InMemoryStore::new(1, 0));
        store.record_failure("alice");
        assert!(!store.is_locked("alice"));
    }

    #[tokio::test]
    async fn layer_records_failure_on_401() {
        let store: Arc<dyn BruteForceStore> = Arc::new(InMemoryStore::new(5, 300));
        let app = build_app(Arc::clone(&store), StatusCode::UNAUTHORIZED);
        let resp = post_login(app).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(store.record_failure("10.0.0.1"), 2);
    }

    #[tokio::test]
    async fn layer_returns_429_when_locked() {
        let store: Arc<dyn BruteForceStore> = Arc::new(InMemoryStore::new(2, 3600));
        store.record_failure("10.0.0.1");
        store.record_failure("10.0.0.1");
        assert!(store.is_locked("10.0.0.1"));

        let app = build_app(Arc::clone(&store), StatusCode::UNAUTHORIZED);
        let resp = post_login(app).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn layer_clears_on_success() {
        let store: Arc<dyn BruteForceStore> = Arc::new(InMemoryStore::new(5, 300));
        store.record_failure("10.0.0.1");

        let app = build_app(Arc::clone(&store), StatusCode::OK);
        let resp = post_login(app).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!store.is_locked("10.0.0.1"));
    }

    #[tokio::test]
    async fn layer_after_n_failures_returns_429() {
        let store: Arc<dyn BruteForceStore> = Arc::new(InMemoryStore::new(3, 3600));
        store.record_failure("10.0.0.1");
        store.record_failure("10.0.0.1");
        store.record_failure("10.0.0.1");

        let app = build_app(Arc::clone(&store), StatusCode::UNAUTHORIZED);
        let resp = post_login(app).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn locked_response_has_accurate_retry_after() {
        let store: Arc<dyn BruteForceStore> = Arc::new(InMemoryStore::new(1, 120));
        store.record_failure("10.0.0.1");
        let resp = post_login(build_app(Arc::clone(&store), StatusCode::OK)).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry: u64 = resp.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((119..=120).contains(&retry), "{retry}");
    }

    #[tokio::test]
    async fn spoofed_xff_is_ignored_by_default() {
        let store: Arc<dyn BruteForceStore> = Arc::new(InMemoryStore::new(2, 3600));
        let app = build_app(Arc::clone(&store), StatusCode::UNAUTHORIZED);
        // Attacker rotates X-Forwarded-For; failures still land on its own peer IP.
        for fake in ["1.1.1.1", "2.2.2.2"] {
            let req = login_from(Some("203.0.113.7"), &[("x-forwarded-for", fake)]);
            assert_eq!(send(&app, req).await.status(), StatusCode::UNAUTHORIZED);
        }
        let req = login_from(Some("203.0.113.7"), &[("x-forwarded-for", "3.3.3.3")]);
        assert_eq!(
            send(&app, req).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // The forged addresses were never locked: no victim lockout.
        assert!(!store.is_locked("1.1.1.1"));
        assert!(!store.is_locked("2.2.2.2"));
        assert!(store.is_locked("203.0.113.7"));
    }

    #[tokio::test]
    async fn missing_connect_info_fails_closed() {
        let store: Arc<dyn BruteForceStore> = Arc::new(InMemoryStore::new(2, 3600));
        let app = build_app(Arc::clone(&store), StatusCode::OK);
        let req = login_from(None, &[("x-forwarded-for", "1.2.3.4")]);
        assert_eq!(
            send(&app, req).await.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let app = build_with(
            BruteLayer::by_ip(store).missing_key_status(StatusCode::SERVICE_UNAVAILABLE),
            StatusCode::OK,
        );
        assert_eq!(
            send(&app, login_from(None, &[])).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn trusted_proxy_resolves_real_client() {
        let store: Arc<dyn BruteForceStore> = Arc::new(InMemoryStore::new(1, 3600));
        let layer = BruteLayer::by_client_ip(
            Arc::clone(&store),
            ClientIpConfig::new().trust_proxy("10.0.0.0/8").unwrap(),
            64,
        );
        let app = build_with(layer, StatusCode::UNAUTHORIZED);
        let req = login_from(
            Some("10.0.0.1"),
            &[("x-forwarded-for", "6.6.6.6, 2001:db8:1:2::77")],
        );
        assert_eq!(send(&app, req).await.status(), StatusCode::UNAUTHORIZED);
        assert!(store.is_locked("2001:db8:1:2::"));
        assert!(!store.is_locked("6.6.6.6"));
        // Another address in the same /64 is locked too.
        let req = login_from(Some("10.0.0.2"), &[("x-forwarded-for", "2001:db8:1:2::99")]);
        assert_eq!(
            send(&app, req).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn map_is_bounded() {
        let store = InMemoryStore::new(5, 3600).with_max_keys(32);
        for i in 0..5_000 {
            store.record_failure(&format!("k{i}"));
            assert!(store.len() <= 32);
        }
    }

    #[test]
    fn eviction_prefers_unlocked_entries() {
        let store = InMemoryStore::new(2, 3600).with_max_keys(16);
        for i in 0..4 {
            store.record_failure(&format!("locked{i}"));
            store.record_failure(&format!("locked{i}"));
        }
        for i in 0..1_000 {
            store.record_failure(&format!("noise{i}"));
        }
        for i in 0..4 {
            assert!(store.is_locked(&format!("locked{i}")));
        }
    }

    #[test]
    fn stale_entries_are_dropped_first() {
        let store = InMemoryStore::with_window(5, 0, 0).with_max_keys(4);
        for i in 0..4 {
            store.record_failure(&format!("old{i}"));
        }
        store.record_failure("new");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn huge_lockout_does_not_panic() {
        let store = InMemoryStore::new(1, u64::MAX);
        store.record_failure("k");
        assert!(store.is_locked("k"));
    }
}
