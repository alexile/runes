//! A [`RateLimitStore`] backed by Redis, for a limit shared by several app instances.
//!
//! Enabled with the `redis` feature. Each check is one atomic Lua script on the server:
//!
//! - **GCRA** stores the theoretical arrival time per key. The script reads the clock with
//!   `TIME` on the Redis server, so instances with skewed clocks still agree.
//! - **Fixed window** is a counter created with `INCR` and given a `PEXPIRE` in the same
//!   script, so a crash between the two can never leave a counter that never expires.
//!
//! Every key gets a TTL equal to the time until its quota is fully restored, so Redis only
//! holds state for clients that are currently limited or recently active.
//!
//! Scripts run with `EVALSHA`; when the server answers `NOSCRIPT` (after a restart, a
//! failover or `SCRIPT FLUSH`) the call is retried once with `EVAL`, which also caches the
//! script again.
//!
//! # Errors and timeouts
//!
//! Every call is bounded by [`RedisStore::timeout`] (default 500 ms). A timeout, a lost
//! connection or a script error becomes a [`StoreError`], and the layer then applies
//! [`RateLimitConfig::on_store_error`](crate::RateLimitConfig::on_store_error): by default
//! the request is rejected with `503` (fail closed); use
//! [`OnStoreError::Allow`](crate::OnStoreError::Allow) to fail open.
//!
//! # Key names
//!
//! Keys look like `<prefix>:<algorithm>:{<client>}`. The client part is the raw key
//! (`ip:203.0.113.7`, `hdr:<api key>`) by default. With [`RedisStore::hash_keys`] it is
//! replaced by an HMAC-SHA256 of the raw key under your secret, so neither client IPs nor
//! API keys appear in Redis. The braces make the client part a Redis Cluster hash tag.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//! use rune_axum_ratelimit::redis::RedisStore;
//! use rune_axum_ratelimit::{Algorithm, RateLimitConfig, RateLimitLayer};
//!
//! # async fn run() -> Result<(), redis::RedisError> {
//! let store = RedisStore::connect("redis://127.0.0.1:6379")
//!     .await?
//!     .prefix("myapp:rl")
//!     .hash_keys(b"a long random secret")
//!     .timeout(Duration::from_millis(200));
//!
//! let layer = RateLimitLayer::with_store(
//!     RateLimitConfig::new().requests(100).algorithm(Algorithm::Gcra),
//!     Arc::new(store),
//! );
//! # Ok(())
//! # }
//! ```

use crate::store::{Algorithm, BoxFuture, Decision, Quota, RateLimitStore, StoreError};
use hmac::{Hmac, Mac};
use redis::aio::{ConnectionLike, ConnectionManager, ConnectionManagerConfig};
use redis::{Cmd, ErrorKind, RedisError, Script, ServerErrorKind};
use sha2::Sha256;
use std::fmt::{self, Write as _};
use std::sync::LazyLock;
use std::time::Duration;

/// The default key prefix.
pub const DEFAULT_PREFIX: &str = "ratelimit";

/// The default bound on each Redis call.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(500);

/// Window and interval lengths are passed to Lua in microseconds and kept below this, so
/// they stay exact in Lua's double-precision numbers even when added to the current time.
const MAX_MICROS: u64 = 1 << 50;

/// GCRA. `KEYS[1]`: the key. `ARGV`: emission interval and burst capacity, in µs.
/// Returns `{allowed, remaining, reset_us, retry_after_us}`.
const GCRA_LUA: &str = r"
if redis.replicate_commands then pcall(redis.replicate_commands) end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000000 + tonumber(t[2])
local interval = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local tat = tonumber(redis.call('GET', KEYS[1]) or now)
if tat < now then tat = now end
local new_tat = tat + interval
local ahead = new_tat - now
if ahead > capacity then
  return {0, 0, tat - now, ahead - capacity}
end
local remaining = burst
if interval > 0 then
  remaining = math.min(math.floor((capacity - ahead) / interval), burst)
end
if ahead > 0 then
  redis.call('SET', KEYS[1], string.format('%.0f', new_tat), 'PX', math.ceil(ahead / 1000))
else
  redis.call('DEL', KEYS[1])
end
return {1, remaining, ahead, 0}
";

/// Fixed window. `KEYS[1]`: the key. `ARGV`: limit, window in ms.
/// Returns `{allowed, remaining, reset_us, retry_after_us}`.
const FIXED_WINDOW_LUA: &str = r"
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local count = tonumber(redis.call('GET', KEYS[1]) or 0)
local ttl = redis.call('PTTL', KEYS[1])
if count >= limit and ttl > 0 then
  return {0, 0, ttl * 1000, ttl * 1000}
end
count = redis.call('INCR', KEYS[1])
if count == 1 or ttl <= 0 then
  if count > 1 then
    redis.call('SET', KEYS[1], 1)
    count = 1
  end
  redis.call('PEXPIRE', KEYS[1], window)
  ttl = window
end
return {1, limit - count, ttl * 1000, 0}
";

static GCRA_SCRIPT: LazyLock<Script> = LazyLock::new(|| Script::new(GCRA_LUA));
static FIXED_WINDOW_SCRIPT: LazyLock<Script> = LazyLock::new(|| Script::new(FIXED_WINDOW_LUA));

/// Returns the Lua script that implements `algorithm`.
fn script_for(algorithm: Algorithm) -> &'static Script {
    match algorithm {
        Algorithm::FixedWindow => &FIXED_WINDOW_SCRIPT,
        Algorithm::Gcra => &GCRA_SCRIPT,
    }
}

/// Whether a failed `EVALSHA` should be retried with `EVAL`.
fn needs_eval(err: &RedisError) -> bool {
    err.kind() == ErrorKind::Server(ServerErrorKind::NoScript)
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros())
        .unwrap_or(u64::MAX)
        .min(MAX_MICROS)
}

/// The script arguments for `quota`, after the key.
fn script_args(quota: &Quota) -> Vec<u64> {
    match quota.algorithm {
        Algorithm::FixedWindow => {
            let ms = u64::try_from(quota.window.as_millis()).unwrap_or(u64::MAX);
            let ms = ms.clamp(1, MAX_MICROS / 1000);
            vec![quota.limit, ms]
        }
        Algorithm::Gcra => {
            let window = micros(quota.window);
            let interval = window / quota.limit.max(1);
            let capacity = interval.saturating_mul(quota.burst).min(MAX_MICROS);
            vec![interval, capacity, quota.burst]
        }
    }
}

/// Builds the `EVALSHA` (or, with `eval`, the `EVAL`) command for one check.
fn script_cmd(key: &str, quota: &Quota, eval: bool) -> Cmd {
    let script = script_for(quota.algorithm);
    let mut cmd = if eval {
        let mut c = redis::cmd("EVAL");
        c.arg(match quota.algorithm {
            Algorithm::FixedWindow => FIXED_WINDOW_LUA,
            Algorithm::Gcra => GCRA_LUA,
        });
        c
    } else {
        let mut c = redis::cmd("EVALSHA");
        c.arg(script.get_hash());
        c
    };
    cmd.arg(1).arg(key);
    for a in script_args(quota) {
        cmd.arg(a);
    }
    cmd
}

/// The decision for a quota that admits nothing; answered without a round trip.
const fn deny_all(quota: &Quota) -> Decision {
    Decision {
        allowed: false,
        limit: quota.limit,
        remaining: 0,
        reset: quota.window,
        retry_after: Some(quota.window),
    }
}

/// Turns the script reply `{allowed, remaining, reset_us, retry_after_us}` into a decision.
fn decode(reply: &[i64], quota: &Quota) -> Result<Decision, StoreError> {
    let &[allowed, remaining, reset, retry] = reply else {
        return Err(StoreError::new(format!(
            "unexpected script reply of {} values",
            reply.len()
        )));
    };
    let us = |v: i64| Duration::from_micros(u64::try_from(v).unwrap_or(0));
    let allowed = allowed == 1;
    Ok(Decision {
        allowed,
        limit: quota.limit,
        remaining: u64::try_from(remaining).unwrap_or(0),
        reset: us(reset),
        retry_after: (!allowed).then(|| us(retry)),
    })
}

/// How client keys are written into Redis key names.
#[derive(Clone)]
enum KeyMode {
    Raw,
    Hmac(Hmac<Sha256>),
}

/// A Redis-backed [`RateLimitStore`] shared by every instance that points at the same server.
///
/// Generic over the async connection so a cluster or a custom connection works too;
/// [`RedisStore::connect`] and [`RedisStore::new`] use a reconnecting [`ConnectionManager`].
/// See the [module docs](self) for the script semantics, key format and error policy.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_axum_ratelimit::redis::RedisStore;
///
/// # async fn run() -> Result<(), redis::RedisError> {
/// let store = RedisStore::connect("redis://127.0.0.1/").await?.hash_keys(b"secret");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct RedisStore<C = ConnectionManager> {
    conn: C,
    prefix: String,
    keys: KeyMode,
    timeout: Duration,
}

impl<C> fmt::Debug for RedisStore<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisStore")
            .field("prefix", &self.prefix)
            .field("hashed_keys", &matches!(self.keys, KeyMode::Hmac(_)))
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl RedisStore<ConnectionManager> {
    /// Connects to `url` (e.g. `redis://127.0.0.1:6379/0`, `rediss://` for TLS when the
    /// `redis` crate's TLS feature is on) with a reconnecting [`ConnectionManager`] whose
    /// connect and response timeouts are [`DEFAULT_TIMEOUT`].
    ///
    /// # Errors
    ///
    /// Returns the error if the URL is invalid or the first connection fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # async fn run() -> Result<(), redis::RedisError> {
    /// let store = rune_axum_ratelimit::redis::RedisStore::connect("redis://127.0.0.1/").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(url: &str) -> Result<Self, RedisError> {
        let client = redis::Client::open(url)?;
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(DEFAULT_TIMEOUT))
            .set_response_timeout(Some(DEFAULT_TIMEOUT));
        let manager = ConnectionManager::new_with_config(client, config).await?;
        Ok(Self::new(manager))
    }
}

impl<C> RedisStore<C>
where
    C: ConnectionLike + Clone + Send + Sync + 'static,
{
    /// Wraps an existing async connection, e.g. a configured [`ConnectionManager`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use redis::aio::ConnectionManager;
    /// use rune_axum_ratelimit::redis::RedisStore;
    ///
    /// # async fn run() -> Result<(), redis::RedisError> {
    /// let client = redis::Client::open("redis://127.0.0.1/")?;
    /// let store = RedisStore::new(ConnectionManager::new(client).await?);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn new(conn: C) -> Self {
        Self {
            conn,
            prefix: DEFAULT_PREFIX.to_owned(),
            keys: KeyMode::Raw,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

impl<C> RedisStore<C> {
    /// Sets the key prefix. Defaults to [`DEFAULT_PREFIX`]. Give each app (and each
    /// differently configured layer sharing a server) its own prefix.
    #[must_use]
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Stores an HMAC-SHA256 of each client key (truncated to 128 bits, hex) instead of the
    /// key itself, so client IPs and API keys never appear in Redis. Use a long random
    /// secret shared by all instances; a plain hash would be easy to reverse for IPv4.
    #[must_use]
    pub fn hash_keys(mut self, secret: &[u8]) -> Self {
        // HMAC accepts keys of any length, so this never fails.
        if let Ok(mac) = Hmac::<Sha256>::new_from_slice(secret) {
            self.keys = KeyMode::Hmac(mac);
        }
        self
    }

    /// Bounds each Redis call, including a `NOSCRIPT` retry. Defaults to
    /// [`DEFAULT_TIMEOUT`].
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns the Redis key used for client key `key` under `algorithm`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # async fn run() -> Result<(), redis::RedisError> {
    /// use rune_axum_ratelimit::{Algorithm, redis::RedisStore};
    ///
    /// let store = RedisStore::connect("redis://127.0.0.1/").await?.prefix("app");
    /// assert_eq!(store.redis_key("ip:192.0.2.1", Algorithm::Gcra), "app:gcra:{ip:192.0.2.1}");
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn redis_key(&self, key: &str, algorithm: Algorithm) -> String {
        let alg = match algorithm {
            Algorithm::FixedWindow => "fw",
            Algorithm::Gcra => "gcra",
        };
        let mut out = format!("{}:{alg}:{{", self.prefix);
        match &self.keys {
            KeyMode::Raw => out.push_str(key),
            KeyMode::Hmac(mac) => {
                let mut mac = mac.clone();
                mac.update(key.as_bytes());
                for b in &mac.finalize().into_bytes()[..16] {
                    let _ = write!(out, "{b:02x}");
                }
            }
        }
        out.push('}');
        out
    }
}

impl<C> RedisStore<C>
where
    C: ConnectionLike + Clone + Send + Sync + 'static,
{
    async fn run(&self, key: &str, quota: &Quota) -> Result<Vec<i64>, RedisError> {
        let mut conn = self.conn.clone();
        match script_cmd(key, quota, false).query_async(&mut conn).await {
            Err(err) if needs_eval(&err) => {
                script_cmd(key, quota, true).query_async(&mut conn).await
            }
            other => other,
        }
    }
}

impl<C> RateLimitStore for RedisStore<C>
where
    C: ConnectionLike + Clone + Send + Sync + 'static,
{
    fn check<'a>(
        &'a self,
        key: &'a str,
        quota: &'a Quota,
    ) -> BoxFuture<'a, Result<Decision, StoreError>> {
        Box::pin(async move {
            if quota.limit == 0 || (quota.algorithm == Algorithm::Gcra && quota.burst == 0) {
                return Ok(deny_all(quota));
            }
            let key = self.redis_key(key, quota.algorithm);
            let reply = tokio::time::timeout(self.timeout, self.run(&key, quota))
                .await
                .map_err(|_| StoreError::new("redis call timed out"))?
                .map_err(StoreError::new)?;
            decode(&reply, quota)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEC: Duration = Duration::from_secs(1);

    /// A connection that is never used: key building and command packing need no server.
    #[derive(Clone)]
    struct NoConn;

    impl ConnectionLike for NoConn {
        fn req_packed_command<'a>(
            &'a mut self,
            _cmd: &'a Cmd,
        ) -> redis::RedisFuture<'a, redis::Value> {
            Box::pin(async { Err((ErrorKind::Io, "no server").into()) })
        }

        fn req_packed_commands<'a>(
            &'a mut self,
            _cmd: &'a redis::Pipeline,
            _offset: usize,
            _count: usize,
        ) -> redis::RedisFuture<'a, Vec<redis::Value>> {
            Box::pin(async { Err((ErrorKind::Io, "no server").into()) })
        }

        fn get_db(&self) -> i64 {
            0
        }
    }

    fn packed(cmd: &Cmd) -> String {
        String::from_utf8_lossy(&cmd.get_packed_command()).into_owned()
    }

    #[test]
    fn raw_keys_are_namespaced_and_tagged() {
        let store = RedisStore::new(NoConn).prefix("app");
        assert_eq!(
            store.redis_key("ip:203.0.113.7", Algorithm::FixedWindow),
            "app:fw:{ip:203.0.113.7}"
        );
        assert_eq!(
            store.redis_key("ip:203.0.113.7", Algorithm::Gcra),
            "app:gcra:{ip:203.0.113.7}"
        );
        assert!(
            RedisStore::new(NoConn)
                .redis_key("k", Algorithm::Gcra)
                .starts_with("ratelimit:")
        );
    }

    #[test]
    fn hashed_keys_hide_the_client() {
        let store = RedisStore::new(NoConn).prefix("app").hash_keys(b"secret");
        let k = store.redis_key("ip:203.0.113.7", Algorithm::Gcra);
        assert!(!k.contains("203.0.113.7"));
        assert!(k.starts_with("app:gcra:{") && k.ends_with('}'));
        let digest = &k["app:gcra:{".len()..k.len() - 1];
        assert_eq!(digest.len(), 32);
        assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
        // Stable for one secret, different for another and for another client.
        assert_eq!(k, store.redis_key("ip:203.0.113.7", Algorithm::Gcra));
        let other = RedisStore::new(NoConn).prefix("app").hash_keys(b"other");
        assert_ne!(k, other.redis_key("ip:203.0.113.7", Algorithm::Gcra));
        assert_ne!(k, store.redis_key("ip:203.0.113.8", Algorithm::Gcra));
    }

    #[test]
    fn known_hmac_value() {
        // HMAC-SHA256("key", "The quick brown fox jumps over the lazy dog"), RFC 4231 style
        // reference value, first 16 bytes.
        let store = RedisStore::new(NoConn).prefix("p").hash_keys(b"key");
        assert_eq!(
            store.redis_key(
                "The quick brown fox jumps over the lazy dog",
                Algorithm::Gcra
            ),
            "p:gcra:{f7bc83f430538424b13298e6aa6fb143}"
        );
    }

    #[test]
    fn script_selection_by_algorithm() {
        assert_eq!(
            script_for(Algorithm::Gcra).get_hash(),
            Script::new(GCRA_LUA).get_hash()
        );
        assert_eq!(
            script_for(Algorithm::FixedWindow).get_hash(),
            Script::new(FIXED_WINDOW_LUA).get_hash()
        );
        assert_ne!(
            script_for(Algorithm::Gcra).get_hash(),
            script_for(Algorithm::FixedWindow).get_hash()
        );
    }

    #[test]
    fn evalsha_first_eval_on_noscript() {
        let q = Quota::new(10, 10 * SEC, Algorithm::Gcra);
        let sha = packed(&script_cmd("k", &q, false));
        assert!(sha.contains("EVALSHA"));
        assert!(sha.contains(GCRA_SCRIPT.get_hash()));
        assert!(!sha.contains("TIME"));
        let eval = packed(&script_cmd("k", &q, true));
        assert!(eval.contains("$4\r\nEVAL\r\n"));
        assert!(eval.contains("redis.call('TIME')"));

        let noscript: RedisError =
            (ErrorKind::Server(ServerErrorKind::NoScript), "no script").into();
        assert!(needs_eval(&noscript));
        let io: RedisError = (ErrorKind::Io, "broken pipe").into();
        assert!(!needs_eval(&io));
        let other: RedisError = (ErrorKind::Server(ServerErrorKind::ResponseError), "ERR").into();
        assert!(!needs_eval(&other));
    }

    #[test]
    fn arguments_are_exact_integers() {
        // 4 per 4 s → 1 s interval, burst 4.
        let q = Quota::new(4, 4 * SEC, Algorithm::Gcra);
        assert_eq!(script_args(&q), vec![1_000_000, 4_000_000, 4]);
        let q = Quota::new(5, 60 * SEC, Algorithm::FixedWindow);
        assert_eq!(script_args(&q), vec![5, 60_000]);
        // A zero window still sets a positive expiry; huge windows are clamped.
        let q = Quota::new(5, Duration::ZERO, Algorithm::FixedWindow);
        assert_eq!(script_args(&q)[1], 1);
        let q = Quota::new(1, Duration::MAX, Algorithm::Gcra);
        assert!(script_args(&q).iter().all(|&v| v <= MAX_MICROS));
    }

    #[test]
    fn decode_reply() {
        let q = Quota::new(4, 4 * SEC, Algorithm::Gcra);
        let d = decode(&[1, 3, 1_000_000, 0], &q).expect("valid reply");
        assert!(d.allowed);
        assert_eq!(d.remaining, 3);
        assert_eq!(d.reset, SEC);
        assert_eq!(d.retry_after, None);
        let d = decode(&[0, 0, 4_000_000, 500_000], &q).expect("valid reply");
        assert!(!d.allowed);
        assert_eq!(d.retry_after, Some(SEC / 2));
        assert!(decode(&[1, 2], &q).is_err());
        // Negative values from a misbehaving script never wrap around.
        let d = decode(&[1, -1, -5, 0], &q).expect("valid reply");
        assert_eq!((d.remaining, d.reset), (0, Duration::ZERO));
    }

    #[tokio::test]
    async fn zero_limit_needs_no_server() {
        let store = RedisStore::new(NoConn);
        for alg in [Algorithm::FixedWindow, Algorithm::Gcra] {
            let d = store
                .check("k", &Quota::new(0, 5 * SEC, alg))
                .await
                .expect("answered locally");
            assert!(!d.allowed);
            assert_eq!(d.retry_after, Some(5 * SEC));
        }
    }

    #[tokio::test]
    async fn connection_errors_become_store_errors() {
        let store = RedisStore::new(NoConn);
        let q = Quota::new(5, SEC, Algorithm::Gcra);
        assert!(store.check("k", &q).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn calls_time_out() {
        #[derive(Clone)]
        struct Hang;
        impl ConnectionLike for Hang {
            fn req_packed_command<'a>(
                &'a mut self,
                _cmd: &'a Cmd,
            ) -> redis::RedisFuture<'a, redis::Value> {
                Box::pin(std::future::pending())
            }
            fn req_packed_commands<'a>(
                &'a mut self,
                _cmd: &'a redis::Pipeline,
                _offset: usize,
                _count: usize,
            ) -> redis::RedisFuture<'a, Vec<redis::Value>> {
                Box::pin(std::future::pending())
            }
            fn get_db(&self) -> i64 {
                0
            }
        }
        let store = RedisStore::new(Hang).timeout(Duration::from_millis(50));
        let err = store
            .check("k", &Quota::new(5, SEC, Algorithm::Gcra))
            .await
            .expect_err("times out");
        assert!(err.to_string().contains("timed out"));
    }
}
