//! Provider presets and the sans-I/O verification core.

use crate::generic::{Algorithm, HmacConfig, any_match, decode_hex, mac};
use crate::replay::{MemoryReplayStore, ReplayStore};
use crate::{InvalidSecret, Secret, VerifyError};
use axum::body::Bytes;
use http::HeaderMap;
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default timestamp tolerance: 5 minutes.
pub const DEFAULT_TOLERANCE: Duration = Duration::from_secs(300);

/// Default body limit: 2 MiB. GitHub can send up to 25 MB; raise the limit
/// with [`WebhookVerifier::max_body_bytes`] if you receive large push events.
pub const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// The signing scheme a verifier implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Provider {
    /// [Standard Webhooks](https://www.standardwebhooks.com/), also used by Svix.
    StandardWebhooks,
    /// Stripe `Stripe-Signature`.
    Stripe,
    /// GitHub `X-Hub-Signature-256`.
    GitHub,
    /// Slack `X-Slack-Signature` (v0).
    Slack,
    /// Shopify `X-Shopify-Hmac-Sha256`.
    Shopify,
    /// HMAC of the body in a configurable header ([`HmacConfig`]).
    Generic,
}

#[derive(Clone)]
enum Scheme {
    StandardWebhooks,
    Stripe,
    GitHub,
    Slack,
    Shopify,
    Generic(HmacConfig),
}

/// Verifies webhook requests for one provider.
///
/// Build one with a preset, optionally add rotation secrets and tune limits,
/// then either call [`verify_at`](Self::verify_at) /
/// [`verify_and_record`](Self::verify_and_record) yourself or wrap routes in
/// a [`WebhookLayer`](crate::WebhookLayer).
///
/// `Debug` shows the provider and settings, never the secrets.
///
/// # Examples
///
/// ```rust
/// use rune_axum_signature::{Secret, WebhookVerifier};
/// use std::time::Duration;
///
/// let verifier = WebhookVerifier::stripe("whsec_new")
///     .with_secret("whsec_old") // accepted until you remove it
///     .tolerance(Duration::from_secs(120))
///     .max_body_bytes(256 * 1024);
/// assert!(!format!("{verifier:?}").contains("whsec_"));
/// ```
#[derive(Clone)]
pub struct WebhookVerifier {
    scheme: Scheme,
    secrets: Vec<Secret>,
    tolerance: Duration,
    max_body: usize,
    replay: Option<Arc<dyn ReplayStore>>,
}

impl fmt::Debug for WebhookVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookVerifier")
            .field("provider", &self.provider())
            .field("secrets", &self.secrets.len())
            .field("tolerance", &self.tolerance)
            .field("max_body", &self.max_body)
            .field("replay_protection", &self.replay.is_some())
            .finish_non_exhaustive()
    }
}

impl WebhookVerifier {
    fn preset(scheme: Scheme, secret: Secret) -> Self {
        Self {
            scheme,
            secrets: vec![secret],
            tolerance: DEFAULT_TOLERANCE,
            max_body: DEFAULT_MAX_BODY_BYTES,
            replay: None,
        }
    }

    /// Standard Webhooks: `webhook-id`, `webhook-timestamp` and
    /// `webhook-signature` (space-separated `v1,<base64>` entries).
    /// Svix's `svix-*` header names are accepted too.
    ///
    /// `secret` is the `whsec_<base64>` string from the provider dashboard.
    /// Replay protection is on by default (in-memory, keyed on `webhook-id`
    /// and `webhook-timestamp`, so a resend of a failed message gets through).
    ///
    /// # Errors
    ///
    /// [`InvalidSecret`] if the secret is not valid base64.
    pub fn standard_webhooks(secret: &str) -> Result<Self, InvalidSecret> {
        let mut v = Self::preset(Scheme::StandardWebhooks, Secret::from_whsec(secret)?);
        v.replay = Some(Arc::new(MemoryReplayStore::default()));
        Ok(v)
    }

    /// Same as [`standard_webhooks`](Self::standard_webhooks).
    ///
    /// # Errors
    ///
    /// [`InvalidSecret`] if the secret is not valid base64.
    pub fn svix(secret: &str) -> Result<Self, InvalidSecret> {
        Self::standard_webhooks(secret)
    }

    /// Stripe: `Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>...]`, signed
    /// over `<t>.<body>`. The `whsec_...` secret is used as-is (not decoded).
    #[must_use]
    pub fn stripe(secret: impl Into<Secret>) -> Self {
        Self::preset(Scheme::Stripe, secret.into())
    }

    /// GitHub: `X-Hub-Signature-256: sha256=<hex>` over the body.
    ///
    /// GitHub signs no timestamp, so there is no tolerance or replay check;
    /// dedupe on [`VerifiedWebhook::id`] (`X-GitHub-Delivery`) in your
    /// handler if you need idempotency.
    #[must_use]
    pub fn github(secret: impl Into<Secret>) -> Self {
        Self::preset(Scheme::GitHub, secret.into())
    }

    /// Slack: `X-Slack-Signature: v0=<hex>` over `v0:<timestamp>:<body>`,
    /// with the timestamp in `X-Slack-Request-Timestamp`.
    #[must_use]
    pub fn slack(signing_secret: impl Into<Secret>) -> Self {
        Self::preset(Scheme::Slack, signing_secret.into())
    }

    /// Shopify: `X-Shopify-Hmac-Sha256: <base64>` over the body.
    ///
    /// Like GitHub, no timestamp is signed; `X-Shopify-Webhook-Id` is exposed
    /// as [`VerifiedWebhook::id`].
    #[must_use]
    pub fn shopify(secret: impl Into<Secret>) -> Self {
        Self::preset(Scheme::Shopify, secret.into())
    }

    /// Generic HMAC mode from a 0.2-style [`HmacConfig`].
    #[must_use]
    pub fn generic(config: HmacConfig) -> Self {
        let secret = config.secret.clone();
        Self::preset(Scheme::Generic(config), secret)
    }

    /// Adds another accepted secret, for key rotation. A request passes if
    /// any secret matches.
    ///
    /// For Standard Webhooks pass `Secret::from_whsec(..)?`, not the raw string.
    #[must_use]
    pub fn with_secret(mut self, secret: impl Into<Secret>) -> Self {
        self.secrets.push(secret.into());
        self
    }

    /// How far the signed timestamp may be from now, in either direction.
    /// Default 5 minutes. Ignored for providers without a signed timestamp.
    #[must_use]
    pub const fn tolerance(mut self, tolerance: Duration) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// Largest body the layer will read; bigger requests get `413`.
    #[must_use]
    pub const fn max_body_bytes(mut self, limit: usize) -> Self {
        self.max_body = limit;
        self
    }

    /// Uses `store` for replay protection and turns it on.
    ///
    /// Standard Webhooks key on `webhook-id` plus timestamp. Stripe and Slack
    /// have no signed id, so they key on a digest of timestamp and body; a sender that
    /// retries with the very same timestamp would then be refused. GitHub,
    /// Shopify and generic mode sign no timestamp, so the store is not used.
    #[must_use]
    pub fn replay_store(self, store: impl ReplayStore) -> Self {
        self.shared_replay_store(Arc::new(store))
    }

    /// Like [`replay_store`](Self::replay_store) with a shared store.
    #[must_use]
    pub fn shared_replay_store(mut self, store: Arc<dyn ReplayStore>) -> Self {
        self.replay = Some(store);
        self
    }

    /// Turns replay protection off.
    #[must_use]
    pub fn without_replay_protection(mut self) -> Self {
        self.replay = None;
        self
    }

    /// Which provider this verifier implements.
    #[must_use]
    pub const fn provider(&self) -> Provider {
        match self.scheme {
            Scheme::StandardWebhooks => Provider::StandardWebhooks,
            Scheme::Stripe => Provider::Stripe,
            Scheme::GitHub => Provider::GitHub,
            Scheme::Slack => Provider::Slack,
            Scheme::Shopify => Provider::Shopify,
            Scheme::Generic(_) => Provider::Generic,
        }
    }

    /// The configured body limit in bytes.
    #[must_use]
    pub const fn body_limit(&self) -> usize {
        self.max_body
    }

    /// Checks signature and timestamp against the system clock. Does not
    /// consult the replay store; see [`verify_and_record`](Self::verify_and_record).
    pub fn verify(
        &self,
        headers: &HeaderMap,
        body: impl Into<Bytes>,
    ) -> Result<VerifiedWebhook, VerifyError> {
        self.verify_at(headers, body, now_unix())
    }

    /// Checks signature and timestamp as if the time were `now` (unix
    /// seconds). Pure: no clock, no I/O, no replay store.
    pub fn verify_at(
        &self,
        headers: &HeaderMap,
        body: impl Into<Bytes>,
        now: i64,
    ) -> Result<VerifiedWebhook, VerifyError> {
        let body = body.into();
        if body.len() > self.max_body {
            return Err(VerifyError::BodyTooLarge {
                limit: self.max_body,
            });
        }
        let checked = match &self.scheme {
            Scheme::StandardWebhooks => self.check_standard(headers, &body)?,
            Scheme::Stripe => self.check_stripe(headers, &body)?,
            Scheme::GitHub => self.check_github(headers, &body)?,
            Scheme::Slack => self.check_slack(headers, &body)?,
            Scheme::Shopify => self.check_shopify(headers, &body)?,
            Scheme::Generic(config) => {
                let raw = header(headers, &config.header_name)?;
                if !config.verify_with(&self.secrets, &body, raw) {
                    return Err(VerifyError::SignatureMismatch);
                }
                Checked::default()
            }
        };
        let replay = match checked.timestamp {
            Some(ts) => {
                let tol = i64::try_from(self.tolerance.as_secs()).unwrap_or(i64::MAX);
                if now.abs_diff(ts) > tol.unsigned_abs() {
                    return Err(VerifyError::TimestampOutOfTolerance);
                }
                // Still verifiable at `ts + tol`, so keep it one second past.
                checked
                    .replay_key
                    .map(|k| (k, ts.saturating_add(tol).saturating_add(1)))
            }
            None => None,
        };
        Ok(VerifiedWebhook {
            provider: self.provider(),
            id: checked.id,
            timestamp: checked.timestamp,
            body,
            replay,
        })
    }

    /// Records `webhook` in the replay store (if enabled) and fails with
    /// [`VerifyError::Replayed`] if it was seen before.
    pub async fn check_replay(&self, webhook: &VerifiedWebhook) -> Result<(), VerifyError> {
        let (Some(store), Some((key, expires))) = (&self.replay, &webhook.replay) else {
            return Ok(());
        };
        match store.check_and_insert(key, *expires).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(VerifyError::Replayed),
            Err(_) => Err(VerifyError::ReplayStoreUnavailable),
        }
    }

    /// [`verify`](Self::verify) followed by [`check_replay`](Self::check_replay).
    /// Use this when you verify by hand instead of through the layer.
    pub async fn verify_and_record(
        &self,
        headers: &HeaderMap,
        body: impl Into<Bytes>,
    ) -> Result<VerifiedWebhook, VerifyError> {
        let webhook = self.verify(headers, body)?;
        self.check_replay(&webhook).await?;
        Ok(webhook)
    }

    fn expected(&self, parts: &[&[u8]]) -> Vec<Vec<u8>> {
        self.secrets
            .iter()
            .filter_map(|s| mac(Algorithm::Sha256, s.as_bytes(), parts))
            .collect()
    }

    fn matches(&self, parts: &[&[u8]], candidates: &[Vec<u8>]) -> Result<(), VerifyError> {
        if any_match(&self.expected(parts), candidates) {
            Ok(())
        } else {
            Err(VerifyError::SignatureMismatch)
        }
    }

    fn check_standard(&self, headers: &HeaderMap, body: &[u8]) -> Result<Checked, VerifyError> {
        let (id_h, ts_h, sig_h) = if headers.contains_key("webhook-id") {
            ("webhook-id", "webhook-timestamp", "webhook-signature")
        } else {
            ("svix-id", "svix-timestamp", "svix-signature")
        };
        let id = header(headers, id_h)?;
        let ts_raw = header(headers, ts_h)?;
        let ts = parse_ts(ts_raw, ts_h)?;
        let candidates: Vec<Vec<u8>> = header(headers, sig_h)?
            .split_whitespace()
            .filter_map(|entry| entry.strip_prefix("v1,"))
            .filter_map(|b64| rune_base64::decode(b64).ok())
            .collect();
        let parts: [&[u8]; 5] = [id.as_bytes(), b".", ts_raw.as_bytes(), b".", body];
        self.matches(&parts, &candidates)?;
        Ok(Checked {
            id: Some(id.to_owned()),
            timestamp: Some(ts),
            // Keyed on what is signed, not the id alone: senders resend a
            // failed message under the same id with a new timestamp.
            replay_key: Some(format!("swh:{id}.{ts_raw}")),
        })
    }

    fn check_stripe(&self, headers: &HeaderMap, body: &[u8]) -> Result<Checked, VerifyError> {
        const H: &str = "stripe-signature";
        let mut t = None;
        let mut candidates = Vec::new();
        for item in header(headers, H)?.split(',') {
            match item.trim().split_once('=') {
                Some(("t", v)) if t.is_none() => t = Some(v),
                Some(("t", _)) => return Err(VerifyError::MalformedHeader(H.into())),
                Some(("v1", v)) => candidates.extend(decode_hex(v)),
                _ => {}
            }
        }
        let t_raw = t.ok_or_else(|| VerifyError::MalformedHeader(H.into()))?;
        let ts = parse_ts(t_raw, H)?;
        let parts: [&[u8]; 3] = [t_raw.as_bytes(), b".", body];
        self.matches(&parts, &candidates)?;
        Ok(Checked {
            id: None,
            timestamp: Some(ts),
            replay_key: Some(digest_key("stripe", &parts)),
        })
    }

    fn check_github(&self, headers: &HeaderMap, body: &[u8]) -> Result<Checked, VerifyError> {
        const H: &str = "x-hub-signature-256";
        let candidate = header(headers, H)?
            .strip_prefix("sha256=")
            .and_then(decode_hex)
            .ok_or_else(|| VerifyError::MalformedHeader(H.into()))?;
        self.matches(&[body], &[candidate])?;
        Ok(Checked {
            id: optional(headers, "x-github-delivery"),
            ..Checked::default()
        })
    }

    fn check_slack(&self, headers: &HeaderMap, body: &[u8]) -> Result<Checked, VerifyError> {
        const SIG: &str = "x-slack-signature";
        const TS: &str = "x-slack-request-timestamp";
        let ts_raw = header(headers, TS)?;
        let ts = parse_ts(ts_raw, TS)?;
        let candidate = header(headers, SIG)?
            .strip_prefix("v0=")
            .and_then(decode_hex)
            .ok_or_else(|| VerifyError::MalformedHeader(SIG.into()))?;
        let parts: [&[u8]; 4] = [b"v0:", ts_raw.as_bytes(), b":", body];
        self.matches(&parts, &[candidate])?;
        Ok(Checked {
            id: None,
            timestamp: Some(ts),
            replay_key: Some(digest_key("slack", &parts)),
        })
    }

    fn check_shopify(&self, headers: &HeaderMap, body: &[u8]) -> Result<Checked, VerifyError> {
        const H: &str = "x-shopify-hmac-sha256";
        let candidate = rune_base64::decode(header(headers, H)?.trim())
            .map_err(|_| VerifyError::MalformedHeader(H.into()))?;
        self.matches(&[body], &[candidate])?;
        Ok(Checked {
            id: optional(headers, "x-shopify-webhook-id"),
            ..Checked::default()
        })
    }
}

impl From<HmacConfig> for WebhookVerifier {
    fn from(config: HmacConfig) -> Self {
        Self::generic(config)
    }
}

#[derive(Default)]
struct Checked {
    id: Option<String>,
    timestamp: Option<i64>,
    replay_key: Option<String>,
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, VerifyError> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| VerifyError::MissingHeader(name.to_owned()))
}

fn optional(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

fn parse_ts(raw: &str, name: &str) -> Result<i64, VerifyError> {
    raw.trim()
        .parse()
        .map_err(|_| VerifyError::MalformedHeader(name.to_owned()))
}

fn digest_key(prefix: &str, parts: &[&[u8]]) -> String {
    use std::fmt::Write as _;
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher
        .finalize()
        .iter()
        .fold(format!("{prefix}:"), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// A request whose signature checked out, with its raw body.
///
/// The layer puts one in the request extensions; take it in a handler as an
/// extractor and parse the body yourself, after verification:
///
/// ```rust,no_run
/// use rune_axum_signature::VerifiedWebhook;
///
/// async fn handler(hook: VerifiedWebhook) -> &'static str {
///     let _len = hook.body().len(); // e.g. serde_json::from_slice(hook.body())
///     "ok"
/// }
/// ```
///
/// `Debug` prints the body length, not its content.
#[derive(Clone)]
pub struct VerifiedWebhook {
    provider: Provider,
    id: Option<String>,
    timestamp: Option<i64>,
    body: Bytes,
    replay: Option<(String, i64)>,
}

impl VerifiedWebhook {
    /// The provider that signed it.
    #[must_use]
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    /// Message or delivery id, if the provider sends one.
    ///
    /// Only the Standard Webhooks id is covered by the signature. GitHub's
    /// `X-GitHub-Delivery` and Shopify's `X-Shopify-Webhook-Id` are not, so
    /// use them for idempotency, not as a security check.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Signed timestamp (unix seconds), if the provider signs one.
    #[must_use]
    pub const fn timestamp(&self) -> Option<i64> {
        self.timestamp
    }

    /// The verified raw body.
    #[must_use]
    pub const fn body(&self) -> &Bytes {
        &self.body
    }

    /// Takes the verified raw body.
    #[must_use]
    pub fn into_body(self) -> Bytes {
        self.body
    }
}

impl fmt::Debug for VerifiedWebhook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedWebhook")
            .field("provider", &self.provider)
            .field("id", &self.id)
            .field("timestamp", &self.timestamp)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use std::fmt::Write as _;

    fn slack(secret: &[u8], ts: i64, body: &[u8]) -> HeaderMap {
        let ts = ts.to_string();
        let tag = mac(
            Algorithm::Sha256,
            secret,
            &[b"v0:", ts.as_bytes(), b":", body],
        )
        .unwrap_or_default();
        let hex = tag.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        let mut h = HeaderMap::new();
        h.insert(
            "x-slack-request-timestamp",
            HeaderValue::from_str(&ts).unwrap(),
        );
        h.insert(
            "x-slack-signature",
            HeaderValue::from_str(&format!("v0={hex}")).unwrap(),
        );
        h
    }

    /// A message still verifies at exactly `ts + tolerance`, so the replay
    /// store has to remember it through that second too.
    #[test]
    fn replay_entry_outlives_the_last_accepted_second() {
        let store = MemoryReplayStore::new(16);
        let v = WebhookVerifier::slack("s").tolerance(Duration::from_secs(300));
        let h = slack(b"s", 1_000, b"x");
        for now in [1_000, 1_300] {
            let hook = v.verify_at(&h, &b"x"[..], now).unwrap();
            let (key, expires) = hook.replay.clone().unwrap();
            let fresh = store.insert_at(&key, expires, now);
            assert_eq!(fresh, now == 1_000, "now = {now}");
        }
    }
}
