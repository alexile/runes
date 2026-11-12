//! `Cache-Control` response directives ([RFC 9111 §5.2.2], [RFC 8246],
//! [RFC 5861]).
//!
//! [RFC 9111 §5.2.2]: https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2
//! [RFC 8246]: https://www.rfc-editor.org/rfc/rfc8246
//! [RFC 5861]: https://www.rfc-editor.org/rfc/rfc5861

use std::fmt;
use std::time::Duration;

use http::HeaderValue;

/// Largest delta-seconds value a sender should emit (RFC 9111 §1.2.2).
const MAX_DELTA_SECONDS: u64 = 2_147_483_648;

/// Who may store the response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Visibility {
    Public,
    Private,
}

/// A set of `Cache-Control` response directives.
///
/// Start from [`CacheControl::new()`] (no directives) or a preset and chain
/// builder methods. Durations are sent in whole seconds, rounded down and
/// capped at 2<sup>31</sup> as RFC 9111 asks. Directives are always rendered
/// in the same order, so equal sets render identically.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_axum_cache::CacheControl;
///
/// let cc = CacheControl::new()
///     .public()
///     .max_age(Duration::from_secs(600))
///     .stale_while_revalidate(Duration::from_secs(30));
/// assert_eq!(cc.to_string(), "public, max-age=600, stale-while-revalidate=30");
///
/// assert_eq!(CacheControl::sensitive().to_string(), "no-store");
/// assert_eq!(
///     CacheControl::immutable_asset(Duration::from_secs(31_536_000)).to_string(),
///     "public, max-age=31536000, immutable",
/// );
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent directive of the header"
)]
pub struct CacheControl {
    visibility: Option<Visibility>,
    no_cache: bool,
    no_store: bool,
    no_transform: bool,
    must_revalidate: bool,
    proxy_revalidate: bool,
    must_understand: bool,
    immutable: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
    stale_while_revalidate: Option<u64>,
    stale_if_error: Option<u64>,
}

impl CacheControl {
    /// An empty directive set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `no-store`: no cache may keep the response. For credentials,
    /// personal data and anything else that must not linger on disk.
    #[must_use]
    pub fn sensitive() -> Self {
        Self::new().no_store()
    }

    /// `private, no-cache`: only the client may store the response, and it
    /// must revalidate (with `ETag` / `Last-Modified`) before every reuse.
    /// The default of [`Cache`](crate::Cache).
    #[must_use]
    pub fn revalidate() -> Self {
        Self::new().private().no_cache()
    }

    /// `public, max-age=N, immutable`: for fingerprinted static assets
    /// whose URL changes when their content does.
    #[must_use]
    pub fn immutable_asset(max_age: Duration) -> Self {
        Self::new().public().max_age(max_age).immutable()
    }

    /// `public`: shared caches may store the response, even one that would
    /// otherwise not be cacheable (for example, to an authenticated request).
    /// Replaces [`private`](Self::private).
    #[must_use]
    pub const fn public(mut self) -> Self {
        self.visibility = Some(Visibility::Public);
        self
    }

    /// `private`: only the client's own cache may store the response.
    /// Replaces [`public`](Self::public).
    #[must_use]
    pub const fn private(mut self) -> Self {
        self.visibility = Some(Visibility::Private);
        self
    }

    /// `no-cache`: caches must revalidate with the origin before each reuse.
    #[must_use]
    pub const fn no_cache(mut self) -> Self {
        self.no_cache = true;
        self
    }

    /// `no-store`: caches must not store any part of the response.
    #[must_use]
    pub const fn no_store(mut self) -> Self {
        self.no_store = true;
        self
    }

    /// `no-transform`: intermediaries must not transform the content.
    #[must_use]
    pub const fn no_transform(mut self) -> Self {
        self.no_transform = true;
        self
    }

    /// `must-revalidate`: once stale, the response must not be reused
    /// without successful revalidation.
    #[must_use]
    pub const fn must_revalidate(mut self) -> Self {
        self.must_revalidate = true;
        self
    }

    /// `proxy-revalidate`: as `must-revalidate`, for shared caches only.
    #[must_use]
    pub const fn proxy_revalidate(mut self) -> Self {
        self.proxy_revalidate = true;
        self
    }

    /// `must-understand`: store only if the cache understands the status
    /// code's caching requirements. Pair it with `no-store` as a fallback.
    #[must_use]
    pub const fn must_understand(mut self) -> Self {
        self.must_understand = true;
        self
    }

    /// `immutable` (RFC 8246): the response will not change while fresh.
    #[must_use]
    pub const fn immutable(mut self) -> Self {
        self.immutable = true;
        self
    }

    /// `max-age=N`: the response is fresh for `max_age`.
    #[must_use]
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(delta_seconds(max_age));
        self
    }

    /// `s-maxage=N`: freshness lifetime for shared caches, overriding
    /// `max-age` there.
    #[must_use]
    pub fn s_maxage(mut self, s_maxage: Duration) -> Self {
        self.s_maxage = Some(delta_seconds(s_maxage));
        self
    }

    /// `stale-while-revalidate=N` (RFC 5861): a stale response may be served
    /// for this long while it is revalidated in the background.
    #[must_use]
    pub fn stale_while_revalidate(mut self, window: Duration) -> Self {
        self.stale_while_revalidate = Some(delta_seconds(window));
        self
    }

    /// `stale-if-error=N` (RFC 5861): a stale response may be served for
    /// this long when revalidation fails with an error.
    #[must_use]
    pub fn stale_if_error(mut self, window: Duration) -> Self {
        self.stale_if_error = Some(delta_seconds(window));
        self
    }

    /// Whether no directive is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Whether `no-store` is set.
    #[must_use]
    pub const fn is_no_store(&self) -> bool {
        self.no_store
    }

    /// The directives as a `Cache-Control` header value.
    #[must_use]
    pub fn to_header_value(&self) -> HeaderValue {
        crate::ascii_header_value(&self.to_string())
    }
}

impl fmt::Display for CacheControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = "";
        let mut flag = |f: &mut fmt::Formatter<'_>, on: bool, name: &str| {
            if on {
                write!(f, "{sep}{name}")?;
                sep = ", ";
            }
            Ok::<(), fmt::Error>(())
        };
        flag(f, self.visibility == Some(Visibility::Public), "public")?;
        flag(f, self.visibility == Some(Visibility::Private), "private")?;
        flag(f, self.no_cache, "no-cache")?;
        flag(f, self.no_store, "no-store")?;
        flag(f, self.no_transform, "no-transform")?;
        flag(f, self.must_revalidate, "must-revalidate")?;
        flag(f, self.proxy_revalidate, "proxy-revalidate")?;
        flag(f, self.must_understand, "must-understand")?;
        for (name, value) in [
            ("max-age", self.max_age),
            ("s-maxage", self.s_maxage),
            ("stale-while-revalidate", self.stale_while_revalidate),
            ("stale-if-error", self.stale_if_error),
        ] {
            if let Some(secs) = value {
                flag(f, true, &format!("{name}={secs}"))?;
            }
        }
        flag(f, self.immutable, "immutable")
    }
}

fn delta_seconds(d: Duration) -> u64 {
    d.as_secs().min(MAX_DELTA_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_directive_in_order() {
        let cc = CacheControl::new()
            .immutable()
            .stale_if_error(Duration::from_secs(4))
            .stale_while_revalidate(Duration::from_secs(3))
            .s_maxage(Duration::from_secs(2))
            .max_age(Duration::from_millis(1_999))
            .must_understand()
            .proxy_revalidate()
            .must_revalidate()
            .no_transform()
            .no_store()
            .no_cache()
            .public();
        assert_eq!(
            cc.to_string(),
            "public, no-cache, no-store, no-transform, must-revalidate, proxy-revalidate, \
             must-understand, max-age=1, s-maxage=2, stale-while-revalidate=3, \
             stale-if-error=4, immutable"
        );
    }

    #[test]
    fn visibility_is_exclusive() {
        assert_eq!(
            CacheControl::new().public().private().to_string(),
            "private"
        );
        assert_eq!(CacheControl::new().private().public().to_string(), "public");
    }

    #[test]
    fn caps_huge_durations() {
        let cc = CacheControl::new().max_age(Duration::MAX);
        assert_eq!(cc.to_string(), "max-age=2147483648");
    }

    #[test]
    fn presets_and_empty() {
        assert!(CacheControl::new().is_empty());
        assert_eq!(CacheControl::new().to_string(), "");
        assert_eq!(CacheControl::revalidate().to_string(), "private, no-cache");
        assert!(CacheControl::sensitive().is_no_store());
        assert_eq!(
            CacheControl::revalidate().to_header_value(),
            "private, no-cache"
        );
    }
}
