//! The cookie jar: the storage model of [RFC 6265 §5.3] and the retrieval
//! algorithm of [§5.4], with the RFC 6265bis security rules.
//!
//! [RFC 6265 §5.3]: https://www.rfc-editor.org/rfc/rfc6265#section-5.3
//! [§5.4]: https://www.rfc-editor.org/rfc/rfc6265#section-5.4

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use url::Url;

use crate::cookie_header::CookiePair;
use crate::date::system_time_from_unix;
use crate::matching::{
    canonical_host, canonicalize_domain, default_path, domain_match, is_same_site,
    is_secure_scheme, path_match,
};
use crate::{Error, Rejection, SameSite, SetCookie};

/// The last second of year 9999: the expiry of a cookie whose `Max-Age`
/// overflows the clock.
const LATEST_EXPIRY_UNIX: i64 = 253_402_300_799;

/// Which kind of API a cookie is set or read through ([RFC 6265 §5.3]).
///
/// [RFC 6265 §5.3]: https://www.rfc-editor.org/rfc/rfc6265#section-5.3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Api {
    /// HTTP headers (`Set-Cookie`, `Cookie`).
    #[default]
    Http,
    /// Anything else, such as `document.cookie`: cannot see or set
    /// `HttpOnly` cookies.
    NonHttp,
}

/// How a request relates to the site that initiated it, for `SameSite`
/// ([RFC 6265bis §5.2]).
///
/// [RFC 6265bis §5.2]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-5.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum SiteContext {
    /// The request is same-site with the site for cookies (also a direct,
    /// user-initiated request such as typing a URL).
    #[default]
    SameSite,
    /// A cross-site request that navigates a top-level browsing context.
    CrossSiteTopLevelNavigation,
    /// Any other cross-site request (subresources, frames, `fetch`).
    CrossSite,
}

impl SiteContext {
    /// The context of a request to `target` made from a document whose
    /// site for cookies is `site_for_cookies`, judged with `list`.
    ///
    /// ```
    /// use rune_cookie::SiteContext;
    /// use url::Url;
    ///
    /// let list = rune_psl::List::embedded();
    /// let page = Url::parse("https://news.example/").unwrap();
    /// let api = Url::parse("https://api.shop.example/cart").unwrap();
    /// assert_eq!(SiteContext::between(&api, &page, false, &list), SiteContext::CrossSite);
    /// assert_eq!(
    ///     SiteContext::between(&api, &page, true, &list),
    ///     SiteContext::CrossSiteTopLevelNavigation,
    /// );
    /// ```
    #[must_use]
    pub fn between(
        target: &Url,
        site_for_cookies: &Url,
        top_level_navigation: bool,
        list: &rune_psl::List,
    ) -> Self {
        if is_same_site(target, site_for_cookies, list) {
            Self::SameSite
        } else if top_level_navigation {
            Self::CrossSiteTopLevelNavigation
        } else {
            Self::CrossSite
        }
    }
}

/// The circumstances of a request that sets or reads cookies.
///
/// The default is an HTTP request, same-site, with a safe method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RequestContext {
    /// HTTP or non-HTTP API.
    pub api: Api,
    /// The request's relation to the site for cookies.
    pub site: SiteContext,
    /// The request method is safe (`GET`, `HEAD`, `OPTIONS`, `TRACE`):
    /// `SameSite=Lax` cookies go with cross-site top-level navigations
    /// only then.
    pub safe_method: bool,
}

impl Default for RequestContext {
    fn default() -> Self {
        Self {
            api: Api::Http,
            site: SiteContext::SameSite,
            safe_method: true,
        }
    }
}

impl RequestContext {
    /// An HTTP request, same-site, with a safe method.
    #[must_use]
    pub fn http() -> Self {
        Self::default()
    }

    /// A non-HTTP API (script), same-site.
    #[must_use]
    pub fn non_http() -> Self {
        Self {
            api: Api::NonHttp,
            ..Self::default()
        }
    }

    /// Sets the site context.
    #[must_use]
    pub const fn with_site(mut self, site: SiteContext) -> Self {
        self.site = site;
        self
    }

    /// Sets [`safe_method`](Self::safe_method) from an HTTP method name.
    #[must_use]
    pub fn with_method(mut self, method: &str) -> Self {
        self.safe_method = ["GET", "HEAD", "OPTIONS", "TRACE"]
            .iter()
            .any(|safe| method.eq_ignore_ascii_case(safe));
        self
    }
}

/// Jar policy. The defaults follow RFC 6265 plus the RFC 6265bis security
/// rules that all major browsers enforce; [`JarOptions::rfc6265`] turns the
/// RFC 6265bis rules off.
#[allow(clippy::struct_excessive_bools, reason = "independent policy switches")]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JarOptions {
    /// Reject `Domain` attributes that are public suffixes (RFC 6265
    /// §5.3 step 5), and judge same-site with this list. `None` disables
    /// the public suffix check. Default: the embedded list of `rune-psl`.
    pub public_suffix_list: Option<rune_psl::List>,
    /// "Strict secure cookies": only secure origins may set `Secure`
    /// cookies, and insecure origins may not overwrite them
    /// (RFC 6265bis §5.7 steps 15–16). Default: on.
    pub strict_secure: bool,
    /// Enforce the `__Secure-` and `__Host-` name prefixes (RFC 6265bis
    /// §4.1.3). Default: on.
    pub cookie_prefixes: bool,
    /// Reject `SameSite=None` without `Secure` (RFC 6265bis §5.7
    /// step 18). Default: on.
    pub same_site_none_requires_secure: bool,
    /// Reject `SameSite=Strict` and `Lax` cookies set by cross-site
    /// requests that are not top-level navigations (RFC 6265bis §5.7
    /// step 17). Default: on.
    pub same_site_store_check: bool,
    /// Treat cookies without `SameSite` as `Lax` ("Lax by default"), as
    /// Chromium does. Default: off.
    pub lax_by_default: bool,
    /// Cap on a persistent cookie's lifetime (RFC 6265bis suggests 400
    /// days). Default: none.
    pub max_lifetime: Option<Duration>,
    /// The most cookies the jar holds; the least recently used go first.
    /// Default: 3000 (RFC 6265 §6.1 asks for at least 3000).
    pub max_cookies: usize,
    /// The most cookies sharing one domain. Default: 180 (RFC 6265 §6.1
    /// asks for at least 50).
    pub max_cookies_per_domain: usize,
}

impl Default for JarOptions {
    fn default() -> Self {
        Self {
            public_suffix_list: Some(rune_psl::List::embedded()),
            strict_secure: true,
            cookie_prefixes: true,
            same_site_none_requires_secure: true,
            same_site_store_check: true,
            lax_by_default: false,
            max_lifetime: None,
            max_cookies: 3000,
            max_cookies_per_domain: 180,
        }
    }
}

impl JarOptions {
    /// RFC 6265 exactly: the defaults with every RFC 6265bis store rule
    /// off (the public suffix check stays on).
    #[must_use]
    pub fn rfc6265() -> Self {
        Self {
            strict_secure: false,
            cookie_prefixes: false,
            same_site_none_requires_secure: false,
            same_site_store_check: false,
            ..Self::default()
        }
    }

    /// Sets the public suffix list; `None` disables the check.
    #[must_use]
    pub fn with_public_suffix_list(mut self, list: Option<rune_psl::List>) -> Self {
        self.public_suffix_list = list;
        self
    }

    /// Sets [`strict_secure`](Self::strict_secure).
    #[must_use]
    pub const fn with_strict_secure(mut self, on: bool) -> Self {
        self.strict_secure = on;
        self
    }

    /// Sets [`cookie_prefixes`](Self::cookie_prefixes).
    #[must_use]
    pub const fn with_cookie_prefixes(mut self, on: bool) -> Self {
        self.cookie_prefixes = on;
        self
    }

    /// Sets [`same_site_none_requires_secure`](Self::same_site_none_requires_secure).
    #[must_use]
    pub const fn with_same_site_none_requires_secure(mut self, on: bool) -> Self {
        self.same_site_none_requires_secure = on;
        self
    }

    /// Sets [`same_site_store_check`](Self::same_site_store_check).
    #[must_use]
    pub const fn with_same_site_store_check(mut self, on: bool) -> Self {
        self.same_site_store_check = on;
        self
    }

    /// Sets [`lax_by_default`](Self::lax_by_default).
    #[must_use]
    pub const fn with_lax_by_default(mut self, on: bool) -> Self {
        self.lax_by_default = on;
        self
    }

    /// Sets [`max_lifetime`](Self::max_lifetime).
    #[must_use]
    pub const fn with_max_lifetime(mut self, max: Option<Duration>) -> Self {
        self.max_lifetime = max;
        self
    }

    /// Sets [`max_cookies`](Self::max_cookies).
    #[must_use]
    pub const fn with_max_cookies(mut self, max: usize) -> Self {
        self.max_cookies = max;
        self
    }

    /// Sets [`max_cookies_per_domain`](Self::max_cookies_per_domain).
    #[must_use]
    pub const fn with_max_cookies_per_domain(mut self, max: usize) -> Self {
        self.max_cookies_per_domain = max;
        self
    }
}

/// A cookie in a jar: the fields of the RFC 6265 §5.3 storage model.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the RFC 6265 storage model has these independent flags"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Cookie {
    /// The name.
    pub name: String,
    /// The value.
    pub value: String,
    /// The canonical domain: the request host for a host-only cookie,
    /// otherwise the `Domain` attribute.
    pub domain: String,
    /// The path.
    pub path: String,
    /// When the cookie expires; `None` for a session cookie.
    pub expires: Option<SystemTime>,
    /// When the cookie was first stored (kept when it is replaced).
    pub creation_time: SystemTime,
    /// When the cookie was last stored or sent.
    pub last_access_time: SystemTime,
    /// Sent only to exactly [`domain`](Self::domain), not its subdomains.
    pub host_only: bool,
    /// Sent only over secure protocols.
    pub secure: bool,
    /// Hidden from non-HTTP APIs.
    pub http_only: bool,
    /// `SameSite`, if set.
    pub same_site: Option<SameSite>,
    /// `Partitioned` was set. The jar records it but does not partition.
    pub partitioned: bool,
}

impl Cookie {
    /// Whether the cookie outlives the session.
    #[must_use]
    pub const fn is_persistent(&self) -> bool {
        self.expires.is_some()
    }

    /// Whether the cookie has expired at `now`.
    #[must_use]
    pub fn is_expired(&self, now: SystemTime) -> bool {
        self.expires.is_some_and(|expires| expires <= now)
    }

    /// The `name=value` pair sent in a `Cookie` header.
    #[must_use]
    pub fn pair(&self) -> CookiePair {
        CookiePair::new(&self.name, &self.value)
    }

    /// A `Set-Cookie` that recreates this cookie when received from its
    /// domain: `Domain` unless host-only, `Path`, `Expires` if persistent,
    /// and the flags.
    #[must_use]
    pub fn to_set_cookie(&self) -> SetCookie {
        let mut set = SetCookie::new(&self.name, &self.value)
            .with_path(&self.path)
            .with_secure(self.secure)
            .with_http_only(self.http_only)
            .with_partitioned(self.partitioned);
        if !self.host_only {
            set = set.with_domain(&self.domain);
        }
        if let Some(expires) = self.expires {
            set = set.with_expires(expires);
        }
        if let Some(same_site) = self.same_site {
            set = set.with_same_site(same_site);
        }
        set
    }

    /// Whether this cookie is the same cookie as `other` for replacement:
    /// same name, domain, host-only flag and path (RFC 6265bis §5.7
    /// step 22).
    fn same_identity(&self, other: &Self) -> bool {
        self.name == other.name
            && self.domain == other.domain
            && self.host_only == other.host_only
            && self.path == other.path
    }
}

/// What [`CookieJar::store`] did with an accepted cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StoreOutcome {
    /// A new cookie was added.
    Inserted,
    /// An existing cookie with the same name, domain and path was
    /// replaced (keeping its creation time).
    Replaced,
    /// The cookie had already expired and deleted the existing cookie
    /// with the same name, domain and path.
    Removed,
    /// The cookie had already expired and there was nothing to delete.
    Discarded,
}

/// An in-memory cookie jar ([RFC 6265 §5.3], [§5.4]).
///
/// Sans-I/O: the caller passes the request URL, the [`RequestContext`]
/// and the current time to every call, so behaviour is deterministic and
/// testable. Cookies are kept in creation order.
///
/// ```
/// use std::time::{Duration, SystemTime};
/// use rune_cookie::{CookieJar, RequestContext};
/// use url::Url;
///
/// let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
/// let ctx = RequestContext::http();
/// let mut jar = CookieJar::new();
///
/// let login = Url::parse("https://shop.example.com/account/login").unwrap();
/// jar.store(&login, "sid=abc; Secure; HttpOnly; Path=/", &ctx, now)?;
/// jar.store(&login, "pref=dark; Domain=example.com; Path=/; Max-Age=3600", &ctx, now)?;
/// // Rejected: `com` is a public suffix.
/// assert!(jar.store(&login, "evil=1; Domain=com", &ctx, now).is_err());
///
/// let cart = Url::parse("https://shop.example.com/cart").unwrap();
/// assert_eq!(jar.cookie_header(&cart, &ctx, now)?.as_deref(), Some("sid=abc; pref=dark"));
///
/// let blog = Url::parse("http://blog.example.com/").unwrap();
/// assert_eq!(jar.cookie_header(&blog, &ctx, now)?.as_deref(), Some("pref=dark"));
///
/// let later = now + Duration::from_secs(7200);
/// assert_eq!(jar.cookie_header(&blog, &ctx, later)?, None);
/// # Ok::<(), rune_cookie::Error>(())
/// ```
///
/// [RFC 6265 §5.3]: https://www.rfc-editor.org/rfc/rfc6265#section-5.3
/// [§5.4]: https://www.rfc-editor.org/rfc/rfc6265#section-5.4
#[derive(Debug, Clone, Default)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
    options: JarOptions,
}

impl CookieJar {
    /// An empty jar with the default [`JarOptions`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty jar with `options`.
    #[must_use]
    pub const fn with_options(options: JarOptions) -> Self {
        Self {
            cookies: Vec::new(),
            options,
        }
    }

    /// A jar holding previously saved `cookies` (for example from
    /// [`CookieJar::iter`] with the `serde` feature), in their creation
    /// order. They are not re-validated.
    #[must_use]
    pub fn from_cookies(options: JarOptions, cookies: impl IntoIterator<Item = Cookie>) -> Self {
        let mut cookies: Vec<Cookie> = cookies.into_iter().collect();
        cookies.sort_by_key(|cookie| cookie.creation_time);
        Self { cookies, options }
    }

    /// The jar's options.
    #[must_use]
    pub const fn options(&self) -> &JarOptions {
        &self.options
    }

    /// The number of cookies held, expired ones included until the next
    /// store, lookup or [`CookieJar::remove_expired`].
    #[must_use]
    pub const fn len(&self) -> usize {
        self.cookies.len()
    }

    /// Whether the jar is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Every cookie, in creation order.
    pub fn iter(&self) -> impl Iterator<Item = &Cookie> {
        self.cookies.iter()
    }

    /// The cookie with exactly this domain, path and name, if any.
    #[must_use]
    pub fn get(&self, domain: &str, path: &str, name: &str) -> Option<&Cookie> {
        self.cookies
            .iter()
            .find(|c| c.domain == domain && c.path == path && c.name == name)
    }

    /// Removes the cookies with exactly this domain, path and name (a
    /// host-only and a domain cookie may both exist) and returns them.
    pub fn remove(&mut self, domain: &str, path: &str, name: &str) -> Vec<Cookie> {
        let (removed, kept) = std::mem::take(&mut self.cookies)
            .into_iter()
            .partition(|c| c.domain == domain && c.path == path && c.name == name);
        self.cookies = kept;
        removed
    }

    /// Removes every cookie.
    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    /// Removes session (non-persistent) cookies, as at the end of a
    /// session. Returns how many were removed.
    pub fn clear_session_cookies(&mut self) -> usize {
        let before = self.cookies.len();
        self.cookies.retain(Cookie::is_persistent);
        before - self.cookies.len()
    }

    /// Removes cookies that have expired at `now`. Returns how many were
    /// removed.
    pub fn remove_expired(&mut self, now: SystemTime) -> usize {
        let before = self.cookies.len();
        self.cookies.retain(|cookie| !cookie.is_expired(now));
        before - self.cookies.len()
    }

    /// Parses a `Set-Cookie` header value received in the response to a
    /// request for `url`, and stores it ([RFC 6265 §5.3]).
    ///
    /// # Errors
    ///
    /// A parse error from [`SetCookie::parse`], [`Error::NoHost`] if `url`
    /// has no host, or [`Error::Rejected`] if the jar's rules refuse the
    /// cookie.
    ///
    /// [RFC 6265 §5.3]: https://www.rfc-editor.org/rfc/rfc6265#section-5.3
    pub fn store(
        &mut self,
        url: &Url,
        set_cookie: &str,
        ctx: &RequestContext,
        now: SystemTime,
    ) -> Result<StoreOutcome, Error> {
        let parsed = SetCookie::parse(set_cookie)?;
        self.store_parsed(url, &parsed, ctx, now)
    }

    /// Stores an already parsed cookie received in the response to a
    /// request for `url`. See [`CookieJar::store`].
    ///
    /// # Errors
    ///
    /// [`Error::NoHost`] or [`Error::Rejected`].
    pub fn store_parsed(
        &mut self,
        url: &Url,
        set_cookie: &SetCookie,
        ctx: &RequestContext,
        now: SystemTime,
    ) -> Result<StoreOutcome, Error> {
        let cookie = self.admit(url, set_cookie, *ctx, now)?;
        let expired = cookie.is_expired(now) || set_cookie.max_age.is_some_and(|age| age <= 0);
        let existing = self
            .cookies
            .iter()
            .position(|old| old.same_identity(&cookie));
        if let Some(index) = existing
            && ctx.api == Api::NonHttp
            && self.cookies.get(index).is_some_and(|c| c.http_only)
        {
            return Err(Rejection::OverwritesHttpOnly.into());
        }
        let outcome = match (existing, expired) {
            (Some(index), true) => {
                self.cookies.remove(index);
                StoreOutcome::Removed
            }
            (None, true) => StoreOutcome::Discarded,
            (Some(index), false) => {
                if let Some(old) = self.cookies.get_mut(index) {
                    let creation_time = old.creation_time;
                    *old = Cookie {
                        creation_time,
                        ..cookie
                    };
                }
                StoreOutcome::Replaced
            }
            (None, false) => {
                let domain = cookie.domain.clone();
                self.cookies.push(cookie);
                self.evict(&domain, now);
                StoreOutcome::Inserted
            }
        };
        Ok(outcome)
    }

    /// Builds the cookie to store, or the reason it is refused (RFC 6265
    /// §5.3 steps 2–10, RFC 6265bis §5.7 steps 14–21).
    fn admit(
        &self,
        url: &Url,
        set: &SetCookie,
        ctx: RequestContext,
        now: SystemTime,
    ) -> Result<Cookie, Error> {
        let host = canonical_host(url).ok_or(Error::NoHost)?;
        let secure_origin = is_secure_scheme(url);
        let options = &self.options;

        let expires = match set.max_age {
            Some(age) if age <= 0 => Some(UNIX_EPOCH),
            Some(age) => Some(
                now.checked_add(Duration::from_secs(age.unsigned_abs()))
                    .or_else(|| system_time_from_unix(LATEST_EXPIRY_UNIX))
                    .unwrap_or(now),
            ),
            None => set.expires,
        };
        let expires = match (expires, options.max_lifetime) {
            (Some(expires), Some(max)) => {
                Some(now.checked_add(max).map_or(expires, |cap| expires.min(cap)))
            }
            (expires, _) => expires,
        };

        let mut domain_attr = match &set.domain {
            Some(domain) => {
                Some(
                    canonicalize_domain(domain).ok_or_else(|| Rejection::InvalidDomain {
                        domain: domain.clone(),
                    })?,
                )
            }
            None => None,
        };
        if let (Some(domain), Some(list)) = (&domain_attr, &options.public_suffix_list)
            && list.is_public_suffix(domain)
        {
            if *domain == host {
                domain_attr = None;
            } else {
                return Err(Rejection::PublicSuffix {
                    domain: domain.clone(),
                }
                .into());
            }
        }
        let (domain, host_only) = match domain_attr {
            Some(domain) => {
                if !domain_match(&host, &domain) {
                    return Err(Rejection::DomainMismatch { host, domain }.into());
                }
                (domain, false)
            }
            None => (host, true),
        };
        let path = set
            .path
            .clone()
            .unwrap_or_else(|| default_path(url.path()).to_owned());

        if set.http_only && ctx.api == Api::NonHttp {
            return Err(Rejection::HttpOnlyFromNonHttp.into());
        }
        if options.strict_secure && set.secure && !secure_origin {
            return Err(Rejection::SecureFromInsecureOrigin.into());
        }
        if options.strict_secure && !set.secure && !secure_origin {
            let shadows_secure = self.cookies.iter().any(|old| {
                old.secure
                    && old.name == set.name
                    && (domain_match(&old.domain, &domain) || domain_match(&domain, &old.domain))
                    && path_match(&path, &old.path)
            });
            if shadows_secure {
                return Err(Rejection::OverwritesSecure.into());
            }
        }
        let same_site = set.same_site;
        if options.same_site_store_check
            && ctx.site == SiteContext::CrossSite
            && matches!(
                self.effective_same_site(same_site),
                Some(SameSite::Strict | SameSite::Lax)
            )
        {
            return Err(Rejection::CrossSiteSameSite.into());
        }
        if options.same_site_none_requires_secure
            && same_site == Some(SameSite::None)
            && !set.secure
        {
            return Err(Rejection::SameSiteNoneWithoutSecure.into());
        }
        if options.cookie_prefixes {
            if set.has_secure_prefix() && !(set.secure && secure_origin) {
                return Err(Rejection::SecurePrefix.into());
            }
            if set.has_host_prefix()
                && !(set.secure
                    && secure_origin
                    && set.domain.is_none()
                    && set.path.as_deref() == Some("/"))
            {
                return Err(Rejection::HostPrefix.into());
            }
        }

        Ok(Cookie {
            name: set.name.clone(),
            value: set.value.clone(),
            domain,
            path,
            expires,
            creation_time: now,
            last_access_time: now,
            host_only,
            secure: set.secure,
            http_only: set.http_only,
            same_site,
            partitioned: set.partitioned,
        })
    }

    /// `SameSite` as enforced: unset means `Lax` under
    /// [`JarOptions::lax_by_default`].
    fn effective_same_site(&self, same_site: Option<SameSite>) -> Option<SameSite> {
        same_site.or_else(|| self.options.lax_by_default.then_some(SameSite::Lax))
    }

    /// Drops expired cookies, then the least recently used cookies of
    /// `domain` and of the whole jar beyond the limits (RFC 6265 §5.3
    /// step 12).
    fn evict(&mut self, domain: &str, now: SystemTime) {
        self.remove_expired(now);
        loop {
            let in_domain = self.cookies.iter().filter(|c| c.domain == domain).count();
            if in_domain <= self.options.max_cookies_per_domain {
                break;
            }
            if !self.remove_least_recent(|c| c.domain == domain) {
                break;
            }
        }
        while self.cookies.len() > self.options.max_cookies {
            if !self.remove_least_recent(|_| true) {
                break;
            }
        }
    }

    /// Removes the least recently accessed cookie among those matching
    /// `filter` (the earliest created on a tie).
    fn remove_least_recent(&mut self, filter: impl Fn(&Cookie) -> bool) -> bool {
        let victim = self
            .cookies
            .iter()
            .enumerate()
            .filter(|(_, c)| filter(c))
            .min_by_key(|(index, c)| (c.last_access_time, *index))
            .map(|(index, _)| index);
        match victim {
            Some(index) => {
                self.cookies.remove(index);
                true
            }
            None => false,
        }
    }

    /// The cookies to send with a request for `url`, in the order of
    /// RFC 6265 §5.4 step 2 (longer paths first, then earlier creation),
    /// updating their last-access time to `now`. Expired cookies are
    /// purged first.
    ///
    /// # Errors
    ///
    /// [`Error::NoHost`] if `url` has no host.
    pub fn cookies_for(
        &mut self,
        url: &Url,
        ctx: &RequestContext,
        now: SystemTime,
    ) -> Result<Vec<&Cookie>, Error> {
        let host = canonical_host(url).ok_or(Error::NoHost)?;
        let secure = is_secure_scheme(url);
        let path = url.path();
        self.remove_expired(now);

        let mut selected: Vec<usize> = self
            .cookies
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                let domain_ok = if c.host_only {
                    c.domain == host
                } else {
                    domain_match(&host, &c.domain)
                };
                domain_ok
                    && path_match(path, &c.path)
                    && (!c.secure || secure)
                    && (!c.http_only || ctx.api == Api::Http)
                    && self.same_site_allows(c, *ctx)
            })
            .map(|(index, _)| index)
            .collect();
        selected.sort_by_key(|&index| {
            self.cookies
                .get(index)
                .map(|c| (std::cmp::Reverse(c.path.len()), c.creation_time, index))
        });
        for &index in &selected {
            if let Some(cookie) = self.cookies.get_mut(index) {
                cookie.last_access_time = now;
            }
        }
        Ok(selected
            .into_iter()
            .filter_map(|index| self.cookies.get(index))
            .collect())
    }

    /// The `Cookie` header value for a request for `url`, or `None` if no
    /// cookie applies. See [`CookieJar::cookies_for`].
    ///
    /// # Errors
    ///
    /// [`Error::NoHost`] if `url` has no host.
    pub fn cookie_header(
        &mut self,
        url: &Url,
        ctx: &RequestContext,
        now: SystemTime,
    ) -> Result<Option<String>, Error> {
        let cookies = self.cookies_for(url, ctx, now)?;
        if cookies.is_empty() {
            return Ok(None);
        }
        let pairs: Vec<CookiePair> = cookies.iter().map(|c| c.pair()).collect();
        Ok(Some(crate::serialize_cookie_header(&pairs)))
    }

    fn same_site_allows(&self, cookie: &Cookie, ctx: RequestContext) -> bool {
        match self.effective_same_site(cookie.same_site) {
            Some(SameSite::Strict) => ctx.site == SiteContext::SameSite,
            Some(SameSite::Lax) => {
                ctx.site == SiteContext::SameSite
                    || (ctx.site == SiteContext::CrossSiteTopLevelNavigation && ctx.safe_method)
            }
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn header(jar: &mut CookieJar, target: &str) -> Option<String> {
        jar.cookie_header(&url(target), &RequestContext::http(), now())
            .unwrap()
    }

    fn store(jar: &mut CookieJar, origin: &str, set_cookie: &str) -> Result<StoreOutcome, Error> {
        jar.store(&url(origin), set_cookie, &RequestContext::http(), now())
    }

    #[test]
    fn host_only_vs_domain() {
        let mut jar = CookieJar::new();
        store(&mut jar, "http://example.com/", "a=1").unwrap();
        store(&mut jar, "http://example.com/", "b=2; Domain=example.com").unwrap();
        assert_eq!(
            header(&mut jar, "http://example.com/").as_deref(),
            Some("a=1; b=2")
        );
        assert_eq!(
            header(&mut jar, "http://www.example.com/").as_deref(),
            Some("b=2")
        );
        assert_eq!(header(&mut jar, "http://example.org/"), None);
    }

    #[test]
    fn domain_rejections() {
        let mut jar = CookieJar::new();
        assert_eq!(
            store(&mut jar, "http://www.example.com/", "a=1; Domain=other.com"),
            Err(Error::Rejected(Rejection::DomainMismatch {
                host: "www.example.com".into(),
                domain: "other.com".into()
            }))
        );
        assert_eq!(
            store(&mut jar, "http://www.example.co.uk/", "a=1; Domain=co.uk"),
            Err(Error::Rejected(Rejection::PublicSuffix {
                domain: "co.uk".into()
            }))
        );
        // Private-section suffixes count too.
        assert!(store(&mut jar, "https://me.github.io/", "a=1; Domain=github.io").is_err());
        // A public suffix that is the host itself becomes host-only.
        assert_eq!(
            store(&mut jar, "http://co.uk/", "a=1; Domain=co.uk"),
            Ok(StoreOutcome::Inserted)
        );
        assert!(jar.iter().all(|c| c.host_only));
        // IP literals only match exactly.
        assert!(store(&mut jar, "http://10.0.0.1/", "a=1; Domain=0.0.1").is_err());
        assert!(store(&mut jar, "http://10.0.0.1/", "a=1; Domain=10.0.0.1").is_ok());
        assert!(!jar.is_empty());
    }

    #[test]
    fn without_public_suffix_list() {
        let mut jar = CookieJar::with_options(JarOptions::default().with_public_suffix_list(None));
        assert!(store(&mut jar, "http://www.example.co.uk/", "a=1; Domain=co.uk").is_ok());
        assert_eq!(
            header(&mut jar, "http://other.co.uk/").as_deref(),
            Some("a=1")
        );
    }

    #[test]
    fn idn_domain_attribute() {
        let mut jar = CookieJar::new();
        store(
            &mut jar,
            "http://www.bücher.example/",
            "a=1; Domain=Bücher.example",
        )
        .unwrap();
        assert_eq!(jar.iter().next().unwrap().domain, "xn--bcher-kva.example");
        assert_eq!(
            header(&mut jar, "http://shop.xn--bcher-kva.example/").as_deref(),
            Some("a=1")
        );
    }

    #[test]
    fn replace_keeps_creation_time_and_delete() {
        let mut jar = CookieJar::new();
        let ctx = RequestContext::http();
        let origin = url("http://example.com/");
        jar.store(&origin, "a=1", &ctx, now()).unwrap();
        let later = now() + Duration::from_secs(10);
        assert_eq!(
            jar.store(&origin, "a=2", &ctx, later),
            Ok(StoreOutcome::Replaced)
        );
        let cookie = jar.get("example.com", "/", "a").unwrap();
        assert_eq!(cookie.value, "2");
        assert_eq!(cookie.creation_time, now());
        assert_eq!(cookie.last_access_time, later);
        assert_eq!(
            jar.store(&origin, "a=; Max-Age=0", &ctx, later),
            Ok(StoreOutcome::Removed)
        );
        assert_eq!(
            jar.store(&origin, "a=; Max-Age=0", &ctx, later),
            Ok(StoreOutcome::Discarded)
        );
        assert_eq!(
            jar.store(
                &origin,
                "a=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
                &ctx,
                later
            ),
            Ok(StoreOutcome::Discarded)
        );
        assert!(jar.is_empty());
    }

    #[test]
    fn expiry_and_lifetime_cap() {
        let mut jar = CookieJar::with_options(
            JarOptions::default().with_max_lifetime(Some(Duration::from_secs(100))),
        );
        store(&mut jar, "http://example.com/", "a=1; Max-Age=1000").unwrap();
        store(
            &mut jar,
            "http://example.com/",
            "b=1; Max-Age=99999999999999999999",
        )
        .unwrap();
        store(&mut jar, "http://example.com/", "s=1").unwrap();
        let cap = now() + Duration::from_secs(100);
        assert!(
            jar.iter()
                .filter(|c| c.is_persistent())
                .all(|c| c.expires == Some(cap))
        );
        let ctx = RequestContext::http();
        let target = url("http://example.com/");
        assert_eq!(
            jar.cookie_header(&target, &ctx, cap).unwrap().as_deref(),
            Some("s=1")
        );
        assert_eq!(jar.len(), 1);
        assert_eq!(jar.clear_session_cookies(), 1);

        let mut jar = CookieJar::new();
        store(
            &mut jar,
            "http://example.com/",
            "b=1; Max-Age=99999999999999999999",
        )
        .unwrap();
        assert!(jar.iter().next().unwrap().expires.is_some());
        // Max-Age wins over Expires.
        store(
            &mut jar,
            "http://example.com/",
            "c=1; Max-Age=10; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        )
        .unwrap();
        assert_eq!(jar.len(), 2);
    }

    #[test]
    fn path_scoping_and_order() {
        let mut jar = CookieJar::new();
        let ctx = RequestContext::http();
        let origin = url("http://example.com/a/b/page");
        jar.store(&origin, "x=default", &ctx, now()).unwrap();
        jar.store(&origin, "y=root; Path=/", &ctx, now()).unwrap();
        jar.store(&origin, "z=deep; Path=/a/b/c", &ctx, now())
            .unwrap();
        assert_eq!(
            jar.get("example.com", "/a/b", "x")
                .map(|c| c.value.as_str()),
            Some("default")
        );
        assert_eq!(
            header(&mut jar, "http://example.com/a/b/c/d").as_deref(),
            Some("z=deep; x=default; y=root")
        );
        assert_eq!(
            header(&mut jar, "http://example.com/a/bc").as_deref(),
            Some("y=root")
        );
    }

    #[test]
    fn http_only_and_non_http_api() {
        let mut jar = CookieJar::new();
        let origin = url("http://example.com/");
        let script = RequestContext::non_http();
        assert_eq!(
            jar.store(&origin, "a=1; HttpOnly", &script, now()),
            Err(Error::Rejected(Rejection::HttpOnlyFromNonHttp))
        );
        store(&mut jar, "http://example.com/", "a=1; HttpOnly").unwrap();
        assert_eq!(
            jar.store(&origin, "a=2", &script, now()),
            Err(Error::Rejected(Rejection::OverwritesHttpOnly))
        );
        jar.store(&origin, "b=2", &script, now()).unwrap();
        assert_eq!(
            jar.cookie_header(&origin, &script, now())
                .unwrap()
                .as_deref(),
            Some("b=2")
        );
        assert_eq!(
            header(&mut jar, "http://example.com/").as_deref(),
            Some("a=1; b=2")
        );
    }

    #[test]
    fn strict_secure() {
        let mut jar = CookieJar::new();
        assert_eq!(
            store(&mut jar, "http://example.com/", "a=1; Secure"),
            Err(Error::Rejected(Rejection::SecureFromInsecureOrigin))
        );
        store(
            &mut jar,
            "https://example.com/",
            "a=1; Secure; Domain=example.com",
        )
        .unwrap();
        assert_eq!(
            store(&mut jar, "http://www.example.com/", "a=evil"),
            Err(Error::Rejected(Rejection::OverwritesSecure))
        );
        store(&mut jar, "http://www.example.com/", "b=fine").unwrap();
        assert_eq!(
            header(&mut jar, "http://www.example.com/").as_deref(),
            Some("b=fine")
        );
        assert_eq!(
            header(&mut jar, "https://www.example.com/").as_deref(),
            Some("a=1; b=fine")
        );
        assert_eq!(
            header(&mut jar, "wss://example.com/").as_deref(),
            Some("a=1")
        );

        let mut jar = CookieJar::with_options(JarOptions::rfc6265());
        store(&mut jar, "http://example.com/", "a=1; Secure").unwrap();
        assert_eq!(header(&mut jar, "http://example.com/"), None);
        assert_eq!(
            header(&mut jar, "https://example.com/").as_deref(),
            Some("a=1")
        );
    }

    #[test]
    fn prefixes() {
        let mut jar = CookieJar::new();
        let https = "https://example.com/x/y";
        assert_eq!(
            store(&mut jar, https, "__Secure-a=1"),
            Err(Error::Rejected(Rejection::SecurePrefix))
        );
        assert!(store(&mut jar, https, "__secure-a=1; Secure").is_ok());
        for bad in [
            "__Host-b=1; Secure",
            "__Host-b=1; Secure; Path=/x",
            "__Host-b=1; Secure; Path=/; Domain=example.com",
            "__Host-b=1; Path=/",
        ] {
            assert_eq!(
                store(&mut jar, https, bad),
                Err(Error::Rejected(Rejection::HostPrefix)),
                "{bad}"
            );
        }
        assert!(store(&mut jar, https, "__Host-b=1; Secure; Path=/").is_ok());
        let mut jar = CookieJar::with_options(JarOptions::rfc6265());
        assert!(store(&mut jar, "http://example.com/", "__Host-b=1").is_ok());
    }

    #[test]
    fn same_site() {
        let mut jar = CookieJar::new();
        let origin = url("https://example.com/");
        let http = RequestContext::http();
        jar.store(&origin, "s=1; SameSite=Strict", &http, now())
            .unwrap();
        jar.store(&origin, "l=1; SameSite=Lax", &http, now())
            .unwrap();
        jar.store(&origin, "n=1; SameSite=None; Secure", &http, now())
            .unwrap();
        jar.store(&origin, "u=1", &http, now()).unwrap();
        let cases = [
            (http, "s=1; l=1; n=1; u=1"),
            (
                http.with_site(SiteContext::CrossSiteTopLevelNavigation),
                "l=1; n=1; u=1",
            ),
            (
                http.with_site(SiteContext::CrossSiteTopLevelNavigation)
                    .with_method("POST"),
                "n=1; u=1",
            ),
            (http.with_site(SiteContext::CrossSite), "n=1; u=1"),
        ];
        for (ctx, expected) in cases {
            assert_eq!(
                jar.cookie_header(&origin, &ctx, now()).unwrap().as_deref(),
                Some(expected)
            );
        }

        let cross = http.with_site(SiteContext::CrossSite);
        assert_eq!(
            jar.store(&origin, "x=1; SameSite=Lax", &cross, now()),
            Err(Error::Rejected(Rejection::CrossSiteSameSite))
        );
        assert!(jar.store(&origin, "x=1", &cross, now()).is_ok());
        assert_eq!(
            jar.store(&origin, "y=1; SameSite=None", &http, now()),
            Err(Error::Rejected(Rejection::SameSiteNoneWithoutSecure))
        );

        let mut jar = CookieJar::with_options(JarOptions::default().with_lax_by_default(true));
        jar.store(&origin, "u=1", &http, now()).unwrap();
        assert_eq!(jar.cookie_header(&origin, &cross, now()).unwrap(), None);
        assert_eq!(
            jar.store(&origin, "v=1", &cross, now()),
            Err(Error::Rejected(Rejection::CrossSiteSameSite))
        );
    }

    #[test]
    fn eviction() {
        let opts = JarOptions::default()
            .with_max_cookies_per_domain(2)
            .with_max_cookies(3);
        let mut jar = CookieJar::with_options(opts);
        let ctx = RequestContext::http();
        let a = url("http://a.example/");
        let b = url("http://b.example/");
        let t = |s: u64| now() + Duration::from_secs(s);
        jar.store(&a, "a1=1", &ctx, t(0)).unwrap();
        jar.store(&a, "a2=1; Path=/x", &ctx, t(1)).unwrap();
        // Touch a1 so a2 is the least recently used.
        jar.cookie_header(&a, &ctx, t(2)).unwrap();
        jar.store(&a, "a3=1", &ctx, t(3)).unwrap();
        let names: Vec<_> = jar.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a1", "a3"]);
        jar.store(&b, "b1=1", &ctx, t(4)).unwrap();
        jar.store(&b, "b2=1", &ctx, t(5)).unwrap();
        let names: Vec<_> = jar.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a3", "b1", "b2"]);
    }

    #[test]
    fn no_host() {
        let mut jar = CookieJar::new();
        let data = url("data:text/plain,hi");
        let ctx = RequestContext::http();
        assert_eq!(jar.store(&data, "a=1", &ctx, now()), Err(Error::NoHost));
        assert_eq!(jar.cookie_header(&data, &ctx, now()), Err(Error::NoHost));
    }

    #[test]
    fn export_and_restore() {
        let mut jar = CookieJar::new();
        store(
            &mut jar,
            "https://www.example.com/a/",
            "h=1; Secure; SameSite=Lax; Max-Age=60",
        )
        .unwrap();
        store(
            &mut jar,
            "https://www.example.com/a/",
            "d=2; Domain=example.com; HttpOnly; Partitioned",
        )
        .unwrap();
        let sets: Vec<String> = jar.iter().map(|c| c.to_set_cookie().to_string()).collect();
        assert_eq!(
            sets,
            [
                "h=1; Expires=Tue, 14 Nov 2023 22:14:20 GMT; Path=/a; Secure; SameSite=Lax",
                "d=2; Domain=example.com; Path=/a; HttpOnly; Partitioned",
            ]
        );
        let mut copy = CookieJar::new();
        for set in &sets {
            store(&mut copy, "https://www.example.com/a/", set).unwrap();
        }
        assert_eq!(
            copy.iter().collect::<Vec<_>>(),
            jar.iter().collect::<Vec<_>>()
        );
        let restored = CookieJar::from_cookies(JarOptions::default(), jar.iter().cloned());
        assert_eq!(restored.len(), 2);
        assert_eq!(jar.remove("example.com", "/a", "d").len(), 1);
        jar.clear();
        assert!(jar.is_empty());
    }
}
