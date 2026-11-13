//! Token-free CSRF protection from `Sec-Fetch-Site` and `Origin`.

use std::fmt;
use std::sync::Arc;

use http::{HeaderMap, StatusCode, header, request::Parts};

use crate::layer::CsrfRejection;

type BypassFn = dyn Fn(&Parts) -> bool + Send + Sync;

/// Configuration for the token-free, header-only CSRF mode.
///
/// Pass it to [`CsrfLayer::origin`](crate::CsrfLayer::origin), or use
/// [`CsrfLayer::origin_only`](crate::CsrfLayer::origin_only) for the defaults.
/// No cookie is set and no token is needed: browsers already say where a request
/// comes from, and this mode refuses state-changing requests from anywhere else.
///
/// Safe methods (GET, HEAD, OPTIONS, TRACE) always pass. Every other method is
/// accepted when:
///
/// 1. `Sec-Fetch-Site` is `same-origin` or `none` (the user typed the URL or used
///    a bookmark); otherwise
/// 2. `Origin` is present and equals the request's own origin (scheme, host and
///    port, compared case-insensitively with default ports dropped) or a
///    [trusted origin](Self::trusted_origin). `Origin: null` never matches.
///    A request whose `Sec-Fetch-Site` says `same-site` or `cross-site` but has no
///    `Origin` is rejected;
/// 3. a request with neither header is rejected unless
///    [`allow_missing_headers`](Self::allow_missing_headers) is on.
///
/// Rejections are the same as in token mode: a bare `403` (configurable) with
/// `Cache-Control: no-store` and a [`CsrfRejection`] response extension.
///
/// # Examples
///
/// ```rust
/// use rune_axum_csrf::{CsrfLayer, CsrfOriginConfig};
///
/// let layer = CsrfLayer::origin(
///     CsrfOriginConfig::new()
///         .trusted_origin("https://app.example.com") // separate front end
///         .trust_proxy_headers(true)                  // TLS ends at the proxy
///         .allow_missing_headers(true)                // curl, server-to-server
///         .exempt_prefix("/webhooks/"),
/// );
/// # let _ = layer;
/// ```
#[derive(Clone)]
pub struct CsrfOriginConfig {
    trusted_origins: Vec<String>,
    exempt_paths: Vec<String>,
    exempt_prefixes: Vec<String>,
    bypass: Vec<Arc<BypassFn>>,
    allow_missing: bool,
    trust_proxy: bool,
    assume_https: bool,
    pub(crate) status: StatusCode,
}

impl Default for CsrfOriginConfig {
    fn default() -> Self {
        Self {
            trusted_origins: Vec::new(),
            exempt_paths: Vec::new(),
            exempt_prefixes: Vec::new(),
            bypass: Vec::new(),
            allow_missing: false,
            trust_proxy: false,
            assume_https: true,
            status: StatusCode::FORBIDDEN,
        }
    }
}

impl fmt::Debug for CsrfOriginConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CsrfOriginConfig")
            .field("trusted_origins", &self.trusted_origins)
            .field("exempt_paths", &self.exempt_paths)
            .field("exempt_prefixes", &self.exempt_prefixes)
            .field("bypass_hooks", &self.bypass.len())
            .field("allow_missing_headers", &self.allow_missing)
            .field("trust_proxy_headers", &self.trust_proxy)
            .field("assume_https", &self.assume_https)
            .field("status", &self.status)
            .finish()
    }
}

impl CsrfOriginConfig {
    /// Creates a configuration with secure defaults: requests without `Origin` and
    /// `Sec-Fetch-Site` are rejected, proxy headers are ignored, the server is
    /// assumed to be reached over `https` unless the request URI says otherwise,
    /// and rejections are `403 Forbidden`.
    ///
    /// ```rust
    /// use rune_axum_csrf::CsrfOriginConfig;
    ///
    /// let config = CsrfOriginConfig::new();
    /// assert!(format!("{config:?}").contains("allow_missing_headers: false"));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accepts unsafe requests from this extra origin (`scheme://host[:port]`),
    /// whatever `Sec-Fetch-Site` says. Case and default ports are normalised;
    /// malformed values (paths, user info, `null`) are ignored, so they never
    /// widen what is accepted.
    ///
    /// ```rust
    /// use rune_axum_csrf::CsrfOriginConfig;
    ///
    /// let config = CsrfOriginConfig::new().trusted_origin("HTTPS://App.Example.com:443");
    /// assert!(format!("{config:?}").contains("https://app.example.com"));
    /// ```
    #[must_use]
    pub fn trusted_origin(mut self, origin: impl AsRef<str>) -> Self {
        if let Some(o) = parse_origin(origin.as_ref().trim().trim_end_matches('/')) {
            self.trusted_origins.push(o);
        }
        self
    }

    /// Accepts unsafe requests that carry neither `Origin` nor `Sec-Fetch-Site`
    /// (default `false`).
    ///
    /// Every current browser sends `Origin` on cross-origin state-changing
    /// requests, so such requests come from non-browser clients (curl, other
    /// servers, mobile apps) or very old browsers. Turning this on matches Go's
    /// `http.CrossOriginProtection` and is safe when you don't need to support
    /// browsers from before 2020. Leave it off and give API clients their own
    /// [exempt prefix](Self::exempt_prefix) if you prefer to fail closed.
    ///
    /// ```rust
    /// use rune_axum_csrf::CsrfOriginConfig;
    ///
    /// let config = CsrfOriginConfig::new().allow_missing_headers(true);
    /// # let _ = config;
    /// ```
    #[must_use]
    pub const fn allow_missing_headers(mut self, allow: bool) -> Self {
        self.allow_missing = allow;
        self
    }

    /// Reads the request's own scheme and host from `Forwarded` (`proto=`,
    /// `host=`) or `X-Forwarded-Proto` / `X-Forwarded-Host` (default `false`).
    ///
    /// Enable it only behind a reverse proxy that sets or overwrites these
    /// headers, e.g. one that terminates TLS and forwards plain HTTP. The first
    /// (client-facing) value of each header is used.
    ///
    /// ```rust
    /// use rune_axum_csrf::CsrfOriginConfig;
    ///
    /// let config = CsrfOriginConfig::new().trust_proxy_headers(true);
    /// # let _ = config;
    /// ```
    #[must_use]
    pub const fn trust_proxy_headers(mut self, trust: bool) -> Self {
        self.trust_proxy = trust;
        self
    }

    /// The scheme assumed for the request when neither the request URI nor a
    /// trusted proxy header names one: `https` when `true` (default), `http`
    /// otherwise. Set it to `false` for plain-HTTP development servers.
    ///
    /// ```rust
    /// use rune_axum_csrf::CsrfOriginConfig;
    ///
    /// let dev = CsrfOriginConfig::new().assume_https(false);
    /// # let _ = dev;
    /// ```
    #[must_use]
    pub const fn assume_https(mut self, https: bool) -> Self {
        self.assume_https = https;
        self
    }

    /// Skips the check for this exact path (e.g. a signed webhook). Paths are
    /// matched as the layer sees them, i.e. relative to any `nest`.
    ///
    /// ```rust
    /// use rune_axum_csrf::CsrfOriginConfig;
    ///
    /// let config = CsrfOriginConfig::new().exempt_path("/hooks/payments");
    /// # let _ = config;
    /// ```
    #[must_use]
    pub fn exempt_path(mut self, path: impl Into<String>) -> Self {
        self.exempt_paths.push(path.into());
        self
    }

    /// Skips the check for `prefix` and every path below it: `/api/v1`
    /// covers `/api/v1` and `/api/v1/x`, not `/api/v10`. A trailing slash
    /// makes no difference.
    ///
    /// ```rust
    /// use rune_axum_csrf::CsrfOriginConfig;
    ///
    /// let config = CsrfOriginConfig::new().exempt_prefix("/api/v1/");
    /// # let _ = config;
    /// ```
    #[must_use]
    pub fn exempt_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.exempt_prefixes.push(prefix.into());
        self
    }

    /// Adds a hook that lets a request through unchecked when it returns `true`.
    ///
    /// This is an escape hatch, hence the name: anything it lets through is
    /// unprotected. Use it for requests authenticated by other means, such as
    /// a bearer token that browsers never attach on their own. Don't key it on
    /// the mere presence of `Authorization`: browsers do resend cached Basic,
    /// Digest and Negotiate credentials with cross-site form posts.
    /// Hooks run in the order they were added.
    ///
    /// ```rust
    /// use rune_axum_csrf::CsrfOriginConfig;
    ///
    /// // Bearer-token clients are not exposed to CSRF.
    /// let config = CsrfOriginConfig::new().insecure_bypass(|parts| {
    ///     parts
    ///         .headers
    ///         .get(http::header::AUTHORIZATION)
    ///         .and_then(|v| v.to_str().ok())
    ///         .is_some_and(|v| v.get(..7).is_some_and(|s| s.eq_ignore_ascii_case("bearer ")))
    /// });
    /// # let _ = config;
    /// ```
    #[must_use]
    pub fn insecure_bypass<F>(mut self, f: F) -> Self
    where
        F: Fn(&Parts) -> bool + Send + Sync + 'static,
    {
        self.bypass.push(Arc::new(f));
        self
    }

    /// Sets the status code of rejections (default `403 Forbidden`).
    ///
    /// ```rust
    /// use http::StatusCode;
    /// use rune_axum_csrf::CsrfOriginConfig;
    ///
    /// let config = CsrfOriginConfig::new().status(StatusCode::BAD_REQUEST);
    /// # let _ = config;
    /// ```
    #[must_use]
    pub const fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    fn is_exempt(&self, parts: &Parts) -> bool {
        let path = parts.uri.path();
        self.exempt_paths.iter().any(|p| p == path)
            || self
                .exempt_prefixes
                .iter()
                .any(|p| crate::layer::prefix_covers(p, path))
            || self.bypass.iter().any(|f| f(parts))
    }

    /// The request's own origin, normalised like an `Origin` header.
    fn request_origin(&self, parts: &Parts) -> Option<String> {
        let headers = &parts.headers;
        let (fwd_proto, fwd_host) = if self.trust_proxy {
            forwarded(headers)
        } else {
            (None, None)
        };
        let scheme = fwd_proto
            .or_else(|| parts.uri.scheme_str().map(str::to_owned))
            .unwrap_or_else(|| (if self.assume_https { "https" } else { "http" }).to_owned());
        let host = fwd_host
            .or_else(|| {
                headers
                    .get(header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(str::to_owned)
            })
            .or_else(|| parts.uri.authority().map(|a| a.as_str().to_owned()))?;
        parse_origin(&format!("{}://{}", scheme.trim(), host.trim()))
    }

    /// Decides an unsafe request. `Ok` lets it through.
    pub(crate) fn check(&self, parts: &Parts) -> Result<(), CsrfRejection> {
        if self.is_exempt(parts) {
            return Ok(());
        }
        let headers = &parts.headers;
        let fetch_site = single(headers, "sec-fetch-site");
        if let Some(site) = fetch_site
            && (site.eq_ignore_ascii_case(b"same-origin") || site.eq_ignore_ascii_case(b"none"))
        {
            return Ok(());
        }

        let mut origins = headers.get_all(header::ORIGIN).iter();
        let Some(origin) = origins.next() else {
            // A browser that sent Fetch Metadata but no `Origin` on a non-same-origin
            // request is unusual; with no origin to compare, refuse.
            return if headers.contains_key("sec-fetch-site") {
                Err(CsrfRejection::CrossOrigin)
            } else if self.allow_missing {
                Ok(())
            } else {
                Err(CsrfRejection::MissingOrigin)
            };
        };
        if origins.next().is_some() {
            return Err(CsrfRejection::CrossOrigin);
        }
        // `null` (sandboxed frames, `data:` pages, some redirects) and garbage
        // fail to parse and are therefore cross-origin.
        let Some(origin) = origin.to_str().ok().and_then(parse_origin) else {
            return Err(CsrfRejection::CrossOrigin);
        };
        if self.trusted_origins.contains(&origin)
            || self.request_origin(parts).is_some_and(|own| own == origin)
        {
            Ok(())
        } else {
            Err(CsrfRejection::CrossOrigin)
        }
    }
}

/// The value of a header that appears exactly once.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a [u8]> {
    let mut all = headers.get_all(name).iter();
    let first = all.next()?;
    all.next().is_none().then(|| first.as_bytes())
}

/// First `proto` and `host` from `Forwarded`, else from `X-Forwarded-*`.
fn forwarded(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let first_element = headers
        .get(header::FORWARDED)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next());
    let param = |name: &str| {
        first_element.and_then(|element| {
            element.split(';').find_map(|pair| {
                let (k, v) = pair.trim().split_once('=')?;
                k.trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| v.trim().trim_matches('"').to_owned())
            })
        })
    };
    let x_first = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    (
        param("proto").or_else(|| x_first("x-forwarded-proto")),
        param("host").or_else(|| x_first("x-forwarded-host")),
    )
}

/// Parses a serialised origin (`scheme://host[:port]`, nothing else) into its
/// canonical form: lowercase, default port (80 for `http`, 443 for `https`)
/// dropped. Returns `None` for `null`, paths, user info, bad ports or empty hosts.
fn parse_origin(s: &str) -> Option<String> {
    let (scheme, authority) = s.split_once("://")?;
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    if authority.is_empty()
        || authority
            .bytes()
            .any(|b| b"/?#@\\".contains(&b) || b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return None;
    }
    let authority = authority.to_ascii_lowercase();
    // `[v6]:port`, `[v6]`, `host:port` or `host`.
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        if inside.is_empty()
            || !inside
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b".:".contains(&b))
        {
            return None;
        }
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?),
        };
        (format!("[{inside}]"), port)
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h.to_owned(), Some(p)),
            None => (authority.clone(), None),
        }
    };
    if host.is_empty() || (host.contains(['[', ']', ':']) && !host.starts_with('[')) {
        return None;
    }
    let port = match port {
        None => None,
        Some(p) if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) => {
            return None;
        }
        Some(p) => Some(p.parse::<u16>().ok()?),
    };
    let default = match scheme.as_str() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    };
    Some(match port {
        Some(p) if Some(p) != default => format!("{scheme}://{host}:{p}"),
        _ => format!("{scheme}://{host}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn canonical_forms() {
        let cases = [
            ("https://example.com", Some("https://example.com")),
            ("HTTPS://EXAMPLE.com", Some("https://example.com")),
            ("https://example.com:443", Some("https://example.com")),
            ("http://example.com:80", Some("http://example.com")),
            ("http://example.com:443", Some("http://example.com:443")),
            ("https://example.com:8443", Some("https://example.com:8443")),
            (
                "https://example.com:08443",
                Some("https://example.com:8443"),
            ),
            ("http://[::1]:8080", Some("http://[::1]:8080")),
            ("http://[::1]:80", Some("http://[::1]")),
            ("http://[::1]", Some("http://[::1]")),
            ("null", None),
            ("example.com", None),
            ("https://", None),
            ("https://u@example.com", None),
            ("https://example.com/", None),
            ("https://example.com/path", None),
            ("https://example.com:", None),
            ("https://example.com:99999", None),
            ("https://example.com:-1", None),
            ("https://a:b:c", None),
            ("https://[zz]", None),
            ("https://ex ample.com", None),
            ("1http://example.com", None),
        ];
        for (input, want) in cases {
            assert_eq!(parse_origin(input).as_deref(), want, "{input}");
        }
    }

    proptest! {
        #[test]
        fn canonical_form_is_a_fixed_point(s in "[a-zA-Z]{1,6}://[a-zA-Z0-9.-]{1,20}(:[0-9]{1,5})?") {
            if let Some(c) = parse_origin(&s) {
                prop_assert_eq!(parse_origin(&c), Some(c.clone()));
                prop_assert_eq!(c.to_ascii_lowercase(), c);
            }
        }

        #[test]
        fn never_panics(s in ".{0,64}") {
            let _ = parse_origin(&s);
        }
    }

    #[test]
    fn forwarded_prefers_rfc7239() {
        let mut h = HeaderMap::new();
        h.insert(
            header::FORWARDED,
            "for=1.2.3.4;proto=https;host=\"example.com\", for=5.6.7.8;proto=http"
                .parse()
                .unwrap(),
        );
        h.insert("x-forwarded-proto", "http".parse().unwrap());
        assert_eq!(
            forwarded(&h),
            (Some("https".to_owned()), Some("example.com".to_owned()))
        );
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "https, http".parse().unwrap());
        assert_eq!(forwarded(&h), (Some("https".to_owned()), None));
    }
}
