//! Fetching helpers (feature `fetch`): build well-known URLs, fetch them
//! through any [`Fetcher`], and parse the responses.
//!
//! The transport is the caller's: implement [`Fetcher`] for your HTTP
//! client, or enable the `reqwest` feature for [`ReqwestFetcher`].
//! Fetchers must not follow redirects, so that `change-password` can be
//! classified and other resources are only accepted from the origin asked.

use std::future::Future;

use crate::{Error, Resource, Response, WellKnown, parse};

/// An HTTP client that performs one `GET` without following redirects.
pub trait Fetcher {
    /// Transport errors.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Fetches `url` and returns the response as received.
    fn get(&self, url: &str) -> impl Future<Output = Result<Response, Self::Error>> + Send;
}

/// Why fetching a resource failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FetchError<E> {
    /// The origin is not `http(s)://host[:port]`.
    #[error("invalid origin {origin:?}: expected scheme://host[:port]")]
    InvalidOrigin {
        /// The origin as given.
        origin: String,
    },
    /// The transport failed.
    #[error("request failed: {0}")]
    Transport(#[source] E),
    /// The response did not parse.
    #[error(transparent)]
    Parse(#[from] Error),
}

/// One resource found by [`discover`].
#[derive(Debug)]
#[non_exhaustive]
pub struct Discovered<E> {
    /// Which resource.
    pub kind: WellKnown,
    /// The URL fetched.
    pub url: String,
    /// The parsed resource, or why there is none.
    pub result: Result<Resource, FetchError<E>>,
}

/// The URL of `path` on `origin` (`https://example.com`, a trailing `/`
/// allowed). Returns `None` when `origin` has a path, query, fragment or
/// userinfo, or a scheme other than `http` / `https`.
///
/// ```
/// use rune_wellknown::{WellKnown, fetch::url_for};
///
/// assert_eq!(
///     url_for("https://example.com/", &WellKnown::SecurityTxt.path()).as_deref(),
///     Some("https://example.com/.well-known/security.txt")
/// );
/// assert_eq!(url_for("https://example.com/app", "/x"), None);
/// ```
#[must_use]
pub fn url_for(origin: &str, path: &str) -> Option<String> {
    let origin = origin.strip_suffix('/').unwrap_or(origin);
    let (scheme, authority) = origin.split_once("://")?;
    let ok_scheme = scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http");
    let ok_authority = !authority.is_empty()
        && !authority.chars().any(|c| {
            matches!(c, '/' | '?' | '#' | '@' | '\\') || c.is_whitespace() || c.is_control()
        });
    let path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    (ok_scheme && ok_authority).then(|| format!("{origin}{path}"))
}

/// The origin that serves the MTA-STS policy of a mail domain
/// (RFC 8461 §3.3): `https://mta-sts.<domain>`.
#[must_use]
pub fn mta_sts_origin(domain: &str) -> String {
    format!(
        "https://mta-sts.{}",
        domain.strip_suffix('.').unwrap_or(domain)
    )
}

/// Fetches `path` from `origin` and parses it (see [`parse`]).
pub async fn fetch<F: Fetcher + Sync>(
    fetcher: &F,
    origin: &str,
    path: &str,
) -> Result<Resource, FetchError<F::Error>> {
    let url = url_for(origin, path).ok_or_else(|| FetchError::InvalidOrigin {
        origin: origin.to_owned(),
    })?;
    let response = fetcher.get(&url).await.map_err(FetchError::Transport)?;
    Ok(parse(path, &response)?)
}

/// Fetches and parses each of `kinds` from `origin`, one after another.
///
/// Every resource is fetched from `origin` as given; the MTA-STS policy
/// normally lives on [`mta_sts_origin`] instead.
pub async fn discover<F: Fetcher + Sync>(
    fetcher: &F,
    origin: &str,
    kinds: &[WellKnown],
) -> Vec<Discovered<F::Error>> {
    let mut out = Vec::with_capacity(kinds.len());
    for &kind in kinds {
        let path = kind.path();
        let url = url_for(origin, &path).unwrap_or_default();
        let result = fetch(fetcher, origin, &path).await;
        out.push(Discovered { kind, url, result });
    }
    out
}

#[cfg(feature = "reqwest")]
pub use self::reqwest_fetcher::ReqwestFetcher;

#[cfg(feature = "reqwest")]
mod reqwest_fetcher {
    use std::future::Future;
    use std::time::Duration;

    use super::Fetcher;
    use crate::{MAX_BODY_LEN, Response};

    /// A [`Fetcher`] backed by `reqwest` (feature `reqwest`). It needs a
    /// Tokio runtime.
    #[derive(Debug, Clone)]
    pub struct ReqwestFetcher {
        client: reqwest::Client,
        max_body: usize,
    }

    impl ReqwestFetcher {
        /// A client that does not follow redirects, times out after ten
        /// seconds and reads at most [`MAX_BODY_LEN`] + 1 body bytes (so an
        /// oversized body still fails to parse).
        pub fn new() -> Result<Self, reqwest::Error> {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .user_agent(concat!("rune-wellknown/", env!("CARGO_PKG_VERSION")))
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
            let request = self.client.get(url);
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
                Ok(Response {
                    status,
                    headers,
                    body,
                })
            }
        }
    }
}
