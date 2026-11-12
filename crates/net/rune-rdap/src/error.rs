//! The crate's error type.

use std::time::Duration;

/// Everything that can go wrong building, routing or answering an RDAP
/// query.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The query text is not a domain, IP address, network, ASN or handle.
    #[error("invalid RDAP query {input:?}: {reason}")]
    InvalidQuery {
        /// The query as given.
        input: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// A bootstrap registry file is malformed.
    #[error("invalid bootstrap registry: {0}")]
    InvalidBootstrap(String),
    /// No bootstrap registry entry covers the query.
    #[error("no RDAP service is registered for {query}")]
    NoService {
        /// The query, as its RDAP path.
        query: String,
    },
    /// The bootstrap registry this query needs has not been loaded.
    #[error("the {0} bootstrap registry is not loaded")]
    MissingRegistry(&'static str),
    /// The server has no such object (HTTP 404).
    #[error("object not found")]
    NotFound,
    /// The server asked the client to slow down (HTTP 429).
    #[error("rate limited by the server{}", retry_hint(*.retry_after))]
    RateLimited {
        /// The `Retry-After` delay, when the server sent one in seconds.
        retry_after: Option<Duration>,
    },
    /// The server answered with an RDAP error response or another failure
    /// status.
    #[error("server error {status}{}", title.as_ref().map(|t| format!(": {t}")).unwrap_or_default())]
    Server {
        /// The HTTP status.
        status: u16,
        /// The RDAP `errorCode`, when the body was an error response.
        error_code: Option<u16>,
        /// The error `title`.
        title: Option<String>,
        /// The error `description` lines.
        description: Vec<String>,
    },
    /// A redirect without a usable `Location`, to a non-HTTP(S) URL, or one
    /// redirect too many.
    #[error("bad redirect: {0}")]
    Redirect(String),
    /// The response body is not a well-formed RDAP object.
    #[error("invalid RDAP response: {0}")]
    InvalidResponse(String),
    /// The response body is larger than the configured limit.
    #[error("response body exceeds {limit} bytes")]
    TooLarge {
        /// The limit in bytes.
        limit: usize,
    },
    /// The transport (the caller's [`Fetcher`](crate::client::Fetcher))
    /// failed.
    #[error("request failed: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),
}

fn retry_hint(retry_after: Option<Duration>) -> String {
    retry_after.map_or_else(String::new, |d| format!(", retry after {}s", d.as_secs()))
}
