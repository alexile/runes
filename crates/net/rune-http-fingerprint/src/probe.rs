//! The probes a fingerprint is built from, and the responses observed.

use std::collections::BTreeMap;
use std::fmt;

use rune_http_model::{ExchangeId, HttpExchange, HttpRequest, HttpResponse, HttpVersion, Url};

use crate::Error;
use crate::error::clip;

/// One request of the [probe plan](probe_plan). Each draws out a different
/// part of a server's default behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ProbeKind {
    /// `GET` of the base URL: the ordinary response.
    Baseline,
    /// `GET` of a path that cannot exist: the default error page.
    NotFound,
    /// `OPTIONS` of the base URL: the `Allow` list.
    Options,
    /// A request with an unregistered method token: how unknown methods
    /// are refused (`405`, `501`, `400` or served as `GET`).
    UnknownMethod,
    /// An HTTP/1.0 `GET` without `Host`: version downgrade behaviour.
    Http10,
}

impl ProbeKind {
    /// Every probe, in the order they appear in fingerprints.
    pub const ALL: [Self; 5] = [
        Self::Baseline,
        Self::NotFound,
        Self::Options,
        Self::UnknownMethod,
        Self::Http10,
    ];

    /// The short name used in raw fingerprints: `base`, `nf`, `opt`, `um`, `h10`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Baseline => "base",
            Self::NotFound => "nf",
            Self::Options => "opt",
            Self::UnknownMethod => "um",
            Self::Http10 => "h10",
        }
    }
}

impl fmt::Display for ProbeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The method token sent by the [`ProbeKind::UnknownMethod`] probe.
pub const UNKNOWN_METHOD: &str = "RUNEFP";

/// The requests to send to fingerprint the server at `base_url`.
///
/// `nonce` makes the [`ProbeKind::NotFound`] path unique (pass a fresh
/// random token per scan; the crate has no randomness of its own). The
/// requests carry no headers: the client adds `Host` (except for
/// [`ProbeKind::Http10`], where it should be omitted) and its usual
/// headers. Send them, then record each response in [`Observations`].
///
/// ```
/// use rune_http_fingerprint::{ProbeKind, probe_plan};
///
/// let plan = probe_plan("https://www.example.test/app/", "x7Kq2")?;
/// assert_eq!(plan.len(), ProbeKind::ALL.len());
/// let (kind, request) = &plan[1];
/// assert_eq!(*kind, ProbeKind::NotFound);
/// assert_eq!(request.url, "https://www.example.test/app/runefp-x7Kq2.html");
/// # Ok::<(), rune_http_fingerprint::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::InvalidUrl`] when `base_url` does not parse or is not
/// `http`/`https`; [`Error::InvalidNonce`] for an unusable nonce.
pub fn probe_plan(base_url: &str, nonce: &str) -> Result<Vec<(ProbeKind, HttpRequest)>, Error> {
    let invalid = |message: String| Error::InvalidUrl {
        url: clip(base_url),
        message,
    };
    let base = Url::parse(base_url).map_err(|error| invalid(error.to_string()))?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(invalid(format!("unsupported scheme {:?}", base.scheme())));
    }
    if nonce.is_empty()
        || nonce.len() > 64
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::InvalidNonce(clip(nonce)));
    }
    let not_found = base
        .join(&format!("runefp-{nonce}.html"))
        .map_err(|error| invalid(error.to_string()))?;
    let base = base.as_str();
    Ok(vec![
        (ProbeKind::Baseline, HttpRequest::get(base)),
        (ProbeKind::NotFound, HttpRequest::get(not_found.as_str())),
        (ProbeKind::Options, HttpRequest::new("OPTIONS", base)),
        (
            ProbeKind::UnknownMethod,
            HttpRequest::new(UNKNOWN_METHOD, base),
        ),
        (
            ProbeKind::Http10,
            HttpRequest::get(base).with_version(HttpVersion::Http10),
        ),
    ])
}

/// The exchanges observed for each probe. Any subset may be present;
/// fingerprints are only comparable between observations of the same
/// probe set.
///
/// ```
/// use rune_http_fingerprint::{Observations, ProbeKind};
/// use rune_http_model::HttpResponse;
///
/// let observations = Observations::new()
///     .with_response(ProbeKind::Baseline, HttpResponse::new(200))
///     .with_response(ProbeKind::NotFound, HttpResponse::new(404));
/// assert_eq!(observations.response(ProbeKind::NotFound).map(|r| r.status), Some(404));
/// assert!(observations.response(ProbeKind::Options).is_none());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observations {
    exchanges: BTreeMap<ProbeKind, HttpExchange>,
}

impl Observations {
    /// No observations.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the exchange of `probe`, replacing any earlier one.
    /// Exchanges without a response count as missing.
    pub fn insert(&mut self, probe: ProbeKind, exchange: HttpExchange) {
        self.exchanges.insert(probe, exchange);
    }

    /// Records the exchange of `probe`.
    #[must_use]
    pub fn with_exchange(mut self, probe: ProbeKind, exchange: HttpExchange) -> Self {
        self.insert(probe, exchange);
        self
    }

    /// Records only the response of `probe`, with a placeholder request.
    #[must_use]
    pub fn with_response(self, probe: ProbeKind, response: HttpResponse) -> Self {
        let exchange = HttpExchange::new(
            ExchangeId(0),
            "rune-http-fingerprint",
            HttpRequest::get(String::new()),
        )
        .with_response(response);
        self.with_exchange(probe, exchange)
    }

    /// The exchange of `probe`, when it has a response.
    #[must_use]
    pub fn exchange(&self, probe: ProbeKind) -> Option<&HttpExchange> {
        self.exchanges
            .get(&probe)
            .filter(|exchange| exchange.response.is_some())
    }

    /// The response of `probe`.
    #[must_use]
    pub fn response(&self, probe: ProbeKind) -> Option<&HttpResponse> {
        self.exchanges.get(&probe)?.response.as_ref()
    }

    /// Whether no probe has a response.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        ProbeKind::ALL
            .iter()
            .all(|probe| self.response(*probe).is_none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_shapes() {
        let plan = probe_plan("http://h.test", "n1").unwrap();
        let kinds: Vec<_> = plan.iter().map(|(kind, _)| *kind).collect();
        assert_eq!(kinds, ProbeKind::ALL);
        assert_eq!(plan[0].1.url, "http://h.test/");
        assert_eq!(plan[1].1.url, "http://h.test/runefp-n1.html");
        assert_eq!(plan[2].1.method, "OPTIONS");
        assert_eq!(plan[3].1.method, UNKNOWN_METHOD);
        assert_eq!(plan[4].1.http_version, HttpVersion::Http10);
        assert!(plan.iter().all(|(_, request)| request.headers.is_empty()));
    }

    #[test]
    fn plan_rejects_bad_input() {
        assert_eq!(
            probe_plan("ftp://h.test/", "n").unwrap_err().code(),
            "invalid_url"
        );
        assert_eq!(probe_plan("::", "n").unwrap_err().code(), "invalid_url");
        for nonce in ["", "a/b", "a b", &"x".repeat(65)] {
            assert_eq!(
                probe_plan("http://h.test/", nonce).unwrap_err().code(),
                "invalid_nonce"
            );
        }
    }

    #[test]
    fn exchanges_without_response_are_missing() {
        let observations = Observations::new().with_exchange(
            ProbeKind::Options,
            HttpExchange::new(ExchangeId(1), "t", HttpRequest::get("http://h/")),
        );
        assert!(observations.exchange(ProbeKind::Options).is_none());
        assert!(observations.is_empty());
        assert_eq!(ProbeKind::Http10.to_string(), "h10");
    }
}
