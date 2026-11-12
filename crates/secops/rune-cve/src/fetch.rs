//! Fetching from the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
//! through a caller-supplied [`Transport`] (feature `fetch`).
//!
//! The crate does no I/O itself: [`NvdQuery::url`] builds request URLs,
//! [`NvdFeed::from_json`] parses responses, and [`fetch_all`] pages through
//! a result with whatever HTTP client the caller wraps in a [`Transport`].

use core::fmt::Write as _;

use crate::{Cpe, Cve, CveId, Error, NvdFeed};

/// The NVD CVE API 2.0 endpoint.
pub const NVD_CVE_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// The most records the API returns per page.
pub const MAX_RESULTS_PER_PAGE: u32 = 2000;

/// The error type a [`Transport`] returns.
pub type TransportError = Box<dyn std::error::Error + Send + Sync>;

/// Performs one HTTP GET.
///
/// Wrap the HTTP client the caller already uses (`ureq`,
/// `reqwest::blocking`, a test double). The implementation should apply a
/// timeout, return an error for any non-2xx status, and respect NVD's rate
/// limits (5 requests per 30 seconds without an API key, 50 with one) by
/// pausing between calls. Closures with the same signature implement it.
pub trait Transport {
    /// Fetches `url` with the extra request `headers` and returns the
    /// response body.
    ///
    /// # Errors
    ///
    /// Any failure, including a non-2xx status.
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Vec<u8>, TransportError>;
}

impl<F> Transport for F
where
    F: Fn(&str, &[(&str, &str)]) -> Result<Vec<u8>, TransportError>,
{
    fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Vec<u8>, TransportError> {
        self(url, headers)
    }
}

/// The parameters of a CVE API query. Unset parameters are left out.
///
/// # Examples
///
/// ```
/// use rune_cve::fetch::NvdQuery;
///
/// let query = NvdQuery::default()
///     .with_cpe_name("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*".parse()?)
///     .with_vulnerable_only()
///     .with_no_rejected();
/// assert_eq!(
///     query.url(0),
///     "https://services.nvd.nist.gov/rest/json/cves/2.0?\
///      cpeName=cpe%3A2.3%3Aa%3Aapache%3Alog4j%3A2.14.1%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A\
///      &isVulnerable&noRejected&resultsPerPage=2000&startIndex=0"
/// );
/// # Ok::<(), rune_cve::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NvdQuery {
    /// The endpoint, [`NVD_CVE_API`] by default (a mirror or a test URL
    /// otherwise).
    pub base_url: String,
    /// `cveId`: one CVE.
    pub cve_id: Option<CveId>,
    /// `cpeName`: CVEs whose criteria match this concrete product.
    pub cpe_name: Option<Cpe>,
    /// `isVulnerable`: with `cpe_name`, only vulnerable matches.
    pub vulnerable_only: bool,
    /// `virtualMatchString`: CVEs whose criteria overlap this pattern.
    pub virtual_match_string: Option<Cpe>,
    /// `keywordSearch`: words in the description.
    pub keyword_search: Option<String>,
    /// `lastModStartDate` and `lastModEndDate` (ISO 8601, at most 120
    /// days apart).
    pub last_modified: Option<(String, String)>,
    /// `pubStartDate` and `pubEndDate` (ISO 8601, at most 120 days apart).
    pub published: Option<(String, String)>,
    /// `hasKev`: only CVEs in CISA's KEV catalog.
    pub has_kev: bool,
    /// `noRejected`: leave out rejected CVEs.
    pub no_rejected: bool,
    /// `resultsPerPage`, 1 to [`MAX_RESULTS_PER_PAGE`].
    pub results_per_page: u32,
    /// [`fetch_all`] stops with [`Error::Paging`] after this many pages.
    pub max_pages: u32,
}

impl Default for NvdQuery {
    fn default() -> Self {
        Self {
            base_url: NVD_CVE_API.to_owned(),
            cve_id: None,
            cpe_name: None,
            vulnerable_only: false,
            virtual_match_string: None,
            keyword_search: None,
            last_modified: None,
            published: None,
            has_kev: false,
            no_rejected: false,
            results_per_page: MAX_RESULTS_PER_PAGE,
            max_pages: 1000,
        }
    }
}

impl NvdQuery {
    /// Sets [`base_url`](Self::base_url).
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Sets [`cve_id`](Self::cve_id).
    #[must_use]
    pub const fn with_cve_id(mut self, id: CveId) -> Self {
        self.cve_id = Some(id);
        self
    }

    /// Sets [`cpe_name`](Self::cpe_name).
    #[must_use]
    pub fn with_cpe_name(mut self, cpe: Cpe) -> Self {
        self.cpe_name = Some(cpe);
        self
    }

    /// Sets [`vulnerable_only`](Self::vulnerable_only).
    #[must_use]
    pub const fn with_vulnerable_only(mut self) -> Self {
        self.vulnerable_only = true;
        self
    }

    /// Sets [`virtual_match_string`](Self::virtual_match_string).
    #[must_use]
    pub fn with_virtual_match_string(mut self, cpe: Cpe) -> Self {
        self.virtual_match_string = Some(cpe);
        self
    }

    /// Sets [`keyword_search`](Self::keyword_search).
    #[must_use]
    pub fn with_keyword_search(mut self, words: impl Into<String>) -> Self {
        self.keyword_search = Some(words.into());
        self
    }

    /// Sets [`last_modified`](Self::last_modified), for incremental
    /// updates.
    #[must_use]
    pub fn with_last_modified(mut self, start: impl Into<String>, end: impl Into<String>) -> Self {
        self.last_modified = Some((start.into(), end.into()));
        self
    }

    /// Sets [`published`](Self::published).
    #[must_use]
    pub fn with_published(mut self, start: impl Into<String>, end: impl Into<String>) -> Self {
        self.published = Some((start.into(), end.into()));
        self
    }

    /// Sets [`has_kev`](Self::has_kev).
    #[must_use]
    pub const fn with_kev_only(mut self) -> Self {
        self.has_kev = true;
        self
    }

    /// Sets [`no_rejected`](Self::no_rejected).
    #[must_use]
    pub const fn with_no_rejected(mut self) -> Self {
        self.no_rejected = true;
        self
    }

    /// Sets [`results_per_page`](Self::results_per_page), clamped to
    /// 1..=[`MAX_RESULTS_PER_PAGE`].
    #[must_use]
    pub fn with_results_per_page(mut self, n: u32) -> Self {
        self.results_per_page = n.clamp(1, MAX_RESULTS_PER_PAGE);
        self
    }

    /// Sets [`max_pages`](Self::max_pages).
    #[must_use]
    pub const fn with_max_pages(mut self, n: u32) -> Self {
        self.max_pages = n;
        self
    }

    /// The request URL for the page starting at record `start_index`.
    #[must_use]
    pub fn url(&self, start_index: u64) -> String {
        let mut url = self.base_url.clone();
        let mut sep = '?';
        let mut param = |name: &str, value: Option<&str>| {
            url.push(sep);
            sep = '&';
            url.push_str(name);
            if let Some(v) = value {
                url.push('=');
                encode_into(&mut url, v);
            }
        };
        if let Some(id) = &self.cve_id {
            param("cveId", Some(&id.to_string()));
        }
        if let Some(cpe) = &self.cpe_name {
            param("cpeName", Some(&cpe.to_string()));
            if self.vulnerable_only {
                param("isVulnerable", None);
            }
        }
        if let Some(cpe) = &self.virtual_match_string {
            param("virtualMatchString", Some(&cpe.to_string()));
        }
        if let Some(words) = &self.keyword_search {
            param("keywordSearch", Some(words));
        }
        if let Some((start, end)) = &self.last_modified {
            param("lastModStartDate", Some(start));
            param("lastModEndDate", Some(end));
        }
        if let Some((start, end)) = &self.published {
            param("pubStartDate", Some(start));
            param("pubEndDate", Some(end));
        }
        if self.has_kev {
            param("hasKev", None);
        }
        if self.no_rejected {
            param("noRejected", None);
        }
        param(
            "resultsPerPage",
            Some(
                &self
                    .results_per_page
                    .clamp(1, MAX_RESULTS_PER_PAGE)
                    .to_string(),
            ),
        );
        param("startIndex", Some(&start_index.to_string()));
        url
    }
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
fn encode_into(out: &mut String, value: &str) {
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
}

/// Fetches every page of `query` and returns all records.
///
/// `api_key`, when given, is sent in the `apiKey` header.
///
/// # Errors
///
/// [`Error::Transport`] when a request fails, [`Error::Json`] when a page
/// does not parse, and [`Error::Paging`] when a page is empty before the
/// total is reached or there are more than
/// [`max_pages`](NvdQuery::max_pages) pages.
///
/// # Examples
///
/// ```
/// use rune_cve::fetch::{NvdQuery, TransportError, fetch_all};
///
/// // A stand-in for an HTTP client.
/// let transport = |url: &str, _headers: &[(&str, &str)]| -> Result<Vec<u8>, TransportError> {
///     assert!(url.contains("cveId=CVE-2014-0160"));
///     Ok(br#"{"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2014-0160"}}]}"#.to_vec())
/// };
/// let query = NvdQuery::default().with_cve_id("CVE-2014-0160".parse()?);
/// let cves = fetch_all(&transport, &query, None)?;
/// assert_eq!(cves.len(), 1);
/// # Ok::<(), rune_cve::Error>(())
/// ```
pub fn fetch_all<T: Transport + ?Sized>(
    transport: &T,
    query: &NvdQuery,
    api_key: Option<&str>,
) -> Result<Vec<Cve>, Error> {
    let headers: Vec<(&str, &str)> = api_key.map(|k| ("apiKey", k)).into_iter().collect();
    let mut out = Vec::new();
    let mut start: u64 = 0;
    for _ in 0..query.max_pages {
        let body = transport
            .get(&query.url(start), &headers)
            .map_err(Error::Transport)?;
        let page = NvdFeed::from_json(&body)?;
        let total = page.total_results;
        let got = page.vulnerabilities.len() as u64;
        out.extend(page.into_cves());
        start += got;
        if start >= total {
            return Ok(out);
        }
        if got == 0 {
            return Err(Error::Paging("empty page before totalResults"));
        }
    }
    Err(Error::Paging("more pages than max_pages"))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    fn page(ids: &[&str], total: u64) -> Vec<u8> {
        let vulns: Vec<String> = ids
            .iter()
            .map(|id| format!(r#"{{"cve": {{"id": "{id}"}}}}"#))
            .collect();
        format!(
            r#"{{"totalResults": {total}, "vulnerabilities": [{}]}}"#,
            vulns.join(",")
        )
        .into_bytes()
    }

    #[test]
    fn pages_until_total() {
        let calls = RefCell::new(Vec::new());
        let transport = |url: &str, headers: &[(&str, &str)]| -> Result<Vec<u8>, TransportError> {
            calls.borrow_mut().push((url.to_owned(), headers.len()));
            Ok(if url.ends_with("startIndex=0") {
                page(&["CVE-2020-0001", "CVE-2020-0002"], 3)
            } else {
                page(&["CVE-2020-0003"], 3)
            })
        };
        let query = NvdQuery::default().with_results_per_page(2).with_kev_only();
        let cves = fetch_all(&transport, &query, Some("k")).unwrap();
        assert_eq!(cves.len(), 3);
        let calls = calls.into_inner();
        assert_eq!(calls.len(), 2);
        assert!(
            calls[1]
                .0
                .ends_with("?hasKev&resultsPerPage=2&startIndex=2")
        );
        assert_eq!(calls[1].1, 1);
    }

    #[test]
    fn empty_page_and_page_limit_are_errors() {
        let empty =
            |_: &str, _: &[(&str, &str)]| -> Result<Vec<u8>, TransportError> { Ok(page(&[], 5)) };
        assert!(matches!(
            fetch_all(&empty, &NvdQuery::default(), None),
            Err(Error::Paging(_))
        ));
        let endless = |_: &str, _: &[(&str, &str)]| -> Result<Vec<u8>, TransportError> {
            Ok(page(&["CVE-2020-0001"], u64::MAX))
        };
        let query = NvdQuery::default().with_max_pages(3);
        assert!(matches!(
            fetch_all(&endless, &query, None),
            Err(Error::Paging(_))
        ));
        let failing =
            |_: &str, _: &[(&str, &str)]| -> Result<Vec<u8>, TransportError> { Err("boom".into()) };
        assert!(matches!(
            fetch_all(&failing, &NvdQuery::default(), None),
            Err(Error::Transport(_))
        ));
    }

    #[test]
    fn builds_every_parameter() {
        let q = NvdQuery::default()
            .with_base_url("http://mirror.test/cves")
            .with_virtual_match_string("cpe:2.3:a:v:p".parse().unwrap())
            .with_keyword_search("remote code")
            .with_last_modified("2024-01-01T00:00:00.000", "2024-02-01T00:00:00.000")
            .with_published("2023-01-01T00:00:00.000", "2023-02-01T00:00:00.000")
            .with_results_per_page(0);
        let url = q.url(40);
        assert!(
            url.starts_with(
                "http://mirror.test/cves?virtualMatchString=cpe%3A2.3%3Aa%3Av%3Ap%3A%2A"
            )
        );
        assert!(url.contains("&keywordSearch=remote%20code"));
        assert!(url.contains("&lastModStartDate=2024-01-01T00%3A00%3A00.000"));
        assert!(url.contains("&pubEndDate=2023-02-01T00%3A00%3A00.000"));
        assert!(url.ends_with("&resultsPerPage=1&startIndex=40"));
        // isVulnerable only applies with cpeName.
        let q = NvdQuery::default().with_vulnerable_only();
        assert!(!q.url(0).contains("isVulnerable"));
    }
}
