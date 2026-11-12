//! Fetching the feeds through a caller-supplied [`Transport`] (feature
//! `fetch`).
//!
//! The crate does no I/O itself. The functions here build the request,
//! call the transport the caller wraps around its HTTP client, and parse
//! the response. Save what they return with [`EpssSnapshot::to_csv`] and
//! [`KevCatalog::to_json`] to work offline afterwards.

use rune_cve::CveId;
pub use rune_cve::fetch::{Transport, TransportError};

use crate::{EpssSnapshot, Error, KevCatalog};

/// The full daily EPSS CSV, gzip-compressed.
pub const EPSS_CURRENT_CSV_GZ: &str =
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

/// The EPSS API.
pub const EPSS_API: &str = "https://api.first.org/data/v1/epss";

/// The KEV catalog JSON.
pub const KEV_JSON: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// CVEs per EPSS API request; keeps the URL well under 2,000 bytes.
pub const EPSS_API_BATCH: usize = 100;

/// Largest decompressed EPSS CSV accepted (the real one is about 10 MB).
pub const MAX_EPSS_CSV: u64 = 256 << 20;

/// Fetches and parses the KEV catalog from `url` (normally [`KEV_JSON`]).
///
/// # Errors
///
/// [`Error::Transport`] or the errors of [`KevCatalog::from_json`].
pub fn fetch_kev<T: Transport + ?Sized>(transport: &T, url: &str) -> Result<KevCatalog, Error> {
    let body = transport.get(url, &[]).map_err(Error::Transport)?;
    KevCatalog::from_json(&body)
}

/// Fetches and parses the full EPSS CSV from `url` (normally
/// [`EPSS_CURRENT_CSV_GZ`]); the body must be gzip-compressed.
///
/// # Errors
///
/// [`Error::Transport`] or the errors of [`EpssSnapshot::from_csv_gz`].
pub fn fetch_epss_csv<T: Transport + ?Sized>(
    transport: &T,
    url: &str,
) -> Result<EpssSnapshot, Error> {
    let body = transport.get(url, &[]).map_err(Error::Transport)?;
    EpssSnapshot::from_csv_gz(&body, MAX_EPSS_CSV)
}

/// Fetches the current EPSS scores of `cves` from the EPSS API at
/// `base_url` (normally [`EPSS_API`]), [`EPSS_API_BATCH`] per request.
///
/// # Errors
///
/// [`Error::Transport`] or the errors of [`EpssSnapshot::from_api_json`].
///
/// # Examples
///
/// ```
/// use rune_epss::fetch::{EPSS_API, TransportError, fetch_epss_api};
///
/// let transport = |url: &str, _: &[(&str, &str)]| -> Result<Vec<u8>, TransportError> {
///     assert_eq!(url, "https://api.first.org/data/v1/epss?cve=CVE-2021-44228");
///     Ok(br#"{"status": "OK", "data": [{"cve": "CVE-2021-44228",
///         "epss": "0.943580000", "percentile": "0.999570000", "date": "2025-11-11"}]}"#.to_vec())
/// };
/// let scores = fetch_epss_api(&transport, EPSS_API, &["CVE-2021-44228".parse()?])?;
/// assert_eq!(scores.len(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn fetch_epss_api<T: Transport + ?Sized>(
    transport: &T,
    base_url: &str,
    cves: &[CveId],
) -> Result<EpssSnapshot, Error> {
    let mut out = EpssSnapshot::new();
    for batch in cves.chunks(EPSS_API_BATCH) {
        let list: Vec<String> = batch.iter().map(ToString::to_string).collect();
        // CVE ids are URL-safe and the comma is a sub-delimiter. The API's
        // default page size (100) covers a whole batch.
        let url = format!("{base_url}?cve={}", list.join(","));
        let body = transport.get(&url, &[]).map_err(Error::Transport)?;
        out.merge(EpssSnapshot::from_api_json(&body)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::Write;

    use super::*;

    #[test]
    fn batches_api_requests() {
        let urls = RefCell::new(Vec::new());
        let transport = |url: &str, _: &[(&str, &str)]| -> Result<Vec<u8>, TransportError> {
            urls.borrow_mut().push(url.to_owned());
            let query = url.split_once("cve=").map(|(_, q)| q).unwrap_or_default();
            let rows: Vec<String> = query
                .split(',')
                .map(|id| format!(r#"{{"cve":"{id}","epss":"0.5","percentile":"0.5"}}"#))
                .collect();
            Ok(format!(r#"{{"status":"OK","data":[{}]}}"#, rows.join(",")).into_bytes())
        };
        let cves: Vec<CveId> = (1..=250).map(|n| CveId::new(2020, n).unwrap()).collect();
        let scores = fetch_epss_api(&transport, "http://epss.test", &cves).unwrap();
        assert_eq!(scores.len(), 250);
        let urls = urls.borrow().clone();
        assert_eq!(urls.len(), 3);
        assert!(urls[0].starts_with("http://epss.test?cve=CVE-2020-0001,CVE-2020-0002,"));
        assert!(urls[0].ends_with(",CVE-2020-0100"));
        assert!(
            urls[2].ends_with("?cve=CVE-2020-0201,CVE-2020-0202")
                || urls[2].contains("CVE-2020-0250")
        );
        assert!(
            fetch_epss_api(&transport, "http://epss.test", &[])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn fetches_kev_and_csv() {
        let kev_body = br#"{"count":1,"vulnerabilities":[{"cveID":"CVE-2021-44228","dateAdded":"2021-12-10"}]}"#;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(b"cve,epss,percentile\nCVE-2021-44228,0.9,0.9\n")
            .unwrap();
        let csv_body = gz.finish().unwrap();
        let transport = |url: &str, _: &[(&str, &str)]| -> Result<Vec<u8>, TransportError> {
            match url {
                KEV_JSON => Ok(kev_body.to_vec()),
                EPSS_CURRENT_CSV_GZ => Ok(csv_body.clone()),
                _ => Err("not found".into()),
            }
        };
        assert_eq!(fetch_kev(&transport, KEV_JSON).unwrap().len(), 1);
        assert_eq!(
            fetch_epss_csv(&transport, EPSS_CURRENT_CSV_GZ)
                .unwrap()
                .len(),
            1
        );
        assert!(matches!(
            fetch_kev(&transport, "http://elsewhere.test"),
            Err(Error::Transport(_))
        ));
    }
}
