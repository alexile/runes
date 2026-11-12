//! [Shodan InternetDB]: free, keyless open-port and vulnerability data.
//!
//! [Shodan InternetDB]: https://internetdb.shodan.io/docs

use std::net::IpAddr;

use serde_json::Value;

use crate::http::{HttpRequest, HttpResponse};
use crate::provider::{check_status, classify_tags, json, strings};
use crate::{Error, ReputationProvider, Verdict};

const NAME: &str = "shodan";

/// Shodan `InternetDB` adapter (no key).
///
/// Reports open ports, host names, CPEs (as `cpe:` tags), Shodan tags and
/// CVEs. `InternetDB` is exposure data, not a reputation feed, so the
/// classification comes from the tags only: `c2`, `malware`,
/// `compromised` or `botnet` make an address
/// [`Malicious`](crate::Classification::Malicious), `tor`, `proxy` or `scanner`
/// [`Suspicious`](crate::Classification::Suspicious); anything else is
/// [`Unknown`](crate::Classification::Unknown). A 404 means "no data".
#[derive(Debug, Clone)]
pub struct ShodanInternetDb {
    base_url: String,
}

impl Default for ShodanInternetDb {
    fn default() -> Self {
        Self::new()
    }
}

impl ShodanInternetDb {
    /// An adapter for `https://internetdb.shodan.io`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base_url: "https://internetdb.shodan.io".to_owned(),
        }
    }

    /// Replaces `https://internetdb.shodan.io`.
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        url.into()
            .trim_end_matches('/')
            .clone_into(&mut self.base_url);
        self
    }
}

impl ReputationProvider for ShodanInternetDb {
    fn name(&self) -> &'static str {
        NAME
    }

    fn request(&self, ip: IpAddr) -> HttpRequest {
        HttpRequest::get(format!("{}/{ip}", self.base_url))
            .with_header("Accept", "application/json")
    }

    fn parse(&self, ip: IpAddr, response: &HttpResponse) -> Result<Verdict, Error> {
        check_status(NAME, response, true)?;
        let mut verdict = Verdict::new(NAME, ip);
        if response.status == 404 {
            verdict.raw = json(NAME, response).unwrap_or(Value::Null);
            return Ok(verdict);
        }
        let raw = json(NAME, response)?;
        if !raw.is_object() {
            return Err(Error::InvalidResponse {
                provider: NAME,
                reason: "answer is not an object".to_owned(),
            });
        }
        verdict.open_ports = raw
            .get("ports")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|p| p.as_u64().and_then(|p| u16::try_from(p).ok()))
            .collect();
        verdict.hostnames = strings(raw.get("hostnames"));
        verdict.vulns = strings(raw.get("vulns"));
        verdict.tags = strings(raw.get("tags"));
        verdict.classification = classify_tags(&verdict.tags);
        verdict
            .tags
            .extend(strings(raw.get("cpes")).into_iter().map(|cpe| {
                if cpe.starts_with("cpe:") {
                    cpe
                } else {
                    format!("cpe:{cpe}")
                }
            }));
        verdict.raw = raw;
        Ok(verdict)
    }
}
