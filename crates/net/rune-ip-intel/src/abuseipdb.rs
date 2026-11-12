//! [AbuseIPDB] `check` endpoint (API v2).
//!
//! [AbuseIPDB]: https://docs.abuseipdb.com/#check-endpoint

use std::net::IpAddr;

use rune_secret_ref::SecretValue;
use serde_json::Value;

use crate::http::{HttpRequest, HttpResponse};
use crate::provider::{check_status, json, parse_time, string, strings};
use crate::{Classification, Error, ReputationProvider, Verdict};

const NAME: &str = "abuseipdb";

/// `AbuseIPDB` report categories by id
/// (<https://www.abuseipdb.com/categories>).
const CATEGORIES: [&str; 23] = [
    "DNS Compromise",
    "DNS Poisoning",
    "Fraud Orders",
    "DDoS Attack",
    "FTP Brute-Force",
    "Ping of Death",
    "Phishing",
    "Fraud VoIP",
    "Open Proxy",
    "Web Spam",
    "Email Spam",
    "Blog Spam",
    "VPN IP",
    "Port Scan",
    "Hacking",
    "SQL Injection",
    "Spoofing",
    "Brute-Force",
    "Bad Web Bot",
    "Exploited Host",
    "Web App Attack",
    "SSH",
    "IoT Targeted",
];

/// The name of an `AbuseIPDB` category id (1-23).
#[must_use]
pub fn category_name(id: u64) -> Option<&'static str> {
    let index = usize::try_from(id.checked_sub(1)?).ok()?;
    CATEGORIES.get(index).copied()
}

/// `AbuseIPDB` adapter.
///
/// `score` is the `abuseConfidenceScore`; the classification is
/// [`Malicious`](Classification::Malicious) from
/// [`malicious_at`](Self::with_thresholds) (75) up,
/// [`Suspicious`](Classification::Suspicious) from `suspicious_at` (25),
/// and [`Benign`](Classification::Benign) for allowlisted addresses.
/// Categories come from the individual reports, which the request asks
/// for (`verbose`).
#[derive(Debug, Clone)]
pub struct AbuseIpDb {
    key: SecretValue,
    base_url: String,
    max_age_days: u16,
    suspicious_at: u8,
    malicious_at: u8,
}

impl AbuseIpDb {
    /// An adapter using `key` (resolve it with `rune-secret-ref`).
    #[must_use]
    pub fn new(key: SecretValue) -> Self {
        Self {
            key,
            base_url: "https://api.abuseipdb.com/api/v2".to_owned(),
            max_age_days: 90,
            suspicious_at: 25,
            malicious_at: 75,
        }
    }

    /// Considers reports from the last `days` days (1-365; default 90).
    #[must_use]
    pub fn with_max_age_days(mut self, days: u16) -> Self {
        self.max_age_days = days.clamp(1, 365);
        self
    }

    /// Sets the confidence scores from which an address is suspicious and
    /// malicious (defaults 25 and 75).
    #[must_use]
    pub const fn with_thresholds(mut self, suspicious_at: u8, malicious_at: u8) -> Self {
        self.suspicious_at = suspicious_at;
        self.malicious_at = malicious_at;
        self
    }

    /// Replaces `https://api.abuseipdb.com/api/v2` (a proxy, a mock).
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        url.into()
            .trim_end_matches('/')
            .clone_into(&mut self.base_url);
        self
    }
}

impl ReputationProvider for AbuseIpDb {
    fn name(&self) -> &'static str {
        NAME
    }

    fn request(&self, ip: IpAddr) -> HttpRequest {
        HttpRequest::get(format!(
            "{}/check?ipAddress={ip}&maxAgeInDays={}&verbose",
            self.base_url, self.max_age_days
        ))
        .with_header("Accept", "application/json")
        .with_secret_header("Key", self.key.clone())
    }

    fn parse(&self, ip: IpAddr, response: &HttpResponse) -> Result<Verdict, Error> {
        if response.status == 422 {
            return Err(Error::Status {
                provider: NAME,
                status: 422,
                message: crate::provider::snippet(&response.body),
            });
        }
        check_status(NAME, response, false)?;
        let raw = json(NAME, response)?;
        let data = raw.get("data").ok_or_else(|| Error::InvalidResponse {
            provider: NAME,
            reason: "no `data` object".to_owned(),
        })?;
        let mut verdict = Verdict::new(NAME, ip);
        let score = data
            .get("abuseConfidenceScore")
            .and_then(Value::as_u64)
            .map(|s| u8::try_from(s.min(100)).unwrap_or(100));
        verdict.score = score;
        verdict.reports = data.get("totalReports").and_then(Value::as_u64);
        verdict.last_seen = data
            .get("lastReportedAt")
            .and_then(Value::as_str)
            .and_then(parse_time);
        verdict.country = string(data, "countryCode");
        verdict.organization = string(data, "isp");
        verdict.hostnames = strings(data.get("hostnames"));
        if let Some(domain) = string(data, "domain") {
            verdict.tags.push(format!("domain:{domain}"));
        }
        if let Some(usage) = string(data, "usageType") {
            verdict.tags.push(format!("usage:{usage}"));
        }
        if data.get("isTor").and_then(Value::as_bool) == Some(true) {
            verdict.tags.push("tor".to_owned());
        }
        let whitelisted = data.get("isWhitelisted").and_then(Value::as_bool) == Some(true);
        if whitelisted {
            verdict.tags.push("whitelisted".to_owned());
        }
        let mut categories = Vec::new();
        for report in data
            .get("reports")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for id in report
                .get("categories")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_u64)
            {
                let name =
                    category_name(id).map_or_else(|| format!("category {id}"), str::to_owned);
                if !categories.contains(&name) {
                    categories.push(name);
                }
            }
        }
        verdict.categories = categories;
        verdict.classification = match score {
            _ if whitelisted => Classification::Benign,
            Some(s) if s >= self.malicious_at => Classification::Malicious,
            Some(s) if s >= self.suspicious_at => Classification::Suspicious,
            _ => Classification::Unknown,
        };
        verdict.raw = raw;
        Ok(verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_names() {
        assert_eq!(category_name(1), Some("DNS Compromise"));
        assert_eq!(category_name(22), Some("SSH"));
        assert_eq!(category_name(23), Some("IoT Targeted"));
        assert_eq!(category_name(0), None);
        assert_eq!(category_name(24), None);
    }

    #[test]
    fn builds_the_check_request() {
        let p = AbuseIpDb::new(SecretValue::new("k3y"))
            .with_max_age_days(1000)
            .with_base_url("http://mock/");
        let r = p.request("2001:db8::1".parse().unwrap());
        assert_eq!(
            r.url,
            "http://mock/check?ipAddress=2001:db8::1&maxAgeInDays=365&verbose"
        );
        assert_eq!(r.header("key").map(crate::HeaderValue::expose), Some("k3y"));
        assert!(!format!("{r:?}").contains("k3y"));
    }
}
