//! [Censys] Search API v2 host view.
//!
//! [Censys]: https://search.censys.io/api#/hosts/viewHost

use std::net::IpAddr;

use rune_secret_ref::SecretValue;
use serde_json::Value;

use crate::http::{HttpRequest, HttpResponse};
use crate::provider::{check_status, classify_tags, json, parse_time, string, strings};
use crate::{Error, ReputationProvider, Verdict};

const NAME: &str = "censys";

/// Censys host adapter (Search API v2, HTTP Basic with an API ID and
/// secret).
///
/// Reports services (open ports and `service:` tags), labels (as tags),
/// AS, country, reverse DNS names and `last_updated_at`. Like `InternetDB`
/// this is exposure data: labels such as `c2` or `tor` drive the
/// classification the same way, otherwise it is
/// [`Unknown`](crate::Classification::Unknown). A 404 means "no data".
#[derive(Debug, Clone)]
pub struct Censys {
    authorization: SecretValue,
    base_url: String,
}

impl Censys {
    /// An adapter with the account's API ID and secret (resolve them with
    /// `rune-secret-ref`).
    #[must_use]
    pub fn new(api_id: &SecretValue, secret: &SecretValue) -> Self {
        let credentials = format!("{}:{}", api_id.expose(), secret.expose());
        Self {
            authorization: SecretValue::new(format!(
                "Basic {}",
                rune_base64::encode(credentials.as_bytes())
            )),
            base_url: "https://search.censys.io/api/v2".to_owned(),
        }
    }

    /// Replaces `https://search.censys.io/api/v2`.
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        url.into()
            .trim_end_matches('/')
            .clone_into(&mut self.base_url);
        self
    }
}

impl ReputationProvider for Censys {
    fn name(&self) -> &'static str {
        NAME
    }

    fn request(&self, ip: IpAddr) -> HttpRequest {
        HttpRequest::get(format!("{}/hosts/{ip}", self.base_url))
            .with_header("Accept", "application/json")
            .with_secret_header("Authorization", self.authorization.clone())
    }

    fn parse(&self, ip: IpAddr, response: &HttpResponse) -> Result<Verdict, Error> {
        check_status(NAME, response, true)?;
        let mut verdict = Verdict::new(NAME, ip);
        if response.status == 404 {
            verdict.raw = json(NAME, response).unwrap_or(Value::Null);
            return Ok(verdict);
        }
        let raw = json(NAME, response)?;
        let result = raw.get("result").ok_or_else(|| Error::InvalidResponse {
            provider: NAME,
            reason: "no `result` object".to_owned(),
        })?;
        let mut tags = strings(result.get("labels"));
        verdict.classification = classify_tags(&tags);
        for service in result
            .get("services")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(port) = service
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|p| u16::try_from(p).ok())
                && !verdict.open_ports.contains(&port)
            {
                verdict.open_ports.push(port);
            }
            if let Some(name) = string(service, "service_name") {
                let tag = format!("service:{}", name.to_ascii_lowercase());
                if !tags.contains(&tag) {
                    tags.push(tag);
                }
            }
        }
        verdict.tags = tags;
        if let Some(asys) = result.get("autonomous_system") {
            verdict.asn = asys
                .get("asn")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok());
            verdict.organization = string(asys, "name");
        }
        verdict.country = result
            .get("location")
            .and_then(|l| string(l, "country_code"));
        verdict.hostnames = strings(
            result
                .get("dns")
                .and_then(|d| d.get("reverse_dns"))
                .and_then(|r| r.get("names")),
        );
        verdict.last_seen = result
            .get("last_updated_at")
            .and_then(Value::as_str)
            .and_then(parse_time);
        verdict.raw = raw;
        Ok(verdict)
    }
}
