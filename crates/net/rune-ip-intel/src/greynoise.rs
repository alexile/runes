//! [GreyNoise] Community API (v3).
//!
//! [GreyNoise]: https://docs.greynoise.io/reference/get_v3-community-ip

use std::net::IpAddr;

use rune_secret_ref::SecretValue;
use serde_json::Value;

use crate::http::{HttpRequest, HttpResponse};
use crate::provider::{check_status, json, parse_time, string};
use crate::{Classification, Error, ReputationProvider, Verdict};

const NAME: &str = "greynoise";

/// `GreyNoise` Community adapter.
///
/// The classification is `GreyNoise`'s own (`benign`, `malicious`,
/// `unknown`); an address in the RIOT set (common business services) is
/// [`Benign`](Classification::Benign). Tags: `scanner` when `GreyNoise` saw
/// it scanning the internet (`noise`), `riot` for RIOT. A 404 means
/// "never observed" and yields an [`Unknown`](Classification::Unknown)
/// verdict, not an error. `GreyNoise` gives no numeric score.
///
/// The Community API works without a key at a low rate limit; pass one
/// with [`with_key`](Self::with_key).
#[derive(Debug, Clone)]
pub struct GreyNoise {
    key: Option<SecretValue>,
    base_url: String,
}

impl Default for GreyNoise {
    fn default() -> Self {
        Self::new()
    }
}

impl GreyNoise {
    /// An adapter without a key.
    #[must_use]
    pub fn new() -> Self {
        Self {
            key: None,
            base_url: "https://api.greynoise.io/v3/community".to_owned(),
        }
    }

    /// Sends `key` (resolve it with `rune-secret-ref`).
    #[must_use]
    pub fn with_key(mut self, key: SecretValue) -> Self {
        self.key = Some(key);
        self
    }

    /// Replaces `https://api.greynoise.io/v3/community`.
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        url.into()
            .trim_end_matches('/')
            .clone_into(&mut self.base_url);
        self
    }
}

impl ReputationProvider for GreyNoise {
    fn name(&self) -> &'static str {
        NAME
    }

    fn request(&self, ip: IpAddr) -> HttpRequest {
        let request = HttpRequest::get(format!("{}/{ip}", self.base_url))
            .with_header("Accept", "application/json");
        match &self.key {
            Some(key) => request.with_secret_header("key", key.clone()),
            None => request,
        }
    }

    fn parse(&self, ip: IpAddr, response: &HttpResponse) -> Result<Verdict, Error> {
        check_status(NAME, response, true)?;
        let mut verdict = Verdict::new(NAME, ip);
        let raw = if response.status == 404 && response.body.is_empty() {
            Value::Null
        } else {
            json(NAME, response)?
        };
        if !raw.is_object() && !raw.is_null() {
            return Err(Error::InvalidResponse {
                provider: NAME,
                reason: "answer is not an object".to_owned(),
            });
        }
        let flag = |key: &str| raw.get(key).and_then(Value::as_bool) == Some(true);
        let riot = flag("riot");
        if flag("noise") {
            verdict.tags.push("scanner".to_owned());
        }
        if riot {
            verdict.tags.push("riot".to_owned());
        }
        verdict.classification = match raw.get("classification").and_then(Value::as_str) {
            Some("malicious") => Classification::Malicious,
            Some("suspicious") => Classification::Suspicious,
            Some("benign") => Classification::Benign,
            _ if riot => Classification::Benign,
            _ => Classification::Unknown,
        };
        verdict.organization = string(&raw, "name").filter(|n| n != "unknown");
        verdict.last_seen = raw
            .get("last_seen")
            .and_then(Value::as_str)
            .and_then(parse_time);
        verdict.raw = raw;
        Ok(verdict)
    }
}
