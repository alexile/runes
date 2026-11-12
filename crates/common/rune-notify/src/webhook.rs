//! A generic JSON webhook.

use rune_finding::Severity;
use rune_secret_ref::SecretValue;
use serde_json::{Value, json};

use crate::text::{check_header, check_url, status_error};
use crate::{Delivery, Error, HeaderValue, HttpRequest, HttpResponse, Message, Method, Sink};

const NAME: &str = "webhook";

/// The `version` member of the [`WebhookSink`] payload.
pub const WEBHOOK_SCHEMA_VERSION: u32 = 1;

/// POSTs every message as JSON to a URL of the caller's choosing, with
/// optional extra headers (an `Authorization` token, a routing key).
///
/// The payload is stable and versioned:
///
/// ```json
/// {
///   "version": 1,
///   "title": "[HIGH] Reflected XSS",
///   "body": "web.xss at https://shop.test/search",
///   "severity": "high",
///   "fields": [{"name": "Severity", "value": "high", "inline": true}],
///   "link": "https://shop.test/search",
///   "labels": ["severity-high", "web.xss"],
///   "fingerprint": "3f9c…"
/// }
/// ```
///
/// `severity`, `link` and `fingerprint` are `null` when unset. Text is sent
/// as is, without cutting or escaping. Any 2xx counts as delivered.
///
/// ```
/// use rune_notify::{Message, Sink, WebhookSink};
/// use rune_secret_ref::SecretValue;
///
/// let hook = WebhookSink::new(SecretValue::new("https://alerts.example.test/in"))?
///     .with_bearer_token(&SecretValue::new("t0ken"))
///     .with_header("X-Source", "rune-notify")?;
/// let request = hook.request(&Message::new("Scan done", "0 findings"))?;
/// assert!(request.header("authorization").is_some_and(|v| v.is_secret()));
/// assert!(!format!("{request:?}").contains("t0ken"));
/// # Ok::<(), rune_notify::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookSink {
    url: SecretValue,
    method: Method,
    headers: Vec<(String, HeaderValue)>,
}

impl WebhookSink {
    /// A sink that POSTs to this URL.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] unless the URL is absolute `http`/`https`.
    pub fn new(url: SecretValue) -> Result<Self, Error> {
        check_url(NAME, &url)?;
        Ok(Self {
            url,
            method: Method::Post,
            headers: Vec::new(),
        })
    }

    /// Sends with this method instead of `POST`.
    #[must_use]
    pub const fn with_method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Adds a plain header.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] for a name that is not an HTTP token or a
    /// value with a line break.
    pub fn with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, Error> {
        let (name, value) = (name.into(), value.into());
        check_header(NAME, &name, &value)?;
        self.headers.push((name, HeaderValue::Plain(value)));
        Ok(self)
    }

    /// Adds a header whose value is a secret (an API key header).
    ///
    /// # Errors
    ///
    /// As [`with_header`](Self::with_header). The error never contains the
    /// value.
    pub fn with_secret_header(
        mut self,
        name: impl Into<String>,
        value: SecretValue,
    ) -> Result<Self, Error> {
        let name = name.into();
        check_header(NAME, &name, value.expose())?;
        self.headers.push((name, HeaderValue::Secret(value)));
        Ok(self)
    }

    /// Adds `Authorization: Bearer <token>`.
    ///
    /// A token with a line break is dropped from the header rather than
    /// sent, so the request then fails authentication instead of carrying an
    /// injected header.
    #[must_use]
    pub fn with_bearer_token(mut self, token: &SecretValue) -> Self {
        let token = token.expose().trim();
        let value = if token.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
            String::from("Bearer")
        } else {
            format!("Bearer {token}")
        };
        self.headers.push((
            "Authorization".to_owned(),
            HeaderValue::Secret(SecretValue::new(value)),
        ));
        self
    }

    /// The JSON payload for `message`.
    #[must_use]
    pub fn payload(message: &Message) -> Value {
        let fields: Vec<Value> = message
            .fields
            .iter()
            .map(|f| json!({"name": f.name, "value": f.value, "inline": f.inline}))
            .collect();
        json!({
            "version": WEBHOOK_SCHEMA_VERSION,
            "title": message.title,
            "body": message.body,
            "severity": message.severity.map(Severity::as_str),
            "fields": fields,
            "link": message.link,
            "labels": message.labels,
            "fingerprint": message.fingerprint,
        })
    }
}

impl Sink for WebhookSink {
    fn name(&self) -> &'static str {
        NAME
    }

    fn request(&self, message: &Message) -> Result<HttpRequest, Error> {
        let mut request = HttpRequest::new(self.method, self.url.clone())
            .with_header("Content-Type", "application/json")
            .with_body(Self::payload(message).to_string());
        request.headers.extend(self.headers.iter().cloned());
        Ok(request)
    }

    fn response(&self, response: &HttpResponse) -> Result<Delivery, Error> {
        if response.is_success() {
            Ok(Delivery::new(response.status))
        } else {
            Err(status_error(NAME, response, None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Field;

    #[test]
    fn payload_shape() {
        let message = Message::new("t", "b")
            .with_severity(Severity::Low)
            .push_field(Field::block("k", "v"))
            .push_label("x");
        assert_eq!(
            WebhookSink::payload(&message),
            json!({
                "version": 1, "title": "t", "body": "b", "severity": "low",
                "fields": [{"name": "k", "value": "v", "inline": false}],
                "link": null, "labels": ["x"], "fingerprint": null,
            })
        );
    }

    #[test]
    fn headers_validated_and_redacted() {
        let url = || SecretValue::new("https://h.test/x");
        assert!(
            WebhookSink::new(url())
                .and_then(|s| s.with_header("Bad Name", "v"))
                .is_err()
        );
        let err = WebhookSink::new(url())
            .and_then(|s| s.with_secret_header("X-Key", SecretValue::new("abc\r\nX: y")))
            .err();
        assert!(!format!("{err:?}").contains("abc"));
        let sink = WebhookSink::new(url())
            .unwrap()
            .with_method(Method::Put)
            .with_bearer_token(&SecretValue::new("a\nb"));
        let req = sink.request(&Message::new("t", "b")).unwrap();
        assert_eq!(req.method, Method::Put);
        assert_eq!(
            req.header("authorization").map(HeaderValue::expose),
            Some("Bearer")
        );
    }

    #[test]
    fn responses_classify() {
        let sink = WebhookSink::new(SecretValue::new("http://h.test/")).unwrap();
        assert_eq!(
            sink.response(&HttpResponse::new(202)),
            Ok(Delivery::new(202))
        );
        assert!(
            sink.response(&HttpResponse::new(502))
                .is_err_and(|e| e.is_retryable())
        );
        assert!(
            sink.response(&HttpResponse::new(401))
                .is_err_and(|e| !e.is_retryable())
        );
    }
}
