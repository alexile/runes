//! Slack incoming webhooks.

use rune_secret_ref::SecretValue;
use serde_json::{Value, json};

use crate::text::{check_url, is_web_link, one_line, status_error, truncate};
use crate::{Delivery, Error, HttpRequest, HttpResponse, Message, Method, Sink};

const NAME: &str = "slack";
/// `header` block `plain_text` limit.
const HEADER_MAX: usize = 150;
/// `section` block text limit.
const SECTION_MAX: usize = 3000;
/// `section` block: at most 10 fields of at most 2000 characters each.
const FIELDS_MAX: usize = 10;
const FIELD_MAX: usize = 2000;
/// Top-level `text` (notification fallback). Slack truncates past 40 000.
const TEXT_MAX: usize = 4000;

/// Posts messages to a Slack [incoming webhook] with [Block Kit] blocks.
///
/// The payload has a top-level `text` (used for notifications and as the
/// fallback), then a `header` block with the title, a `section` with the
/// body in `mrkdwn`, a `section` with up to ten fields, and a `context`
/// with the link and fingerprint. Text is escaped (`&`, `<`, `>`) so
/// finding data cannot inject `<!channel>` mentions or links, and cut to
/// Block Kit's limits.
///
/// Slack answers `200 ok`; errors come as 4xx with a short code
/// (`invalid_payload`, `invalid_token`, `no_service`, `channel_is_archived`)
/// that ends up in [`Error::Rejected`].
///
/// [incoming webhook]: https://api.slack.com/messaging/webhooks
/// [Block Kit]: https://api.slack.com/reference/block-kit/blocks
///
/// ```
/// use rune_notify::{Message, Sink, SlackSink};
/// use rune_secret_ref::SecretValue;
///
/// let slack = SlackSink::new(SecretValue::new("https://hooks.slack.com/services/T0/B0/XXXX"))?;
/// let request = slack.request(&Message::new("Scan done", "0 findings <3"))?;
/// let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
/// assert_eq!(body["blocks"][1]["text"]["text"], "0 findings &lt;3");
/// # Ok::<(), rune_notify::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackSink {
    url: SecretValue,
}

impl SlackSink {
    /// A sink for this webhook URL.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] unless the URL is absolute `http`/`https`.
    pub fn new(webhook_url: SecretValue) -> Result<Self, Error> {
        check_url(NAME, &webhook_url)?;
        Ok(Self { url: webhook_url })
    }

    /// The JSON payload for `message`.
    #[must_use]
    pub fn payload(&self, message: &Message) -> Value {
        let title = if message.title.trim().is_empty() {
            "Notification"
        } else {
            message.title.trim()
        };
        let mut blocks = vec![json!({
            "type": "header",
            "text": {"type": "plain_text", "text": truncate(&one_line(title), HEADER_MAX), "emoji": true},
        })];
        if !message.body.trim().is_empty() {
            blocks.push(json!({
                "type": "section",
                "text": {"type": "mrkdwn", "text": truncate(&escape(&message.body), SECTION_MAX)},
            }));
        }
        let fields: Vec<Value> = message
            .fields
            .iter()
            .take(FIELDS_MAX)
            .map(|field| {
                let text = format!("*{}*\n{}", escape(&field.name), escape(&field.value));
                json!({"type": "mrkdwn", "text": truncate(&text, FIELD_MAX)})
            })
            .collect();
        if !fields.is_empty() {
            blocks.push(json!({"type": "section", "fields": fields}));
        }
        let mut context = Vec::new();
        if let Some(link) = &message.link {
            let text = if is_web_link(link) {
                format!("<{}|Details>", link_target(link))
            } else {
                escape(link)
            };
            context.push(json!({"type": "mrkdwn", "text": truncate(&text, FIELD_MAX)}));
        }
        if let Some(fingerprint) = &message.fingerprint {
            let text = format!("fingerprint `{}`", escape(fingerprint));
            context.push(json!({"type": "mrkdwn", "text": truncate(&text, FIELD_MAX)}));
        }
        if !context.is_empty() {
            blocks.push(json!({"type": "context", "elements": context}));
        }

        let mut text = escape(title);
        if !message.body.trim().is_empty() {
            text.push('\n');
            text.push_str(&escape(&message.body));
        }
        json!({"text": truncate(&text, TEXT_MAX), "blocks": blocks})
    }
}

impl Sink for SlackSink {
    fn name(&self) -> &'static str {
        NAME
    }

    fn request(&self, message: &Message) -> Result<HttpRequest, Error> {
        Ok(HttpRequest::new(Method::Post, self.url.clone())
            .with_header("Content-Type", "application/json; charset=utf-8")
            .with_body(self.payload(message).to_string()))
    }

    fn response(&self, response: &HttpResponse) -> Result<Delivery, Error> {
        if response.is_success() {
            Ok(Delivery::new(response.status))
        } else {
            Err(status_error(NAME, response, None))
        }
    }
}

/// Escapes text for Slack `mrkdwn` (the three characters Slack's docs
/// require).
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

/// A URL made safe inside `<url|label>`.
fn link_target(link: &str) -> String {
    link.replace('&', "&amp;")
        .replace('|', "%7C")
        .replace('<', "%3C")
        .replace('>', "%3E")
}

#[cfg(test)]
mod tests {
    use rune_finding::Severity;

    use super::*;
    use crate::Field;
    use crate::text::chars;

    fn sink() -> SlackSink {
        SlackSink::new(SecretValue::new("https://hooks.slack.test/services/T/B/X")).unwrap()
    }

    #[test]
    fn payload_matches_block_kit() {
        let message = Message::new("Title\nwith newline", "body *bold* <!channel> & co")
            .with_severity(Severity::High)
            .push_field(Field::new("Sev", "high"))
            .with_link("https://x.test/a?b=1&c=2|d")
            .with_fingerprint("abc");
        let p = sink().payload(&message);
        assert_eq!(p["blocks"][0]["type"], "header");
        assert_eq!(p["blocks"][0]["text"]["type"], "plain_text");
        assert_eq!(p["blocks"][0]["text"]["text"], "Title with newline");
        assert_eq!(
            p["blocks"][1]["text"]["text"],
            "body *bold* &lt;!channel&gt; &amp; co"
        );
        assert_eq!(p["blocks"][2]["fields"][0]["text"], "*Sev*\nhigh");
        assert_eq!(
            p["blocks"][3]["elements"][0]["text"],
            "<https://x.test/a?b=1&amp;c=2%7Cd|Details>"
        );
        assert_eq!(p["blocks"][3]["elements"][1]["text"], "fingerprint `abc`");
        assert!(p["text"].as_str().is_some_and(|t| t.starts_with("Title")));
    }

    #[test]
    fn limits_are_enforced() {
        let mut message = Message::new("t".repeat(500), "b".repeat(5000));
        for i in 0..15 {
            message = message.push_field(Field::new(format!("f{i}"), "v".repeat(3000)));
        }
        let p = sink().payload(&message);
        let len = |v: &Value| v.as_str().map_or(0, chars);
        assert_eq!(len(&p["blocks"][0]["text"]["text"]), HEADER_MAX);
        assert_eq!(len(&p["blocks"][1]["text"]["text"]), SECTION_MAX);
        let fields = p["blocks"][2]["fields"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(fields.len(), FIELDS_MAX);
        assert!(fields.iter().all(|f| len(&f["text"]) <= FIELD_MAX));
        assert!(len(&p["text"]) <= TEXT_MAX);
    }

    #[test]
    fn empty_parts_are_left_out() {
        let p = sink().payload(&Message::new("  ", ""));
        assert_eq!(p["blocks"].as_array().map(Vec::len), Some(1));
        assert_eq!(p["blocks"][0]["text"]["text"], "Notification");
        let p = sink().payload(&Message::new("t", "").with_link("javascript:alert(1)"));
        assert_eq!(p["blocks"][1]["elements"][0]["text"], "javascript:alert(1)");
    }

    #[test]
    fn responses_classify() {
        let s = sink();
        assert_eq!(
            s.response(&HttpResponse::new(200).with_body("ok")),
            Ok(Delivery::new(200))
        );
        let err = s.response(&HttpResponse::new(403).with_body("invalid_token"));
        assert!(
            matches!(err, Err(Error::Rejected { status: 403, ref detail, .. }) if detail == "invalid_token")
        );
        assert!(
            s.response(&HttpResponse::new(429))
                .is_err_and(|e| e.is_retryable())
        );
    }

    #[test]
    fn bad_url_rejected() {
        assert!(SlackSink::new(SecretValue::new("hooks.slack.com/x")).is_err());
    }
}
