//! Discord webhooks.

use rune_finding::Severity;
use rune_secret_ref::SecretValue;
use serde_json::{Value, json};

use crate::text::{chars, check_url, is_web_link, one_line, status_error, truncate};
use crate::{Delivery, Error, HttpRequest, HttpResponse, Message, Method, Sink};

const NAME: &str = "discord";
const TITLE_MAX: usize = 256;
const DESCRIPTION_MAX: usize = 4096;
const FIELDS_MAX: usize = 25;
const FIELD_NAME_MAX: usize = 256;
const FIELD_VALUE_MAX: usize = 1024;
const FOOTER_MAX: usize = 2048;
/// Sum of every text in one embed.
const EMBED_TOTAL_MAX: usize = 6000;
const USERNAME_MAX: usize = 80;
/// Discord rejects empty field names and values; a zero-width space is the
/// usual stand-in.
const BLANK: &str = "\u{200b}";

/// Posts messages to a [Discord webhook] as one embed.
///
/// The embed has the title, the body as `description`, a colour from the
/// severity, the link as `url` (when it is `http`/`https`), the fields, and
/// the fingerprint as the footer. `allowed_mentions` is empty, so finding
/// text containing `@everyone` or role mentions pings nobody; Markdown
/// characters in the body and fields are escaped. Text is cut to Discord's
/// per-field limits and to the 6000-character total of an embed.
///
/// Discord answers `204 No Content`, or `200` with the created message when
/// [`with_wait`](Self::with_wait) is on; its id lands in [`Delivery::id`].
/// A `429` carries the wait in `Retry-After` and in the JSON body's
/// `retry_after`, both read into [`Error::RateLimited`].
///
/// [Discord webhook]: https://discord.com/developers/docs/resources/webhook#execute-webhook
///
/// ```
/// use rune_finding::Severity;
/// use rune_notify::{DiscordSink, Message, Sink};
/// use rune_secret_ref::SecretValue;
///
/// let discord = DiscordSink::new(SecretValue::new("https://discord.com/api/webhooks/1/XXXX"))?;
/// let request = discord.request(&Message::new("Scan done", "ping @everyone").with_severity(Severity::Low))?;
/// let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
/// assert_eq!(body["allowed_mentions"]["parse"], serde_json::json!([]));
/// assert_eq!(body["embeds"][0]["color"], 0x3498DB);
/// # Ok::<(), rune_notify::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscordSink {
    url: SecretValue,
    username: Option<String>,
    wait: bool,
}

impl DiscordSink {
    /// A sink for this webhook URL (`https://discord.com/api/webhooks/{id}/{token}`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] unless the URL is absolute `http`/`https`.
    pub fn new(webhook_url: SecretValue) -> Result<Self, Error> {
        check_url(NAME, &webhook_url)?;
        Ok(Self {
            url: webhook_url,
            username: None,
            wait: false,
        })
    }

    /// Overrides the webhook's display name.
    #[must_use]
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Asks Discord to answer with the created message (`?wait=true`), so
    /// [`Delivery::id`] is set.
    #[must_use]
    pub const fn with_wait(mut self, wait: bool) -> Self {
        self.wait = wait;
        self
    }

    /// The embed colour for a severity, as a 24-bit RGB integer.
    #[must_use]
    pub const fn color(severity: Severity) -> u32 {
        match severity {
            Severity::Informational => 0x0095_A5A6,
            Severity::Low => 0x0034_98DB,
            Severity::Medium => 0x00F1_C40F,
            Severity::High => 0x00E6_7E22,
            Severity::Critical => 0x00E7_4C3C,
        }
    }

    /// The JSON payload for `message`.
    #[must_use]
    pub fn payload(&self, message: &Message) -> Value {
        let mut embed = serde_json::Map::new();
        let mut used = 0;

        let title = truncate(&one_line(&message.title), TITLE_MAX);
        used += chars(&title);
        if !title.is_empty() {
            embed.insert("title".into(), title.into());
        }
        if let Some(severity) = message.severity {
            embed.insert("color".into(), Self::color(severity).into());
        }
        let mut extra = Vec::new();
        match &message.link {
            Some(link) if is_web_link(link) => {
                embed.insert("url".into(), link.clone().into());
            }
            Some(link) => extra.push(("Link", link.as_str())),
            None => {}
        }
        if let Some(fingerprint) = &message.fingerprint {
            let footer = truncate(&format!("fingerprint {fingerprint}"), FOOTER_MAX);
            used += chars(&footer);
            embed.insert("footer".into(), json!({ "text": footer }));
        }

        let mut fields = Vec::new();
        let all = message
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.value.as_str(), f.inline))
            .chain(extra.into_iter().map(|(name, value)| (name, value, false)));
        for (name, value, inline) in all.take(FIELDS_MAX) {
            let name = non_blank(truncate(&one_line(name), FIELD_NAME_MAX));
            let value = non_blank(truncate(&escape(value), FIELD_VALUE_MAX));
            let size = chars(&name) + chars(&value);
            if used + size > EMBED_TOTAL_MAX {
                break;
            }
            used += size;
            fields.push(json!({ "name": name, "value": value, "inline": inline }));
        }
        if !fields.is_empty() {
            embed.insert("fields".into(), fields.into());
        }

        let room = DESCRIPTION_MAX.min(EMBED_TOTAL_MAX.saturating_sub(used));
        let description = truncate(&escape(message.body.trim()), room);
        if !description.is_empty() {
            embed.insert("description".into(), description.into());
        }

        let mut payload = serde_json::Map::new();
        payload.insert("allowed_mentions".into(), json!({ "parse": [] }));
        if let Some(username) = &self.username {
            payload.insert(
                "username".into(),
                truncate(&one_line(username), USERNAME_MAX).into(),
            );
        }
        if embed.is_empty() {
            // Discord refuses a message with neither content nor embeds.
            payload.insert("content".into(), BLANK.into());
        } else {
            payload.insert("embeds".into(), json!([embed]));
        }
        Value::Object(payload)
    }
}

impl Sink for DiscordSink {
    fn name(&self) -> &'static str {
        NAME
    }

    fn request(&self, message: &Message) -> Result<HttpRequest, Error> {
        let url = if self.wait {
            let mut url = check_url(NAME, &self.url)?;
            url.query_pairs_mut().append_pair("wait", "true");
            SecretValue::new(String::from(url))
        } else {
            self.url.clone()
        };
        Ok(HttpRequest::new(Method::Post, url)
            .with_header("Content-Type", "application/json")
            .with_body(self.payload(message).to_string()))
    }

    fn response(&self, response: &HttpResponse) -> Result<Delivery, Error> {
        if !response.is_success() {
            let retry_after = serde_json::from_slice::<Value>(&response.body)
                .ok()
                .and_then(|body| body.get("retry_after")?.as_f64())
                .and_then(|secs| std::time::Duration::try_from_secs_f64(secs).ok());
            return Err(status_error(NAME, response, retry_after));
        }
        let mut delivery = Delivery::new(response.status);
        if response.status == 200 && !response.body.is_empty() {
            let body: Value =
                serde_json::from_slice(&response.body).map_err(|e| Error::InvalidResponse {
                    sink: NAME,
                    reason: format!("message body is not JSON: {e}"),
                })?;
            delivery.id = body.get("id").and_then(Value::as_str).map(str::to_owned);
        }
        Ok(delivery)
    }
}

/// Escapes Discord Markdown so finding text shows literally and cannot
/// form masked links.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '*' | '_' | '~' | '`' | '|' | '>' | '[' | ']') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn non_blank(text: String) -> String {
    if text.trim().is_empty() {
        BLANK.to_owned()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Field;

    fn sink() -> DiscordSink {
        DiscordSink::new(SecretValue::new("https://discord.test/api/webhooks/1/tok")).unwrap()
    }

    #[test]
    fn payload_matches_execute_webhook() {
        let message = Message::new("Critical!", "see [here](https://evil.test) **now**")
            .with_severity(Severity::Critical)
            .push_field(Field::new("Check", "a_b"))
            .push_field(Field::block("", ""))
            .with_link("https://shop.test/x")
            .with_fingerprint("ff00");
        let p = sink().with_username("runes").payload(&message);
        let e = &p["embeds"][0];
        assert_eq!(e["title"], "Critical!");
        assert_eq!(e["color"], 0x00E7_4C3C);
        assert_eq!(e["url"], "https://shop.test/x");
        assert_eq!(
            e["description"],
            "see \\[here\\](https://evil.test) \\*\\*now\\*\\*"
        );
        assert_eq!(
            e["fields"][0],
            json!({"name": "Check", "value": "a\\_b", "inline": true})
        );
        assert_eq!(e["fields"][1]["name"], BLANK);
        assert_eq!(e["fields"][1]["value"], BLANK);
        assert_eq!(e["footer"]["text"], "fingerprint ff00");
        assert_eq!(p["username"], "runes");
        assert_eq!(p["allowed_mentions"], json!({"parse": []}));
    }

    #[test]
    fn non_web_link_becomes_field() {
        let p = sink().payload(&Message::new("t", "").with_link("ftp://x"));
        assert!(p["embeds"][0].get("url").is_none());
        assert_eq!(p["embeds"][0]["fields"][0]["name"], "Link");
    }

    #[test]
    fn embed_total_stays_under_limit() {
        let mut message =
            Message::new("t".repeat(400), "d".repeat(9000)).with_fingerprint("f".repeat(3000));
        for _ in 0..40 {
            message = message.push_field(Field::new("n".repeat(300), "v".repeat(2000)));
        }
        let p = sink().payload(&message);
        let e = &p["embeds"][0];
        let len = |v: &Value| v.as_str().map_or(0, chars);
        let fields = e["fields"].as_array().cloned().unwrap_or_default();
        assert!(fields.len() <= FIELDS_MAX);
        let total = len(&e["title"])
            + len(&e["description"])
            + len(&e["footer"]["text"])
            + fields
                .iter()
                .map(|f| len(&f["name"]) + len(&f["value"]))
                .sum::<usize>();
        assert!(total <= EMBED_TOTAL_MAX, "{total}");
        assert_eq!(len(&e["title"]), TITLE_MAX);
        assert_eq!(len(&e["footer"]["text"]), FOOTER_MAX);
    }

    #[test]
    fn empty_message_still_valid() {
        let p = sink().payload(&Message::new("", ""));
        assert_eq!(p["content"], BLANK);
    }

    #[test]
    fn wait_and_responses() {
        let s = sink().with_wait(true);
        let req = s.request(&Message::new("t", "b")).unwrap();
        assert!(req.url.expose().ends_with("?wait=true"));
        let ok = s.response(&HttpResponse::new(200).with_body(r#"{"id":"123","type":0}"#));
        assert_eq!(ok.map(|d| d.id), Ok(Some("123".into())));
        assert_eq!(
            sink().response(&HttpResponse::new(204)),
            Ok(Delivery::new(204))
        );
        let limited = sink().response(&HttpResponse::new(429).with_body(
            r#"{"message":"You are being rate limited.","retry_after":0.25,"global":false}"#,
        ));
        assert_eq!(
            limited.err().and_then(|e| e.retry_after()),
            Some(std::time::Duration::from_millis(250))
        );
        assert!(matches!(
            sink().response(&HttpResponse::new(200).with_body("<html>")),
            Err(Error::InvalidResponse { .. })
        ));
    }
}
