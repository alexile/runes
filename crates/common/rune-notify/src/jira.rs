//! Jira issues.

use rune_finding::Severity;
use rune_secret_ref::SecretValue;
use serde_json::{Value, json};

use crate::text::{check_url, is_web_link, one_line, status_error, truncate};
use crate::{Delivery, Error, HttpRequest, HttpResponse, Message, Method, Sink};

const NAME: &str = "jira";
const SUMMARY_MAX: usize = 255;
const DESCRIPTION_MAX: usize = 32_767;
const LABEL_MAX: usize = 255;

/// How [`JiraSink`] authenticates.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JiraAuth {
    /// Jira Cloud: the account e-mail and an [API token], sent as HTTP
    /// Basic.
    ///
    /// [API token]: https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/
    Basic {
        /// Account e-mail.
        email: String,
        /// API token.
        api_token: SecretValue,
    },
    /// Jira Data Center / Server: a personal access token, sent as
    /// `Bearer`.
    Bearer(SecretValue),
}

impl JiraAuth {
    /// Basic authentication with an e-mail and API token.
    pub fn basic(email: impl Into<String>, api_token: SecretValue) -> Self {
        Self::Basic {
            email: email.into(),
            api_token,
        }
    }

    fn header(&self) -> SecretValue {
        match self {
            Self::Basic { email, api_token } => {
                let mut pair = String::with_capacity(email.len() + 1 + api_token.expose().len());
                pair.push_str(email);
                pair.push(':');
                pair.push_str(api_token.expose());
                let header = format!("Basic {}", rune_base64::encode(pair.as_bytes()));
                // Hand the plain pair to SecretValue so its drop wipes it
                // when rune-secret-ref's `zeroize` feature is on.
                drop(SecretValue::new(pair));
                SecretValue::new(header)
            }
            Self::Bearer(token) => SecretValue::new(format!("Bearer {}", token.expose().trim())),
        }
    }
}

/// Opens one Jira issue per message through the [REST API v2]
/// (`POST /rest/api/2/issue`).
///
/// The issue gets the title as `summary` (one line, at most 255
/// characters), a wiki-markup `description` with the body, the fields as
/// `*Name:* value` lines, the link and the fingerprint, and the message's
/// labels plus `fp-<first 16 hex of the fingerprint>` so callers can search
/// for an existing issue before filing a duplicate. Wiki-markup characters
/// in finding text are escaped. With
/// [`with_priorities`](Self::with_priorities) the severity also sets the
/// priority (`Highest` … `Lowest`).
///
/// API v2 is used because it takes the description as text; v3 needs
/// Atlassian Document Format. Both Jira Cloud and Data Center serve v2.
///
/// Jira answers `201 Created` with `{"id", "key", "self"}`; the key goes to
/// [`Delivery::id`] and `<base>/browse/<key>` to [`Delivery::url`]. A `400`
/// carries `errorMessages` and per-field `errors`, which are joined into
/// [`Error::Rejected`].
///
/// [REST API v2]: https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issues/#api-rest-api-2-issue-post
///
/// ```
/// use rune_notify::{JiraAuth, JiraSink, Message, Sink};
/// use rune_secret_ref::SecretValue;
///
/// let jira = JiraSink::new(
///     "https://acme.atlassian.net",
///     "SEC",
///     JiraAuth::basic("bot@acme.test", SecretValue::new("api-token")),
/// )?;
/// let request = jira.request(&Message::new("SQL injection", "in app.py"))?;
/// assert_eq!(request.url.expose(), "https://acme.atlassian.net/rest/api/2/issue");
/// let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
/// assert_eq!(body["fields"]["project"]["key"], "SEC");
/// assert_eq!(body["fields"]["issuetype"]["name"], "Bug");
/// # Ok::<(), rune_notify::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JiraSink {
    base: String,
    project_key: String,
    auth: JiraAuth,
    issue_type: String,
    labels: Vec<String>,
    priorities: bool,
}

impl JiraSink {
    /// A sink filing issues in `project_key` on the Jira at `base_url`
    /// (e.g. `https://acme.atlassian.net`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] unless `base_url` is absolute `http`/`https`;
    /// [`Error::InvalidConfig`] for an empty project key or one with
    /// characters other than ASCII letters, digits and `_`.
    pub fn new(
        base_url: &str,
        project_key: impl Into<String>,
        auth: JiraAuth,
    ) -> Result<Self, Error> {
        let parsed = check_url(NAME, &SecretValue::new(base_url))?;
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(Error::InvalidUrl {
                sink: NAME,
                reason: "base URL must not have a query or fragment".to_owned(),
            });
        }
        let project_key = project_key.into();
        if project_key.is_empty()
            || !project_key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(Error::InvalidConfig {
                sink: NAME,
                reason: format!("invalid project key {project_key:?}"),
            });
        }
        Ok(Self {
            base: base_url.trim().trim_end_matches('/').to_owned(),
            project_key,
            auth,
            issue_type: "Bug".to_owned(),
            labels: Vec::new(),
            priorities: false,
        })
    }

    /// Files issues of this type instead of `Bug` (e.g. `Task`,
    /// `Vulnerability`).
    #[must_use]
    pub fn with_issue_type(mut self, issue_type: impl Into<String>) -> Self {
        self.issue_type = issue_type.into();
        self
    }

    /// Adds a label to every issue, after the message's own.
    #[must_use]
    pub fn push_label(mut self, label: impl Into<String>) -> Self {
        self.labels.push(label.into());
        self
    }

    /// Sets the issue priority from the message severity. Off by default,
    /// because a project whose create screen lacks the priority field
    /// rejects the issue.
    #[must_use]
    pub const fn with_priorities(mut self, on: bool) -> Self {
        self.priorities = on;
        self
    }

    /// The Jira priority name for a severity.
    #[must_use]
    pub const fn priority(severity: Severity) -> &'static str {
        match severity {
            Severity::Critical => "Highest",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Informational => "Lowest",
        }
    }

    /// The JSON payload for `message`.
    #[must_use]
    pub fn payload(&self, message: &Message) -> Value {
        let summary = match one_line(&message.title) {
            empty if empty.is_empty() => "Notification".to_owned(),
            title => truncate(&title, SUMMARY_MAX),
        };

        let mut labels: Vec<String> = Vec::new();
        let fingerprint_label = message
            .fingerprint
            .as_deref()
            .map(|fp| format!("fp-{}", fp.chars().take(16).collect::<String>()));
        for label in message
            .labels
            .iter()
            .chain(&self.labels)
            .chain(fingerprint_label.as_ref())
        {
            let label = label_text(label);
            if !label.is_empty() && !labels.contains(&label) {
                labels.push(label);
            }
        }

        let mut fields = serde_json::Map::new();
        fields.insert("project".into(), json!({ "key": self.project_key }));
        fields.insert("summary".into(), summary.into());
        fields.insert(
            "description".into(),
            truncate(&description(message), DESCRIPTION_MAX).into(),
        );
        fields.insert("issuetype".into(), json!({ "name": self.issue_type }));
        fields.insert("labels".into(), labels.into());
        if self.priorities
            && let Some(severity) = message.severity
        {
            fields.insert(
                "priority".into(),
                json!({ "name": Self::priority(severity) }),
            );
        }
        json!({ "fields": fields })
    }
}

impl Sink for JiraSink {
    fn name(&self) -> &'static str {
        NAME
    }

    fn request(&self, message: &Message) -> Result<HttpRequest, Error> {
        let url = SecretValue::new(format!("{}/rest/api/2/issue", self.base));
        Ok(HttpRequest::new(Method::Post, url)
            .with_header("Content-Type", "application/json")
            .with_header("Accept", "application/json")
            .with_secret_header("Authorization", self.auth.header())
            .with_body(self.payload(message).to_string()))
    }

    fn response(&self, response: &HttpResponse) -> Result<Delivery, Error> {
        if !response.is_success() {
            return Err(match status_error(NAME, response, None) {
                Error::Rejected {
                    sink,
                    status,
                    detail,
                } => Error::Rejected {
                    sink,
                    status,
                    detail: jira_errors(&response.body).unwrap_or(detail),
                },
                other => other,
            });
        }
        let body: Value =
            serde_json::from_slice(&response.body).map_err(|e| Error::InvalidResponse {
                sink: NAME,
                reason: format!("issue body is not JSON: {e}"),
            })?;
        let key =
            body.get("key")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::InvalidResponse {
                    sink: NAME,
                    reason: "issue body has no `key`".to_owned(),
                })?;
        let mut delivery = Delivery::new(response.status);
        delivery.url = Some(format!("{}/browse/{key}", self.base));
        delivery.id = Some(key.to_owned());
        Ok(delivery)
    }
}

/// The wiki-markup description.
fn description(message: &Message) -> String {
    let mut out = escape(message.body.trim());
    let mut lines = Vec::new();
    for field in &message.fields {
        lines.push(format!(
            "*{}:* {}",
            escape(&one_line(&field.name)),
            escape(&one_line(&field.value))
        ));
    }
    if let Some(link) = &message.link {
        if is_web_link(link) {
            let target = link
                .replace('|', "%7C")
                .replace(']', "%5D")
                .replace('[', "%5B");
            lines.push(format!("[Details|{target}]"));
        } else {
            lines.push(format!("*Link:* {}", escape(&one_line(link))));
        }
    }
    if let Some(fingerprint) = &message.fingerprint {
        lines.push(format!("*Fingerprint:* {}", escape(&one_line(fingerprint))));
    }
    if !lines.is_empty() {
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str(&lines.join("\n"));
    }
    out
}

/// Escapes Jira wiki markup with backslashes.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(
            c,
            '\\' | '{' | '}' | '[' | ']' | '|' | '*' | '_' | '+' | '^' | '~' | '!' | '?'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A Jira label: no whitespace, at most 255 characters.
fn label_text(label: &str) -> String {
    let joined = label.split_whitespace().collect::<Vec<_>>().join("_");
    joined.chars().take(LABEL_MAX).collect()
}

/// `errorMessages` and `errors` from a Jira error body, joined.
fn jira_errors(body: &[u8]) -> Option<String> {
    let body: Value = serde_json::from_slice(body).ok()?;
    let mut parts: Vec<String> = body
        .get("errorMessages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    if let Some(errors) = body.get("errors").and_then(Value::as_object) {
        for (field, message) in errors {
            if let Some(message) = message.as_str() {
                parts.push(format!("{field}: {message}"));
            }
        }
    }
    (!parts.is_empty()).then(|| truncate(&parts.join("; "), 300))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Field, HeaderValue};

    fn sink() -> JiraSink {
        JiraSink::new(
            "https://jira.test/",
            "SEC",
            JiraAuth::basic("bot@x.test", SecretValue::new("tok")),
        )
        .unwrap()
    }

    #[test]
    fn payload_matches_create_issue() {
        let message = Message::new("SQLi in\napp", "uses {code} and [x|y]")
            .with_severity(Severity::Critical)
            .push_field(Field::new("Check", "py_sqli"))
            .with_link("https://shop.test/a|b")
            .push_label("severity critical")
            .with_fingerprint("0123456789abcdef0123");
        let p = sink()
            .with_priorities(true)
            .push_label("runes")
            .payload(&message);
        let f = &p["fields"];
        assert_eq!(f["project"], json!({"key": "SEC"}));
        assert_eq!(f["summary"], "SQLi in app");
        assert_eq!(f["issuetype"], json!({"name": "Bug"}));
        assert_eq!(f["priority"], json!({"name": "Highest"}));
        assert_eq!(
            f["labels"],
            json!(["severity_critical", "runes", "fp-0123456789abcdef"])
        );
        assert_eq!(
            f["description"],
            "uses \\{code\\} and \\[x\\|y\\]\n\n*Check:* py\\_sqli\n[Details|https://shop.test/a%7Cb]\n*Fingerprint:* 0123456789abcdef0123"
        );
        assert!(sink().payload(&message)["fields"].get("priority").is_none());
    }

    #[test]
    fn auth_headers() {
        let req = sink().request(&Message::new("t", "")).unwrap();
        let auth = req.header("authorization").unwrap();
        assert!(auth.is_secret());
        assert_eq!(
            auth.expose(),
            format!("Basic {}", rune_base64::encode(b"bot@x.test:tok"))
        );
        assert_eq!(req.url.expose(), "https://jira.test/rest/api/2/issue");
        let bearer = JiraSink::new(
            "http://dc.test/jira",
            "OPS",
            JiraAuth::Bearer(SecretValue::new("pat")),
        )
        .unwrap()
        .request(&Message::new("t", ""))
        .unwrap();
        assert_eq!(
            bearer.header("Authorization").map(HeaderValue::expose),
            Some("Bearer pat")
        );
        assert_eq!(bearer.url.expose(), "http://dc.test/jira/rest/api/2/issue");
    }

    #[test]
    fn config_checked() {
        let auth = || JiraAuth::Bearer(SecretValue::new("x"));
        assert!(JiraSink::new("https://j.test", "", auth()).is_err());
        assert!(JiraSink::new("https://j.test", "SE C", auth()).is_err());
        assert!(JiraSink::new("https://j.test?x=1", "SEC", auth()).is_err());
        assert!(JiraSink::new("j.test", "SEC", auth()).is_err());
    }

    #[test]
    fn responses() {
        let ok = sink().response(&HttpResponse::new(201).with_body(
            r#"{"id":"10000","key":"SEC-24","self":"https://jira.test/rest/api/2/issue/10000"}"#,
        ));
        let d = ok.unwrap();
        assert_eq!(d.id.as_deref(), Some("SEC-24"));
        assert_eq!(d.url.as_deref(), Some("https://jira.test/browse/SEC-24"));
        let bad = sink().response(&HttpResponse::new(400).with_body(
            r#"{"errorMessages":["Bad"],"errors":{"priority":"Field 'priority' cannot be set."}}"#,
        ));
        assert_eq!(
            bad,
            Err(Error::Rejected {
                sink: "jira",
                status: 400,
                detail: "Bad; priority: Field 'priority' cannot be set.".into()
            })
        );
        assert!(matches!(
            sink().response(&HttpResponse::new(201).with_body("{}")),
            Err(Error::InvalidResponse { .. })
        ));
    }
}
