//! The provider-neutral notification every sink renders.

use rune_finding::{Finding, Severity};

use crate::template::MessageTemplate;

/// One labelled value shown with a message (a Slack section field, a
/// Discord embed field, a line in a Jira description).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Field {
    /// Label, e.g. `Severity`.
    pub name: String,
    /// Value, plain text.
    pub value: String,
    /// Whether the provider may lay the field out next to others.
    pub inline: bool,
}

impl Field {
    /// An inline field.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            inline: true,
        }
    }

    /// A field that takes a full row.
    pub fn block(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            inline: false,
            ..Self::new(name, value)
        }
    }
}

/// A notification, independent of where it is sent.
///
/// Text is plain: each sink escapes it for its provider's markup (Slack
/// `mrkdwn`, Jira wiki markup) and cuts it to the provider's length limits.
/// Build one by hand with [`Message::new`], or from a finding with
/// [`Message::from_finding`] or a [`MessageTemplate`].
///
/// ```
/// use rune_notify::{Field, Message};
/// use rune_finding::Severity;
///
/// let message = Message::new("Deploy blocked", "3 critical findings in api-gateway")
///     .with_severity(Severity::Critical)
///     .push_field(Field::new("Service", "api-gateway"))
///     .with_link("https://ci.example.test/runs/42");
/// assert_eq!(message.fields.len(), 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Message {
    /// One-line headline.
    pub title: String,
    /// Main text. May span lines.
    pub body: String,
    /// Severity, used for colours, routing and Jira priority.
    pub severity: Option<Severity>,
    /// Labelled values shown below the body.
    pub fields: Vec<Field>,
    /// An `http`/`https` link to more detail. Other schemes are shown as
    /// text, never as a link.
    pub link: Option<String>,
    /// Tags, e.g. Jira labels.
    pub labels: Vec<String>,
    /// A stable identity for deduplication on the receiving side, e.g.
    /// [`Finding::fingerprint`].
    pub fingerprint: Option<String>,
}

impl Message {
    /// A message with a title and body and nothing else.
    pub fn new(title: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            body: body.into(),
            severity: None,
            fields: Vec::new(),
            link: None,
            labels: Vec::new(),
            fingerprint: None,
        }
    }

    /// The message [`MessageTemplate::default`] renders for `finding`.
    pub fn from_finding<X>(finding: &Finding<X>) -> Self {
        MessageTemplate::default().render(finding)
    }

    /// Sets the severity.
    #[must_use]
    pub const fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Appends a field.
    #[must_use]
    pub fn push_field(mut self, field: Field) -> Self {
        self.fields.push(field);
        self
    }

    /// Sets the link.
    #[must_use]
    pub fn with_link(mut self, link: impl Into<String>) -> Self {
        self.link = Some(link.into());
        self
    }

    /// Appends a label.
    #[must_use]
    pub fn push_label(mut self, label: impl Into<String>) -> Self {
        self.labels.push(label.into());
        self
    }

    /// Sets the fingerprint.
    #[must_use]
    pub fn with_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }
}
