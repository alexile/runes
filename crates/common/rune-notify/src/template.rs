//! Text templates that turn a [`Finding`] into a [`Message`].

use std::fmt::Write as _;

use rune_finding::{Finding, Location, Taxonomy};

use crate::{Error, Field, Message};

/// A value a template can insert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Var {
    Title,
    CheckId,
    Severity,
    SeverityUpper,
    Confidence,
    Location,
    Fingerprint,
    FingerprintShort,
    Cwe,
    Taxonomy,
    Remediation,
    References,
    Cvss,
    CvssScore,
    Evidence,
}

impl Var {
    const ALL: [(&'static str, Self); 15] = [
        ("title", Self::Title),
        ("check_id", Self::CheckId),
        ("severity", Self::Severity),
        ("severity_upper", Self::SeverityUpper),
        ("confidence", Self::Confidence),
        ("location", Self::Location),
        ("fingerprint", Self::Fingerprint),
        ("fingerprint_short", Self::FingerprintShort),
        ("cwe", Self::Cwe),
        ("taxonomy", Self::Taxonomy),
        ("remediation", Self::Remediation),
        ("references", Self::References),
        ("cvss", Self::Cvss),
        ("cvss_score", Self::CvssScore),
        ("evidence", Self::Evidence),
    ];

    fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, var)| *var)
    }

    fn render<X>(self, finding: &Finding<X>, out: &mut String) {
        match self {
            Self::Title => out.push_str(&finding.title),
            Self::CheckId => out.push_str(&finding.check_id),
            Self::Severity => out.push_str(finding.severity.as_str()),
            Self::SeverityUpper => out.push_str(&finding.severity.as_str().to_ascii_uppercase()),
            Self::Confidence => out.push_str(finding.confidence.as_str()),
            Self::Location => out.push_str(&location_text(&finding.location)),
            Self::Fingerprint => out.push_str(&finding.fingerprint()),
            Self::FingerprintShort => out.extend(finding.fingerprint().chars().take(12)),
            Self::Cwe => join(
                out,
                finding.taxonomy_in(&Taxonomy::Cwe).map(|t| t.id.as_str()),
                ", ",
            ),
            Self::Taxonomy => out.push_str(&taxonomy_text(finding)),
            Self::Remediation => {
                if let Some(remediation) = &finding.remediation {
                    out.push_str(&remediation.summary);
                }
            }
            Self::References => join(out, references(finding), "\n"),
            Self::Cvss => {
                if let Some(cvss) = &finding.cvss {
                    let _ = write!(out, "{:.1} ({})", cvss.base_score, cvss.vector);
                }
            }
            Self::CvssScore => {
                if let Some(cvss) = &finding.cvss {
                    let _ = write!(out, "{:.1}", cvss.base_score);
                }
            }
            Self::Evidence => {
                if let Some(evidence) = finding.evidence.first() {
                    let _ = write!(out, "{}: {}", evidence.label, evidence.snippet);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Text(String),
    Var(Var),
}

/// A text template with `{placeholder}`s filled from a [`Finding`].
///
/// `{{` and `}}` insert literal braces. Placeholders:
///
/// | Placeholder | Value |
/// | --- | --- |
/// | `{title}` | the finding's title |
/// | `{check_id}` | the check or rule id |
/// | `{severity}` / `{severity_upper}` | `high` / `HIGH` |
/// | `{confidence}` | `tentative`, `firm` or `certain` |
/// | `{location}` | the location as one line, e.g. `src/app.py:42:5` |
/// | `{fingerprint}` / `{fingerprint_short}` | the 64-hex fingerprint / its first 12 characters |
/// | `{cwe}` | CWE ids, comma-separated |
/// | `{taxonomy}` | every taxonomy reference, e.g. `CWE-89, OWASP Top 10 2021 A03:2021` |
/// | `{remediation}` | the remediation summary |
/// | `{references}` | remediation reference URLs, one per line |
/// | `{cvss}` / `{cvss_score}` | `9.8 (CVSS:3.1/…)` / `9.8` |
/// | `{evidence}` | the first evidence item as `label: snippet` |
///
/// Missing optional values render as empty text. An unknown placeholder is
/// an error when the template is parsed, not when it is rendered.
///
/// ```
/// use rune_finding::{Confidence, Finding, Location, Severity};
/// use rune_notify::Template;
///
/// let template = Template::parse("[{severity_upper}] {title} @ {location}")?;
/// let finding = Finding::<()>::new(
///     "tls.weak_protocol",
///     "TLS 1.0 enabled",
///     Severity::Medium,
///     Confidence::Certain,
///     Location::network("mail.example.test", 465),
/// );
/// assert_eq!(template.render(&finding), "[MEDIUM] TLS 1.0 enabled @ mail.example.test:465");
/// assert!(Template::parse("{nope}").is_err());
/// # Ok::<(), rune_notify::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    parts: Vec<Part>,
}

impl Template {
    /// Parses template text.
    ///
    /// # Errors
    ///
    /// [`Error::Template`] for an unknown or unterminated placeholder or a
    /// lone `}`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut parts = Vec::new();
        let mut literal = String::new();
        let mut chars = text.char_indices().peekable();
        while let Some((at, c)) = chars.next() {
            match c {
                '{' if chars.peek().is_some_and(|&(_, n)| n == '{') => {
                    chars.next();
                    literal.push('{');
                }
                '}' if chars.peek().is_some_and(|&(_, n)| n == '}') => {
                    chars.next();
                    literal.push('}');
                }
                '{' => {
                    let start = at + 1;
                    let Some(len) = text[start..].find('}') else {
                        return Err(Error::Template {
                            position: at,
                            reason: "unterminated placeholder".to_owned(),
                        });
                    };
                    let name = &text[start..start + len];
                    let var = Var::parse(name.trim()).ok_or_else(|| Error::Template {
                        position: at,
                        reason: format!("unknown placeholder {{{name}}}"),
                    })?;
                    while chars.peek().is_some_and(|&(i, _)| i <= start + len) {
                        chars.next();
                    }
                    if !literal.is_empty() {
                        parts.push(Part::Text(std::mem::take(&mut literal)));
                    }
                    parts.push(Part::Var(var));
                }
                '}' => {
                    return Err(Error::Template {
                        position: at,
                        reason: "lone `}` (write `}}` for a literal brace)".to_owned(),
                    });
                }
                other => literal.push(other),
            }
        }
        if !literal.is_empty() {
            parts.push(Part::Text(literal));
        }
        Ok(Self { parts })
    }

    /// The placeholder names a template may use.
    pub fn placeholders() -> impl Iterator<Item = &'static str> {
        Var::ALL.iter().map(|(name, _)| *name)
    }

    /// Fills the template from `finding`.
    #[must_use]
    pub fn render<X>(&self, finding: &Finding<X>) -> String {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                Part::Text(text) => out.push_str(text),
                Part::Var(var) => var.render(finding, &mut out),
            }
        }
        out
    }
}

/// Renders a [`Finding`] into a [`Message`]: a title and a body
/// [`Template`], plus standard fields, link, labels and fingerprint.
///
/// The default title is `[{severity_upper}] {title}` and the default body is
/// `{check_id} at {location}`, a blank line and `{remediation}`. Trailing
/// whitespace is trimmed from both.
///
/// The rendered message carries:
///
/// - `severity`: the finding's severity;
/// - `fields` (unless turned off): Severity, Confidence, Check, Location,
///   then Taxonomy and CVSS when the finding has them;
/// - `link`: the finding's URL for a URL location, else its first
///   remediation reference;
/// - `labels`: `severity-<level>` and the check id;
/// - `fingerprint`: [`Finding::fingerprint`].
///
/// ```
/// use rune_finding::{Confidence, Finding, Location, Severity, TaxonomyRef};
/// use rune_notify::{MessageTemplate, Template};
///
/// let finding = Finding::<()>::new(
///     "python.sqli",
///     "SQL injection",
///     Severity::High,
///     Confidence::Firm,
///     Location::file("app.py").with_lines(42, 42),
/// )
/// .push_taxonomy(TaxonomyRef::cwe(89));
///
/// let message = MessageTemplate::default()
///     .with_title(Template::parse("{title} ({cwe})")?)
///     .render(&finding);
/// assert_eq!(message.title, "SQL injection (CWE-89)");
/// assert_eq!(message.body, "python.sqli at app.py:42");
/// assert_eq!(message.fingerprint.as_deref().map(str::len), Some(64));
/// # Ok::<(), rune_notify::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MessageTemplate {
    /// Template for [`Message::title`].
    pub title: Template,
    /// Template for [`Message::body`].
    pub body: Template,
    /// Whether to add the standard fields.
    pub fields: bool,
}

impl Default for MessageTemplate {
    fn default() -> Self {
        Self {
            title: Template {
                parts: vec![
                    Part::Text("[".to_owned()),
                    Part::Var(Var::SeverityUpper),
                    Part::Text("] ".to_owned()),
                    Part::Var(Var::Title),
                ],
            },
            body: Template {
                parts: vec![
                    Part::Var(Var::CheckId),
                    Part::Text(" at ".to_owned()),
                    Part::Var(Var::Location),
                    Part::Text("\n\n".to_owned()),
                    Part::Var(Var::Remediation),
                ],
            },
            fields: true,
        }
    }
}

impl MessageTemplate {
    /// Replaces the title template.
    #[must_use]
    pub fn with_title(mut self, title: Template) -> Self {
        self.title = title;
        self
    }

    /// Replaces the body template.
    #[must_use]
    pub fn with_body(mut self, body: Template) -> Self {
        self.body = body;
        self
    }

    /// Turns the standard fields on or off.
    #[must_use]
    pub const fn with_fields(mut self, fields: bool) -> Self {
        self.fields = fields;
        self
    }

    /// Renders `finding`.
    #[must_use]
    pub fn render<X>(&self, finding: &Finding<X>) -> Message {
        let mut message = Message::new(
            self.title.render(finding).trim_end(),
            self.body.render(finding).trim_end(),
        )
        .with_severity(finding.severity)
        .with_fingerprint(finding.fingerprint())
        .push_label(format!("severity-{}", finding.severity.as_str()))
        .push_label(finding.check_id.clone());

        if self.fields {
            message = message
                .push_field(Field::new("Severity", finding.severity.as_str()))
                .push_field(Field::new("Confidence", finding.confidence.as_str()))
                .push_field(Field::new("Check", finding.check_id.clone()))
                .push_field(Field::block("Location", location_text(&finding.location)));
            let taxonomy = taxonomy_text(finding);
            if !taxonomy.is_empty() {
                message = message.push_field(Field::block("Taxonomy", taxonomy));
            }
            if let Some(cvss) = &finding.cvss {
                message = message.push_field(Field::block(
                    "CVSS",
                    format!("{:.1} ({})", cvss.base_score, cvss.vector),
                ));
            }
        }

        let link = match &finding.location {
            Location::Url { url, .. } => Some(url.clone()),
            _ => None,
        }
        .or_else(|| references(finding).next().map(str::to_owned));
        if let Some(link) = link {
            message = message.with_link(link);
        }
        message
    }
}

/// A location as one line of text.
fn location_text(location: &Location) -> String {
    match location {
        Location::Network { host, port } => {
            if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            }
        }
        Location::Url { url, parameter } => parameter
            .as_ref()
            .map_or_else(|| url.clone(), |name| format!("{url} (parameter {name})")),
        Location::File {
            path,
            start_line,
            start_column,
            ..
        } => {
            let mut out = path.clone();
            if let Some(line) = start_line {
                let _ = write!(out, ":{line}");
                if let Some(column) = start_column {
                    let _ = write!(out, ":{column}");
                }
            }
            out
        }
        Location::ClusterObject {
            namespace,
            kind,
            name,
        } => format!("{namespace}/{kind}/{name}"),
        Location::Artifact { path, offset } => {
            offset.map_or_else(|| path.clone(), |offset| format!("{path}@{offset:#x}"))
        }
        _ => "(unknown location)".to_owned(),
    }
}

fn taxonomy_text<X>(finding: &Finding<X>) -> String {
    let mut out = String::new();
    for (i, entry) in finding.taxonomy.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        if entry.framework != Taxonomy::Cwe {
            out.push_str(entry.framework.display_name());
            out.push(' ');
        }
        out.push_str(&entry.id);
    }
    out
}

fn references<X>(finding: &Finding<X>) -> impl Iterator<Item = &str> {
    finding
        .remediation
        .iter()
        .flat_map(|r| r.references.iter())
        .chain(finding.remediation_refs.iter())
        .map(String::as_str)
}

fn join<'a>(out: &mut String, items: impl Iterator<Item = &'a str>, sep: &str) {
    for (i, item) in items.enumerate() {
        if i > 0 {
            out.push_str(sep);
        }
        out.push_str(item);
    }
}

#[cfg(test)]
mod tests {
    use rune_finding::{Confidence, Cvss, Evidence, Remediation, Severity, TaxonomyRef};

    use super::*;

    fn finding() -> Finding {
        Finding::<()>::new(
            "web.xss",
            "Reflected XSS",
            Severity::High,
            Confidence::Certain,
            Location::url("https://shop.test/search").with_parameter("q"),
        )
        .push_taxonomy(TaxonomyRef::cwe(79))
        .push_taxonomy(TaxonomyRef::owasp("A03:2021"))
        .push_evidence(Evidence::new("payload", "<script>"))
        .with_remediation(
            Remediation::new("Encode output").push_reference("https://cheatsheets.test/xss"),
        )
        .with_cvss(Cvss::new("CVSS:3.1/AV:N", 6.1))
    }

    #[test]
    fn every_placeholder_renders() {
        let f = finding();
        let render = |t: &str| Template::parse(t).map(|t| t.render(&f));
        assert_eq!(render("{title}").as_deref(), Ok("Reflected XSS"));
        assert_eq!(render("{check_id}").as_deref(), Ok("web.xss"));
        assert_eq!(
            render("{severity}/{severity_upper}").as_deref(),
            Ok("high/HIGH")
        );
        assert_eq!(render("{confidence}").as_deref(), Ok("certain"));
        assert_eq!(
            render("{location}").as_deref(),
            Ok("https://shop.test/search (parameter q)")
        );
        assert_eq!(render("{fingerprint}").map(|s| s.len()), Ok(64));
        assert_eq!(render("{fingerprint_short}").map(|s| s.len()), Ok(12));
        assert_eq!(render("{cwe}").as_deref(), Ok("CWE-79"));
        assert_eq!(
            render("{taxonomy}").as_deref(),
            Ok("CWE-79, OWASP Top 10 2021 A03:2021")
        );
        assert_eq!(render("{remediation}").as_deref(), Ok("Encode output"));
        assert_eq!(
            render("{references}").as_deref(),
            Ok("https://cheatsheets.test/xss")
        );
        assert_eq!(render("{cvss}").as_deref(), Ok("6.1 (CVSS:3.1/AV:N)"));
        assert_eq!(render("{cvss_score}").as_deref(), Ok("6.1"));
        assert_eq!(render("{evidence}").as_deref(), Ok("payload: <script>"));
        assert_eq!(
            render("{{x}} { title }").as_deref(),
            Ok("{x} Reflected XSS")
        );
        assert_eq!(Template::placeholders().count(), Var::ALL.len());
    }

    #[test]
    fn parse_errors_have_positions() {
        let err = |t: &str| match Template::parse(t) {
            Err(Error::Template { position, .. }) => Some(position),
            _ => None,
        };
        assert_eq!(err("ab {nope}"), Some(3));
        assert_eq!(err("ab {title"), Some(3));
        assert_eq!(err("ab } c"), Some(3));
        assert_eq!(err("é{title}}"), Some(9));
    }

    #[test]
    fn default_template_renders_message() {
        let message = Message::from_finding(&finding());
        assert_eq!(message.title, "[HIGH] Reflected XSS");
        assert_eq!(
            message.body,
            "web.xss at https://shop.test/search (parameter q)\n\nEncode output"
        );
        assert_eq!(message.link.as_deref(), Some("https://shop.test/search"));
        assert_eq!(message.labels, ["severity-high", "web.xss"]);
        let names: Vec<_> = message.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Severity",
                "Confidence",
                "Check",
                "Location",
                "Taxonomy",
                "CVSS"
            ]
        );
        let bare = MessageTemplate::default()
            .with_fields(false)
            .render(&finding());
        assert_eq!(bare.fields, []);
    }

    #[test]
    fn locations_render() {
        assert_eq!(location_text(&Location::network("::1", 22)), "[::1]:22");
        assert_eq!(
            location_text(&Location::file("a.rs").with_lines(3, 4).with_columns(5, 6)),
            "a.rs:3:5"
        );
        assert_eq!(
            location_text(&Location::cluster_object("prod", "Ingress", "web")),
            "prod/Ingress/web"
        );
        assert_eq!(
            location_text(&Location::artifact("app.bin", Some(255))),
            "app.bin@0xff"
        );
        assert_eq!(
            location_text(&Location::artifact("app.bin", None)),
            "app.bin"
        );
    }
}
