//! SMTP and SMTPS: greeting, `EHLO` extensions, `STARTTLS`.

use rune_service_probe::rune_finding::{
    Confidence, Evidence, Finding, Remediation, Severity, TaxonomyRef,
};
use rune_service_probe::{
    Action, End, Error, ProbeSession, ServiceInfo, ServiceProbe, Target, TlsSupport,
};

use crate::Reply;
use crate::conversation::{Conversation, command};
use crate::reply::{detect_product, sanitize_arg};

/// The `EHLO` name the probe sends unless told otherwise. `.invalid` is
/// reserved (RFC 2606), so it names no real host.
pub const DEFAULT_HELO_NAME: &str = "probe.invalid";

/// Greeting substrings and the products they identify, most specific first.
const PRODUCTS: &[(&str, &str)] = &[
    ("Microsoft ESMTP MAIL Service", "Microsoft SMTP Service"),
    ("Postfix", "Postfix"),
    ("Exim", "Exim"),
    ("Sendmail", "Sendmail"),
    ("OpenSMTPD", "OpenSMTPD"),
    ("hMailServer", "hMailServer"),
    ("Haraka", "Haraka"),
    ("MDaemon", "MDaemon"),
    ("IceWarp", "IceWarp"),
    ("Kerio Connect", "Kerio Connect"),
    ("CommuniGate Pro", "CommuniGate Pro"),
    ("Zimbra", "Zimbra"),
    ("qmail", "qmail"),
    ("Courier", "Courier"),
];

/// A read-only SMTP probe (RFC 5321), for SMTP (25), submission (587) and,
/// over a TLS stream the caller opened, SMTPS (465).
///
/// It reads the greeting, sends `EHLO` (falling back to `HELO`), records
/// the advertised extensions and sends `QUIT`. It sends no `MAIL`, `RCPT`,
/// `VRFY`, `EXPN` or `AUTH`. With [`with_starttls_check`](Self::with_starttls_check)
/// it also sends `STARTTLS` to confirm the upgrade is accepted, then hangs
/// up before any TLS handshake.
///
/// [`ServiceInfo`] fields: `product`/`version` from the greeting, `banner`
/// (the greeting's first line), `capabilities` (the `EHLO` extension lines),
/// `tls` (`Optional` when `STARTTLS` is advertised, `NotOffered` when it is
/// not, `Implicit` for SMTPS) and `details` under `smtp.*` (`smtps.*`).
///
/// | Check id                   | When (plaintext SMTP only, except the last)                 |
/// | -------------------------- | ----------------------------------------------------------- |
/// | `smtp.starttls_missing`    | `EHLO` succeeded and `STARTTLS` is not advertised           |
/// | `smtp.auth_before_tls`     | `AUTH PLAIN` or `LOGIN` is offered before TLS               |
/// | `smtp.user_enumeration`    | `VRFY` or `EXPN` is advertised                              |
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SmtpProbe {
    helo_name: String,
    implicit_tls: bool,
    starttls_check: bool,
}

impl Default for SmtpProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtpProbe {
    /// A plaintext SMTP probe (ports 25 and 587).
    #[must_use]
    pub fn new() -> Self {
        Self {
            helo_name: DEFAULT_HELO_NAME.to_owned(),
            implicit_tls: false,
            starttls_check: false,
        }
    }

    /// An SMTPS probe (port 465), for a stream that is already TLS. Its id
    /// is `smtps` and its TLS support is reported as implicit.
    #[must_use]
    pub fn smtps() -> Self {
        Self {
            implicit_tls: true,
            ..Self::new()
        }
    }

    /// The name to send in `EHLO`/`HELO`. Characters other than ASCII
    /// letters, digits, `.`, `-`, `:`, `[` and `]` are dropped; an empty
    /// result falls back to [`DEFAULT_HELO_NAME`].
    #[must_use]
    pub fn with_helo_name(mut self, name: &str) -> Self {
        let clean = sanitize_arg(name, |c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']')
        });
        self.helo_name = if clean.is_empty() {
            DEFAULT_HELO_NAME.to_owned()
        } else {
            clean
        };
        self
    }

    /// Whether to send `STARTTLS` when it is advertised, to confirm the
    /// server accepts it (default off). The probe hangs up right after the
    /// reply. Ignored for SMTPS.
    #[must_use]
    pub const fn with_starttls_check(mut self, check: bool) -> Self {
        self.starttls_check = check;
        self
    }

    const fn id_str(&self) -> &'static str {
        if self.implicit_tls { "smtps" } else { "smtp" }
    }
}

impl ServiceProbe for SmtpProbe {
    fn id(&self) -> &str {
        self.id_str()
    }

    fn default_ports(&self) -> &[u16] {
        if self.implicit_tls {
            &[465]
        } else {
            &[25, 587]
        }
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(Session {
            target: target.clone(),
            probe: self.clone(),
            conv: Conversation::default(),
            state: State::Greeting,
            greeting: None,
            ehlo: None,
            helo: None,
            starttls: None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Greeting,
    Ehlo,
    Helo,
    StartTls,
    Quit,
    Over,
}

struct Session {
    target: Target,
    probe: SmtpProbe,
    conv: Conversation,
    state: State,
    greeting: Option<Reply>,
    ehlo: Option<Reply>,
    helo: Option<Reply>,
    starttls: Option<Reply>,
}

/// The `EHLO` extensions: keyword (uppercase) and parameters.
fn extensions(ehlo: &Reply) -> Vec<(String, Vec<&str>)> {
    ehlo.lines
        .iter()
        .skip(1)
        .filter_map(|line| {
            let mut words = line.split([' ', '=']).filter(|w| !w.is_empty());
            let keyword = words.next()?.to_ascii_uppercase();
            Some((keyword, words.collect()))
        })
        .collect()
}

impl Session {
    fn handle(&mut self, reply: Reply) -> Action {
        match self.state {
            State::Greeting => {
                let ready = reply.code == 220;
                self.greeting = Some(reply);
                if ready {
                    self.state = State::Ehlo;
                    command("EHLO", Some(&self.probe.helo_name))
                } else {
                    self.state = State::Over;
                    Action::Done
                }
            }
            State::Ehlo => {
                let ok = reply.is_positive();
                self.ehlo = Some(reply);
                if ok {
                    self.after_hello()
                } else {
                    self.state = State::Helo;
                    command("HELO", Some(&self.probe.helo_name))
                }
            }
            State::Helo => {
                self.helo = Some(reply);
                self.after_hello()
            }
            State::StartTls => {
                self.starttls = Some(reply);
                self.state = State::Over;
                Action::Done
            }
            State::Quit | State::Over => {
                self.state = State::Over;
                Action::Done
            }
        }
    }

    fn advertised(&self, keyword: &str) -> bool {
        self.ehlo_ok()
            .is_some_and(|e| extensions(e).iter().any(|(k, _)| k == keyword))
    }

    fn ehlo_ok(&self) -> Option<&Reply> {
        self.ehlo.as_ref().filter(|e| e.is_positive())
    }

    fn after_hello(&mut self) -> Action {
        if self.probe.starttls_check && !self.probe.implicit_tls && self.advertised("STARTTLS") {
            self.state = State::StartTls;
            command("STARTTLS", None)
        } else {
            self.state = State::Quit;
            command("QUIT", None)
        }
    }

    fn finding(
        &self,
        issue: &str,
        title: &str,
        severity: Severity,
        confidence: Confidence,
    ) -> Finding {
        self.target.finding(
            format!("{}.{issue}", self.probe.id_str()),
            title,
            severity,
            confidence,
        )
    }

    fn report(&self, greeting: &Reply) -> ServiceInfo {
        let id = self.probe.id_str();
        let mut info = ServiceInfo::new(id)
            .with_banner(format!("{} {}", greeting.code, greeting.first_line()))
            .with_detail(format!("{id}.greeting_code"), greeting.code.to_string());
        if let Some(host) = greeting.first_line().split_whitespace().next() {
            info = info.with_detail(format!("{id}.hostname"), host);
        }
        let text = greeting.lines.join(" ");
        if let Some((product, version)) = detect_product(&text, PRODUCTS) {
            info = info.with_product(product);
            if let Some(version) = version {
                info = info.with_version(version);
            }
        }
        if self.probe.implicit_tls {
            info = info.with_tls(TlsSupport::Implicit);
        }
        if let Some(ehlo) = &self.ehlo {
            info = info.with_detail(format!("{id}.ehlo_code"), ehlo.code.to_string());
        }
        if let Some(helo) = &self.helo {
            info = info.with_detail(format!("{id}.helo_code"), helo.code.to_string());
            if !self.probe.implicit_tls && helo.is_positive() {
                // A server without ESMTP cannot offer STARTTLS.
                info = info.with_tls(TlsSupport::NotOffered);
            }
        }
        let Some(ehlo) = self.ehlo_ok() else {
            return info;
        };
        let exts = extensions(ehlo);
        for line in ehlo.lines.iter().skip(1) {
            info = info.push_capability(line.clone());
        }
        let starttls = exts.iter().any(|(k, _)| k == "STARTTLS");
        let mechs: Vec<String> = exts
            .iter()
            .filter(|(k, _)| k == "AUTH")
            .flat_map(|(_, p)| p.iter().map(|m| m.to_ascii_uppercase()))
            .fold(Vec::new(), |mut acc, m| {
                if !acc.contains(&m) {
                    acc.push(m);
                }
                acc
            });
        if !mechs.is_empty() {
            info = info.with_detail(format!("{id}.auth_mechanisms"), mechs.join(" "));
        }
        if let Some(size) = exts
            .iter()
            .find(|(k, _)| k == "SIZE")
            .and_then(|(_, p)| p.first())
        {
            info = info.with_detail(format!("{id}.size"), *size);
        }
        if let Some(reply) = &self.starttls {
            info = info.with_detail(format!("{id}.starttls_code"), reply.code.to_string());
        }

        let enumeration: Vec<&str> = ["VRFY", "EXPN"]
            .into_iter()
            .filter(|k| exts.iter().any(|(e, _)| e == k))
            .collect();
        if !enumeration.is_empty() {
            info = info.push_finding(
                self.finding(
                    "user_enumeration",
                    &format!("SMTP server advertises {}", enumeration.join(" and ")),
                    Severity::Low,
                    Confidence::Tentative,
                )
                .push_evidence(Evidence::new("ehlo", enumeration.join(" ")))
                .push_taxonomy(TaxonomyRef::cwe(204))
                .with_remediation(Remediation::new(
                    "Disable VRFY and EXPN, or make them answer without revealing whether a mailbox exists.",
                )),
            );
        }
        if self.probe.implicit_tls {
            return info;
        }

        let accepted = self.starttls.as_ref().is_none_or(|r| r.code == 220);
        info = info.with_tls(if starttls && accepted {
            TlsSupport::Optional
        } else {
            TlsSupport::NotOffered
        });
        if !starttls {
            info = info.push_finding(
                self.finding(
                    "starttls_missing",
                    "SMTP server does not offer STARTTLS",
                    Severity::Medium,
                    Confidence::Certain,
                )
                .push_evidence(Evidence::new("ehlo", "no STARTTLS extension"))
                .push_taxonomy(TaxonomyRef::cwe(319))
                .with_remediation(Remediation::new(
                    "Enable STARTTLS with a valid certificate so mail and credentials are not sent in clear text.",
                )),
            );
        }
        let cleartext: Vec<&str> = mechs
            .iter()
            .map(String::as_str)
            .filter(|m| matches!(*m, "PLAIN" | "LOGIN"))
            .collect();
        if !cleartext.is_empty() {
            let severity = if starttls {
                Severity::Low
            } else {
                Severity::Medium
            };
            info = info.push_finding(
                self.finding(
                    "auth_before_tls",
                    "SMTP server offers clear-text authentication before TLS",
                    severity,
                    Confidence::Firm,
                )
                .push_evidence(Evidence::new("auth", cleartext.join(" ")))
                .push_taxonomy(TaxonomyRef::cwe(523))
                .with_remediation(Remediation::new(
                    "Advertise AUTH only after STARTTLS (e.g. Postfix smtpd_tls_auth_only = yes).",
                )),
            );
        }
        info
    }
}

impl ProbeSession for Session {
    fn start(&mut self) -> Action {
        // The server speaks first.
        Action::Receive
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        if self.state == State::Over {
            return Action::Done;
        }
        let mut conv = std::mem::take(&mut self.conv);
        let action = conv.feed(data, |reply| Some(self.handle(reply)));
        self.conv = conv;
        action
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, Error> {
        let id = self.probe.id_str();
        let Some(greeting) = &self.greeting else {
            if !self.conv.received {
                return Err(Error::no_response(id));
            }
            let reason = self
                .conv
                .problem
                .clone()
                .unwrap_or_else(|| "no complete greeting".to_owned());
            return Err(Error::unrecognized(id, reason));
        };
        let mut info = self.report(greeting);
        if let Some(problem) = &self.conv.problem {
            info = info.with_detail(format!("{id}.probe_error"), problem.clone());
        }
        Ok(info)
    }
}
