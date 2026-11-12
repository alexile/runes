//! FTP and FTPS: greeting, `FEAT`, `SYST`, `AUTH TLS`.

use rune_service_probe::rune_finding::{
    Confidence, Evidence, Finding, Remediation, Severity, TaxonomyRef,
};
use rune_service_probe::{
    Action, End, Error, ProbeSession, ServiceInfo, ServiceProbe, Target, TlsSupport,
};

use crate::Reply;
use crate::conversation::{Conversation, command};
use crate::reply::detect_product;

/// Greeting substrings and the products they identify, most specific first.
const PRODUCTS: &[(&str, &str)] = &[
    ("vsFTPd", "vsFTPd"),
    ("ProFTPD", "ProFTPD"),
    ("Pure-FTPd", "Pure-FTPd"),
    ("FileZilla Server", "FileZilla Server"),
    ("Microsoft FTP Service", "Microsoft FTP Service"),
    ("Serv-U FTP Server", "Serv-U"),
    ("Wing FTP Server", "Wing FTP Server"),
    ("WS_FTP Server", "WS_FTP Server"),
    ("glFTPd", "glFTPd"),
    ("wu-", "WU-FTPD"),
];

/// Releases distributed with a backdoor: product, version, reference.
const BACKDOORED: &[(&str, &str, Option<&str>)] = &[
    (
        "vsFTPd",
        "2.3.4",
        Some("https://nvd.nist.gov/vuln/detail/CVE-2011-2523"),
    ),
    ("ProFTPD", "1.3.3c", None),
];

/// A read-only FTP probe (RFC 959), for FTP (21) and, over a TLS stream the
/// caller opened, implicit FTPS (990).
///
/// It reads the greeting, sends `FEAT` (RFC 2389) and `SYST`, and sends
/// `QUIT`. It does not log in, not even anonymously: confirming anonymous
/// access is a separate, intrusive check. With
/// [`with_auth_tls_check`](Self::with_auth_tls_check) it also sends
/// `AUTH TLS` (RFC 4217) to confirm the upgrade, then hangs up before any
/// TLS handshake.
///
/// [`ServiceInfo`] fields: `product`/`version` from the greeting, `banner`
/// (the greeting's first line), `capabilities` (the `FEAT` lines), `tls`
/// (`Optional` when `AUTH TLS`/`AUTH SSL` is offered, `NotOffered` when
/// `FEAT` works and lists neither, `Implicit` for FTPS) and `details` under
/// `ftp.*` (`ftps.*`).
///
/// | Check id                  | When                                                         |
/// | ------------------------- | ------------------------------------------------------------ |
/// | `ftp.tls_not_offered`     | plaintext FTP and no `AUTH TLS` (credentials in clear text)  |
/// | `ftp.backdoored_version`  | the banner names vsFTPd 2.3.4 or ProFTPD 1.3.3c              |
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FtpProbe {
    implicit_tls: bool,
    auth_tls_check: bool,
}

impl Default for FtpProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl FtpProbe {
    /// A plaintext FTP probe (port 21).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            implicit_tls: false,
            auth_tls_check: false,
        }
    }

    /// An implicit FTPS probe (port 990), for a stream that is already TLS.
    /// Its id is `ftps`.
    #[must_use]
    pub const fn ftps() -> Self {
        Self {
            implicit_tls: true,
            auth_tls_check: false,
        }
    }

    /// Whether to send `AUTH TLS` to confirm TLS support (default off):
    /// when `FEAT` lists it, or when `FEAT` is not supported. The probe
    /// hangs up right after the reply. Ignored for FTPS.
    #[must_use]
    pub const fn with_auth_tls_check(mut self, check: bool) -> Self {
        self.auth_tls_check = check;
        self
    }

    const fn id_str(&self) -> &'static str {
        if self.implicit_tls { "ftps" } else { "ftp" }
    }
}

impl ServiceProbe for FtpProbe {
    fn id(&self) -> &str {
        self.id_str()
    }

    fn default_ports(&self) -> &[u16] {
        if self.implicit_tls { &[990] } else { &[21] }
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(Session {
            target: target.clone(),
            probe: self.clone(),
            conv: Conversation::default(),
            state: State::Greeting,
            greeting: None,
            feat: None,
            syst: None,
            auth_tls: None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Greeting,
    Feat,
    Syst,
    AuthTls,
    Quit,
    Over,
}

struct Session {
    target: Target,
    probe: FtpProbe,
    conv: Conversation,
    state: State,
    greeting: Option<Reply>,
    feat: Option<Reply>,
    syst: Option<Reply>,
    auth_tls: Option<Reply>,
}

impl Session {
    fn handle(&mut self, reply: Reply) -> Option<Action> {
        match self.state {
            // RFC 959: 120 "ready in nnn minutes" precedes the real greeting.
            State::Greeting if reply.is_preliminary() => {
                self.greeting = Some(reply);
                None
            }
            State::Greeting => {
                let ready = reply.code == 220;
                self.greeting = Some(reply);
                if ready {
                    self.state = State::Feat;
                    Some(command("FEAT", None))
                } else {
                    self.state = State::Over;
                    Some(Action::Done)
                }
            }
            State::Feat => {
                self.feat = Some(reply);
                self.state = State::Syst;
                Some(command("SYST", None))
            }
            State::Syst => {
                self.syst = Some(reply);
                let feat_ok = self.features().is_some();
                if self.probe.auth_tls_check
                    && !self.probe.implicit_tls
                    && (!feat_ok || self.tls_feature())
                {
                    self.state = State::AuthTls;
                    Some(command("AUTH", Some("TLS")))
                } else {
                    self.state = State::Quit;
                    Some(command("QUIT", None))
                }
            }
            State::AuthTls => {
                self.auth_tls = Some(reply);
                self.state = State::Over;
                Some(Action::Done)
            }
            State::Quit | State::Over => {
                self.state = State::Over;
                Some(Action::Done)
            }
        }
    }

    /// The `FEAT` feature lines, trimmed, when `FEAT` succeeded.
    fn features(&self) -> Option<Vec<&str>> {
        let feat = self.feat.as_ref().filter(|f| f.code == 211)?;
        let n = feat.lines.len();
        Some(
            feat.lines
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != 0 && *i + 1 != n)
                .map(|(_, l)| l.trim())
                .filter(|l| !l.is_empty())
                .collect(),
        )
    }

    /// True when `FEAT` lists `AUTH` with `TLS` or `SSL` (RFC 4217 §6).
    fn tls_feature(&self) -> bool {
        self.features().is_some_and(|f| {
            f.iter().any(|line| {
                let mut words = line.split_whitespace();
                words.next().is_some_and(|w| w.eq_ignore_ascii_case("AUTH"))
                    && words.any(|w| {
                        w.split(';').any(|m| {
                            let m = m.to_ascii_uppercase();
                            m.starts_with("TLS") || m.starts_with("SSL")
                        })
                    })
            })
        })
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

    fn tls(&self) -> TlsSupport {
        if self.probe.implicit_tls {
            return TlsSupport::Implicit;
        }
        if let Some(reply) = &self.auth_tls {
            return if reply.code == 234 {
                TlsSupport::Optional
            } else {
                TlsSupport::NotOffered
            };
        }
        match self.features() {
            Some(_) if self.tls_feature() => TlsSupport::Optional,
            Some(_) => TlsSupport::NotOffered,
            None => TlsSupport::Unknown,
        }
    }

    fn report(&self, greeting: &Reply) -> ServiceInfo {
        let id = self.probe.id_str();
        let mut info = ServiceInfo::new(id)
            .with_banner(format!("{} {}", greeting.code, greeting.first_line()))
            .with_detail(format!("{id}.greeting_code"), greeting.code.to_string());
        let text = greeting.lines.join(" ");
        let product = detect_product(&text, PRODUCTS);
        if let Some((name, version)) = &product {
            info = info.with_product(name.clone());
            if let Some(version) = version {
                info = info.with_version(version.clone());
            }
        }
        if let Some(features) = self.features() {
            for feature in &features {
                info = info.push_capability(*feature);
            }
        } else if let Some(feat) = &self.feat {
            info = info.with_detail(format!("{id}.feat_code"), feat.code.to_string());
        }
        if let Some(syst) = self.syst.as_ref().filter(|s| s.code == 215) {
            info = info.with_detail(format!("{id}.system"), syst.first_line());
        }
        if let Some(reply) = &self.auth_tls {
            info = info.with_detail(format!("{id}.auth_tls_code"), reply.code.to_string());
        }
        let tls = self.tls();
        info = info.with_tls(tls);

        if tls == TlsSupport::NotOffered {
            let evidence = self.auth_tls.as_ref().map_or_else(
                || "FEAT lists no AUTH TLS".to_owned(),
                |r| format!("AUTH TLS answered {}", r.code),
            );
            info = info.push_finding(
                self.finding(
                    "tls_not_offered",
                    "FTP server does not offer TLS (AUTH TLS)",
                    Severity::Medium,
                    Confidence::Firm,
                )
                .push_evidence(Evidence::new("tls", evidence))
                .push_taxonomy(TaxonomyRef::cwe(319))
                .with_remediation(Remediation::new(
                    "Enable explicit FTPS (AUTH TLS) and require it for logins, or replace FTP with SFTP.",
                )),
            );
        }
        if let Some((name, Some(version))) = &product
            && let Some((_, _, reference)) = BACKDOORED
                .iter()
                .find(|(p, v, _)| p == name && v == version)
        {
            let mut finding = self.finding(
                        "backdoored_version",
                        &format!("FTP banner reports backdoored release {name} {version}"),
                        Severity::Critical,
                        Confidence::Tentative,
                    )
                    .push_evidence(Evidence::new("banner", greeting.first_line()))
                    .push_taxonomy(TaxonomyRef::cwe(506))
                    .with_remediation(Remediation::new(
                        "Confirm the installed build and replace it with a release from a trusted source.",
                    ));
            if let Some(reference) = reference {
                finding = finding.push_remediation_ref(*reference);
            }
            info = info.push_finding(finding);
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
        let action = conv.feed(data, |reply| self.handle(reply));
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
