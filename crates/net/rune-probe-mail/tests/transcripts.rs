//! The probes against scripted server transcripts, in memory.

// Test helpers outside `#[test]` functions may unwrap too.
#![allow(clippy::unwrap_used, reason = "test code")]

use rune_probe_mail::{FtpProbe, SmtpProbe};
use rune_service_probe::rune_finding::Severity;
use rune_service_probe::{End, Error, Options, ServiceInfo, Target, TlsSupport, simulate};

fn checks(info: &ServiceInfo) -> Vec<&str> {
    info.findings.iter().map(|f| f.check_id.as_str()).collect()
}

fn sent(sim: &rune_service_probe::Simulation) -> Vec<String> {
    sim.sent
        .iter()
        .map(|s| String::from_utf8(s.clone()).unwrap())
        .collect()
}

fn mx() -> Target {
    Target::new("mx.example.test", 25)
}

const POSTFIX_EHLO: &[u8] = b"250-mail.example.test\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n\
250-ETRN\r\n250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-DSN\r\n\
250-SMTPUTF8\r\n250 CHUNKING\r\n";

#[test]
fn hardened_postfix() {
    let sim = simulate(
        &SmtpProbe::new(),
        &mx(),
        &[
            b"220 mail.example.test ESMTP Postfix (Ubuntu)\r\n",
            POSTFIX_EHLO,
            b"221 2.0.0 Bye\r\n",
        ],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sent(&sim), ["EHLO probe.invalid\r\n", "QUIT\r\n"]);
    assert_eq!(sim.end, End::Done);
    let info = sim.result.unwrap();
    assert_eq!(info.service, "smtp");
    assert_eq!(info.product.as_deref(), Some("Postfix"));
    assert_eq!(info.version, None);
    assert_eq!(
        info.banner.as_deref(),
        Some("220 mail.example.test ESMTP Postfix (Ubuntu)")
    );
    assert_eq!(info.tls, TlsSupport::Optional);
    assert_eq!(info.details["smtp.hostname"], "mail.example.test");
    assert_eq!(info.details["smtp.size"], "52428800");
    assert!(!info.details.contains_key("smtp.auth_mechanisms"));
    assert_eq!(info.capabilities.len(), 9);
    assert_eq!(info.capabilities[3], "STARTTLS");
    assert_eq!(checks(&info), Vec::<&str>::new());
}

#[test]
fn exim_with_multiline_greeting_and_auth_before_tls() {
    // Greeting and EHLO reply split at awkward places.
    let sim = simulate(
        &SmtpProbe::new().with_helo_name("scanner.example.org"),
        &mx(),
        &[
            b"220-mx.example.test ESMTP Exim 4.96 Mon, 11 Nov 2026\r\n220-No UCE\r",
            b"\n220 Hi\r\n",
            b"250-mx.example.test Hello\r\n250-SIZE 52428800\r\n250-AUTH=PLAIN",
            b" CRAM-MD5\r\n250-AUTH PLAIN LOGIN CRAM-MD5\r\n250-STARTTLS\r\n250 HELP\r\n",
        ],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sent(&sim), ["EHLO scanner.example.org\r\n", "QUIT\r\n"]);
    assert_eq!(sim.end, End::Closed);
    let info = sim.result.unwrap();
    assert_eq!(info.product.as_deref(), Some("Exim"));
    assert_eq!(info.version.as_deref(), Some("4.96"));
    assert_eq!(info.details["smtp.auth_mechanisms"], "PLAIN CRAM-MD5 LOGIN");
    assert_eq!(checks(&info), ["smtp.auth_before_tls"]);
    assert_eq!(info.findings[0].severity, Severity::Low);
    assert_eq!(info.findings[0].evidence[0].snippet, "PLAIN LOGIN");
}

#[test]
fn ehlo_rejected_falls_back_to_helo() {
    let sim = simulate(
        &SmtpProbe::new(),
        &mx(),
        &[
            b"220 legacy.test Microsoft ESMTP MAIL Service, Version: 6.0.3790.4675 ready\r\n",
            b"502 5.5.2 Error: command not recognized\r\n",
            b"250 legacy.test Hello\r\n",
            b"221 bye\r\n",
        ],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(
        sent(&sim),
        [
            "EHLO probe.invalid\r\n",
            "HELO probe.invalid\r\n",
            "QUIT\r\n"
        ]
    );
    let info = sim.result.unwrap();
    assert_eq!(info.product.as_deref(), Some("Microsoft SMTP Service"));
    assert_eq!(info.version.as_deref(), Some("6.0.3790.4675"));
    assert_eq!(info.tls, TlsSupport::NotOffered);
    assert_eq!(info.details["smtp.ehlo_code"], "502");
    assert_eq!(info.details["smtp.helo_code"], "250");
    assert_eq!(info.capabilities, Vec::<String>::new());
}

#[test]
fn starttls_check_and_enumeration() {
    let probe = SmtpProbe::new().with_starttls_check(true);
    let ehlo = b"250-relay.test\r\n250-VRFY\r\n250-EXPN\r\n250-STARTTLS\r\n250 8BITMIME\r\n";
    let sim = simulate(
        &probe,
        &mx(),
        &[
            b"220 relay.test ESMTP Sendmail 8.15.2/8.15.2; Mon\r\n",
            ehlo,
            b"220 2.0.0 Ready to start TLS\r\n",
        ],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sent(&sim), ["EHLO probe.invalid\r\n", "STARTTLS\r\n"]);
    let info = sim.result.unwrap();
    assert_eq!(info.version.as_deref(), Some("8.15.2"));
    assert_eq!(info.details["smtp.starttls_code"], "220");
    assert_eq!(info.tls, TlsSupport::Optional);
    assert_eq!(checks(&info), ["smtp.user_enumeration"]);
    assert_eq!(
        info.findings[0].title,
        "SMTP server advertises VRFY and EXPN"
    );

    // Advertised but refused.
    let sim = simulate(
        &probe,
        &mx(),
        &[
            b"220 relay.test ESMTP\r\n",
            ehlo,
            b"454 4.7.0 TLS not available\r\n",
        ],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sim.result.unwrap().tls, TlsSupport::NotOffered);
}

#[test]
fn smtps_reports_implicit_tls() {
    let probe = SmtpProbe::smtps();
    let sim = simulate(
        &probe,
        &Target::new("mx.example.test", 465),
        &[
            b"220 mx ESMTP OpenSMTPD\r\n",
            b"250-mx Hello\r\n250-AUTH PLAIN LOGIN\r\n250 HELP\r\n",
            b"221 Bye\r\n",
        ],
        &Options::default(),
    )
    .unwrap();
    let info = sim.result.unwrap();
    assert_eq!(info.service, "smtps");
    assert_eq!(info.tls, TlsSupport::Implicit);
    assert_eq!(info.details["smtps.auth_mechanisms"], "PLAIN LOGIN");
    assert_eq!(checks(&info), Vec::<&str>::new());
}

#[test]
fn smtp_refusals_and_non_smtp() {
    let options = Options::default();
    let sim = simulate(
        &SmtpProbe::new(),
        &mx(),
        &[b"554 5.7.1 blocked\r\n"],
        &options,
    )
    .unwrap();
    assert_eq!(sim.sent.len(), 0);
    let info = sim.result.unwrap();
    assert_eq!(info.details["smtp.greeting_code"], "554");
    assert_eq!(info.tls, TlsSupport::Unknown);

    let ssh = simulate(
        &SmtpProbe::new(),
        &mx(),
        &[b"SSH-2.0-OpenSSH_9.6\r\n"],
        &options,
    )
    .unwrap();
    assert!(matches!(ssh.result, Err(Error::Unrecognized { .. })));
    let silent = simulate(&SmtpProbe::new(), &mx(), &[], &options).unwrap();
    assert!(matches!(silent.result, Err(Error::NoResponse { .. })));
}

#[test]
fn helo_name_is_sanitised() {
    let probe = SmtpProbe::new().with_helo_name("evil\r\nRCPT TO:<x>");
    let sim = simulate(&probe, &mx(), &[b"220 x\r\n"], &Options::default()).unwrap();
    assert_eq!(sent(&sim), ["EHLO evilRCPTTO:x\r\n"]);
}

fn ftp() -> Target {
    Target::new("files.example.test", 21)
}

#[test]
fn vsftpd_with_auth_tls() {
    let sim = simulate(
        &FtpProbe::new(),
        &ftp(),
        &[
            b"220 (vsFTPd 3.0.5)\r\n",
            b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n UTF8\r\n211 End\r\n",
            b"215 UNIX Type: L8\r\n",
            b"221 Goodbye.\r\n",
        ],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sent(&sim), ["FEAT\r\n", "SYST\r\n", "QUIT\r\n"]);
    let info = sim.result.unwrap();
    assert_eq!(info.service, "ftp");
    assert_eq!(info.product.as_deref(), Some("vsFTPd"));
    assert_eq!(info.version.as_deref(), Some("3.0.5"));
    assert_eq!(info.banner.as_deref(), Some("220 (vsFTPd 3.0.5)"));
    assert_eq!(info.tls, TlsSupport::Optional);
    assert_eq!(info.details["ftp.system"], "UNIX Type: L8");
    assert_eq!(info.capabilities.len(), 11);
    assert!(info.capabilities.contains(&"AUTH TLS".to_owned()));
    assert_eq!(checks(&info), Vec::<&str>::new());
}

#[test]
fn backdoored_vsftpd_without_tls() {
    let sim = simulate(
        &FtpProbe::new(),
        &ftp(),
        &[
            b"220 (vsFTPd 2.3.4)\r\n",
            b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n SIZE\r\n TVFS\r\n211 End\r\n",
            b"215 UNIX Type: L8\r\n",
        ],
        &Options::default(),
    )
    .unwrap();
    let info = sim.result.unwrap();
    assert_eq!(info.tls, TlsSupport::NotOffered);
    assert_eq!(
        checks(&info),
        ["ftp.tls_not_offered", "ftp.backdoored_version"]
    );
    let backdoor = &info.findings[1];
    assert_eq!(backdoor.severity, Severity::Critical);
    assert!(backdoor.remediation_refs[0].contains("CVE-2011-2523"));
}

#[test]
fn ftp_without_feat_and_auth_tls_check() {
    let probe = FtpProbe::new().with_auth_tls_check(true);
    // A 120 delay reply before the greeting; FEAT unsupported; SYST
    // refused before login; AUTH TLS accepted.
    let sim = simulate(
        &probe,
        &ftp(),
        &[
            b"120 Service ready in 1 minute\r\n",
            b"220-Microsoft FTP Service\r\n220 Welcome\r\n",
            b"500 'FEAT': command not understood\r\n",
            b"530 Please login with USER and PASS.\r\n",
            b"234 AUTH command ok. Expecting TLS Negotiation.\r\n",
        ],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sent(&sim), ["FEAT\r\n", "SYST\r\n", "AUTH TLS\r\n"]);
    let info = sim.result.unwrap();
    assert_eq!(info.product.as_deref(), Some("Microsoft FTP Service"));
    assert_eq!(info.details["ftp.feat_code"], "500");
    assert!(!info.details.contains_key("ftp.system"));
    assert_eq!(info.details["ftp.auth_tls_code"], "234");
    assert_eq!(info.tls, TlsSupport::Optional);

    // Without the check the TLS status stays unknown.
    let sim = simulate(
        &FtpProbe::new(),
        &ftp(),
        &[
            b"220 ProFTPD 1.3.3c Server (Debian)\r\n",
            b"502 no\r\n",
            b"215 UNIX\r\n",
        ],
        &Options::default(),
    )
    .unwrap();
    let info = sim.result.unwrap();
    assert_eq!(info.version.as_deref(), Some("1.3.3c"));
    assert_eq!(info.tls, TlsSupport::Unknown);
    assert_eq!(checks(&info), ["ftp.backdoored_version"]);
}

#[test]
fn ftps_and_refusals() {
    let sim = simulate(
        &FtpProbe::ftps(),
        &Target::new("files.example.test", 990),
        &[
            b"220 FileZilla Server 1.8.2\r\n",
            b"211 no features\r\n",
            b"215 UNIX emulated by FileZilla\r\n",
        ],
        &Options::default(),
    )
    .unwrap();
    let info = sim.result.unwrap();
    assert_eq!(info.service, "ftps");
    assert_eq!(info.tls, TlsSupport::Implicit);
    assert_eq!(info.version.as_deref(), Some("1.8.2"));
    assert_eq!(info.details["ftps.system"], "UNIX emulated by FileZilla");
    assert_eq!(checks(&info), Vec::<&str>::new());

    let sim = simulate(
        &FtpProbe::new(),
        &ftp(),
        &[b"421 Too many connections\r\n"],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sim.sent.len(), 0);
    assert_eq!(sim.result.unwrap().details["ftp.greeting_code"], "421");

    let http = simulate(
        &FtpProbe::new(),
        &ftp(),
        &[b"HTTP/1.0 400 Bad\r\n"],
        &Options::default(),
    )
    .unwrap();
    assert!(matches!(http.result, Err(Error::Unrecognized { .. })));
}
