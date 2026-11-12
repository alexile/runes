//! Service and OS hints from port numbers and server-first banners.
//!
//! Hints are guesses for triage, not identification: a port number says
//! what *usually* listens there, and a banner says what the service
//! *claims* to be. Confirm with a protocol probe (`rune-service-probe` and
//! the `rune-probe-*` crates) before relying on either.

use std::fmt;

/// Where a [`ServiceHint`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum HintSource {
    /// The IANA / customary service for the port number.
    Port,
    /// The banner the service sent after the connection opened.
    Banner,
}

/// A guess at the service listening on a port.
///
/// ```
/// use rune_port_scan::{HintSource, hint};
///
/// let ssh = hint(2222, Some(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")).unwrap();
/// assert_eq!((ssh.service.as_str(), ssh.source), ("ssh", HintSource::Banner));
/// assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
/// assert_eq!(ssh.version.as_deref(), Some("9.6p1"));
///
/// let https = hint(443, None).unwrap();
/// assert_eq!((https.service.as_str(), https.source), ("https", HintSource::Port));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ServiceHint {
    /// Service name in IANA style: `ssh`, `http`, `smtp`, ...
    pub service: String,
    /// Server software, when the banner names it.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub product: Option<String>,
    /// Software version, when the banner names it.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub version: Option<String>,
    /// Whether the hint came from the port number or the banner.
    pub source: HintSource,
}

impl ServiceHint {
    /// A hint for `service` with no product or version.
    #[must_use]
    pub fn new(service: impl Into<String>, source: HintSource) -> Self {
        Self {
            service: service.into(),
            product: None,
            version: None,
            source,
        }
    }

    /// Sets the product.
    #[must_use]
    pub fn with_product(mut self, product: impl Into<String>) -> Self {
        self.product = Some(product.into());
        self
    }

    /// Sets the version.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }
}

/// A coarse operating-system family, guessed from banner text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum OsHint {
    /// A Linux distribution.
    Linux,
    /// Microsoft Windows.
    Windows,
    /// FreeBSD, OpenBSD or NetBSD.
    Bsd,
    /// Apple macOS.
    MacOs,
}

impl fmt::Display for OsHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::Bsd => "bsd",
            Self::MacOs => "macos",
        })
    }
}

/// Banner bytes examined by the hint functions; the rest is ignored.
pub const MAX_HINT_BANNER: usize = 4096;

/// The customary service for a TCP port, if it has a well-known one.
///
/// ```
/// assert_eq!(rune_port_scan::port_service(22), Some("ssh"));
/// assert_eq!(rune_port_scan::port_service(40000), None);
/// ```
#[must_use]
pub const fn port_service(port: u16) -> Option<&'static str> {
    Some(match port {
        7 => "echo",
        9 => "discard",
        13 => "daytime",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        37 => "time",
        53 => "domain",
        79 => "finger",
        80 | 81 | 8000 | 8008 | 8080 | 8081 | 8888 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpcbind",
        113 => "ident",
        119 => "nntp",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        179 => "bgp",
        389 => "ldap",
        443 | 8443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        513 => "login",
        514 => "shell",
        515 => "printer",
        548 => "afp",
        554 => "rtsp",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        990 => "ftps",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "ms-sql-s",
        1521 => "oracle",
        1723 => "pptp",
        1883 => "mqtt",
        2049 => "nfs",
        2375 | 2376 => "docker",
        3128 => "squid-http",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5060 => "sip",
        5432 => "postgresql",
        5672 => "amqp",
        5900..=5903 => "vnc",
        5985 | 5986 => "wsman",
        6000 => "x11",
        6379 => "redis",
        6443 => "kubernetes-api",
        8009 => "ajp13",
        9000 => "cslistener",
        9092 => "kafka",
        9100 => "jetdirect",
        9200 => "elasticsearch",
        11211 => "memcache",
        27017 => "mongodb",
        _ => return None,
    })
}

/// Guesses the service from a banner the server sent first.
///
/// Only the first [`MAX_HINT_BANNER`] bytes are examined. Returns `None`
/// when the banner matches no known greeting.
///
/// ```
/// use rune_port_scan::banner_hint;
///
/// let ftp = banner_hint(b"220 (vsFTPd 3.0.5)\r\n").unwrap();
/// assert_eq!(ftp.service, "ftp");
/// assert_eq!((ftp.product.as_deref(), ftp.version.as_deref()), (Some("vsFTPd"), Some("3.0.5")));
/// assert!(banner_hint(b"\x00\x01garbage").is_none());
/// ```
#[must_use]
pub fn banner_hint(banner: &[u8]) -> Option<ServiceHint> {
    let banner = banner.get(..MAX_HINT_BANNER).unwrap_or(banner);
    if let Some(hint) = binary_hint(banner) {
        return Some(hint);
    }
    let text = String::from_utf8_lossy(banner);
    let line = text.lines().next().unwrap_or_default().trim();
    let hint = |service| ServiceHint::new(service, HintSource::Banner);

    if let Some(rest) = line.strip_prefix("SSH-") {
        return Some(ssh_hint(rest));
    }
    if line.starts_with("HTTP/1.") || line.starts_with("HTTP/2") {
        let mut found = hint("http");
        if let Some(server) = header(&text, "server") {
            let (product, version) = product_version(server, '/');
            found.product = product;
            found.version = version;
        }
        return Some(found);
    }
    if line.starts_with("220") {
        return greeting_220(line);
    }
    if line.starts_with("+OK") {
        let mut found = hint("pop3");
        found.product = known_product(line, &["Dovecot", "Cyrus", "Courier", "Exchange"]);
        return Some(found);
    }
    if line.starts_with("* OK") || line.starts_with("* PREAUTH") {
        let mut found = hint("imap");
        found.product = known_product(line, &["Dovecot", "Cyrus", "Courier", "Exchange"]);
        return Some(found);
    }
    if let Some(version) = line.strip_prefix("RFB ") {
        let mut found = hint("vnc");
        if let Some((major, minor)) = version.trim().split_once('.')
            && let (Ok(major), Ok(minor)) = (major.parse::<u16>(), minor.parse::<u16>())
        {
            found.version = Some(format!("{major}.{minor}"));
        }
        return Some(found);
    }
    if let Some(version) = line.strip_prefix("@RSYNCD:") {
        return Some(hint("rsync").with_version(bounded(version.trim())));
    }
    if line.starts_with("-NOAUTH") || line.starts_with("-DENIED Redis") {
        return Some(hint("redis").with_product("Redis"));
    }
    if line.starts_with("RTSP/1.0") {
        return Some(hint("rtsp"));
    }
    if line.starts_with("SIP/2.0") {
        return Some(hint("sip"));
    }
    if line.starts_with("AMQP") {
        return Some(hint("amqp"));
    }
    if text.contains("<stream:stream") {
        return Some(hint("xmpp"));
    }
    None
}

/// Guesses the OS family from banner text: distribution tags in SSH
/// identification strings, `Server:` comments, Microsoft service names
/// and the like. Only the first [`MAX_HINT_BANNER`] bytes are examined.
///
/// ```
/// use rune_port_scan::{OsHint, os_hint};
///
/// assert_eq!(os_hint(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"), Some(OsHint::Linux));
/// assert_eq!(os_hint(b"220 Microsoft FTP Service"), Some(OsHint::Windows));
/// assert_eq!(os_hint(b"SSH-2.0-OpenSSH_9.6"), None);
/// ```
#[must_use]
pub fn os_hint(banner: &[u8]) -> Option<OsHint> {
    const TABLE: &[(&str, OsHint)] = &[
        ("windows", OsHint::Windows),
        ("microsoft", OsHint::Windows),
        ("win32", OsHint::Windows),
        ("win64", OsHint::Windows),
        ("freebsd", OsHint::Bsd),
        ("openbsd", OsHint::Bsd),
        ("netbsd", OsHint::Bsd),
        ("darwin", OsHint::MacOs),
        ("mac os", OsHint::MacOs),
        ("macos", OsHint::MacOs),
        ("ubuntu", OsHint::Linux),
        ("debian", OsHint::Linux),
        ("raspbian", OsHint::Linux),
        ("centos", OsHint::Linux),
        ("red hat", OsHint::Linux),
        ("rhel", OsHint::Linux),
        ("fedora", OsHint::Linux),
        ("alpine", OsHint::Linux),
        ("suse", OsHint::Linux),
        ("linux", OsHint::Linux),
    ];
    let banner = banner.get(..MAX_HINT_BANNER).unwrap_or(banner);
    let text = String::from_utf8_lossy(banner).to_ascii_lowercase();
    TABLE
        .iter()
        .find(|(needle, _)| text.contains(needle))
        .map(|&(_, os)| os)
}

/// Combines the banner hint (preferred) with the port's customary service.
#[must_use]
pub fn hint(port: u16, banner: Option<&[u8]>) -> Option<ServiceHint> {
    banner
        .and_then(banner_hint)
        .or_else(|| port_service(port).map(|service| ServiceHint::new(service, HintSource::Port)))
}

/// Greetings that are not text lines.
fn binary_hint(banner: &[u8]) -> Option<ServiceHint> {
    // Telnet option negotiation: IAC followed by WILL/WONT/DO/DONT.
    if let [0xff, 0xfb..=0xfe, ..] = banner {
        return Some(ServiceHint::new("telnet", HintSource::Banner));
    }
    // MySQL / MariaDB initial handshake: 3-byte length, sequence 0,
    // protocol 10, NUL-terminated server version.
    if let [len0, len1, len2, 0, 10, rest @ ..] = banner {
        let len = usize::from(*len0) | usize::from(*len1) << 8 | usize::from(*len2) << 16;
        let end = rest.iter().position(|&b| b == 0)?;
        let version = rest.get(..end)?;
        if len > end && !version.is_empty() && version.iter().all(u8::is_ascii_graphic) {
            let version = String::from_utf8_lossy(version);
            let product = if version.contains("MariaDB") {
                "MariaDB"
            } else {
                "MySQL"
            };
            let version = version.trim_start_matches("5.5.5-");
            let version = version.split('-').next().unwrap_or_default();
            return Some(
                ServiceHint::new("mysql", HintSource::Banner)
                    .with_product(product)
                    .with_version(bounded(version)),
            );
        }
    }
    None
}

fn ssh_hint(rest: &str) -> ServiceHint {
    let mut found = ServiceHint::new("ssh", HintSource::Banner);
    // SSH-protoversion-softwareversion SP comments
    let software = rest
        .split_once('-')
        .map_or("", |(_, software)| software)
        .split_whitespace()
        .next()
        .unwrap_or_default();
    if let Some((product, version)) = software.split_once('_') {
        found.product = Some(bounded(product));
        if !version.is_empty() {
            found.version = Some(bounded(version));
        }
    } else if !software.is_empty() {
        found.product = Some(bounded(software));
    }
    found
}

fn greeting_220(line: &str) -> Option<ServiceHint> {
    let lower = line.to_ascii_lowercase();
    let service = if ["smtp", "esmtp", "postfix", "exim", "sendmail", "mail"]
        .iter()
        .any(|word| lower.contains(word))
    {
        "smtp"
    } else if lower.contains("ftp") {
        "ftp"
    } else {
        return None;
    };
    let mut found = ServiceHint::new(service, HintSource::Banner);
    for (name, needle) in [
        ("vsFTPd", "vsftpd "),
        ("ProFTPD", "proftpd "),
        ("Pure-FTPd", "pure-ftpd"),
        ("FileZilla Server", "filezilla server "),
        ("Exim", "exim "),
        ("Postfix", "postfix"),
        ("Sendmail", "sendmail "),
        ("Microsoft FTP Service", "microsoft ftp service"),
        ("Microsoft ESMTP", "microsoft esmtp"),
    ] {
        if let Some(at) = lower.find(needle) {
            found.product = Some(name.to_owned());
            let after = line.get(at + needle.len()..).unwrap_or_default();
            let version = after
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
                .next()
                .unwrap_or_default();
            if needle.ends_with(' ') && version.starts_with(|c: char| c.is_ascii_digit()) {
                found.version = Some(bounded(version));
            }
            break;
        }
    }
    Some(found)
}

/// The value of the first `name:` header line in an HTTP response head.
fn header<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
        })
}

/// Splits `nginx/1.24.0 (Ubuntu)` into product and version.
fn product_version(value: &str, sep: char) -> (Option<String>, Option<String>) {
    let token = value.split_whitespace().next().unwrap_or_default();
    if token.is_empty() {
        return (None, None);
    }
    match token.split_once(sep) {
        Some((product, version)) if !version.is_empty() => {
            (Some(bounded(product)), Some(bounded(version)))
        }
        _ => (Some(bounded(token.trim_end_matches(sep))), None),
    }
}

fn known_product(line: &str, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find(|name| line.contains(*name))
        .map(|&name| name.to_owned())
}

/// Printable, at most 64 characters: banner fields are untrusted.
fn bounded(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pv(hint: &ServiceHint) -> (&str, Option<&str>, Option<&str>) {
        (
            hint.service.as_str(),
            hint.product.as_deref(),
            hint.version.as_deref(),
        )
    }

    #[test]
    fn ssh_banners() {
        let h = banner_hint(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n").unwrap();
        assert_eq!(pv(&h), ("ssh", Some("OpenSSH"), Some("9.6p1")));
        let h = banner_hint(b"SSH-2.0-dropbear_2022.83\r\n").unwrap();
        assert_eq!(pv(&h), ("ssh", Some("dropbear"), Some("2022.83")));
        let h = banner_hint(b"SSH-1.99-Cisco-1.25\r\n").unwrap();
        assert_eq!(pv(&h), ("ssh", Some("Cisco-1.25"), None));
        assert_eq!(pv(&banner_hint(b"SSH-").unwrap()), ("ssh", None, None));
    }

    #[test]
    fn http_server_header() {
        let h = banner_hint(
            b"HTTP/1.1 400 Bad Request\r\nServer: nginx/1.24.0 (Ubuntu)\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(pv(&h), ("http", Some("nginx"), Some("1.24.0")));
        let h = banner_hint(b"HTTP/1.0 200 OK\r\nserver: Microsoft-IIS/10.0\r\n\r\n").unwrap();
        assert_eq!(pv(&h), ("http", Some("Microsoft-IIS"), Some("10.0")));
        let h = banner_hint(b"HTTP/1.1 200 OK\r\n\r\nServer: fake/1\r\n").unwrap();
        assert_eq!(pv(&h), ("http", None, None));
    }

    #[test]
    fn ftp_and_smtp_greetings() {
        let h = banner_hint(b"220 ProFTPD 1.3.8 Server (Debian) [::ffff:10.0.0.5]\r\n").unwrap();
        assert_eq!(pv(&h), ("ftp", Some("ProFTPD"), Some("1.3.8")));
        let h = banner_hint(b"220 mx.example.com ESMTP Postfix (Ubuntu)\r\n").unwrap();
        assert_eq!(pv(&h), ("smtp", Some("Postfix"), None));
        let h = banner_hint(b"220 mail.example.org ESMTP Exim 4.96 Mon, 1 Jan 2024\r\n").unwrap();
        assert_eq!(pv(&h), ("smtp", Some("Exim"), Some("4.96")));
        let h = banner_hint(b"220 Microsoft FTP Service\r\n").unwrap();
        assert_eq!(pv(&h), ("ftp", Some("Microsoft FTP Service"), None));
        assert!(banner_hint(b"220 ready\r\n").is_none());
    }

    #[test]
    fn mail_and_misc_greetings() {
        let h = banner_hint(b"+OK Dovecot (Ubuntu) ready.\r\n").unwrap();
        assert_eq!(pv(&h), ("pop3", Some("Dovecot"), None));
        let h = banner_hint(b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n").unwrap();
        assert_eq!(pv(&h), ("imap", Some("Dovecot"), None));
        assert_eq!(
            pv(&banner_hint(b"RFB 003.008\n").unwrap()),
            ("vnc", None, Some("3.8"))
        );
        assert_eq!(
            pv(&banner_hint(b"@RSYNCD: 31.0\n").unwrap()),
            ("rsync", None, Some("31.0"))
        );
        assert_eq!(
            pv(&banner_hint(b"-NOAUTH Authentication required.\r\n").unwrap()),
            ("redis", Some("Redis"), None)
        );
        assert_eq!(
            banner_hint(b"\xff\xfd\x18\xff\xfd\x20").unwrap().service,
            "telnet"
        );
        assert_eq!(banner_hint(b"RTSP/1.0 200 OK\r\n").unwrap().service, "rtsp");
    }

    #[test]
    fn mysql_handshakes() {
        let mut packet = vec![0x4a, 0, 0, 0, 10];
        packet.extend_from_slice(b"8.0.36-0ubuntu0.22.04.1\0");
        packet.extend_from_slice(&[1; 40]);
        assert_eq!(
            pv(&banner_hint(&packet).unwrap()),
            ("mysql", Some("MySQL"), Some("8.0.36"))
        );
        let mut packet = vec![0x50, 0, 0, 0, 10];
        packet.extend_from_slice(b"5.5.5-10.11.6-MariaDB-0+deb12u1\0");
        assert_eq!(
            pv(&banner_hint(&packet).unwrap()),
            ("mysql", Some("MariaDB"), Some("10.11.6"))
        );
        // Truncated: no NUL terminator.
        assert!(banner_hint(&[0x4a, 0, 0, 0, 10, b'8']).is_none());
        // Length shorter than the version string.
        assert!(banner_hint(b"\x02\x00\x00\x00\x0a8.0\x00").is_none());
    }

    #[test]
    fn port_fallback_and_preference() {
        assert_eq!(hint(22, None).unwrap().source, HintSource::Port);
        assert_eq!(hint(80, Some(b"SSH-2.0-x")).unwrap().service, "ssh");
        assert_eq!(hint(3306, Some(b"???")).unwrap().service, "mysql");
        assert!(hint(41234, Some(b"???")).is_none());
        assert_eq!(port_service(5901), Some("vnc"));
    }

    #[test]
    fn os_hints() {
        assert_eq!(
            os_hint(b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"),
            Some(OsHint::Linux)
        );
        assert_eq!(
            os_hint(b"SSH-2.0-OpenSSH_for_Windows_8.1"),
            Some(OsHint::Windows)
        );
        assert_eq!(
            os_hint(b"SSH-2.0-OpenSSH_9.3 FreeBSD-20230719"),
            Some(OsHint::Bsd)
        );
        assert_eq!(
            os_hint(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58 (Win64)\r\n"),
            Some(OsHint::Windows)
        );
        assert_eq!(os_hint(b""), None);
        assert_eq!(OsHint::MacOs.to_string(), "macos");
    }

    #[test]
    fn fields_are_bounded_and_printable() {
        let mut banner = b"SSH-2.0-".to_vec();
        banner.extend(std::iter::repeat_n(b'A', 10_000));
        let h = banner_hint(&banner).unwrap();
        assert_eq!(h.product.unwrap().len(), 64);
        let h = banner_hint(b"HTTP/1.1 200 OK\r\nServer: a\x1bb/1\x07\r\n\r\n").unwrap();
        assert_eq!(pv(&h), ("http", Some("ab"), Some("1")));
    }
}
