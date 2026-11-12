//! The [`ServiceProbe`] implementation.

use rune_service_probe::banner::{printable, split_line};
use rune_service_probe::rune_finding::{
    Confidence, Evidence, Finding, Remediation, Severity, TaxonomyRef,
};
use rune_service_probe::{Action, End, ProbeSession, ServiceInfo, ServiceProbe, Target};

use crate::audit::{Category, audit, terrapin_exposed};
use crate::hostkey::parse_kex_reply_host_key;
use crate::wire::{
    MSG_DEBUG, MSG_DISCONNECT, MSG_IGNORE, MSG_KEX_INIT, MSG_UNIMPLEMENTED, Reader, encode_packet,
    put_string,
};
use crate::{HostKey, Identification, KexInit};

/// The probe id, also the [`ServiceInfo::service`] and check-id prefix.
pub const PROBE_ID: &str = "ssh";

/// The software version the probe announces by default.
pub const DEFAULT_CLIENT_SOFTWARE: &str = "rune_probe_ssh";

/// Bytes the probe buffers looking for the identification line before it
/// gives up on the peer.
const MAX_PRE_IDENT: usize = 8 * 1024;

/// Key exchanges the probe can start, best first, with the public value it
/// sends. The probe never completes the exchange, so a fixed, valid public
/// value is enough to make the server reply with its host key.
fn kex_init_value(kex: &str) -> Option<Vec<u8>> {
    match kex {
        // RFC 8731: any 32-byte u-coordinate; 9 is the base point, so the
        // server's shared secret is its own public key, never zero.
        "curve25519-sha256" | "curve25519-sha256@libssh.org" => {
            let mut point = [0u8; 32];
            point[0] = 9;
            Some(point.to_vec())
        }
        // RFC 4253 §8 / RFC 8268: e in (1, p-1), with enough bits set to
        // pass OpenSSH's sanity check. 2^255 - 2^248 - 1 is below every
        // group's prime.
        "diffie-hellman-group14-sha256"
        | "diffie-hellman-group16-sha512"
        | "diffie-hellman-group18-sha512"
        | "diffie-hellman-group14-sha1"
        | "diffie-hellman-group1-sha1" => {
            let mut e = [0xffu8; 32];
            e[0] = 0x7f;
            // Encoded as a positive mpint: the top bit is clear.
            Some(e.to_vec())
        }
        _ => None,
    }
}

/// The key-exchange methods the probe can use to fetch a host key, best
/// first.
pub const SUPPORTED_KEX: [&str; 7] = [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
];

/// Host-key algorithms the probe asks for, best first, when the caller did
/// not name one. Any algorithm the server offers works, since the probe
/// does not verify the signature.
const HOST_KEY_PREFERENCE: [&str; 8] = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ssh-dss",
];

/// A read-only SSH probe.
///
/// The probe reads the server's identification string, sends its own,
/// and reads the server's `SSH_MSG_KEXINIT`. To learn the host key it then
/// sends a KEXINIT naming one key exchange and one host-key algorithm the
/// server offered, plus the key-exchange init, and reads `K_S` from the
/// reply, like `ssh-keyscan`. It closes the connection there: no keys are
/// derived, no `NEWKEYS` is sent and no authentication is attempted.
///
/// Key exchanges the probe can drive are listed in [`SUPPORTED_KEX`]
/// (curve25519 and the fixed Diffie-Hellman groups). Against a server that
/// offers none of them, the report has the algorithm audit but no host
/// key.
///
/// [`ServiceInfo`] fields it fills: `product` and `version` from the
/// software version, `banner` (the identification line), `capabilities`
/// (every offered algorithm as `kex:…`, `host_key:…`, `cipher:…`, `mac:…`,
/// `compression:…`) and `details` under `ssh.*`. Findings:
///
/// | Check id                       | When                                                      |
/// | ------------------------------ | --------------------------------------------------------- |
/// | `ssh.protocol_v1`              | the server offers SSH-1 (`SSH-1.x`, `SSH-1.99`)          |
/// | `ssh.weak_kex`                 | SHA-1 or 1024-bit key exchange offered                    |
/// | `ssh.weak_host_key_algorithm`  | `ssh-rsa` or `ssh-dss` signatures offered                 |
/// | `ssh.weak_cipher`              | CBC, RC4, 64-bit block or `none` ciphers offered          |
/// | `ssh.weak_mac`                 | MD5, SHA-1, truncated, 64-bit or `none` MACs offered      |
/// | `ssh.terrapin`                 | exposed to CVE-2023-48795 (no strict KEX)                 |
/// | `ssh.weak_host_key`            | the host key is DSA or RSA below 2048 bits                |
///
/// See [`audit::classify`](crate::audit::classify) for the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SshProbe {
    client_software: String,
    host_key: bool,
    host_key_algorithm: Option<String>,
}

impl Default for SshProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl SshProbe {
    /// A probe that fetches the host key and announces itself as
    /// `SSH-2.0-rune_probe_ssh`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client_software: DEFAULT_CLIENT_SOFTWARE.to_owned(),
            host_key: true,
            host_key_algorithm: None,
        }
    }

    /// Whether to run the key-exchange step that fetches the host key
    /// (default on). Off, the probe stops after the server's KEXINIT.
    #[must_use]
    pub const fn with_host_key(mut self, fetch: bool) -> Self {
        self.host_key = fetch;
        self
    }

    /// Ask for the host key of this signature algorithm, e.g. `ssh-rsa`
    /// or `ecdsa-sha2-nistp256`, instead of the best one offered. Run one
    /// probe per algorithm to collect every host key a server has. If the
    /// server does not offer it, no host key is fetched.
    #[must_use]
    pub fn with_host_key_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.host_key_algorithm = Some(algorithm.into());
        self
    }

    /// The software version to announce (`SSH-2.0-<software>`). Characters
    /// RFC 4253 forbids there (whitespace, `-`, non-printable) are dropped;
    /// an empty result falls back to [`DEFAULT_CLIENT_SOFTWARE`].
    #[must_use]
    pub fn with_client_software(mut self, software: &str) -> Self {
        let clean: String = software
            .chars()
            .filter(|c| c.is_ascii_graphic() && *c != '-')
            .take(200)
            .collect();
        self.client_software = if clean.is_empty() {
            DEFAULT_CLIENT_SOFTWARE.to_owned()
        } else {
            clean
        };
        self
    }

    /// The identification line the probe sends, CR LF included.
    #[must_use]
    pub fn client_identification(&self) -> String {
        format!("SSH-2.0-{}\r\n", self.client_software)
    }
}

impl ServiceProbe for SshProbe {
    fn id(&self) -> &str {
        PROBE_ID
    }

    fn default_ports(&self) -> &[u16] {
        &[22]
    }

    fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
        Box::new(Session {
            target: target.clone(),
            probe: self.clone(),
            state: State::Ident,
            buf: Vec::new(),
            received: false,
            ident_sent: false,
            ident: None,
            pre_banner: None,
            kexinit: None,
            negotiated: None,
            host_key: None,
            disconnect: None,
            problem: None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ident,
    KexInit,
    KexReply,
    Over,
}

struct Session {
    target: Target,
    probe: SshProbe,
    state: State,
    buf: Vec<u8>,
    received: bool,
    ident_sent: bool,
    ident: Option<(Identification, String)>,
    pre_banner: Option<String>,
    kexinit: Option<KexInit>,
    negotiated: Option<(String, String)>,
    host_key: Option<HostKey>,
    disconnect: Option<String>,
    problem: Option<String>,
}

/// What reading the next packet found.
enum Packet {
    Incomplete,
    Payload(Vec<u8>),
    Stop,
}

impl Session {
    fn stop(&mut self, problem: impl Into<String>) -> Action {
        self.problem = Some(problem.into());
        self.state = State::Over;
        Action::Done
    }

    /// Process as much of the buffer as possible and decide what's next.
    fn advance(&mut self) -> Action {
        loop {
            match self.state {
                State::Ident => {
                    if let Some(action) = self.read_ident() {
                        return action;
                    }
                }
                State::KexInit => return self.read_kexinit(),
                State::KexReply => return self.read_kex_reply(),
                State::Over => return Action::Done,
            }
        }
    }

    /// `Some(action)` to return, `None` when the state moved on.
    fn read_ident(&mut self) -> Option<Action> {
        let mut lines = 0usize;
        loop {
            let Some((line, rest)) = split_line(&self.buf) else {
                if self.buf.len() > MAX_PRE_IDENT {
                    return Some(self.stop("no identification string"));
                }
                return Some(Action::Receive);
            };
            if line.starts_with(b"SSH-") {
                let parsed = Identification::parse(line);
                let text = printable(line, 255);
                let rest = rest.to_vec();
                return match parsed {
                    Ok(ident) => {
                        let ssh2 = ident.speaks_ssh2();
                        self.ident = Some((ident, text));
                        self.buf = rest;
                        if ssh2 {
                            self.state = State::KexInit;
                            None
                        } else {
                            self.state = State::Over;
                            Some(Action::Done)
                        }
                    }
                    Err(e) => Some(self.stop(e.to_string())),
                };
            }
            // RFC 4253 §4.2: other lines may precede the identification,
            // but they are text.
            if line.iter().any(|&b| b < 0x20 && b != b'\t') || lines >= 32 {
                return Some(self.stop("no identification string"));
            }
            if self.pre_banner.is_none() && !line.is_empty() {
                self.pre_banner = Some(printable(line, 255));
            }
            lines += 1;
            let rest = rest.to_vec();
            self.buf = rest;
        }
    }

    /// Split the next packet off the buffer, skipping transport messages
    /// that carry nothing (`IGNORE`, `DEBUG`, `UNIMPLEMENTED`) and stopping
    /// on `DISCONNECT`.
    fn next_packet(&mut self) -> Packet {
        loop {
            let (payload, used) = match crate::parse_packet(&self.buf) {
                Ok(Some((payload, used))) => (payload.to_vec(), used),
                Ok(None) => return Packet::Incomplete,
                Err(e) => {
                    self.stop(e.to_string());
                    return Packet::Stop;
                }
            };
            self.buf.drain(..used);
            match payload.first().copied() {
                Some(MSG_IGNORE | MSG_DEBUG | MSG_UNIMPLEMENTED) => {}
                Some(MSG_DISCONNECT) => {
                    let mut r = Reader::new(payload.get(1..).unwrap_or_default());
                    let code = r.u32("reason code").unwrap_or_default();
                    let text = r.string("description").unwrap_or_default();
                    self.disconnect = Some(format!("{code}: {}", printable(text, 255)));
                    self.state = State::Over;
                    return Packet::Stop;
                }
                _ => return Packet::Payload(payload),
            }
        }
    }

    fn read_kexinit(&mut self) -> Action {
        let payload = match self.next_packet() {
            Packet::Incomplete if self.ident_sent => return Action::Receive,
            Packet::Incomplete => {
                // OpenSSH waits for the client's identification before it
                // sends KEXINIT.
                self.ident_sent = true;
                return Action::Send(self.probe.client_identification().into_bytes());
            }
            Packet::Stop => return Action::Done,
            Packet::Payload(payload) => payload,
        };
        let kexinit = match KexInit::parse(&payload) {
            Ok(k) => k,
            Err(e) => return self.stop(format!("KEXINIT: {e}")),
        };
        let request = if self.probe.host_key {
            self.host_key_request(&kexinit)
        } else {
            None
        };
        self.kexinit = Some(kexinit);
        let Some(mut bytes) = request else {
            self.state = State::Over;
            return Action::Done;
        };
        if !self.ident_sent {
            self.ident_sent = true;
            let mut out = self.probe.client_identification().into_bytes();
            out.append(&mut bytes);
            bytes = out;
        }
        self.state = State::KexReply;
        Action::Send(bytes)
    }

    /// Our KEXINIT and key-exchange init, or `None` when the server offers
    /// nothing the probe can drive (the reason is recorded).
    fn host_key_request(&mut self, server: &KexInit) -> Option<Vec<u8>> {
        let Some(kex) = SUPPORTED_KEX
            .iter()
            .find(|k| server.kex_algorithms.iter().any(|s| s == *k))
        else {
            self.problem = Some("no key exchange the probe supports".to_owned());
            return None;
        };
        let offered = &server.server_host_key_algorithms;
        let host_key = self.probe.host_key_algorithm.as_ref().map_or_else(
            || {
                HOST_KEY_PREFERENCE
                    .iter()
                    .find_map(|p| offered.iter().find(|s| s == p))
                    .or_else(|| offered.first())
            },
            |wanted| offered.iter().find(|s| *s == wanted),
        );
        let Some(host_key) = host_key.cloned() else {
            self.problem = Some("host-key algorithm not offered".to_owned());
            return None;
        };
        let value = kex_init_value(kex)?;

        let ours = KexInit {
            kex_algorithms: vec![(*kex).to_owned()],
            server_host_key_algorithms: vec![host_key.clone()],
            encryption_client_to_server: server.encryption_client_to_server.clone(),
            encryption_server_to_client: server.encryption_server_to_client.clone(),
            mac_client_to_server: server.mac_client_to_server.clone(),
            mac_server_to_client: server.mac_server_to_client.clone(),
            compression_client_to_server: server.compression_client_to_server.clone(),
            compression_server_to_client: server.compression_server_to_client.clone(),
            ..KexInit::default()
        };

        let mut init = vec![MSG_KEX_INIT];
        put_string(&mut init, &value);
        let mut out = encode_packet(&ours.encode());
        out.extend_from_slice(&encode_packet(&init));
        self.negotiated = Some(((*kex).to_owned(), host_key));
        Some(out)
    }

    fn read_kex_reply(&mut self) -> Action {
        let payload = match self.next_packet() {
            Packet::Incomplete => return Action::Receive,
            Packet::Stop => return Action::Done,
            Packet::Payload(payload) => payload,
        };
        self.state = State::Over;
        match parse_kex_reply_host_key(&payload).and_then(HostKey::parse) {
            Ok(key) => {
                self.host_key = Some(key);
                Action::Done
            }
            Err(e) => self.stop(format!("key-exchange reply: {e}")),
        }
    }

    fn report(&mut self) -> ServiceInfo {
        let Some((ident, banner)) = self.ident.take() else {
            return ServiceInfo::new(PROBE_ID);
        };
        let (product, version) = ident.product();
        let mut info = ServiceInfo::new(PROBE_ID)
            .with_product(product)
            .with_banner(banner)
            .with_detail("ssh.protocol_version", ident.proto_version.clone())
            .with_detail("ssh.software_version", ident.software_version.clone());
        if let Some(version) = version {
            info = info.with_version(version);
        }
        if let Some(comments) = &ident.comments {
            info = info.with_detail("ssh.comments", comments.clone());
        }
        if let Some(pre) = self.pre_banner.take() {
            info = info.with_detail("ssh.pre_banner", pre);
        }
        if ident.offers_ssh1() {
            info = info.push_finding(self.protocol_v1(&ident));
        }
        if let Some(kexinit) = self.kexinit.take() {
            info = self.report_kexinit(info, &kexinit);
        }
        if let Some((kex, host_key)) = self.negotiated.take() {
            info = info
                .with_detail("ssh.negotiated_kex", kex)
                .with_detail("ssh.negotiated_host_key_algorithm", host_key);
        }
        if let Some(key) = self.host_key.take() {
            info = self.report_host_key(info, &key);
        }
        if let Some(reason) = self.disconnect.take() {
            info = info.with_detail("ssh.disconnect", reason);
        }
        if let Some(problem) = self.problem.take() {
            info = info.with_detail("ssh.probe_error", problem);
        }
        info
    }

    fn protocol_v1(&self, ident: &Identification) -> Finding {
        let severity = if ident.speaks_ssh2() {
            Severity::Medium
        } else {
            Severity::High
        };
        self.target
            .finding(
                "ssh.protocol_v1",
                "SSH server offers protocol version 1",
                severity,
                Confidence::Certain,
            )
            .push_evidence(Evidence::new(
                "protocol_version",
                ident.proto_version.clone(),
            ))
            .push_taxonomy(TaxonomyRef::cwe(327))
            .with_remediation(Remediation::new(
                "Disable SSH protocol 1; it has known cryptographic weaknesses.",
            ))
    }

    fn report_kexinit(&self, mut info: ServiceInfo, kexinit: &KexInit) -> ServiceInfo {
        let lists: [(&str, Vec<&str>); 5] = [
            ("kex", strs(&kexinit.kex_algorithms)),
            ("host_key", strs(&kexinit.server_host_key_algorithms)),
            ("cipher", kexinit.ciphers()),
            ("mac", kexinit.macs()),
            ("compression", kexinit.compression()),
        ];
        for (label, names) in &lists {
            for name in names {
                info = info.push_capability(format!("{label}:{name}"));
            }
        }
        info = info
            .with_detail("ssh.kex_algorithms", kexinit.kex_algorithms.join(","))
            .with_detail(
                "ssh.host_key_algorithms",
                kexinit.server_host_key_algorithms.join(","),
            )
            .with_detail(
                "ssh.ciphers_client_to_server",
                kexinit.encryption_client_to_server.join(","),
            )
            .with_detail(
                "ssh.ciphers_server_to_client",
                kexinit.encryption_server_to_client.join(","),
            )
            .with_detail(
                "ssh.macs_client_to_server",
                kexinit.mac_client_to_server.join(","),
            )
            .with_detail(
                "ssh.macs_server_to_client",
                kexinit.mac_server_to_client.join(","),
            )
            .with_detail("ssh.compression", kexinit.compression().join(","))
            .with_detail("ssh.strict_kex", kexinit.strict_kex().to_string());

        let weak = audit(kexinit);
        for category in Category::ALL {
            let mine: Vec<_> = weak.iter().filter(|w| w.category == category).collect();
            let Some(severity) = mine.iter().map(|w| w.severity).max() else {
                continue;
            };
            let names: Vec<&str> = mine.iter().map(|w| w.algorithm.as_str()).collect();
            let mut finding = self
                .target
                .finding(
                    category.check_id(),
                    format!(
                        "SSH server offers weak {} algorithms: {}",
                        category_title(category),
                        names.join(", ")
                    ),
                    severity,
                    Confidence::Certain,
                )
                .push_taxonomy(TaxonomyRef::cwe(327))
                .with_remediation(Remediation::new(format!(
                    "Remove the listed {} algorithms from the server configuration.",
                    category_title(category)
                )));
            for w in mine {
                finding = finding.push_evidence(Evidence::new(w.algorithm.clone(), w.reason));
            }
            info = info.push_finding(finding);
        }
        if terrapin_exposed(kexinit) {
            info = info.push_finding(
                self.target
                    .finding(
                        "ssh.terrapin",
                        "SSH server is exposed to the Terrapin attack (CVE-2023-48795)",
                        Severity::Medium,
                        Confidence::Firm,
                    )
                    .push_evidence(Evidence::new("strict_kex", "not offered"))
                    .push_taxonomy(TaxonomyRef::cwe(354))
                    .with_remediation(
                        Remediation::new(
                            "Upgrade to a server that supports strict key exchange, or disable \
                             chacha20-poly1305@openssh.com and encrypt-then-MAC MACs with CBC ciphers.",
                        )
                        .push_reference("https://terrapin-attack.com/"),
                    )
                    .push_remediation_ref("https://nvd.nist.gov/vuln/detail/CVE-2023-48795"),
            );
        }
        info
    }

    fn report_host_key(&self, mut info: ServiceInfo, key: &HostKey) -> ServiceInfo {
        info = info
            .with_detail("ssh.host_key_type", key.key_type.clone())
            .with_detail("ssh.host_key_fingerprint", key.fingerprint_sha256())
            .with_detail("ssh.host_key", key.to_openssh());
        if let Some(bits) = key.bits {
            info = info.with_detail("ssh.host_key_bits", bits.to_string());
        }
        let base = key
            .key_type
            .strip_suffix("-cert-v01@openssh.com")
            .unwrap_or(&key.key_type);
        let weak = match (base, key.bits) {
            ("ssh-dss", _) => Some("DSA host key"),
            ("ssh-rsa", Some(bits)) if bits < 2048 => Some("RSA host key shorter than 2048 bits"),
            _ => None,
        };
        if let Some(title) = weak {
            let bits = key.bits.map_or_else(|| "?".to_owned(), |b| b.to_string());
            info = info.push_finding(
                self.target
                    .finding("ssh.weak_host_key", title, Severity::Medium, Confidence::Certain)
                    .push_evidence(Evidence::new(
                        "host_key",
                        format!("{} {bits} {}", key.key_type, key.fingerprint_sha256()),
                    ))
                    .push_taxonomy(TaxonomyRef::cwe(326))
                    .with_remediation(Remediation::new(
                        "Replace the host key with an Ed25519, ECDSA or RSA (3072-bit or longer) key.",
                    )),
            );
        }
        info
    }
}

const fn category_title(category: Category) -> &'static str {
    match category {
        Category::Kex => "key-exchange",
        Category::HostKey => "host-key",
        Category::Cipher => "cipher",
        Category::Mac => "MAC",
    }
}

fn strs(list: &[String]) -> Vec<&str> {
    list.iter().map(String::as_str).collect()
}

impl ProbeSession for Session {
    fn start(&mut self) -> Action {
        // The server speaks first.
        Action::Receive
    }

    fn on_data(&mut self, data: &[u8]) -> Action {
        self.received = true;
        if self.state == State::Over {
            return Action::Done;
        }
        self.buf.extend_from_slice(data);
        self.advance()
    }

    fn finish(&mut self, _end: End) -> Result<ServiceInfo, rune_service_probe::Error> {
        if self.ident.is_none() {
            if !self.received {
                return Err(rune_service_probe::Error::no_response(PROBE_ID));
            }
            let reason = self
                .problem
                .take()
                .unwrap_or_else(|| "no SSH identification string".to_owned());
            return Err(rune_service_probe::Error::unrecognized(PROBE_ID, reason));
        }
        Ok(self.report())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_software_is_sanitised() {
        let probe = SshProbe::new().with_client_software("My Scanner-1.0\r\n");
        assert_eq!(probe.client_identification(), "SSH-2.0-MyScanner1.0\r\n");
        let probe = SshProbe::new().with_client_software(" - ");
        assert_eq!(probe.client_identification(), "SSH-2.0-rune_probe_ssh\r\n");
    }

    #[test]
    fn every_supported_kex_has_an_init_value() {
        for kex in SUPPORTED_KEX {
            assert!(kex_init_value(kex).is_some(), "{kex}");
        }
        assert!(kex_init_value("sntrup761x25519-sha512@openssh.com").is_none());
    }
}
