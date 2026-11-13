//! The probe against scripted server transcripts, in memory.

#![allow(
    clippy::field_reassign_with_default,
    reason = "KexInit is non_exhaustive: other crates build it from Default"
)]
// Test helpers outside `#[test]` functions may unwrap too.
#![allow(clippy::unwrap_used, reason = "test code")]

use rune_probe_ssh::{KexInit, SshProbe, encode_packet, parse_packet};
use rune_service_probe::rune_finding::{Confidence, Severity};
use rune_service_probe::{End, Error, Options, ServiceInfo, Target, simulate};

const ED25519: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIOJv+0BnO5Sq9IS18Q8eLfxJL3GuLtonL4clXHHkg4EX";
const ED25519_FP: &str = "SHA256:sy6hgZYNW2YfQFZt6xYCu+D96SlMGrevKRhp8XYPN74";
const RSA_1024: &str = "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDLwSlEGUNEBIVQSwfSPQOHPacwU27hKFDUCYvzRNix6RK4/Nv/fEvnyCxgEkWT8AMDj0YV60Jk0wA0bhVjzBG8kZkvjOYuz7CbSVwU6ReXjheIK2Ggp8DQUJmNOy5qFCcPenwFiAs+2Ex45Pj+oUoxYZiUhHAEkxvV+64MArJCSw==";
const RSA_1024_FP: &str = "SHA256:8D8GBIFYgHY22Io7k9Y90vtTR4JEV0xijzyuXEDchos";

fn names(list: &str) -> Vec<String> {
    list.split(',').map(str::to_owned).collect()
}

fn string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
    out.extend_from_slice(s);
}

/// The default server offer of OpenSSH 9.6p1 (Ubuntu 24.04).
fn openssh_9_6() -> KexInit {
    let ciphers = names(
        "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    );
    let macs = names(
        "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
    );
    let mut k = KexInit::default();
    k.cookie = *b"0123456789abcdef";
    k.kex_algorithms = names(
        "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
    );
    k.server_host_key_algorithms =
        names("rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519");
    k.encryption_client_to_server.clone_from(&ciphers);
    k.encryption_server_to_client = ciphers;
    k.mac_client_to_server.clone_from(&macs);
    k.mac_server_to_client = macs;
    k.compression_client_to_server = names("none,zlib@openssh.com");
    k.compression_server_to_client = names("none,zlib@openssh.com");
    k
}

/// The default offer of OpenSSH 5.3p1 (`CentOS` 6), weak by today's rules.
fn openssh_5_3() -> KexInit {
    let ciphers = names(
        "aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se",
    );
    let macs = names(
        "hmac-md5,hmac-sha1,umac-64@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96",
    );
    let mut k = KexInit::default();
    k.kex_algorithms = names(
        "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
    );
    k.server_host_key_algorithms = names("ssh-rsa,ssh-dss");
    k.encryption_client_to_server.clone_from(&ciphers);
    k.encryption_server_to_client = ciphers;
    k.mac_client_to_server.clone_from(&macs);
    k.mac_server_to_client = macs;
    k.compression_client_to_server = names("none,zlib@openssh.com");
    k.compression_server_to_client = names("none,zlib@openssh.com");
    k
}

fn kex_reply(host_key_b64: &str) -> Vec<u8> {
    let mut reply = vec![31];
    string(&mut reply, &rune_base64::decode(host_key_b64).unwrap());
    string(&mut reply, &[0x42; 32]);
    string(&mut reply, b"\0\0\0\x0bssh-ed25519\0\0\0\x40signature");
    encode_packet(&reply)
}

fn hello(ident: &str, offer: &KexInit) -> Vec<u8> {
    let mut out = format!("{ident}\r\n").into_bytes();
    out.extend(encode_packet(&offer.encode()));
    out
}

/// The probe's packets after its identification line.
fn sent_packets(sent: &[u8]) -> Vec<Vec<u8>> {
    let mut rest = sent;
    let mut out = Vec::new();
    while let Some((payload, used)) = parse_packet(rest).unwrap() {
        out.push(payload.to_vec());
        rest = &rest[used..];
    }
    assert_eq!(rest, b"");
    out
}

fn checks(info: &ServiceInfo) -> Vec<&str> {
    info.findings.iter().map(|f| f.check_id.as_str()).collect()
}

#[test]
fn modern_openssh_server() {
    let target = Target::new("bastion.test", 22);
    let server_hello = hello("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", &openssh_9_6());
    // The server holds its KEXINIT until it has read our identification,
    // as OpenSSH does.
    let (ident, kexinit) = server_hello.split_at(42);
    let reply = kex_reply(ED25519);
    let sim = simulate(
        &SshProbe::new(),
        &target,
        &[ident, kexinit, &reply],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sim.end, End::Done);
    assert_eq!(sim.sent.len(), 2);
    assert_eq!(sim.sent[0], b"SSH-2.0-rune_probe_ssh\r\n");

    // Our KEXINIT names one kex and one host-key algorithm; then the
    // curve25519 init with the base point. Nothing else.
    let packets = sent_packets(&sim.sent[1]);
    assert_eq!(packets.len(), 2);
    let ours = KexInit::parse(&packets[0]).unwrap();
    assert_eq!(ours.kex_algorithms, ["curve25519-sha256"]);
    assert_eq!(ours.server_host_key_algorithms, ["ssh-ed25519"]);
    assert_eq!(
        ours.encryption_client_to_server,
        openssh_9_6().encryption_client_to_server
    );
    let mut init = vec![30, 0, 0, 0, 32, 9];
    init.resize(37, 0);
    assert_eq!(packets[1], init);

    let info = sim.result.unwrap();
    assert_eq!(info.service, "ssh");
    assert_eq!(info.product.as_deref(), Some("OpenSSH"));
    assert_eq!(info.version.as_deref(), Some("9.6p1"));
    assert_eq!(
        info.banner.as_deref(),
        Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
    );
    assert_eq!(info.details["ssh.comments"], "Ubuntu-3ubuntu13.5");
    assert_eq!(info.details["ssh.host_key_fingerprint"], ED25519_FP);
    assert_eq!(info.details["ssh.host_key_type"], "ssh-ed25519");
    assert_eq!(info.details["ssh.host_key_bits"], "256");
    assert_eq!(
        info.details["ssh.host_key"],
        format!("ssh-ed25519 {ED25519}")
    );
    assert_eq!(info.details["ssh.negotiated_kex"], "curve25519-sha256");
    assert_eq!(info.details["ssh.strict_kex"], "true");
    assert!(
        info.capabilities
            .contains(&"kex:sntrup761x25519-sha512@openssh.com".to_owned())
    );
    assert!(
        info.capabilities
            .contains(&"compression:zlib@openssh.com".to_owned())
    );
    assert!(!info.details.contains_key("ssh.probe_error"));
    // Under the modern policy only the SHA-1 and 64-bit-tag MACs fail;
    // NIST curves, the 2048-bit group and encrypt-and-MAC MACs draw
    // warnings. Strict KEX blocks Terrapin. 9.6p1 is in two CVE ranges by
    // version alone, even though Ubuntu backports the fixes.
    assert_eq!(
        checks(&info),
        [
            "ssh.discouraged_kex",
            "ssh.discouraged_host_key_algorithm",
            "ssh.weak_mac",
            "ssh.discouraged_mac",
            "ssh.cve-2024-6387",
            "ssh.cve-2025-26466",
        ]
    );
    assert_eq!(info.details["ssh.grade"], "C");
    assert_eq!(info.details["ssh.policy"], "modern");
    let cve = &info.findings[4];
    assert_eq!(cve.confidence, Confidence::Tentative);
    assert!(cve.evidence.iter().any(|e| e.label == "distribution"));
    let mac = &info.findings[2];
    assert_eq!(mac.severity, Severity::Low);
    let flagged: Vec<&str> = mac.evidence.iter().map(|e| e.label.as_str()).collect();
    assert_eq!(
        flagged,
        [
            "umac-64-etm@openssh.com",
            "hmac-sha1-etm@openssh.com",
            "umac-64@openssh.com",
            "hmac-sha1"
        ]
    );
}

#[test]
fn legacy_server_with_dh_and_short_rsa_key() {
    let target = Target::new("legacy.test", 2222);
    let server_hello = hello("SSH-1.99-OpenSSH_5.3", &openssh_5_3());
    let reply = kex_reply(RSA_1024);
    // Everything in one read, the reply split across reads.
    let (a, b) = reply.split_at(7);
    let sim = simulate(
        &SshProbe::new(),
        &target,
        &[&server_hello, a, b],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sim.sent.len(), 1, "identification and KEX sent together");
    assert!(sim.sent[0].starts_with(b"SSH-2.0-rune_probe_ssh\r\n"));
    let packets = sent_packets(&sim.sent[0][24..]);
    let ours = KexInit::parse(&packets[0]).unwrap();
    assert_eq!(ours.kex_algorithms, ["diffie-hellman-group14-sha1"]);
    assert_eq!(ours.server_host_key_algorithms, ["ssh-rsa"]);
    assert_eq!(packets[1][0], 30);
    assert_eq!(&packets[1][1..5], &[0, 0, 0, 32]);
    assert_eq!(packets[1][5], 0x7f, "e is a positive mpint");

    let info = sim.result.unwrap();
    assert_eq!(info.details["ssh.host_key_fingerprint"], RSA_1024_FP);
    assert_eq!(info.details["ssh.host_key_bits"], "1024");
    assert_eq!(
        checks(&info),
        [
            "ssh.protocol_v1",
            "ssh.weak_kex",
            "ssh.discouraged_kex",
            "ssh.weak_host_key_algorithm",
            "ssh.weak_cipher",
            "ssh.weak_mac",
            "ssh.discouraged_mac",
            "ssh.cve-2018-15473",
            "ssh.cve-2016-6210",
            "ssh.weak_host_key",
        ]
    );
    assert_eq!(info.details["ssh.grade"], "F");
    let sev: Vec<Severity> = info
        .findings
        .iter()
        .filter(|f| f.check_id.starts_with("ssh.weak") || f.check_id == "ssh.protocol_v1")
        .map(|f| f.severity)
        .collect();
    assert_eq!(
        sev,
        [
            Severity::Medium,
            Severity::Medium,
            Severity::Medium,
            Severity::Medium,
            Severity::Medium,
            Severity::Medium
        ]
    );
    let kex = &info.findings[1];
    assert!(kex.title.contains("diffie-hellman-group1-sha1"));
    assert!(!kex.title.contains("group-exchange-sha256"));
    // No chacha20 and no EtM MACs: not Terrapin-exposed.
    assert!(!checks(&info).contains(&"ssh.terrapin"));
}

#[test]
fn terrapin_exposed_server() {
    let mut offer = openssh_9_6();
    offer
        .kex_algorithms
        .retain(|k| !k.starts_with("kex-strict"));
    let sim = simulate(
        &SshProbe::new().with_host_key(false),
        &Target::new("old.test", 22),
        &[&hello("SSH-2.0-OpenSSH_9.3", &offer)],
        &Options::default(),
    )
    .unwrap();
    assert!(
        sim.sent.is_empty(),
        "KEXINIT was already there: nothing to send"
    );
    let info = sim.result.unwrap();
    assert!(checks(&info).contains(&"ssh.terrapin"));
    assert_eq!(info.details["ssh.strict_kex"], "false");
    assert!(!info.details.contains_key("ssh.host_key_fingerprint"));
}

#[test]
fn requested_host_key_algorithm() {
    let probe = SshProbe::new().with_host_key_algorithm("rsa-sha2-256");
    let mut server = b"SSH-2.0-OpenSSH_9.6\r\n".to_vec();
    server.extend(encode_packet(&openssh_9_6().encode()));
    let sim = simulate(
        &probe,
        &Target::new("h", 22),
        &[&server],
        &Options::default(),
    )
    .unwrap();
    let packets = sent_packets(&sim.sent[0][24..]);
    let ours = KexInit::parse(&packets[0]).unwrap();
    assert_eq!(ours.server_host_key_algorithms, ["rsa-sha2-256"]);
    assert_eq!(sim.end, End::Closed);

    let probe = SshProbe::new().with_host_key_algorithm("ssh-dss");
    let sim = simulate(
        &probe,
        &Target::new("h", 22),
        &[&server],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sim.sent, Vec::<Vec<u8>>::new());
    let info = sim.result.unwrap();
    assert_eq!(
        info.details["ssh.probe_error"],
        "host-key algorithm not offered"
    );
}

#[test]
fn no_supported_kex() {
    let mut offer = openssh_9_6();
    offer.kex_algorithms = names("ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256");
    let sim = simulate(
        &SshProbe::new(),
        &Target::new("h", 22),
        &[&hello("SSH-2.0-x_1", &offer)],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sim.sent, Vec::<Vec<u8>>::new());
    let info = sim.result.unwrap();
    assert_eq!(
        info.details["ssh.probe_error"],
        "no key exchange the probe supports"
    );
    assert!(info.details.contains_key("ssh.kex_algorithms"));
}

#[test]
fn ignore_debug_and_disconnect() {
    let mut server = b"Welcome to the jump host\r\nSSH-2.0-dropbear_2022.83\r\n".to_vec();
    server.extend(encode_packet(&[2, 0, 0, 0, 3, b'a', b'b', b'c']));
    server.extend(encode_packet(&[4, 1, 0, 0, 0, 0, 0, 0, 0, 0]));
    let mut offer = openssh_9_6();
    offer.server_host_key_algorithms = names("ssh-ed25519");
    server.extend(encode_packet(&offer.encode()));
    let mut disconnect = vec![1, 0, 0, 0, 3];
    string(&mut disconnect, b"Key exchange failed\x1b");
    string(&mut disconnect, b"");
    let disconnect = encode_packet(&disconnect);
    let sim = simulate(
        &SshProbe::new(),
        &Target::new("h", 22),
        &[&server, &disconnect],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sim.end, End::Done);
    let info = sim.result.unwrap();
    assert_eq!(info.product.as_deref(), Some("Dropbear"));
    assert_eq!(info.version.as_deref(), Some("2022.83"));
    assert_eq!(info.details["ssh.pre_banner"], "Welcome to the jump host");
    assert_eq!(
        info.details["ssh.disconnect"],
        r"3: Key exchange failed\x1b"
    );
    assert!(!info.details.contains_key("ssh.host_key"));
}

#[test]
fn ssh1_only_server() {
    let sim = simulate(
        &SshProbe::new(),
        &Target::new("h", 22),
        &[b"SSH-1.5-1.2.27\n"],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sim.sent, Vec::<Vec<u8>>::new());
    let info = sim.result.unwrap();
    assert_eq!(checks(&info), ["ssh.protocol_v1"]);
    assert_eq!(info.findings[0].severity, Severity::High);
}

#[test]
fn not_ssh() {
    let options = Options::default();
    let target = Target::new("h", 22);
    let http = simulate(
        &SshProbe::new(),
        &target,
        &[b"HTTP/1.1 400 Bad Request\r\n\r\n\x00"],
        &options,
    )
    .unwrap();
    assert!(matches!(http.result, Err(Error::Unrecognized { .. })));

    let silent = simulate(&SshProbe::new(), &target, &[], &options).unwrap();
    assert!(matches!(silent.result, Err(Error::NoResponse { .. })));

    let mut bad = b"SSH-2.0-x\r\n".to_vec();
    bad.extend_from_slice(&[0, 0, 0, 1, 0]);
    let sim = simulate(&SshProbe::new(), &target, &[&bad], &options).unwrap();
    let info = sim.result.unwrap();
    assert_eq!(
        info.details["ssh.probe_error"],
        "packet length 1 is out of range"
    );
}

#[test]
fn byte_at_a_time() {
    let mut server = hello("SSH-2.0-OpenSSH_9.6", &openssh_9_6());
    server.extend(kex_reply(ED25519));
    let chunks: Vec<&[u8]> = server.chunks(1).collect();
    let sim = simulate(
        &SshProbe::new(),
        &Target::new("h", 22),
        &chunks,
        &Options::default().with_max_exchanges(10_000),
    )
    .unwrap();
    assert_eq!(sim.sent.len(), 2);
    assert_eq!(
        sim.result.unwrap().details["ssh.host_key_fingerprint"],
        ED25519_FP
    );
}

#[test]
fn odd_names_do_not_hide_the_rest_of_the_offer() {
    // A server can add a non-ASCII or empty name to its lists; clients that
    // only look for names they know still connect, so the grade must not
    // fall back to the banner alone.
    for odd in ["aes256-ctr\u{ff}", "caf\u{e9}", ""] {
        let mut offer = openssh_5_3();
        offer.encryption_server_to_client.insert(0, odd.to_owned());
        offer.kex_algorithms.push(odd.to_owned());
        let sim = simulate(
            &SshProbe::new().with_host_key(false),
            &Target::new("legacy.test", 22),
            &[&hello("SSH-2.0-OpenSSH_9.9p2", &offer)],
            &Options::default(),
        )
        .unwrap();
        let info = sim.result.unwrap();
        assert!(
            !info.details.contains_key("ssh.probe_error"),
            "{odd:?}: {:?}",
            info.details.get("ssh.probe_error")
        );
        assert!(checks(&info).contains(&"ssh.weak_cipher"), "{odd:?}");
        assert_eq!(info.details["ssh.grade"], "D", "{odd:?}");
    }
}
