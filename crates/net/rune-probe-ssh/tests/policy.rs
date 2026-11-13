//! The policy grader against captured server hellos: an identification
//! line followed by the KEXINIT packet, as they come off the wire.

#![allow(
    clippy::field_reassign_with_default,
    reason = "KexInit is non_exhaustive: other crates build it from Default"
)]
#![allow(clippy::unwrap_used, reason = "test code")]

use rune_probe_ssh::audit::Category;
use rune_probe_ssh::policy::{Grade, Level, Policy, Report};
use rune_probe_ssh::software::Family;
use rune_probe_ssh::{Identification, KexInit, encode_packet, parse_packet};
use rune_service_probe::rune_finding::{Confidence, Location, Severity};

fn names(list: &str) -> Vec<String> {
    if list.is_empty() {
        return Vec::new();
    }
    list.split(',').map(str::to_owned).collect()
}

/// Build the bytes a server sends first. `algorithms` holds kex, host key,
/// ciphers, MACs and compression; both directions get the same lists.
fn server_hello(banner: &str, algorithms: [&str; 5]) -> Vec<u8> {
    let [kex, host_key, ciphers, macs, compression] = algorithms;
    let mut k = KexInit::default();
    k.cookie = *b"\x8c\x1f\x02\x9a\x41\x77\xd0\x13\x5e\x2b\xc4\x66\x09\xf1\xa8\x3d";
    k.kex_algorithms = names(kex);
    k.server_host_key_algorithms = names(host_key);
    k.encryption_client_to_server = names(ciphers);
    k.encryption_server_to_client = names(ciphers);
    k.mac_client_to_server = names(macs);
    k.mac_server_to_client = names(macs);
    k.compression_client_to_server = names(compression);
    k.compression_server_to_client = names(compression);
    let mut out = format!("{banner}\r\n").into_bytes();
    out.extend(encode_packet(&k.encode()));
    out
}

/// Split a captured hello back into its identification and KEXINIT.
fn parse_hello(bytes: &[u8]) -> (Identification, KexInit) {
    let end = bytes.iter().position(|&b| b == b'\n').unwrap() + 1;
    let ident = Identification::parse(&bytes[..end]).unwrap();
    let (payload, used) = parse_packet(&bytes[end..]).unwrap().unwrap();
    assert_eq!(end + used, bytes.len());
    (ident, KexInit::parse(payload).unwrap())
}

fn grade(policy: &Policy, hello: &[u8]) -> Report {
    let (ident, kexinit) = parse_hello(hello);
    policy.grade(Some(&ident), Some(&kexinit))
}

fn at(report: &Report, level: Level) -> Vec<&str> {
    report
        .algorithms
        .iter()
        .filter(|a| a.level == level)
        .map(|a| a.algorithm.as_str())
        .collect()
}

fn check_ids(report: &Report) -> Vec<String> {
    report
        .findings(&Location::network("server.test", 22))
        .into_iter()
        .map(|f| f.check_id)
        .collect()
}

/// OpenSSH 9.9p2 hardened along the lines of current upstream defaults
/// minus SHA-1, 64-bit tags, NIST curves and encrypt-and-MAC.
fn openssh_9_9_hardened() -> Vec<u8> {
    server_hello(
        "SSH-2.0-OpenSSH_9.9p2",
        [
            "mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ext-info-s,kex-strict-s-v00@openssh.com",
            "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256",
            "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
            "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com",
            "none,zlib@openssh.com",
        ],
    )
}

/// The stock sshd offer of OpenSSH 9.9p2.
fn openssh_9_9_stock() -> Vec<u8> {
    server_hello(
        "SSH-2.0-OpenSSH_9.9p2",
        [
            "mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
            "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
            "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
            "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
            "none,zlib@openssh.com",
        ],
    )
}

/// OpenSSH 7.4 as shipped on an enterprise distribution: CBC and 3DES
/// still on, no strict KEX (it predates Terrapin).
fn openssh_7_4() -> Vec<u8> {
    server_hello(
        "SSH-2.0-OpenSSH_7.4",
        [
            "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
            "ssh-rsa,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519",
            "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc,cast128-cbc,3des-cbc",
            "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1",
            "none,zlib@openssh.com",
        ],
    )
}

/// Dropbear 2020.81 defaults.
fn dropbear_2020_81() -> Vec<u8> {
    server_hello(
        "SSH-2.0-dropbear_2020.81",
        [
            "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,kexguess2@matt.ucc.asn.au",
            "ecdsa-sha2-nistp256,ssh-ed25519,rsa-sha2-256,ssh-rsa",
            "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr",
            "hmac-sha1,hmac-sha2-256",
            "zlib@openssh.com,none",
        ],
    )
}

/// A server with modern algorithms except that CBC ciphers sit next to
/// encrypt-then-MAC MACs, without strict KEX.
fn terrapin_cbc_etm(strict: bool) -> Vec<u8> {
    let kex = if strict {
        "curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com"
    } else {
        "curve25519-sha256,ext-info-s"
    };
    server_hello(
        "SSH-2.0-OpenSSH_9.9p2",
        [
            kex,
            "ssh-ed25519",
            "aes256-gcm@openssh.com,aes256-ctr,aes256-cbc",
            "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
            "none",
        ],
    )
}

#[test]
fn hello_round_trips() {
    let hello = openssh_7_4();
    let (ident, kexinit) = parse_hello(&hello);
    assert_eq!(ident.software_version, "OpenSSH_7.4");
    assert_eq!(kexinit.ciphers().len(), 12);
}

#[test]
fn modern_openssh_9_hardened_gets_an_a() {
    let report = grade(&Policy::modern(), &openssh_9_9_hardened());
    assert_eq!(report.grade, Grade::A, "{}", report.grade_reason);
    assert_eq!(at(&report, Level::Fail), Vec::<&str>::new());
    assert_eq!(at(&report, Level::Warn), Vec::<&str>::new());
    assert!(report.algorithms.iter().all(|a| a.known));
    let t = report.terrapin.unwrap();
    assert!(t.chacha20 && t.strict_kex && !t.vulnerable());
    let sw = report.software.as_ref().unwrap();
    assert_eq!(
        (sw.family, sw.version.as_deref()),
        (Family::OpenSsh, Some("9.9p2"))
    );
    assert_eq!(report.vulnerabilities.len(), 0);
    assert_eq!(check_ids(&report), Vec::<String>::new());
}

#[test]
fn stock_openssh_9_depends_on_the_profile() {
    let modern = grade(&Policy::modern(), &openssh_9_9_stock());
    assert_eq!(modern.grade, Grade::C);
    assert_eq!(
        at(&modern, Level::Fail),
        [
            "umac-64-etm@openssh.com",
            "hmac-sha1-etm@openssh.com",
            "umac-64@openssh.com",
            "hmac-sha1"
        ]
    );
    assert_eq!(
        at(&modern, Level::Warn),
        [
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group14-sha256",
            "ecdsa-sha2-nistp256",
            "umac-128@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
        ]
    );

    let compatible = grade(&Policy::compatible(), &openssh_9_9_stock());
    assert_eq!(compatible.grade, Grade::B);
    assert_eq!(at(&compatible, Level::Fail), Vec::<&str>::new());
    assert_eq!(at(&compatible, Level::Warn).len(), 4);
}

#[test]
fn old_openssh_7_4() {
    let report = grade(&Policy::modern(), &openssh_7_4());
    assert_eq!(report.grade, Grade::D);
    assert_eq!(report.grade_reason, "offers a badly broken algorithm");
    let fails = at(&report, Level::Fail);
    for name in [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "ssh-rsa",
        "aes128-cbc",
        "3des-cbc",
        "blowfish-cbc",
        "hmac-sha1",
    ] {
        assert!(fails.contains(&name), "{name}");
    }
    let t = report.terrapin.unwrap();
    assert!(t.chacha20 && t.cbc_etm && !t.strict_kex);
    assert!(report.terrapin_vulnerable());
    let cves: Vec<&str> = report.vulnerabilities.iter().map(|c| c.id).collect();
    assert_eq!(cves, ["CVE-2021-41617", "CVE-2018-15473"]);

    let findings = report.findings(&Location::network("legacy.test", 22));
    let ids: Vec<&str> = findings.iter().map(|f| f.check_id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "ssh.weak_kex",
            "ssh.discouraged_kex",
            "ssh.weak_host_key_algorithm",
            "ssh.discouraged_host_key_algorithm",
            "ssh.weak_cipher",
            "ssh.weak_mac",
            "ssh.discouraged_mac",
            "ssh.terrapin",
            "ssh.cve-2021-41617",
            "ssh.cve-2018-15473",
        ]
    );
    let cipher = &findings[4];
    assert_eq!(cipher.severity, Severity::Medium);
    assert_eq!(cipher.location, Location::network("legacy.test", 22));
    let terrapin = &findings[7];
    assert_eq!(terrapin.confidence, Confidence::Firm);
    assert!(
        terrapin
            .evidence
            .iter()
            .any(|e| e.snippet == "chacha20-poly1305@openssh.com, CBC cipher with an -etm MAC")
    );
    assert!(
        findings[8..]
            .iter()
            .all(|f| f.confidence == Confidence::Tentative)
    );

    // Compatible still fails the broken ones and keeps the D.
    let report = grade(&Policy::compatible(), &openssh_7_4());
    assert_eq!(report.grade, Grade::D);
    assert_eq!(
        at(&report, Level::Fail),
        [
            "diffie-hellman-group1-sha1",
            "blowfish-cbc",
            "cast128-cbc",
            "3des-cbc"
        ]
    );
}

#[test]
fn dropbear() {
    let report = grade(&Policy::modern(), &dropbear_2020_81());
    let sw = report.software.as_ref().unwrap();
    assert_eq!(
        (sw.family, sw.version.as_deref()),
        (Family::Dropbear, Some("2020.81"))
    );
    assert_eq!(report.vulnerabilities.len(), 0);
    assert_eq!(
        at(&report, Level::Fail),
        ["diffie-hellman-group14-sha1", "ssh-rsa", "hmac-sha1"]
    );
    // chacha20 without strict KEX: Dropbear added it in 2024.84.
    assert!(report.terrapin_vulnerable());
    assert_eq!(report.grade, Grade::C);
    let kexguess = report
        .algorithms
        .iter()
        .find(|a| a.algorithm == "kexguess2@matt.ucc.asn.au")
        .unwrap();
    assert_eq!(kexguess.level, Level::Info);

    // An old Dropbear trips the version table.
    let old = server_hello(
        "SSH-2.0-dropbear_2016.72",
        [
            "diffie-hellman-group14-sha1",
            "ssh-rsa",
            "aes128-ctr",
            "hmac-sha1",
            "none",
        ],
    );
    let report = grade(&Policy::compatible(), &old);
    let cves: Vec<&str> = report.vulnerabilities.iter().map(|c| c.id).collect();
    assert_eq!(cves, ["CVE-2016-7406", "CVE-2017-9078", "CVE-2018-15599"]);
    assert_eq!(report.grade, Grade::C);
    assert_eq!(
        report.grade_reason,
        "version matches a serious known CVE (heuristic)"
    );
}

#[test]
fn terrapin_through_cbc_and_etm() {
    let report = grade(&Policy::compatible(), &terrapin_cbc_etm(false));
    let t = report.terrapin.unwrap();
    assert!(!t.chacha20 && t.cbc_etm && t.vulnerable());
    assert_eq!(report.grade, Grade::C);
    assert_eq!(
        report.grade_reason,
        "exposed to the Terrapin attack (CVE-2023-48795)"
    );
    assert!(check_ids(&report).contains(&"ssh.terrapin".to_owned()));

    let report = grade(&Policy::compatible(), &terrapin_cbc_etm(true));
    assert!(!report.terrapin_vulnerable());
    assert_eq!(report.grade, Grade::B, "CBC still draws a warning");
    assert!(!check_ids(&report).contains(&"ssh.terrapin".to_owned()));
}

#[test]
fn custom_allow_and_deny_lists() {
    // A site policy: compatible, but only the AEAD ciphers and no NIST
    // curves at all.
    let policy = Policy::compatible()
        .allow_only(
            Category::Cipher,
            ["chacha20-poly1305@openssh.com", "*-gcm@openssh.com"],
        )
        .deny(Category::Kex, "ecdh-sha2-*")
        .deny(Category::HostKey, "ecdsa-*");
    let report = grade(&policy, &openssh_9_9_stock());
    assert!(report.customised);
    assert_eq!(
        at(&report, Level::Fail),
        [
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "ecdsa-sha2-nistp256",
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
        ]
    );
    assert_eq!(report.grade, Grade::C);
    let ctr = report
        .algorithms
        .iter()
        .find(|a| a.algorithm == "aes128-ctr")
        .unwrap();
    assert_eq!(ctr.reason, "not in the policy's allow list");
    assert_eq!(ctr.source, Some("policy"));

    // And an allow rule rescues a single legacy algorithm.
    let policy = Policy::modern()
        .allow(Category::Mac, "hmac-sha1*")
        .allow(Category::Mac, "umac-64*");
    let report = grade(&policy, &openssh_9_9_stock());
    assert_eq!(at(&report, Level::Fail), Vec::<&str>::new());
    assert_eq!(report.grade, Grade::B);
}

#[test]
fn none_cipher_is_an_f() {
    let hello = server_hello(
        "SSH-2.0-OpenSSH_9.9p2",
        [
            "curve25519-sha256",
            "ssh-ed25519",
            "aes128-ctr,none",
            "hmac-sha2-256-etm@openssh.com",
            "none",
        ],
    );
    let report = grade(&Policy::compatible(), &hello);
    assert_eq!(report.grade, Grade::F);
    let findings = report.findings(&Location::network("h", 22));
    assert_eq!(findings[0].severity, Severity::High);
}

#[test]
fn a_category_that_only_fails_is_a_d() {
    let hello = server_hello(
        "SSH-2.0-OpenSSH_9.9p2",
        [
            "curve25519-sha256",
            "ssh-ed25519",
            "aes128-cbc,aes256-cbc",
            "hmac-sha2-256-etm@openssh.com",
            "none",
        ],
    );
    let report = grade(&Policy::modern(), &hello);
    assert_eq!(report.grade, Grade::D);
    assert_eq!(
        report.grade_reason,
        "every algorithm of a required category fails"
    );
}

#[test]
fn grading_a_maximal_kexinit_stays_linear() {
    // About 61 KB of distinct cipher names, just under the packet limit,
    // graded under an allow list so every one of them fails.
    let names: Vec<String> = (0..7000).map(|i| format!("{i:x}")).collect();
    let mut offer = KexInit::default();
    offer.encryption_client_to_server.clone_from(&names);
    offer.encryption_server_to_client = names.into_iter().rev().collect();
    assert!(encode_packet(&offer.encode()).len() < 65_536);
    let policy = Policy::modern().allow_only(Category::Cipher, ["aes*"]);
    let start = std::time::Instant::now();
    let report = policy.grade(None, Some(&offer));
    let elapsed = start.elapsed();
    assert_eq!(report.failures().count(), 7000);
    assert_eq!(report.grade, Grade::D);
    assert!(
        elapsed < std::time::Duration::from_millis(300),
        "{elapsed:?}"
    );
}
