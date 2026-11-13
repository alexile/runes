# rune-probe-ssh

> Read-only SSH probe and policy grader: banner, KEXINIT algorithm grading, Terrapin check, version CVE hints and host-key fingerprint

[![crates.io](https://img.shields.io/crates/v/rune-probe-ssh)](https://crates.io/crates/rune-probe-ssh)
[![docs.rs](https://img.shields.io/docsrs/rune-probe-ssh)](https://docs.rs/rune-probe-ssh)
[![license](https://img.shields.io/crates/l/rune-probe-ssh)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

An SSH module for [`rune-service-probe`](../rune-service-probe). `SshProbe`
implements its `ServiceProbe` trait and

1. reads the server's identification string
   ([RFC 4253 §4.2](https://www.rfc-editor.org/rfc/rfc4253#section-4.2)):
   product, version, comments, SSH-1 support;
2. reads the server's `SSH_MSG_KEXINIT`
   ([§7.1](https://www.rfc-editor.org/rfc/rfc4253#section-7.1)) and grades the
   offered key-exchange, host-key, cipher, MAC and compression algorithms
   against a policy;
3. starts a key exchange (curve25519 or a fixed Diffie-Hellman group) only far
   enough to read the server's public host key, like `ssh-keyscan`, and
   reports its type, size and OpenSSH `SHA256:` fingerprint.

It is read-only: it never derives keys, sends `NEWKEYS` or attempts
authentication, and closes the connection after the key-exchange reply.

The grading is sans-I/O and works just as well on captured traffic:

- **Per-algorithm levels.** Every offered algorithm is `fail`, `warn` or
  `info`, with a reason and a source, from a table built on RFC 9142 (key
  exchange), RFC 8332 / 8709 (host keys), the NIST SP 800-131A and 800-57
  notes, RFC 8758 (RC4) and OpenSSH release notes. The table is public
  (`algorithms::ALGORITHMS`).
- **Profiles.** `modern` (the default) fails SHA-1, CBC, 64-bit tags and the
  like, and warns about NIST curves, 2048-bit groups and encrypt-and-MAC.
  `compatible` only fails what is broken or prohibited. Add your own
  `allow`, `deny` and `allow_only` lists on top of either.
- **Terrapin** (CVE-2023-48795): exposed when
  `chacha20-poly1305@openssh.com`, or a CBC cipher together with an `-etm`
  MAC, is offered without `kex-strict-s-v00@openssh.com`.
- **Software and known CVEs.** OpenSSH, Dropbear, libssh, libssh2, Erlang/OTP,
  Apache MINA SSHD and others are recognised from the banner, and the
  version is matched against a small table of notable server-side CVEs
  (regreSSHion, the libssh authentication bypass, the Erlang/OTP pre-auth
  RCE, ...). This is a heuristic: distributions backport fixes without
  changing the version, so these findings are `tentative`.
- **Grade** `A` to `F`, with the main reason.

| Grade | When                                                                            |
| ----- | ------------------------------------------------------------------------------- |
| F     | `none` cipher or MAC, or SSH-1                                                  |
| D     | a badly broken algorithm (medium severity or worse), or a category that only fails |
| C     | any failing algorithm, Terrapin exposure, or a high/critical CVE version match  |
| B     | only warnings, or a lesser CVE version match                                   |
| A     | nothing the policy objects to                                                   |

Findings use the `rune-finding` format:

| Check id                       | When                                                  |
| ------------------------------ | ----------------------------------------------------- |
| `ssh.protocol_v1`              | SSH-1 offered (`SSH-1.x`, `SSH-1.99`)                 |
| `ssh.weak_<category>`          | algorithms that fail the policy                       |
| `ssh.discouraged_<category>`   | algorithms the policy warns about                     |
| `ssh.terrapin`                 | CVE-2023-48795 exposure (no strict key exchange)      |
| `ssh.cve-<year>-<n>`           | banner version in a known CVE's range (tentative)     |
| `ssh.weak_host_key`            | DSA host key, or RSA shorter than 2048 bits (probe)   |

`<category>` is `kex`, `host_key_algorithm`, `cipher`, `mac` or `compression`.
The probe also sets `ssh.grade`, `ssh.grade_reason` and `ssh.policy` in its
details.

## Installation

```toml
[dependencies]
rune-probe-ssh = "0.1"
rune-service-probe = { version = "0.1", features = ["tokio"] }
```

## Usage

### Probing a server

```rust,no_run
use rune_probe_ssh::SshProbe;
use rune_service_probe::{Options, Runner, Target};

# async fn demo() -> Result<(), rune_service_probe::Error> {
let runner = Runner::new(Options::default());
let target = Target::new("bastion.example", 22);
let info = runner.probe(&SshProbe::new(), &target).await?;
println!("{:?} {:?}", info.product, info.version);
println!("{}", info.details["ssh.host_key_fingerprint"]);
for finding in &info.findings {
    println!("{} {:?}: {}", finding.check_id, finding.severity, finding.title);
}
# Ok(())
# }
```

`SshProbe::new().with_host_key(false)` stops after the KEXINIT;
`with_host_key_algorithm("ssh-rsa")` asks for one particular host key, so one
probe per offered algorithm collects all of a server's keys.

### Choosing a policy

```rust
use rune_probe_ssh::SshProbe;
use rune_probe_ssh::audit::Category;
use rune_probe_ssh::policy::Policy;

// Old clients still connect, but no NIST curves and only AEAD ciphers.
let policy = Policy::compatible()
    .deny(Category::Kex, "ecdh-sha2-*")
    .allow_only(Category::Cipher, ["chacha20-poly1305@openssh.com", "*-gcm@openssh.com"]);
let probe = SshProbe::new().with_policy(policy);
# let _ = probe;
```

### Grading captured traffic

```rust
use rune_probe_ssh::policy::{Grade, Level, Policy};
use rune_probe_ssh::{Identification, KexInit};
use rune_service_probe::rune_finding::Location;

let ident = Identification::parse(b"SSH-2.0-OpenSSH_7.4\r\n").unwrap();
let mut offer = KexInit::default();
offer.kex_algorithms = vec!["curve25519-sha256".into(), "diffie-hellman-group14-sha1".into()];
offer.server_host_key_algorithms = vec!["ssh-ed25519".into(), "ssh-rsa".into()];
offer.encryption_server_to_client = vec!["chacha20-poly1305@openssh.com".into(), "aes128-ctr".into()];
offer.mac_server_to_client = vec!["hmac-sha2-256-etm@openssh.com".into()];

let report = Policy::modern().grade(Some(&ident), Some(&offer));
assert_eq!(report.grade, Grade::C);
assert!(report.terrapin_vulnerable());
for a in &report.algorithms {
    if a.level != Level::Info {
        println!("{} {} {}: {}", a.level, a.category, a.algorithm, a.reason);
    }
}
for cve in &report.vulnerabilities {
    println!("maybe {} ({})", cve.id, cve.summary);
}
let findings = report.findings(&Location::network("legacy.example", 22));
assert!(findings.iter().any(|f| f.check_id == "ssh.terrapin"));
```

### Parsing captured traffic

```rust
use rune_probe_ssh::{HostKey, Identification, audit};

let id = Identification::parse(b"SSH-2.0-OpenSSH_7.4\r\n").unwrap();
assert_eq!(id.product(), ("OpenSSH".to_owned(), Some("7.4".to_owned())));

let blob = rune_base64::decode(
    "AAAAC3NzaC1lZDI1NTE5AAAAIOJv+0BnO5Sq9IS18Q8eLfxJL3GuLtonL4clXHHkg4EX",
).unwrap();
let key = HostKey::parse(&blob).unwrap();
assert_eq!(key.fingerprint_sha256(), "SHA256:sy6hgZYNW2YfQFZt6xYCu+D96SlMGrevKRhp8XYPN74");

assert!(audit::classify(audit::Category::Cipher, "3des-cbc").is_some());
```

## License

MIT
