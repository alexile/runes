# rune-probe-ssh

> Read-only SSH probe: identification string, KEXINIT algorithm audit and host-key fingerprint

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
   ([§7.1](https://www.rfc-editor.org/rfc/rfc4253#section-7.1)) and audits the
   offered key-exchange, host-key, cipher and MAC algorithms;
3. starts a key exchange (curve25519 or a fixed Diffie-Hellman group) only far
   enough to read the server's public host key, like `ssh-keyscan`, and
   reports its type, size and OpenSSH `SHA256:` fingerprint.

It is read-only: it never derives keys, sends `NEWKEYS` or attempts
authentication, and closes the connection after the key-exchange reply.

| Check id                      | When                                                 |
| ----------------------------- | ---------------------------------------------------- |
| `ssh.protocol_v1`             | SSH-1 offered (`SSH-1.x`, `SSH-1.99`)                |
| `ssh.weak_kex`                | SHA-1 or 1024-bit key exchange                       |
| `ssh.weak_host_key_algorithm` | `ssh-rsa` (SHA-1) or `ssh-dss` signatures            |
| `ssh.weak_cipher`             | CBC, RC4, DES/3DES and other 64-bit blocks, `none`   |
| `ssh.weak_mac`                | MD5, SHA-1, 96-bit truncated, `umac-64`, `none`      |
| `ssh.terrapin`                | CVE-2023-48795 exposure (no strict key exchange)     |
| `ssh.weak_host_key`           | DSA host key, or RSA shorter than 2048 bits          |

The sans-I/O building blocks are public: `Identification`, `parse_packet` /
`encode_packet`, `KexInit`, `HostKey` and `audit::{classify, audit,
terrapin_exposed}`.

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
