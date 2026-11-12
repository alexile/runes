//! Weak-algorithm classification for a server's KEXINIT.

use std::fmt;

use rune_service_probe::rune_finding::Severity;

use crate::KexInit;

/// Which KEXINIT list an algorithm comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Category {
    /// Key-exchange method.
    Kex,
    /// Host-key (signature) algorithm.
    HostKey,
    /// Cipher, either direction.
    Cipher,
    /// MAC, either direction.
    Mac,
}

impl Category {
    /// Every category, in KEXINIT order.
    pub const ALL: [Self; 4] = [Self::Kex, Self::HostKey, Self::Cipher, Self::Mac];

    /// The finding check id for weak algorithms of this category, e.g.
    /// `ssh.weak_kex`.
    #[must_use]
    pub const fn check_id(self) -> &'static str {
        match self {
            Self::Kex => "ssh.weak_kex",
            Self::HostKey => "ssh.weak_host_key_algorithm",
            Self::Cipher => "ssh.weak_cipher",
            Self::Mac => "ssh.weak_mac",
        }
    }

    /// A short lowercase label: `kex`, `host_key`, `cipher` or `mac`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kex => "kex",
            Self::HostKey => "host_key",
            Self::Cipher => "cipher",
            Self::Mac => "mac",
        }
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One weak algorithm a server offers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Weakness {
    /// The list it was offered in.
    pub category: Category,
    /// The algorithm name, as the server sent it.
    pub algorithm: String,
    /// How much offering it matters.
    pub severity: Severity,
    /// Why it is weak.
    pub reason: &'static str,
}

/// Classify one algorithm name. `None` means it is not known to be weak.
///
/// The policy follows RFC 9142 (key exchange), RFC 8332 (`ssh-rsa`
/// signatures), RFC 8758 (RC4) and current OpenSSH defaults:
///
/// | Category | Flagged                                                                 |
/// | -------- | ----------------------------------------------------------------------- |
/// | KEX      | SHA-1 exchange hashes; 1024-bit groups (`diffie-hellman-group1-sha1`)   |
/// | Host key | `ssh-rsa` (SHA-1 signatures), `ssh-dss`                                 |
/// | Cipher   | `none`, RC4, DES/3DES and other 64-bit blocks, any CBC mode             |
/// | MAC      | `none`, MD5, SHA-1, 96-bit truncated tags, `umac-64`                    |
///
/// ```
/// use rune_probe_ssh::audit::{Category, classify};
/// use rune_service_probe::rune_finding::Severity;
///
/// assert_eq!(classify(Category::Cipher, "aes128-cbc").map(|w| w.0), Some(Severity::Low));
/// assert_eq!(classify(Category::Kex, "diffie-hellman-group1-sha1").map(|w| w.0), Some(Severity::Medium));
/// assert_eq!(classify(Category::Kex, "curve25519-sha256"), None);
/// ```
#[must_use]
pub fn classify(category: Category, name: &str) -> Option<(Severity, &'static str)> {
    match category {
        Category::Kex => classify_kex(name),
        Category::HostKey => classify_host_key(name),
        Category::Cipher => classify_cipher(name),
        Category::Mac => classify_mac(name),
    }
}

fn classify_kex(name: &str) -> Option<(Severity, &'static str)> {
    if name == "diffie-hellman-group1-sha1" || name.starts_with("gss-group1-sha1-") {
        Some((Severity::Medium, "1024-bit Diffie-Hellman group with SHA-1"))
    } else if name == "rsa1024-sha1" {
        Some((Severity::Medium, "1024-bit RSA key exchange with SHA-1"))
    } else if name.ends_with("-sha1") || name.contains("-sha1-") {
        Some((Severity::Low, "SHA-1 exchange hash"))
    } else {
        None
    }
}

fn classify_host_key(name: &str) -> Option<(Severity, &'static str)> {
    let base = name.strip_prefix("x509v3-").unwrap_or(name);
    let base = base.strip_suffix("-cert-v01@openssh.com").unwrap_or(base);
    match base {
        "ssh-dss" => Some((Severity::Medium, "DSA: 1024-bit keys and SHA-1 signatures")),
        "ssh-rsa" => Some((Severity::Low, "RSA signatures with SHA-1")),
        _ => None,
    }
}

fn classify_cipher(name: &str) -> Option<(Severity, &'static str)> {
    if name == "none" {
        Some((Severity::High, "no encryption"))
    } else if name.starts_with("arcfour") {
        Some((Severity::Medium, "RC4 stream cipher"))
    } else if name == "des" || name.starts_with("des-") {
        Some((Severity::Medium, "56-bit DES"))
    } else if ["3des", "blowfish", "cast128", "idea"]
        .iter()
        .any(|p| name.starts_with(p))
    {
        Some((Severity::Medium, "64-bit block cipher (Sweet32)"))
    } else if name.contains("-cbc") {
        Some((Severity::Low, "CBC mode (plaintext recovery attacks)"))
    } else {
        None
    }
}

fn classify_mac(name: &str) -> Option<(Severity, &'static str)> {
    if name == "none" {
        Some((Severity::High, "no integrity protection"))
    } else if name.starts_with("hmac-md5") {
        Some((Severity::Medium, "MD5-based MAC"))
    } else if name.ends_with("-96") || name.contains("-96-") {
        Some((Severity::Low, "truncated 96-bit MAC"))
    } else if name.starts_with("umac-64") {
        Some((Severity::Low, "64-bit MAC tag"))
    } else if name.starts_with("hmac-sha1") {
        Some((Severity::Low, "SHA-1-based MAC"))
    } else {
        None
    }
}

/// Every weak algorithm in `kexinit`, by category and then in the server's
/// order, each name once.
///
/// ```
/// use rune_probe_ssh::KexInit;
/// use rune_probe_ssh::audit::{Category, audit};
///
/// let mut offer = KexInit::default();
/// offer.server_host_key_algorithms = vec!["rsa-sha2-512".into(), "ssh-rsa".into()];
/// offer.encryption_client_to_server = vec!["aes256-ctr".into(), "3des-cbc".into()];
/// offer.encryption_server_to_client = offer.encryption_client_to_server.clone();
/// let weak = audit(&offer);
/// assert_eq!(weak.len(), 2);
/// assert_eq!((weak[0].category, weak[0].algorithm.as_str()), (Category::HostKey, "ssh-rsa"));
/// assert_eq!((weak[1].category, weak[1].algorithm.as_str()), (Category::Cipher, "3des-cbc"));
/// ```
#[must_use]
pub fn audit(kexinit: &KexInit) -> Vec<Weakness> {
    let lists: [(Category, Vec<&str>); 4] = [
        (
            Category::Kex,
            kexinit.kex_algorithms.iter().map(String::as_str).collect(),
        ),
        (
            Category::HostKey,
            kexinit
                .server_host_key_algorithms
                .iter()
                .map(String::as_str)
                .collect(),
        ),
        (Category::Cipher, kexinit.ciphers()),
        (Category::Mac, kexinit.macs()),
    ];
    let mut out = Vec::new();
    for (category, names) in lists {
        for name in names {
            if let Some((severity, reason)) = classify(category, name) {
                out.push(Weakness {
                    category,
                    algorithm: name.to_owned(),
                    severity,
                    reason,
                });
            }
        }
    }
    out
}

/// True when the offer is exposed to the Terrapin prefix-truncation attack.
///
/// That is [CVE-2023-48795](https://terrapin-attack.com/): the server offers
/// `chacha20-poly1305@openssh.com`, or a CBC cipher together with an
/// encrypt-then-MAC MAC, and does not signal strict key exchange.
#[must_use]
pub fn terrapin_exposed(kexinit: &KexInit) -> bool {
    if kexinit.strict_kex() {
        return false;
    }
    let ciphers = kexinit.ciphers();
    let chacha = ciphers.contains(&"chacha20-poly1305@openssh.com");
    let cbc = ciphers.iter().any(|c| c.contains("-cbc"));
    let etm = kexinit
        .macs()
        .iter()
        .any(|m| m.ends_with("-etm@openssh.com"));
    chacha || (cbc && etm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_names() {
        let weak = [
            (Category::Kex, "diffie-hellman-group14-sha1", Severity::Low),
            (
                Category::Kex,
                "diffie-hellman-group-exchange-sha1",
                Severity::Low,
            ),
            (
                Category::Kex,
                "gss-gex-sha1-toWM5Slw5Ew8Mqkay+al2g==",
                Severity::Low,
            ),
            (
                Category::Kex,
                "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==",
                Severity::Medium,
            ),
            (Category::HostKey, "ssh-dss", Severity::Medium),
            (
                Category::HostKey,
                "ssh-rsa-cert-v01@openssh.com",
                Severity::Low,
            ),
            (Category::Cipher, "none", Severity::High),
            (Category::Cipher, "arcfour256", Severity::Medium),
            (Category::Cipher, "3des-cbc", Severity::Medium),
            (Category::Cipher, "blowfish-cbc", Severity::Medium),
            (
                Category::Cipher,
                "rijndael-cbc@lysator.liu.se",
                Severity::Low,
            ),
            (
                Category::Mac,
                "hmac-md5-96-etm@openssh.com",
                Severity::Medium,
            ),
            (Category::Mac, "hmac-sha1-96", Severity::Low),
            (Category::Mac, "hmac-sha1-etm@openssh.com", Severity::Low),
            (Category::Mac, "umac-64@openssh.com", Severity::Low),
        ];
        for (category, name, severity) in weak {
            assert_eq!(
                classify(category, name).map(|w| w.0),
                Some(severity),
                "{name}"
            );
        }
        let strong = [
            (Category::Kex, "curve25519-sha256"),
            (Category::Kex, "sntrup761x25519-sha512@openssh.com"),
            (Category::Kex, "mlkem768x25519-sha256"),
            (Category::Kex, "diffie-hellman-group14-sha256"),
            (Category::Kex, "ext-info-s"),
            (Category::HostKey, "rsa-sha2-512"),
            (Category::HostKey, "ssh-ed25519"),
            (Category::Cipher, "aes256-gcm@openssh.com"),
            (Category::Cipher, "aes128-ctr"),
            (Category::Cipher, "chacha20-poly1305@openssh.com"),
            (Category::Mac, "hmac-sha2-256-etm@openssh.com"),
            (Category::Mac, "umac-128@openssh.com"),
        ];
        for (category, name) in strong {
            assert_eq!(classify(category, name), None, "{name}");
        }
    }

    #[test]
    fn terrapin() {
        let mut k = KexInit {
            encryption_server_to_client: vec!["chacha20-poly1305@openssh.com".into()],
            ..KexInit::default()
        };
        assert!(terrapin_exposed(&k));
        k.kex_algorithms = vec!["kex-strict-s-v00@openssh.com".into()];
        assert!(!terrapin_exposed(&k));

        let mut k = KexInit {
            encryption_client_to_server: vec!["aes128-cbc".into()],
            ..KexInit::default()
        };
        assert!(!terrapin_exposed(&k));
        k.mac_server_to_client = vec!["hmac-sha2-256-etm@openssh.com".into()];
        assert!(terrapin_exposed(&k));
    }
}
