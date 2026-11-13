//! Weak-algorithm classification and the Terrapin check for a server's
//! KEXINIT.
//!
//! This is the plain "what is broken" view: an algorithm is weak when it
//! fails the [`modern`](crate::policy::Profile::Modern) profile of the
//! [algorithm table](crate::algorithms). For per-algorithm levels, other
//! profiles, custom allow/deny lists and an overall grade, see
//! [`policy`](crate::policy).

use std::fmt;

use rune_service_probe::rune_finding::Severity;

use crate::KexInit;
use crate::algorithms::lookup;
use crate::policy::{Level, Profile};

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
    /// Compression method, either direction.
    Compression,
}

impl Category {
    /// Every category, in KEXINIT order.
    pub const ALL: [Self; 5] = [
        Self::Kex,
        Self::HostKey,
        Self::Cipher,
        Self::Mac,
        Self::Compression,
    ];

    /// The finding check id for algorithms of this category that fail a
    /// policy, e.g. `ssh.weak_kex`.
    #[must_use]
    pub const fn check_id(self) -> &'static str {
        match self {
            Self::Kex => "ssh.weak_kex",
            Self::HostKey => "ssh.weak_host_key_algorithm",
            Self::Cipher => "ssh.weak_cipher",
            Self::Mac => "ssh.weak_mac",
            Self::Compression => "ssh.weak_compression",
        }
    }

    /// The finding check id for algorithms a policy warns about, e.g.
    /// `ssh.discouraged_kex`.
    #[must_use]
    pub const fn warn_check_id(self) -> &'static str {
        match self {
            Self::Kex => "ssh.discouraged_kex",
            Self::HostKey => "ssh.discouraged_host_key_algorithm",
            Self::Cipher => "ssh.discouraged_cipher",
            Self::Mac => "ssh.discouraged_mac",
            Self::Compression => "ssh.discouraged_compression",
        }
    }

    /// A short lowercase label: `kex`, `host_key`, `cipher`, `mac` or
    /// `compression`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kex => "kex",
            Self::HostKey => "host_key",
            Self::Cipher => "cipher",
            Self::Mac => "mac",
            Self::Compression => "compression",
        }
    }

    /// A label for prose: `key-exchange`, `host-key`, `cipher`, `MAC` or
    /// `compression`.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Kex => "key-exchange",
            Self::HostKey => "host-key",
            Self::Cipher => "cipher",
            Self::Mac => "MAC",
            Self::Compression => "compression",
        }
    }

    /// The names `kexinit` offers in this category, in the server's order.
    /// Ciphers, MACs and compression merge both directions.
    ///
    /// ```
    /// use rune_probe_ssh::KexInit;
    /// use rune_probe_ssh::audit::Category;
    ///
    /// let mut offer = KexInit::default();
    /// offer.mac_client_to_server = vec!["hmac-sha2-256".into()];
    /// offer.mac_server_to_client = vec!["hmac-sha2-512".into()];
    /// assert_eq!(Category::Mac.offered(&offer), ["hmac-sha2-256", "hmac-sha2-512"]);
    /// ```
    #[must_use]
    pub fn offered(self, kexinit: &KexInit) -> Vec<&str> {
        match self {
            Self::Kex => kexinit.kex_algorithms.iter().map(String::as_str).collect(),
            Self::HostKey => kexinit
                .server_host_key_algorithms
                .iter()
                .map(String::as_str)
                .collect(),
            Self::Cipher => kexinit.ciphers(),
            Self::Mac => kexinit.macs(),
            Self::Compression => kexinit.compression(),
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

/// Classify one algorithm name. `None` means it does not fail the modern
/// profile (it may still draw a warning there; see
/// [`Policy::assess`](crate::policy::Policy::assess)).
///
/// | Category    | Weak                                                              |
/// | ----------- | ----------------------------------------------------------------- |
/// | KEX         | SHA-1 exchange hashes, 1024-bit groups, `rsa1024-sha1`, ECMQV     |
/// | Host key    | `ssh-rsa` (SHA-1 signatures), `ssh-dss`                           |
/// | Cipher      | `none`, RC4, DES/3DES and other 64-bit blocks, any CBC mode       |
/// | MAC         | `none`, MD5, SHA-1, RIPEMD-160, 96-bit truncated tags, `umac-64`  |
/// | Compression | nothing                                                           |
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
    lookup(category, name)
        .filter(|a| a.level(Profile::Modern) == Level::Fail)
        .map(|a| (a.severity, a.reason))
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
    let mut out = Vec::new();
    for category in Category::ALL {
        for name in category.offered(kexinit) {
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

/// What the Terrapin check
/// ([CVE-2023-48795](https://terrapin-attack.com/)) found in a KEXINIT.
///
/// The prefix-truncation attack works against
/// `chacha20-poly1305@openssh.com` and against CBC ciphers combined with
/// an encrypt-then-MAC MAC. Strict key exchange
/// (`kex-strict-s-v00@openssh.com`, OpenSSH 9.6) shuts it out.
///
/// ```
/// use rune_probe_ssh::KexInit;
/// use rune_probe_ssh::audit::Terrapin;
///
/// let mut offer = KexInit::default();
/// offer.encryption_server_to_client = vec!["aes256-cbc".into()];
/// offer.mac_server_to_client = vec!["hmac-sha2-256-etm@openssh.com".into()];
/// let t = Terrapin::assess(&offer);
/// assert!(t.cbc_etm && !t.chacha20 && t.vulnerable());
///
/// offer.kex_algorithms.push("kex-strict-s-v00@openssh.com".into());
/// assert!(!Terrapin::assess(&offer).vulnerable());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub struct Terrapin {
    /// `chacha20-poly1305@openssh.com` is offered.
    pub chacha20: bool,
    /// A CBC cipher and an `-etm` MAC are both offered.
    pub cbc_etm: bool,
    /// The server advertises strict key exchange.
    pub strict_kex: bool,
}

impl Terrapin {
    /// Check `kexinit`.
    #[must_use]
    pub fn assess(kexinit: &KexInit) -> Self {
        let ciphers = kexinit.ciphers();
        let cbc = ciphers.iter().any(|c| c.contains("-cbc"));
        let etm = kexinit
            .macs()
            .iter()
            .any(|m| m.ends_with("-etm@openssh.com"));
        Self {
            chacha20: ciphers.contains(&"chacha20-poly1305@openssh.com"),
            cbc_etm: cbc && etm,
            strict_kex: kexinit.strict_kex(),
        }
    }

    /// True when an affected mode is offered and strict key exchange is not.
    #[must_use]
    pub const fn vulnerable(&self) -> bool {
        (self.chacha20 || self.cbc_etm) && !self.strict_kex
    }
}

/// True when the offer is exposed to the Terrapin prefix-truncation attack;
/// shorthand for `Terrapin::assess(kexinit).vulnerable()`; see [`Terrapin`].
#[must_use]
pub fn terrapin_exposed(kexinit: &KexInit) -> bool {
    Terrapin::assess(kexinit).vulnerable()
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
            (
                Category::Kex,
                "vendor-group-sha1@example.com",
                Severity::Low,
            ),
            (Category::HostKey, "ssh-dss", Severity::Medium),
            (
                Category::HostKey,
                "ssh-rsa-cert-v01@openssh.com",
                Severity::Low,
            ),
            (Category::Cipher, "none", Severity::High),
            (Category::Cipher, "des-cbc", Severity::High),
            (Category::Cipher, "arcfour256", Severity::Medium),
            (Category::Cipher, "3des-cbc", Severity::Medium),
            (Category::Cipher, "blowfish-cbc", Severity::Medium),
            (Category::Cipher, "twofish256-cbc", Severity::Low),
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
            (Category::Mac, "hmac-ripemd160@openssh.com", Severity::Low),
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
            (Category::Compression, "zlib"),
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
