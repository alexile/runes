//! The algorithm table behind [`policy`](crate::policy) and
//! [`audit`](crate::audit).
//!
//! Every entry gives an algorithm's level under the two built-in
//! [`Profile`]s, the severity to report when it fails, a short reason and
//! the public source the judgement rests on. The sources are:
//!
//! - [RFC 9142](https://www.rfc-editor.org/rfc/rfc9142#section-4), the
//!   MUST / SHOULD / MAY / SHOULD NOT / MUST NOT list for key exchange.
//! - [RFC 8332](https://www.rfc-editor.org/rfc/rfc8332) (`rsa-sha2-*`
//!   signatures) and [RFC 8709](https://www.rfc-editor.org/rfc/rfc8709)
//!   (Ed25519 / Ed448).
//! - RFC 4253, 4344, 4419, 4432, 5647, 5656, 6187, 6668, 8268, 8308, 8731,
//!   8732 and 8758 for the algorithms they define or deprecate. The IANA
//!   "Secure Shell (SSH) Protocol Parameters" registries hold the names
//!   (their registration rules were updated by RFC 9519).
//! - NIST SP 800-131A Rev. 2 (SHA-1 signatures disallowed, Triple DES
//!   disallowed for encryption after 2023) and SP 800-57 Part 1 Rev. 5
//!   (2048-bit finite-field groups give about 112 bits of security).
//! - OpenSSH release notes, for what upstream turned off and when: 6.7 (CBC
//!   and RC4 out of the server defaults), 7.0 (`ssh-dss`,
//!   `diffie-hellman-group1-sha1`), 7.4 (pre-authentication compression),
//!   7.6 (RIPEMD-160), 8.8 (`ssh-rsa`), 9.0 (`sntrup761x25519`), 9.6 (strict
//!   key exchange), 9.9 / 10.0 (`mlkem768x25519-sha256`).
//!
//! `modern` follows current OpenSSH defaults with the SHA-1, 64-bit-tag and
//! encrypt-and-MAC leftovers removed. `compatible` only fails what is
//! actually broken or prohibited, and warns about the rest.

use rune_service_probe::rune_finding::Severity;

use crate::audit::Category;
use crate::policy::{Level, Profile};

/// One row of the algorithm table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Algorithm {
    /// The list the name belongs to.
    pub category: Category,
    /// The algorithm name. A leading or trailing `*` makes it a suffix,
    /// prefix or (both) substring pattern; see [`glob_match`].
    pub name: &'static str,
    /// Level under [`Profile::Modern`].
    pub modern: Level,
    /// Level under [`Profile::Compatible`].
    pub compatible: Level,
    /// The severity reported when the algorithm fails a policy.
    pub severity: Severity,
    /// Why it gets that level, in a few words.
    pub reason: &'static str,
    /// Where the judgement comes from.
    pub source: &'static str,
}

impl Algorithm {
    /// The level under `profile`.
    ///
    /// ```
    /// use rune_probe_ssh::algorithms::lookup;
    /// use rune_probe_ssh::audit::Category;
    /// use rune_probe_ssh::policy::{Level, Profile};
    ///
    /// let rsa = lookup(Category::HostKey, "ssh-rsa").unwrap();
    /// assert_eq!(rsa.level(Profile::Modern), Level::Fail);
    /// assert_eq!(rsa.level(Profile::Compatible), Level::Warn);
    /// ```
    #[must_use]
    pub const fn level(&self, profile: Profile) -> Level {
        match profile {
            Profile::Modern => self.modern,
            Profile::Compatible => self.compatible,
        }
    }
}

const I: Level = Level::Info;
const W: Level = Level::Warn;
const F: Level = Level::Fail;

const INFO: Severity = Severity::Informational;
const LOW: Severity = Severity::Low;
const MEDIUM: Severity = Severity::Medium;
const HIGH: Severity = Severity::High;

#[allow(clippy::too_many_arguments, reason = "one table row")]
const fn row(
    category: Category,
    name: &'static str,
    modern: Level,
    compatible: Level,
    severity: Severity,
    reason: &'static str,
    source: &'static str,
) -> Algorithm {
    Algorithm {
        category,
        name,
        modern,
        compatible,
        severity,
        reason,
        source,
    }
}

use Category::{Cipher, Compression, HostKey, Kex, Mac};

const RFC9142: &str = "RFC 9142 §4";
const SHA1_KEX: &str = "SHA-1 exchange hash";
const NIST_CURVE_KEX: &str =
    "NIST P-curve ECDH; RFC 9142 lists it as SHOULD, but X25519 is simpler to implement safely";
const NIST_CURVE_SIG: &str =
    "ECDSA over a NIST P-curve; Ed25519 is deterministic and simpler to implement safely";
const SWEET32: &str = "64-bit block cipher (Sweet32, CVE-2016-2183)";
const CBC: &str =
    "CBC mode: plaintext recovery (CVE-2008-5161); off in sshd's defaults since OpenSSH 6.7";
const EAM: &str = "encrypt-and-MAC; prefer the -etm@openssh.com variant";
const ETM: &str = "encrypt-then-MAC with a strong hash";

/// The table. [`lookup`] tries exact names before patterns, and patterns
/// in table order.
#[rustfmt::skip]
pub const ALGORITHMS: &[Algorithm] = &[
    // Key exchange. Levels in the reasons are RFC 9142's.
    row(Kex, "mlkem768x25519-sha256", I, I, INFO,
        "post-quantum hybrid (ML-KEM-768 + X25519); sshd's default since OpenSSH 10.0",
        "draft-ietf-sshm-mlkem-hybrid-kex; OpenSSH 9.9 and 10.0 release notes"),
    row(Kex, "mlkem768nistp256-sha256", I, I, INFO, "post-quantum hybrid (ML-KEM-768 + P-256)",
        "draft-ietf-sshm-mlkem-hybrid-kex"),
    row(Kex, "mlkem1024nistp384-sha384", I, I, INFO, "post-quantum hybrid (ML-KEM-1024 + P-384)",
        "draft-ietf-sshm-mlkem-hybrid-kex"),
    row(Kex, "sntrup761x25519-sha512@openssh.com", I, I, INFO,
        "post-quantum hybrid (Streamlined NTRU Prime + X25519); default since OpenSSH 9.0",
        "OpenSSH 9.0 release notes"),
    row(Kex, "sntrup761x25519-sha512", I, I, INFO,
        "post-quantum hybrid (Streamlined NTRU Prime + X25519)",
        "draft-ietf-sshm-ntruprime-ssh; OpenSSH 9.9 release notes"),
    row(Kex, "curve25519-sha256", I, I, INFO, "X25519; SHOULD", "RFC 8731; RFC 9142 §4"),
    row(Kex, "curve25519-sha256@libssh.org", I, I, INFO,
        "pre-standard name of curve25519-sha256", "RFC 8731 §3"),
    row(Kex, "curve448-sha512", I, I, INFO, "X448; MAY", "RFC 8731; RFC 9142 §4"),
    row(Kex, "ecdh-sha2-nistp256", W, I, LOW, NIST_CURVE_KEX, "RFC 5656; RFC 9142 §4"),
    row(Kex, "ecdh-sha2-nistp384", W, I, LOW, NIST_CURVE_KEX, "RFC 5656; RFC 9142 §4"),
    row(Kex, "ecdh-sha2-nistp521", W, I, LOW, NIST_CURVE_KEX, "RFC 5656; RFC 9142 §4"),
    row(Kex, "diffie-hellman-group14-sha256", W, I, LOW,
        "2048-bit MODP group, about 112-bit security; MUST",
        "RFC 8268; RFC 9142 §4; NIST SP 800-57 Pt 1 Rev 5"),
    row(Kex, "diffie-hellman-group15-sha512", I, I, INFO, "3072-bit MODP group; MAY",
        "RFC 8268; RFC 9142 §4"),
    row(Kex, "diffie-hellman-group16-sha512", I, I, INFO, "4096-bit MODP group; SHOULD",
        "RFC 8268; RFC 9142 §4"),
    row(Kex, "diffie-hellman-group17-sha512", I, I, INFO, "6144-bit MODP group; MAY",
        "RFC 8268; RFC 9142 §4"),
    row(Kex, "diffie-hellman-group18-sha512", I, I, INFO, "8192-bit MODP group; MAY",
        "RFC 8268; RFC 9142 §4"),
    row(Kex, "diffie-hellman-group-exchange-sha256", W, I, LOW,
        "the server picks the group, so its size is not visible in KEXINIT; MAY",
        "RFC 4419; RFC 9142 §4"),
    row(Kex, "diffie-hellman-group14-sha1", F, W, LOW,
        "SHA-1 exchange hash; RFC 9142 lowers it from MUST to MAY", RFC9142),
    row(Kex, "diffie-hellman-group-exchange-sha1", F, W, LOW,
        "SHA-1 exchange hash; SHOULD NOT", "RFC 4419; RFC 9142 §4"),
    row(Kex, "diffie-hellman-group1-sha1", F, F, MEDIUM,
        "1024-bit MODP group with SHA-1; SHOULD NOT, off by default since OpenSSH 7.0",
        "RFC 9142 §4; OpenSSH 7.0 release notes"),
    row(Kex, "rsa1024-sha1", F, F, MEDIUM, "1024-bit RSA key exchange with SHA-1; MUST NOT",
        "RFC 4432; RFC 9142 §4"),
    row(Kex, "rsa2048-sha256", W, I, LOW, "RSA key transport; MAY, and rarely implemented",
        "RFC 4432; RFC 9142 §4"),
    row(Kex, "ecmqv-sha2", F, F, LOW, "ECMQV; SHOULD NOT", "RFC 5656; RFC 9142 §4"),
    // Extension signals ride in the kex list but are not key exchanges.
    row(Kex, "ext-info-s", I, I, INFO, "extension negotiation signal", "RFC 8308 §2.1"),
    row(Kex, "ext-info-c", I, I, INFO, "extension negotiation signal", "RFC 8308 §2.1"),
    row(Kex, "kex-strict-s-v00@openssh.com", I, I, INFO,
        "strict key exchange signal (Terrapin countermeasure)", "OpenSSH 9.6 release notes"),
    row(Kex, "kex-strict-c-v00@openssh.com", I, I, INFO,
        "strict key exchange signal (Terrapin countermeasure)", "OpenSSH 9.6 release notes"),
    row(Kex, "kexguess2@matt.ucc.asn.au", I, I, INFO, "Dropbear key-exchange guess signal",
        "Dropbear source"),
    // GSS-API key exchange (RFC 8732); the suffix is a mechanism hash.
    row(Kex, "gss-group1-sha1-*", F, F, MEDIUM, "GSS-API with a 1024-bit group and SHA-1",
        "RFC 8732; RFC 9142 §4"),
    row(Kex, "gss-gex-sha1-*", F, W, LOW, "GSS-API with SHA-1", "RFC 8732; RFC 9142 §4"),
    row(Kex, "gss-group14-sha1-*", F, W, LOW, "GSS-API with SHA-1", "RFC 8732; RFC 9142 §4"),
    row(Kex, "gss-group14-sha256-*", W, I, LOW, "GSS-API with a 2048-bit group",
        "RFC 8732; RFC 9142 §4"),
    row(Kex, "gss-group16-sha512-*", I, I, INFO, "GSS-API with a 4096-bit group", "RFC 8732"),
    row(Kex, "gss-curve25519-sha256-*", I, I, INFO, "GSS-API with X25519", "RFC 8732"),
    row(Kex, "gss-nistp256-sha256-*", W, I, LOW, "GSS-API with a NIST P-curve", "RFC 8732"),
    row(Kex, "*-sha1", F, W, LOW, SHA1_KEX, RFC9142),
    row(Kex, "*-sha1@*", F, W, LOW, SHA1_KEX, RFC9142),
    // Host-key (signature) algorithms. Certificate and X.509 variants are
    // looked up by their base name.
    row(HostKey, "ssh-ed25519", I, I, INFO, "Ed25519 signatures", "RFC 8709"),
    row(HostKey, "ssh-ed448", I, I, INFO, "Ed448 signatures", "RFC 8709"),
    row(HostKey, "sk-ssh-ed25519@openssh.com", I, I, INFO, "Ed25519 on a FIDO security key",
        "OpenSSH 8.2 release notes"),
    row(HostKey, "rsa-sha2-256", I, I, INFO,
        "RSA with SHA-256; the key length is only visible in the host key", "RFC 8332"),
    row(HostKey, "rsa-sha2-512", I, I, INFO,
        "RSA with SHA-512; the key length is only visible in the host key", "RFC 8332"),
    row(HostKey, "ecdsa-sha2-nistp256", W, I, LOW, NIST_CURVE_SIG, "RFC 5656"),
    row(HostKey, "ecdsa-sha2-nistp384", W, I, LOW, NIST_CURVE_SIG, "RFC 5656"),
    row(HostKey, "ecdsa-sha2-nistp521", W, I, LOW, NIST_CURVE_SIG, "RFC 5656"),
    row(HostKey, "sk-ecdsa-sha2-nistp256@openssh.com", W, I, LOW, NIST_CURVE_SIG,
        "OpenSSH 8.2 release notes"),
    row(HostKey, "ssh-rsa", F, W, LOW,
        "RSA with SHA-1 signatures; off by default since OpenSSH 8.8",
        "RFC 8332; OpenSSH 8.8 release notes; NIST SP 800-131A Rev 2"),
    row(HostKey, "ssh-dss", F, F, MEDIUM,
        "DSA: 1024-bit keys and SHA-1; off by default since OpenSSH 7.0",
        "RFC 4253; OpenSSH 7.0 release notes; FIPS 186-5"),
    row(HostKey, "x509v3-sign-rsa", F, W, LOW, "X.509 RSA with SHA-1 signatures", "RFC 6187"),
    row(HostKey, "x509v3-sign-dss", F, F, MEDIUM, "X.509 DSA with SHA-1 signatures", "RFC 6187"),
    // Ciphers.
    row(Cipher, "chacha20-poly1305@openssh.com", I, I, INFO,
        "ChaCha20-Poly1305 AEAD (see the Terrapin check)", "OpenSSH 6.5 release notes"),
    row(Cipher, "aes128-gcm@openssh.com", I, I, INFO, "AES-GCM AEAD", "RFC 5647; OpenSSH 6.2 release notes"),
    row(Cipher, "aes256-gcm@openssh.com", I, I, INFO, "AES-GCM AEAD", "RFC 5647; OpenSSH 6.2 release notes"),
    row(Cipher, "AEAD_AES_128_GCM", I, I, INFO, "AES-GCM AEAD", "RFC 5647"),
    row(Cipher, "AEAD_AES_256_GCM", I, I, INFO, "AES-GCM AEAD", "RFC 5647"),
    row(Cipher, "aes128-ctr", I, I, INFO, "AES in counter mode", "RFC 4344"),
    row(Cipher, "aes192-ctr", I, I, INFO, "AES in counter mode", "RFC 4344"),
    row(Cipher, "aes256-ctr", I, I, INFO, "AES in counter mode", "RFC 4344"),
    row(Cipher, "none", F, F, HIGH, "no encryption", "RFC 4253 §6.3"),
    row(Cipher, "des", F, F, HIGH, "56-bit DES", "RFC 4253 §6.3; NIST SP 800-131A Rev 2"),
    row(Cipher, "des-cbc", F, F, HIGH, "56-bit DES", "RFC 4253 §6.3; NIST SP 800-131A Rev 2"),
    row(Cipher, "des-cbc@ssh.com", F, F, HIGH, "56-bit DES", "NIST SP 800-131A Rev 2"),
    row(Cipher, "3des-cbc", F, F, MEDIUM,
        "Triple DES: 64-bit block (Sweet32), disallowed for encryption after 2023",
        "NIST SP 800-131A Rev 2; RFC 4253 §6.3"),
    row(Cipher, "3des-ctr", F, F, MEDIUM,
        "Triple DES: 64-bit block (Sweet32), disallowed for encryption after 2023",
        "NIST SP 800-131A Rev 2; RFC 4344"),
    row(Cipher, "arcfour", F, F, MEDIUM, "RC4 stream cipher", "RFC 8758"),
    row(Cipher, "arcfour128", F, F, MEDIUM, "RC4 stream cipher", "RFC 8758"),
    row(Cipher, "arcfour256", F, F, MEDIUM, "RC4 stream cipher", "RFC 8758"),
    row(Cipher, "rijndael-cbc@lysator.liu.se", F, W, LOW, "old name of aes256-cbc; CBC mode",
        "OpenSSH 6.7 release notes"),
    row(Cipher, "blowfish-*", F, F, MEDIUM, SWEET32, "RFC 4253 §6.3; RFC 4344"),
    row(Cipher, "cast128-*", F, F, MEDIUM, SWEET32, "RFC 4253 §6.3; RFC 4344"),
    row(Cipher, "idea-*", F, F, MEDIUM, SWEET32, "RFC 4253 §6.3; RFC 4344"),
    row(Cipher, "*-cbc", F, W, LOW, CBC, "OpenSSH 6.7 release notes"),
    row(Cipher, "*-cbc@*", F, W, LOW, CBC, "OpenSSH 6.7 release notes"),
    // MACs.
    row(Mac, "hmac-sha2-256-etm@openssh.com", I, I, INFO, ETM, "RFC 6668; OpenSSH 6.2 release notes"),
    row(Mac, "hmac-sha2-512-etm@openssh.com", I, I, INFO, ETM, "RFC 6668; OpenSSH 6.2 release notes"),
    row(Mac, "umac-128-etm@openssh.com", I, I, INFO, "encrypt-then-MAC, 128-bit UMAC tag",
        "RFC 4418; OpenSSH 6.2 release notes"),
    row(Mac, "AEAD_AES_128_GCM", I, I, INFO, "AES-GCM AEAD", "RFC 5647"),
    row(Mac, "AEAD_AES_256_GCM", I, I, INFO, "AES-GCM AEAD", "RFC 5647"),
    row(Mac, "hmac-sha2-256", W, I, LOW, EAM, "RFC 6668"),
    row(Mac, "hmac-sha2-512", W, I, LOW, EAM, "RFC 6668"),
    row(Mac, "umac-128@openssh.com", W, I, LOW, EAM, "RFC 4418"),
    row(Mac, "none", F, F, HIGH, "no integrity protection", "RFC 4253 §6.4"),
    row(Mac, "hmac-sha1", F, W, LOW, "HMAC-SHA1, encrypt-and-MAC; legacy, outside current defaults",
        "RFC 4253 §6.4"),
    row(Mac, "hmac-sha1-etm@openssh.com", F, W, LOW, "HMAC-SHA1; legacy, outside current defaults",
        "RFC 4253 §6.4"),
    row(Mac, "umac-64@openssh.com", F, W, LOW, "64-bit UMAC tag", "RFC 4418"),
    row(Mac, "umac-64-etm@openssh.com", F, W, LOW, "64-bit UMAC tag", "RFC 4418"),
    row(Mac, "hmac-md5*", F, F, MEDIUM, "MD5-based MAC", "RFC 6151; RFC 4253 §6.4"),
    row(Mac, "hmac-ripemd160*", F, W, LOW, "RIPEMD-160; removed in OpenSSH 7.6",
        "OpenSSH 7.6 release notes"),
    row(Mac, "*-96", F, W, LOW, "96-bit truncated tag", "RFC 4253 §6.4"),
    row(Mac, "*-96-*", F, W, LOW, "96-bit truncated tag", "RFC 4253 §6.4"),
    row(Mac, "*-96@*", F, W, LOW, "96-bit truncated tag", "RFC 4253 §6.4"),
    // Compression.
    row(Compression, "none", I, I, INFO, "no compression", "RFC 4253 §6.2"),
    row(Compression, "zlib@openssh.com", I, I, INFO, "compression starts after authentication",
        "OpenSSH 4.2 release notes"),
    row(Compression, "zlib", W, I, LOW,
        "compression before authentication widens the pre-auth attack surface; sshd dropped it in OpenSSH 7.4",
        "RFC 4253 §6.2; OpenSSH 7.4 release notes"),
];

/// Match `name` against a pattern: `*x` is a suffix match, `x*` a prefix
/// match, `*x*` a substring match and anything else exact. A lone `*`
/// matches everything.
///
/// ```
/// use rune_probe_ssh::algorithms::glob_match;
///
/// assert!(glob_match("*-cbc", "aes128-cbc"));
/// assert!(glob_match("hmac-md5*", "hmac-md5-96"));
/// assert!(glob_match("*sha1*", "hmac-sha1-etm@openssh.com"));
/// assert!(!glob_match("aes128-ctr", "aes128-ctr2"));
/// ```
#[must_use]
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let (lead, rest) = pattern
        .strip_prefix('*')
        .map_or((false, pattern), |r| (true, r));
    let (trail, core) = rest.strip_suffix('*').map_or((false, rest), |c| (true, c));
    match (lead, trail) {
        (false, false) => name == core,
        (true, false) => name.ends_with(core),
        (false, true) => name.starts_with(core),
        (true, true) => name.contains(core),
    }
}

/// True for kex-list entries that signal an extension rather than name a
/// key exchange (`ext-info-s`, `kex-strict-s-v00@openssh.com`, ...).
///
/// ```
/// use rune_probe_ssh::algorithms::is_signal;
/// use rune_probe_ssh::audit::Category;
///
/// assert!(is_signal(Category::Kex, "kex-strict-s-v00@openssh.com"));
/// assert!(!is_signal(Category::Kex, "curve25519-sha256"));
/// ```
#[must_use]
pub fn is_signal(category: Category, name: &str) -> bool {
    category == Category::Kex
        && matches!(
            name,
            "ext-info-s"
                | "ext-info-c"
                | "kex-strict-s-v00@openssh.com"
                | "kex-strict-c-v00@openssh.com"
                | "kexguess2@matt.ucc.asn.au"
        )
}

/// The table entry for an algorithm, or `None` for names it does not know.
///
/// Host-key certificate names (`…-cert-v01@openssh.com`) and RFC 6187
/// `x509v3-…` names are looked up by their base algorithm. Exact entries
/// win over patterns.
///
/// ```
/// use rune_probe_ssh::algorithms::lookup;
/// use rune_probe_ssh::audit::Category;
///
/// assert_eq!(lookup(Category::Cipher, "aes192-cbc").unwrap().name, "*-cbc");
/// assert_eq!(lookup(Category::HostKey, "ssh-rsa-cert-v01@openssh.com").unwrap().name, "ssh-rsa");
/// assert!(lookup(Category::Cipher, "serpent256-ctr").is_none());
/// ```
#[must_use]
pub fn lookup(category: Category, name: &str) -> Option<&'static Algorithm> {
    if category == Category::HostKey {
        let base = name.strip_suffix("-cert-v01@openssh.com").unwrap_or(name);
        let base = if base.starts_with("x509v3-sign-") {
            base
        } else {
            base.strip_prefix("x509v3-").unwrap_or(base)
        };
        if let Some(hit) = lookup_exact(category, base) {
            return Some(hit);
        }
        if base != name {
            // sk-ssh-ed25519-cert-v01@openssh.com → sk-ssh-ed25519@openssh.com
            let vendor = format!("{base}@openssh.com");
            if let Some(hit) = lookup_exact(category, &vendor) {
                return Some(hit);
            }
        }
        return lookup_pattern(category, base);
    }
    lookup_exact(category, name).or_else(|| lookup_pattern(category, name))
}

fn lookup_exact(category: Category, name: &str) -> Option<&'static Algorithm> {
    ALGORITHMS
        .iter()
        .find(|a| a.category == category && !a.name.contains('*') && a.name == name)
}

fn lookup_pattern(category: Category, name: &str) -> Option<&'static Algorithm> {
    ALGORITHMS
        .iter()
        .find(|a| a.category == category && a.name.contains('*') && glob_match(a.name, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_names_are_unique_per_category() {
        for (i, a) in ALGORITHMS.iter().enumerate() {
            for b in &ALGORITHMS[i + 1..] {
                assert!(
                    !(a.category == b.category && a.name == b.name),
                    "{} listed twice",
                    a.name
                );
            }
        }
    }

    #[test]
    fn compatible_is_never_stricter_than_modern() {
        for a in ALGORITHMS {
            assert!(a.compatible <= a.modern, "{}", a.name);
            if a.modern == Level::Info {
                assert_eq!(a.severity, Severity::Informational, "{}", a.name);
            } else {
                assert!(a.severity >= Severity::Low, "{}", a.name);
            }
        }
    }

    #[test]
    fn patterns() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*-96-*", "hmac-sha1-96-etm@openssh.com"));
        assert_eq!(
            lookup(Category::Mac, "hmac-md5-96").map(|a| a.severity),
            Some(Severity::Medium)
        );
        assert_eq!(
            lookup(Category::Kex, "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==").map(|a| a.name),
            Some("gss-group1-sha1-*")
        );
        assert_eq!(
            lookup(Category::HostKey, "sk-ssh-ed25519-cert-v01@openssh.com").map(|a| a.name),
            Some("sk-ssh-ed25519@openssh.com")
        );
        assert_eq!(
            lookup(Category::HostKey, "x509v3-ssh-rsa").map(|a| a.name),
            Some("ssh-rsa")
        );
        assert_eq!(
            lookup(Category::HostKey, "x509v3-sign-rsa").map(|a| a.name),
            Some("x509v3-sign-rsa")
        );
        assert!(lookup(Category::Kex, "made-up").is_none());
    }
}
