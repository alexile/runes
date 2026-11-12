//! Cipher-suite names and weak-suite classification.

use std::fmt;

use rune_tls_hello::CipherSuite;

use crate::registry::SUITES;

/// A reason a cipher suite is weak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Weakness {
    /// Export-grade (`_EXPORT`, `_EXPORT1024`): 40- or 56-bit keys,
    /// FREAK and Logjam.
    Export,
    /// No encryption at all (`_WITH_NULL_`).
    NullCipher,
    /// Anonymous key exchange (`DH_anon`, `ECDH_anon`): no server
    /// authentication, trivially intercepted.
    Anonymous,
    /// RC4 ([RFC 7465](https://www.rfc-editor.org/rfc/rfc7465) prohibits it).
    Rc4,
    /// Single DES or RC2: 56-bit or weaker keys.
    Des,
    /// A 64-bit block cipher (3DES, IDEA): Sweet32 (CVE-2016-2183).
    Sweet32,
    /// MD5 as the record MAC.
    Md5,
    /// Static RSA, DH or ECDH key exchange: no forward secrecy.
    NoForwardSecrecy,
}

impl Weakness {
    /// A short lowercase label, used in finding check ids
    /// (`tls.cipher.<label>`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Export => "export",
            Self::NullCipher => "null",
            Self::Anonymous => "anon",
            Self::Rc4 => "rc4",
            Self::Des => "des",
            Self::Sweet32 => "sweet32",
            Self::Md5 => "md5",
            Self::NoForwardSecrecy => "no_forward_secrecy",
        }
    }
}

impl fmt::Display for Weakness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Export => "export-grade cipher",
            Self::NullCipher => "NULL cipher (no encryption)",
            Self::Anonymous => "anonymous key exchange",
            Self::Rc4 => "RC4",
            Self::Des => "DES or RC2",
            Self::Sweet32 => "64-bit block cipher (Sweet32)",
            Self::Md5 => "MD5 MAC",
            Self::NoForwardSecrecy => "no forward secrecy",
        })
    }
}

/// The IANA name of a cipher suite, e.g. `TLS_RSA_WITH_RC4_128_SHA`.
///
/// ```
/// use rune_tls_hello::CipherSuite;
///
/// assert_eq!(rune_tls_probe::suite_name(CipherSuite(0x0005)), Some("TLS_RSA_WITH_RC4_128_SHA"));
/// assert_eq!(rune_tls_probe::suite_name(CipherSuite(0x1301)), Some("TLS_AES_128_GCM_SHA256"));
/// assert_eq!(rune_tls_probe::suite_name(CipherSuite(0xabcd)), None);
/// ```
#[must_use]
pub fn suite_name(suite: CipherSuite) -> Option<&'static str> {
    SUITES
        .binary_search_by_key(&suite.0, |&(code, _)| code)
        .ok()
        .and_then(|i| SUITES.get(i))
        .map(|&(_, name)| name)
}

/// The suite's IANA name, or its hex code when it is not in the registry.
#[must_use]
pub fn suite_label(suite: CipherSuite) -> String {
    suite_name(suite).map_or_else(|| format!("0x{:04x}", suite.0), str::to_owned)
}

/// Every weakness of a suite, derived from its IANA name; empty for a
/// strong suite and for a suite not in the registry.
///
/// ```
/// use rune_tls_hello::CipherSuite;
/// use rune_tls_probe::{Weakness, weaknesses};
///
/// // TLS_RSA_EXPORT_WITH_RC4_40_MD5
/// assert_eq!(
///     weaknesses(CipherSuite(0x0003)),
///     [Weakness::Export, Weakness::Rc4, Weakness::Md5, Weakness::NoForwardSecrecy]
/// );
/// // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
/// assert!(weaknesses(CipherSuite(0xc02f)).is_empty());
/// ```
#[must_use]
pub fn weaknesses(suite: CipherSuite) -> Vec<Weakness> {
    suite_name(suite).map_or_else(Vec::new, classify)
}

/// Classifies an IANA suite name (`TLS_<kx>_WITH_<cipher>_<mac>`, or a
/// TLS 1.3 `TLS_<aead>_<hash>`).
fn classify(name: &str) -> Vec<Weakness> {
    let Some((kx, rest)) = name
        .strip_prefix("TLS_")
        .and_then(|body| body.split_once("_WITH_"))
    else {
        // TLS 1.3 suites: AEAD only, always ephemeral.
        return Vec::new();
    };
    let mut found = Vec::new();
    if kx.contains("EXPORT") {
        found.push(Weakness::Export);
    }
    if rest.starts_with("NULL_") {
        found.push(Weakness::NullCipher);
    }
    if kx.contains("anon") {
        found.push(Weakness::Anonymous);
    }
    if rest.starts_with("RC4_") {
        found.push(Weakness::Rc4);
    }
    if rest.starts_with("DES") || rest.starts_with("RC2_") {
        found.push(Weakness::Des);
    }
    if rest.starts_with("3DES_") || rest.starts_with("IDEA_") {
        found.push(Weakness::Sweet32);
    }
    if rest.ends_with("_MD5") {
        found.push(Weakness::Md5);
    }
    if !is_ephemeral(kx) {
        found.push(Weakness::NoForwardSecrecy);
    }
    found
}

/// Whether a key exchange gives forward secrecy. Pure PSK and anonymous
/// exchanges are judged by their other weaknesses.
fn is_ephemeral(kx: &str) -> bool {
    let kx = kx.split("_EXPORT").next().unwrap_or(kx);
    kx.starts_with("DHE_")
        || kx.starts_with("ECDHE_")
        || kx.starts_with("SRP_")
        || kx.contains("anon")
        || kx == "PSK"
}

/// Every non-TLS 1.3 suite of the registry, in code order.
pub fn legacy_suites() -> impl Iterator<Item = CipherSuite> {
    SUITES
        .iter()
        .map(|&(code, _)| CipherSuite(code))
        .filter(|suite| !is_tls13(*suite))
}

/// The TLS 1.3 suites (`0x1301`-`0x1305`).
pub fn tls13_suites() -> impl Iterator<Item = CipherSuite> {
    SUITES
        .iter()
        .map(|&(code, _)| CipherSuite(code))
        .filter(|suite| is_tls13(*suite))
}

pub const fn is_tls13(suite: CipherSuite) -> bool {
    suite.0 >> 8 == 0x13
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(code: u16) -> Vec<Weakness> {
        weaknesses(CipherSuite(code))
    }

    #[test]
    fn registry_is_sorted_and_unique() {
        assert!(SUITES.windows(2).all(|p| p[0].0 < p[1].0));
        assert_eq!(tls13_suites().count(), 5);
        assert_eq!(legacy_suites().count() + 5, SUITES.len());
        assert!(SUITES.iter().all(|(_, n)| n.starts_with("TLS_")));
    }

    #[test]
    fn classification_known_answers() {
        use Weakness::*;
        assert_eq!(w(0x0001), [NullCipher, Md5, NoForwardSecrecy]); // RSA_WITH_NULL_MD5
        assert_eq!(w(0x0005), [Rc4, NoForwardSecrecy]); // RSA_WITH_RC4_128_SHA
        assert_eq!(w(0x0006), [Export, Des, Md5, NoForwardSecrecy]); // RSA_EXPORT_WITH_RC2_CBC_40_MD5
        assert_eq!(w(0x0007), [Sweet32, NoForwardSecrecy]); // RSA_WITH_IDEA_CBC_SHA
        assert_eq!(w(0x0009), [Des, NoForwardSecrecy]); // RSA_WITH_DES_CBC_SHA
        assert_eq!(w(0x000a), [Sweet32, NoForwardSecrecy]); // RSA_WITH_3DES_EDE_CBC_SHA
        assert_eq!(w(0x0014), [Export, Des]); // DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
        assert_eq!(w(0x0016), [Sweet32]); // DHE_RSA_WITH_3DES_EDE_CBC_SHA
        assert_eq!(w(0x0018), [Anonymous, Rc4, Md5]); // DH_anon_WITH_RC4_128_MD5
        assert_eq!(w(0x0034), [Anonymous]); // DH_anon_WITH_AES_128_CBC_SHA
        assert_eq!(w(0x0062), [Export, Des, NoForwardSecrecy]); // RSA_EXPORT1024_WITH_DES_CBC_SHA
        assert_eq!(w(0x002f), [NoForwardSecrecy]); // RSA_WITH_AES_128_CBC_SHA
        assert_eq!(w(0xc011), [Rc4]); // ECDHE_RSA_WITH_RC4_128_SHA
        assert_eq!(w(0xc015), [NullCipher, Anonymous]); // ECDH_anon_WITH_NULL_SHA
        assert_eq!(w(0xc00e), [NoForwardSecrecy]); // ECDH_RSA_WITH_AES_128_CBC_SHA
        assert_eq!(w(0xc02f), []);
        assert_eq!(w(0xcca8), []);
        assert_eq!(w(0x1301), []);
        assert_eq!(w(0x00a8), []); // PSK_WITH_AES_128_GCM_SHA256
        assert_eq!(w(0xabcd), []);
    }

    #[test]
    fn labels() {
        assert_eq!(
            suite_label(CipherSuite(0xc02f)),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
        assert_eq!(suite_label(CipherSuite(0x5600)), "0x5600");
        assert_eq!(Weakness::Sweet32.label(), "sweet32");
        assert_eq!(Weakness::Rc4.to_string(), "RC4");
    }
}
