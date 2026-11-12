//! JA3 and JA3S, the original MD5 TLS fingerprints.
//!
//! Specification: <https://github.com/salesforce/ja3> (BSD-3-Clause).

use rune_tls_hello::{ClientHello, ServerHello, is_grease};

use crate::fingerprint::{Fingerprint, dec_list};

/// The JA3 fingerprint of a `ClientHello`.
///
/// The raw form is
/// `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`:
/// decimal values, `-` within a field, GREASE values left out, and empty
/// fields left empty. `SSLVersion` is the hello's `legacy_version` (not
/// `supported_versions`). The hash is the lowercase MD5 of the raw form.
///
/// ```
/// use rune_ja::ja3;
/// use rune_tls_hello::{CipherSuite, ClientHello, ProtocolVersion};
///
/// // The second example of the JA3 README: no extensions at all.
/// let hello = ClientHello::new()
///     .with_legacy_version(ProtocolVersion::TLS_1_0)
///     .with_cipher_suites([4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99].map(CipherSuite))
///     .without_extensions();
/// let fp = ja3(&hello);
/// assert_eq!(fp.raw, "769,4-5-10-9-100-98-3-6-19-18-99,,,");
/// assert_eq!(fp.hash, "de350869b8c85de67a350c8d186f11e6");
/// ```
#[must_use]
pub fn ja3(hello: &ClientHello) -> Fingerprint {
    let ciphers = dec_list(
        hello
            .cipher_suites
            .iter()
            .map(|c| c.0)
            .filter(|&c| !is_grease(c)),
    );
    let extensions = dec_list(
        hello
            .extension_types()
            .map(|e| e.0)
            .filter(|&e| !is_grease(e)),
    );
    let curves = dec_list(
        hello
            .supported_groups()
            .unwrap_or_default()
            .into_iter()
            .map(|g| g.0)
            .filter(|&g| !is_grease(g)),
    );
    let formats = dec_list(hello.ec_point_formats().unwrap_or_default());
    let raw = format!(
        "{},{ciphers},{extensions},{curves},{formats}",
        hello.legacy_version.0
    );
    Fingerprint {
        hash: rune_md5::hash_bytes(raw.as_bytes()),
        raw,
    }
}

/// The JA3S fingerprint of a `ServerHello`.
///
/// The raw form is `SSLVersion,Cipher,Extensions` in decimal, with the
/// server's `legacy_version` and GREASE extension types left out; the hash
/// is its lowercase MD5.
///
/// ```
/// use rune_ja::ja3s;
/// use rune_tls_hello::{CipherSuite, Extension, ExtensionType, ProtocolVersion, ServerHello};
///
/// let hello = ServerHello::new()
///     .with_legacy_version(ProtocolVersion::TLS_1_2)
///     .with_cipher_suite(CipherSuite(0xc02f))
///     .with_extension(Extension::empty(ExtensionType::RENEGOTIATION_INFO));
/// assert_eq!(ja3s(&hello).raw, "771,49199,65281");
/// ```
#[must_use]
pub fn ja3s(hello: &ServerHello) -> Fingerprint {
    let extensions = dec_list(
        hello
            .extension_types()
            .map(|e| e.0)
            .filter(|&e| !is_grease(e)),
    );
    let raw = format!(
        "{},{},{extensions}",
        hello.legacy_version.0, hello.cipher_suite.0
    );
    Fingerprint {
        hash: rune_md5::hash_bytes(raw.as_bytes()),
        raw,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_tls_hello::{CipherSuite, Extension, ExtensionType, NamedGroup, ProtocolVersion};

    /// The first example of the JA3 README, rebuilt as a hello.
    #[test]
    fn readme_example_with_extensions() {
        let hello = ClientHello::new()
            .with_legacy_version(ProtocolVersion::TLS_1_0)
            .with_cipher_suites(
                [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4].map(CipherSuite),
            )
            .with_extension(Extension::server_name("example.com").unwrap())
            .with_extension(
                Extension::supported_groups(&[NamedGroup(23), NamedGroup(24), NamedGroup(25)])
                    .unwrap(),
            )
            .with_extension(Extension::ec_point_formats(&[0]).unwrap());
        let fp = ja3(&hello);
        assert_eq!(
            fp.raw,
            "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
        );
        assert_eq!(fp.hash, "ada70206e40642a3e4461f35503241d5");
        assert_eq!(fp.to_string(), fp.hash);
    }

    #[test]
    fn grease_is_ignored_everywhere() {
        let plain = ClientHello::new()
            .with_cipher_suites([CipherSuite(0x1301)])
            .with_extension(Extension::supported_groups(&[NamedGroup::X25519]).unwrap());
        let greased = ClientHello::new()
            .with_cipher_suites([CipherSuite(0x0a0a), CipherSuite(0x1301)])
            .with_extension(Extension::empty(ExtensionType(0x2a2a)))
            .with_extension(
                Extension::supported_groups(&[NamedGroup(0xfafa), NamedGroup::X25519]).unwrap(),
            );
        assert_eq!(ja3(&plain), ja3(&greased));
        assert_eq!(ja3(&plain).raw, "771,4865,10,29,");
    }

    #[test]
    fn server_without_extensions() {
        let hello = ServerHello::new()
            .with_legacy_version(ProtocolVersion::TLS_1_0)
            .with_cipher_suite(CipherSuite(47))
            .without_extensions();
        let fp = ja3s(&hello);
        assert_eq!(fp.raw, "769,47,");
        assert_eq!(fp.hash, rune_md5::hash_bytes(b"769,47,"));
    }
}
