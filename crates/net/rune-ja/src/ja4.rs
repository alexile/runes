//! JA4 (TLS client) and JA4S (TLS server).
//!
//! Specification: <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>.
//! JA4 is BSD-3-Clause; JA4S is part of JA4+ (`FoxIO` License 1.1).

use rune_tls_hello::{ClientHello, ExtensionType, ProtocolVersion, ServerHello, is_grease};

use crate::fingerprint::{Fingerprint, count2, hash12, hex_list};

/// What carried the hello: the first character of a JA4 or JA4S.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Transport {
    /// TLS over TCP: `t`.
    #[default]
    Tcp,
    /// QUIC: `q`.
    Quic,
    /// DTLS: `d`.
    Dtls,
}

impl Transport {
    /// The fingerprint character.
    #[must_use]
    pub const fn marker(self) -> char {
        match self {
            Self::Tcp => 't',
            Self::Quic => 'q',
            Self::Dtls => 'd',
        }
    }
}

/// The ordering of the JA4 cipher and extension lists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Order {
    /// Sorted, with SNI and ALPN left out of the extension list: `JA4` and
    /// `JA4_r`. This is the form normally shared.
    #[default]
    Sorted,
    /// Wire order, SNI and ALPN kept: `JA4_o` and `JA4_ro`.
    Original,
}

/// Options for [`ja4_with`] and [`ja4s_with`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Ja4Options {
    /// What carried the hello. Default: TCP.
    pub transport: Transport,
    /// List ordering (JA4 only; JA4S always keeps wire order). Default:
    /// sorted.
    pub order: Order,
}

impl Ja4Options {
    /// Sets [`Ja4Options::transport`].
    #[must_use]
    pub const fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// Sets [`Ja4Options::order`].
    #[must_use]
    pub const fn with_order(mut self, order: Order) -> Self {
        self.order = order;
        self
    }
}

/// The two-character JA4 version code: `13`, `12`, `11`, `10`, `s3`, `s2`,
/// `d1`, `d2`, `d3`, or `00` for anything else.
#[must_use]
pub const fn version_code(version: ProtocolVersion) -> &'static str {
    match version.0 {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

/// The two JA4 characters for an ALPN protocol name.
///
/// The first and last byte when both are ASCII alphanumerics (one byte
/// counts as both), else the first and last character of the name's hex
/// form; `00` when there is no name or it is empty.
///
/// ```
/// use rune_ja::alpn_code;
///
/// assert_eq!(alpn_code(Some(b"h2")), "h2");
/// assert_eq!(alpn_code(Some(b"http/1.1")), "h1");
/// assert_eq!(alpn_code(Some(&[0x30, 0xab])), "3b");
/// assert_eq!(alpn_code(None), "00");
/// ```
#[must_use]
pub fn alpn_code(name: Option<&[u8]>) -> String {
    let Some((&first, rest)) = name.and_then(<[u8]>::split_first) else {
        return "00".to_owned();
    };
    let last = rest.last().copied().unwrap_or(first);
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        [char::from(first), char::from(last)].iter().collect()
    } else {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let hi = HEX[usize::from(first >> 4)];
        let lo = HEX[usize::from(last & 0x0f)];
        [char::from(hi), char::from(lo)].iter().collect()
    }
}

/// The JA4 fingerprint of a `ClientHello` sent over TCP, sorted: the form
/// normally shared. See [`ja4_with`] for QUIC, DTLS and wire order.
///
/// ```
/// use rune_ja::ja4;
/// use rune_tls_hello::{CipherSuite, ClientHello, Extension, ProtocolVersion, SignatureScheme};
///
/// let hello = ClientHello::new()
///     .with_cipher_suites([CipherSuite(0x1302), CipherSuite(0x1301)])
///     .with_extension(Extension::server_name("example.com")?)
///     .with_extension(Extension::alpn(["h2"])?)
///     .with_extension(Extension::supported_versions(&[ProtocolVersion::TLS_1_3])?)
///     .with_extension(Extension::signature_algorithms(&[SignatureScheme(0x0403)])?);
/// let fp = ja4(&hello);
/// assert_eq!(fp.raw, "t13d0204h2_1301,1302_000d,002b_0403");
/// assert!(fp.hash.starts_with("t13d0204h2_"));
/// # Ok::<(), rune_tls_hello::Error>(())
/// ```
#[must_use]
pub fn ja4(hello: &ClientHello) -> Fingerprint {
    ja4_with(hello, Ja4Options::default())
}

/// The JA4 fingerprint of a `ClientHello` with explicit options.
///
/// - `a`: transport, version (the highest non-GREASE `supported_versions`
///   entry, else `legacy_version`), `d` if SNI is present else `i`, the
///   cipher and extension counts (GREASE left out, capped at 99), and the
///   [`alpn_code`] of the first ALPN protocol.
/// - `b`: the non-GREASE cipher suites as four-digit hex.
/// - `c`: the non-GREASE extension types, then `_` and the
///   `signature_algorithms` in wire order (no `_` if there are none).
///
/// With [`Order::Sorted`] the ciphers and extensions are sorted and SNI and
/// ALPN are left out of `c`; with [`Order::Original`] both keep wire order
/// and SNI and ALPN stay. The raw form joins `a`, `b` and `c` with `_`; the
/// hashed form replaces `b` and `c` with the first 12 hex characters of
/// their SHA-256 (`000000000000` for an empty list).
#[must_use]
pub fn ja4_with(hello: &ClientHello, options: Ja4Options) -> Fingerprint {
    let mut ciphers: Vec<u16> = hello
        .cipher_suites
        .iter()
        .map(|c| c.0)
        .filter(|&c| !is_grease(c))
        .collect();
    let mut extensions: Vec<u16> = hello
        .extension_types()
        .map(|e| e.0)
        .filter(|&e| !is_grease(e))
        .collect();
    let sni = if hello.extension(ExtensionType::SERVER_NAME).is_some() {
        'd'
    } else {
        'i'
    };
    let alpn = hello
        .alpn_protocols()
        .and_then(|protocols| protocols.into_iter().next());
    let a = format!(
        "{}{}{sni}{}{}{}",
        options.transport.marker(),
        version_code(hello.max_version()),
        count2(ciphers.len()),
        count2(extensions.len()),
        alpn_code(alpn.as_deref()),
    );

    if options.order == Order::Sorted {
        ciphers.sort_unstable();
        extensions.retain(|&e| e != ExtensionType::SERVER_NAME.0 && e != ExtensionType::ALPN.0);
        extensions.sort_unstable();
    }
    let b = hex_list(ciphers);
    let signatures = hex_list(
        hello
            .signature_algorithms()
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.0)
            .filter(|&s| !is_grease(s)),
    );
    let mut c = hex_list(extensions);
    if !signatures.is_empty() {
        c.push('_');
        c.push_str(&signatures);
    }

    Fingerprint {
        hash: format!("{a}_{}_{}", hash12(&b), hash12(&c)),
        raw: format!("{a}_{b}_{c}"),
    }
}

/// The JA4S fingerprint of a `ServerHello` sent over TCP. See
/// [`ja4s_with`].
///
/// ```
/// use rune_ja::ja4s;
/// use rune_tls_hello::{CipherSuite, Extension, ExtensionType, ProtocolVersion, ServerHello};
///
/// let hello = ServerHello::new()
///     .with_cipher_suite(CipherSuite(0x1301))
///     .with_extension(Extension::selected_version(ProtocolVersion::TLS_1_3))
///     .with_extension(Extension::empty(ExtensionType(0x0033)));
/// assert_eq!(ja4s(&hello).raw, "t130200_1301_002b,0033");
/// ```
#[must_use]
pub fn ja4s(hello: &ServerHello) -> Fingerprint {
    ja4s_with(hello, Ja4Options::default())
}

/// The JA4S fingerprint of a `ServerHello` with explicit options
/// ([`Ja4Options::order`] is ignored).
///
/// `a` is the transport, the selected version (`supported_versions`, else
/// `legacy_version`), the extension count (capped at 99) and the
/// [`alpn_code`] of the chosen ALPN protocol; `b` is the cipher suite in
/// four-digit hex; `c` is the extension types in wire order. The hashed form
/// replaces `c` with the first 12 hex characters of its SHA-256.
#[must_use]
pub fn ja4s_with(hello: &ServerHello, options: Ja4Options) -> Fingerprint {
    let extensions: Vec<u16> = hello.extension_types().map(|e| e.0).collect();
    let alpn = hello.alpn_protocol();
    let a = format!(
        "{}{}{}{}",
        options.transport.marker(),
        version_code(hello.selected_version()),
        count2(extensions.len()),
        alpn_code(alpn.as_deref()),
    );
    let b = format!("{:04x}", hello.cipher_suite.0);
    let c = hex_list(extensions);
    Fingerprint {
        hash: format!("{a}_{b}_{}", hash12(&c)),
        raw: format!("{a}_{b}_{c}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_tls_hello::{CipherSuite, Extension, SignatureScheme};

    /// The worked example of the JA4 technical details, rebuilt as a hello.
    fn spec_example() -> ClientHello {
        let ciphers = [
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let extensions = [
            0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
            0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ];
        let signatures = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let mut hello = ClientHello::new().with_cipher_suites(
            std::iter::once(CipherSuite(0x3a3a)).chain(ciphers.map(CipherSuite)),
        );
        hello = hello.with_extension(Extension::empty(ExtensionType(0x0a0a)));
        for ext in extensions {
            let extension = match ext {
                0x0000 => Extension::server_name("example.com").unwrap(),
                0x0010 => Extension::alpn(["h2", "http/1.1"]).unwrap(),
                0x002b => Extension::supported_versions(&[
                    ProtocolVersion(0x7a7a),
                    ProtocolVersion::TLS_1_3,
                    ProtocolVersion::TLS_1_2,
                ])
                .unwrap(),
                0x000d => {
                    Extension::signature_algorithms(&signatures.map(SignatureScheme)).unwrap()
                }
                other => Extension::empty(ExtensionType(other)),
            };
            hello = hello.with_extension(extension);
        }
        hello
    }

    #[test]
    fn spec_example_sorted() {
        let fp = ja4(&spec_example());
        assert_eq!(fp.hash, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(
            fp.raw,
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
        );
    }

    #[test]
    fn spec_example_original_order() {
        let fp = ja4_with(
            &spec_example(),
            Ja4Options::default().with_order(Order::Original),
        );
        assert_eq!(fp.hash, "t13d1516h2_acb858a92679_18f69afefd3d");
        assert_eq!(
            fp.raw,
            "t13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_001b,0000,0033,0010,4469,0017,002d,000d,0005,0023,0012,002b,ff01,000b,000a,0015_0403,0804,0401,0503,0805,0501,0806,0601"
        );
    }

    #[test]
    fn transport_marker() {
        let fp = ja4_with(
            &spec_example(),
            Ja4Options::default().with_transport(Transport::Quic),
        );
        assert_eq!(fp.hash, "q13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(Transport::Dtls.marker(), 'd');
    }

    #[test]
    fn no_signature_algorithms_and_no_extensions() {
        // "If there are no signature algorithms … the string ends without
        // an underscore" (spec example hash 6d807ffa2a79).
        let mut hello = spec_example();
        if let Some(extensions) = hello.extensions.as_mut() {
            extensions.retain(|e| e.extension_type != ExtensionType::SIGNATURE_ALGORITHMS);
            extensions.push(Extension::empty(ExtensionType::SIGNATURE_ALGORITHMS));
        }
        // An empty (undecodable) signature_algorithms counts as no list.
        let fp = ja4(&hello);
        assert!(fp.hash.ends_with("_6d807ffa2a79"), "{}", fp.hash);

        let bare = ClientHello::new()
            .with_legacy_version(ProtocolVersion::TLS_1_0)
            .without_extensions();
        let fp = ja4(&bare);
        assert_eq!(fp.hash, "t10i000000_000000000000_000000000000");
        assert_eq!(fp.raw, "t10i000000__");
    }

    #[test]
    fn alpn_codes_from_spec() {
        let cases: [(&[u8], &str); 11] = [
            (b"h2", "h2"),
            (b"http/1.1", "h1"),
            (b"a", "aa"),
            (&[0xab], "ab"),
            (&[0x20], "20"),
            (&[0xab, 0xcd], "ad"),
            (&[0x20, 0x61], "21"),
            (&[0x30, 0xab], "3b"),
            (&[0x61, 0x20], "60"),
            (&[0x30, 0x31, 0xab, 0xcd], "3d"),
            (&[0x30, 0xab, 0xcd, 0x31], "01"),
        ];
        for (name, code) in cases {
            assert_eq!(alpn_code(Some(name)), code, "{name:02x?}");
        }
        assert_eq!(alpn_code(Some(b"")), "00");
    }

    #[test]
    fn version_codes() {
        assert_eq!(version_code(ProtocolVersion::SSL_3_0), "s3");
        assert_eq!(version_code(ProtocolVersion(0xfefd)), "d2");
        assert_eq!(version_code(ProtocolVersion(0x0305)), "00");
    }

    #[test]
    fn counts_cap_at_99() {
        let hello = ClientHello::new()
            .with_cipher_suites((1..=120).map(CipherSuite))
            .without_extensions();
        assert!(ja4(&hello).hash.starts_with("t12i9900"));
    }
}
