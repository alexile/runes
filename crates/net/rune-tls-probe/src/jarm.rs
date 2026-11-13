//! JARM active TLS server fingerprinting, sans-I/O.
//!
//! JARM sends ten deliberately different `ClientHello`s (versions, cipher
//! orders, GREASE, ALPN lists, `supported_versions`) and condenses how the
//! server answers each one into a 62-character fingerprint: servers with
//! the same TLS stack and configuration get the same fingerprint. It was
//! published by Salesforce under the BSD 3-Clause licence; this module is
//! an independent implementation of the published design, and gives the
//! same fingerprints for the same server answers.
//!
//! - [`PROBES`] describes the ten hellos; [`ProbeSpec::client_hello`]
//!   builds one.
//! - [`ResponseReader`] reads one answer into an [`Entry`].
//! - [`Fingerprint`] holds the ten entries; [`Fingerprint::raw`] is the
//!   unhashed form and [`Fingerprint::hash`] the 62-character one.
//! - [`hash`] hashes a raw string, from this crate or any other JARM
//!   tool, and [`decode`] reads the cipher and version answers back out of
//!   a fingerprint.
//! - With the `tokio` feature, [`fingerprint`] runs the ten probes over
//!   `rune-service-probe`'s runner (timeouts, read budget).
//!
//! ## The hash
//!
//! Each answer becomes `cipher|version|alpn|extensions`: the selected
//! suite and the `ServerHello` `legacy_version` as four hex digits, the
//! selected ALPN protocol, and the server's extension types in order,
//! hex, joined by `-`. An alert, a non-TLS answer or a dead connection
//! gives `|||`. The fingerprint is, for each of the ten answers in order,
//! the suite's 1-based position in a fixed list of 69 suites as two hex
//! digits (`00` for no answer, `46` for a suite outside the list) and one
//! letter for the version (`a` SSL 3.0 to `e` TLS 1.3, `0` for no
//! answer), followed by the first 32 hex digits of the SHA-256 of all the
//! ALPN and extension fields concatenated. Ten empty answers give 62
//! zeros.
//!
//! ```
//! use rune_tls_probe::jarm::{self, Entry, Fingerprint};
//!
//! // A server that refuses everything:
//! assert_eq!(Fingerprint::default().hash(), "0".repeat(62));
//!
//! // One that answers the first probe only.
//! let mut fp = Fingerprint::default();
//! fp.entries[0] = Entry::answered(0xc02f, 0x0303, "h2", [0xff01, 0x0010]);
//! assert_eq!(fp.entries[0].to_string(), "c02f|0303|h2|ff01-0010");
//! let hash = fp.hash();
//! assert!(hash.starts_with("29d000000000000000000000000000"));
//! assert_eq!(hash, jarm::hash(&fp.raw()));
//!
//! let decoded = jarm::decode(&hash).unwrap();
//! assert_eq!(decoded.answers[0].unwrap().cipher_suite.unwrap().0, 0xc02f);
//! assert!(decoded.answers[1].is_none());
//! ```

use std::fmt::{self, Write as _};

use rune_tls_hello::{
    CipherSuite, ClientHello, Extension, ExtensionType, HandshakeMessage, Message, MessageReader,
    ProtocolVersion,
};

/// Most bytes a [`ResponseReader`] buffers before giving up: far more than
/// any `ServerHello`.
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024;

/// Largest `ServerHello` accepted.
const MAX_HELLO_LEN: usize = 16 * 1024;

/// Length of a fingerprint.
pub const HASH_LEN: usize = 62;

/// The suites JARM offers, in its forward order. TLS 1.3 suites sit in
/// the middle of the list, so that orderings move them about.
const ALL_SUITES: [u16; 69] = [
    0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045,
    0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024,
    0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0x1302, 0x1301, 0xcc14, 0xc007, 0xc012, 0xc013,
    0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0x1305, 0x1304,
    0x1303, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d,
    0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005,
];

/// The hash's suite index: the same 69 suites sorted by code, with the
/// TLS 1.3 suites last.
fn hash_order() -> Vec<u16> {
    let mut sorted = ALL_SUITES.to_vec();
    sorted.sort_by_key(|&code| (code >> 8 == 0x13, code));
    sorted
}

/// The 16 GREASE values ([RFC 8701](https://www.rfc-editor.org/rfc/rfc8701)).
const fn grease(index: u8) -> u16 {
    let nibble = (index & 0x0f) as u16;
    0x0a0a | (nibble << 12) | (nibble << 4)
}

const ALPN_ALL: [&str; 9] = [
    "http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "h2", "h2c", "hq",
];
const ALPN_RARE: [&str; 7] = [
    "http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "hq",
];

/// How a list is reordered before it is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Order {
    /// As listed.
    Forward,
    /// Reversed.
    Reverse,
    /// The first half reversed; for an odd length the middle item leads.
    TopHalf,
    /// The second half, past the middle item.
    BottomHalf,
    /// From the middle outwards, alternating the item after and the item
    /// before.
    MiddleOut,
}

impl Order {
    /// Reorders `items`.
    ///
    /// ```
    /// use rune_tls_probe::jarm::Order;
    ///
    /// let items = [1, 2, 3, 4, 5];
    /// assert_eq!(Order::Reverse.apply(&items), [5, 4, 3, 2, 1]);
    /// assert_eq!(Order::TopHalf.apply(&items), [3, 2, 1]);
    /// assert_eq!(Order::BottomHalf.apply(&items), [4, 5]);
    /// assert_eq!(Order::MiddleOut.apply(&items), [3, 4, 2, 5, 1]);
    /// assert_eq!(Order::MiddleOut.apply(&[1, 2, 3, 4]), [3, 2, 4, 1]);
    /// ```
    #[must_use]
    pub fn apply<T: Clone>(self, items: &[T]) -> Vec<T> {
        let len = items.len();
        let half = len / 2;
        match self {
            Self::Forward => items.to_vec(),
            Self::Reverse => items.iter().rev().cloned().collect(),
            Self::BottomHalf => items.get(half + len % 2..).unwrap_or_default().to_vec(),
            Self::TopHalf => {
                let mut out = Vec::with_capacity(half + 1);
                if len % 2 == 1 {
                    out.extend(items.get(half).cloned());
                }
                out.extend(Self::BottomHalf.apply(&Self::Reverse.apply(items)));
                out
            }
            Self::MiddleOut => {
                let mut out = Vec::with_capacity(len);
                if len % 2 == 1 {
                    out.extend(items.get(half).cloned());
                    for i in 1..=half {
                        out.extend(items.get(half + i).cloned());
                        out.extend(items.get(half - i).cloned());
                    }
                } else {
                    for i in 1..=half {
                        out.extend(items.get(half - 1 + i).cloned());
                        out.extend(items.get(half - i).cloned());
                    }
                }
                out
            }
        }
    }
}

/// Which `supported_versions` extension a probe sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SupportedVersions {
    /// None.
    Absent,
    /// TLS 1.0 to 1.2.
    UpToTls12,
    /// TLS 1.0 to 1.3.
    UpToTls13,
}

/// One of the ten JARM hellos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ProbeSpec {
    /// A short name, e.g. `tls1_2_forward`.
    pub name: &'static str,
    /// `legacy_version` of the hello (TLS 1.3 probes say TLS 1.2 there
    /// and TLS 1.0 on the record, as browsers do).
    pub version: ProtocolVersion,
    /// Offer the TLS 1.3 suites.
    pub tls13_suites: bool,
    /// Cipher-suite order.
    pub cipher_order: Order,
    /// Put GREASE values in the suites, extensions, key share and versions.
    pub grease: bool,
    /// Offer the "rare" ALPN list, without `http/1.1` and `h2`.
    pub rare_alpn: bool,
    /// The `supported_versions` extension.
    pub supported_versions: SupportedVersions,
    /// Order of the ALPN and `supported_versions` lists.
    pub extension_order: Order,
}

#[allow(clippy::too_many_arguments, reason = "one row of the probe table")]
const fn spec(
    name: &'static str,
    version: ProtocolVersion,
    tls13_suites: bool,
    cipher_order: Order,
    grease: bool,
    rare_alpn: bool,
    supported_versions: SupportedVersions,
    extension_order: Order,
) -> ProbeSpec {
    ProbeSpec {
        name,
        version,
        tls13_suites,
        cipher_order,
        grease,
        rare_alpn,
        supported_versions,
        extension_order,
    }
}

/// The ten JARM probes, in fingerprint order.
pub const PROBES: [ProbeSpec; 10] = {
    use Order::{BottomHalf, Forward, MiddleOut, Reverse, TopHalf};
    use SupportedVersions::{Absent, UpToTls12, UpToTls13};
    const T12: ProtocolVersion = ProtocolVersion::TLS_1_2;
    const T11: ProtocolVersion = ProtocolVersion::TLS_1_1;
    const T13: ProtocolVersion = ProtocolVersion::TLS_1_3;
    [
        spec(
            "tls1_2_forward",
            T12,
            true,
            Forward,
            false,
            false,
            UpToTls12,
            Reverse,
        ),
        spec(
            "tls1_2_reverse",
            T12,
            true,
            Reverse,
            false,
            false,
            UpToTls12,
            Forward,
        ),
        spec(
            "tls1_2_top_half",
            T12,
            true,
            TopHalf,
            false,
            false,
            Absent,
            Forward,
        ),
        spec(
            "tls1_2_bottom_half",
            T12,
            true,
            BottomHalf,
            false,
            true,
            Absent,
            Forward,
        ),
        spec(
            "tls1_2_middle_out",
            T12,
            true,
            MiddleOut,
            true,
            true,
            Absent,
            Reverse,
        ),
        spec(
            "tls1_1_middle_out",
            T11,
            true,
            Forward,
            false,
            false,
            Absent,
            Forward,
        ),
        spec(
            "tls1_3_forward",
            T13,
            true,
            Forward,
            false,
            false,
            UpToTls13,
            Reverse,
        ),
        spec(
            "tls1_3_reverse",
            T13,
            true,
            Reverse,
            false,
            false,
            UpToTls13,
            Forward,
        ),
        spec(
            "tls1_3_invalid",
            T13,
            false,
            Forward,
            false,
            false,
            UpToTls13,
            Forward,
        ),
        spec(
            "tls1_3_middle_out",
            T13,
            true,
            MiddleOut,
            true,
            false,
            UpToTls13,
            Reverse,
        ),
    ]
};

/// Pseudo-random bytes for one hello, derived from a seed so that hellos
/// are reproducible in tests. None of it is secret: no key is derived.
fn expand(seed: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut input = seed.to_vec();
    input.extend_from_slice(label);
    rune_sha256::hash_raw(&input)
}

impl ProbeSpec {
    /// The cipher suites offered, GREASE included.
    #[must_use]
    pub fn cipher_suites(&self, seed: &[u8; 32]) -> Vec<CipherSuite> {
        let list: Vec<u16> = ALL_SUITES
            .iter()
            .copied()
            .filter(|&s| self.tls13_suites || s >> 8 != 0x13)
            .collect();
        let mut suites: Vec<CipherSuite> = self
            .cipher_order
            .apply(&list)
            .into_iter()
            .map(CipherSuite)
            .collect();
        if self.grease {
            suites.insert(0, CipherSuite(grease(expand(seed, b"suite")[0])));
        }
        suites
    }

    /// The ALPN protocols offered, in order.
    #[must_use]
    pub fn alpn_protocols(&self) -> Vec<&'static str> {
        let list: &[&str] = if self.rare_alpn {
            &ALPN_RARE
        } else {
            &ALPN_ALL
        };
        self.extension_order.apply(list)
    }

    /// The `ClientHello` for `host` (sent as SNI, IP literals included),
    /// with random, session id, key share and GREASE choices derived from
    /// `seed`. Use a fresh seed per connection on the wire.
    ///
    /// The hello carries a random 32-byte X25519 key share, as JARM
    /// requires; it is not a real public key and nothing is derived from
    /// it, and the connection is closed after the server's first answer.
    ///
    /// ```
    /// use rune_tls_hello::{ClientHello, ProtocolVersion};
    /// use rune_tls_probe::jarm::PROBES;
    ///
    /// let wire = PROBES[0].client_hello("example.com", &[7; 32]).unwrap();
    /// assert_eq!(&wire[..3], [22, 3, 3]); // a TLS 1.2 record
    /// let hello = ClientHello::parse_records(&wire)?;
    /// assert_eq!(hello.server_name(), Some("example.com"));
    /// assert_eq!(hello.cipher_suites.len(), 69);
    /// assert_eq!(
    ///     hello.supported_versions(),
    ///     Some(vec![ProtocolVersion::TLS_1_2, ProtocolVersion::TLS_1_1, ProtocolVersion::TLS_1_0])
    /// );
    /// # Ok::<(), rune_tls_hello::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::Hello`](crate::Error::Hello) for a host name too long to
    /// encode.
    pub fn client_hello(&self, host: &str, seed: &[u8; 32]) -> Result<Vec<u8>, crate::Error> {
        let (legacy, record) = if self.version >= ProtocolVersion::TLS_1_3 {
            (ProtocolVersion::TLS_1_2, ProtocolVersion::TLS_1_0)
        } else {
            (self.version, self.version)
        };
        if host.len() > usize::from(u16::MAX) - 1024 {
            return Err(rune_tls_hello::Error::TooLong {
                what: "server name",
                len: host.len(),
                max: usize::from(u16::MAX) - 1024,
            }
            .into());
        }
        Ok(ClientHello::new()
            .with_legacy_version(legacy)
            .with_random(expand(seed, b"random"))
            .with_session_id(expand(seed, b"session").to_vec())
            .with_cipher_suites(self.cipher_suites(seed))
            .with_compression_methods(vec![0])
            .with_extensions(self.extensions(host, seed))
            .to_records(record, rune_tls_hello::MAX_PLAINTEXT_LEN)?)
    }

    fn extensions(&self, host: &str, seed: &[u8; 32]) -> Vec<Extension> {
        let raw = |code: u16, data: Vec<u8>| Extension::new(ExtensionType(code), data);
        let mut out = Vec::new();
        if self.grease {
            out.push(raw(grease(expand(seed, b"extension")[0]), Vec::new()));
        }
        let name = host.as_bytes();
        let mut sni = Vec::with_capacity(name.len() + 5);
        put_u16(&mut sni, name.len().saturating_add(3));
        sni.push(0);
        put_u16(&mut sni, name.len());
        sni.extend_from_slice(name);
        out.push(raw(0x0000, sni));
        out.push(raw(0x0017, Vec::new())); // extended_master_secret
        out.push(raw(0x0001, vec![1])); // max_fragment_length: 512
        out.push(raw(0xff01, vec![0])); // renegotiation_info
        out.push(raw(0x000a, u16_list(&[0x001d, 0x0017, 0x0018, 0x0019])));
        out.push(raw(0x000b, vec![1, 0])); // ec_point_formats: uncompressed
        out.push(raw(0x0023, Vec::new())); // session_ticket
        let mut alpn = Vec::new();
        for protocol in self.alpn_protocols() {
            alpn.push(u8::try_from(protocol.len()).unwrap_or(0));
            alpn.extend_from_slice(protocol.as_bytes());
        }
        let mut alpn_data = Vec::with_capacity(alpn.len() + 2);
        put_u16(&mut alpn_data, alpn.len());
        alpn_data.extend(alpn);
        out.push(raw(0x0010, alpn_data));
        out.push(raw(
            0x000d,
            u16_list(&[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ]),
        ));
        let mut shares = Vec::new();
        if self.grease {
            shares.extend(grease(expand(seed, b"share")[0]).to_be_bytes());
            shares.extend([0, 1, 0]);
        }
        shares.extend([0x00, 0x1d, 0x00, 0x20]);
        shares.extend(expand(seed, b"key_share"));
        let mut key_share = Vec::with_capacity(shares.len() + 2);
        put_u16(&mut key_share, shares.len());
        key_share.extend(shares);
        out.push(raw(0x0033, key_share));
        out.push(raw(0x002d, vec![1, 1])); // psk_key_exchange_modes: psk_dhe_ke
        let versions: &[u16] = match self.supported_versions {
            SupportedVersions::UpToTls12 => &[0x0301, 0x0302, 0x0303],
            SupportedVersions::UpToTls13 => &[0x0301, 0x0302, 0x0303, 0x0304],
            SupportedVersions::Absent if self.version >= ProtocolVersion::TLS_1_3 => {
                &[0x0301, 0x0302, 0x0303, 0x0304]
            }
            SupportedVersions::Absent => &[],
        };
        if !versions.is_empty() {
            let mut list = Vec::new();
            if self.grease {
                list.push(grease(expand(seed, b"versions")[0]));
            }
            list.extend(self.extension_order.apply(versions));
            let body: Vec<u8> = list.iter().flat_map(|v| v.to_be_bytes()).collect();
            let mut data = vec![u8::try_from(body.len()).unwrap_or(0)];
            data.extend(body);
            out.push(raw(0x002b, data));
        }
        out
    }
}

fn put_u16(out: &mut Vec<u8>, value: usize) {
    out.extend(u16::try_from(value).unwrap_or(u16::MAX).to_be_bytes());
}

fn u16_list(values: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len() * 2 + 2);
    put_u16(&mut out, values.len() * 2);
    out.extend(values.iter().flat_map(|v| v.to_be_bytes()));
    out
}

/// How the server answered one probe.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum Entry {
    /// An alert, no answer, or not TLS: `|||`.
    #[default]
    NoAnswer,
    /// A `ServerHello` (or `HelloRetryRequest`).
    Answered {
        /// The selected suite.
        cipher_suite: u16,
        /// The `legacy_version` field (TLS 1.3 servers put TLS 1.2 there).
        version: u16,
        /// The selected ALPN protocol, empty when none.
        alpn: String,
        /// The server's extension types in wire order.
        extensions: Vec<u16>,
    },
}

impl Entry {
    /// An answered entry.
    #[must_use]
    pub fn answered(
        cipher_suite: u16,
        version: u16,
        alpn: impl Into<String>,
        extensions: impl IntoIterator<Item = u16>,
    ) -> Self {
        Self::Answered {
            cipher_suite,
            version,
            alpn: alpn.into(),
            extensions: extensions.into_iter().collect(),
        }
    }

    /// Reads a complete answer at once; see [`ResponseReader`].
    ///
    /// ```
    /// use rune_tls_hello::{CipherSuite, Extension, ProtocolVersion, ServerHello};
    /// use rune_tls_probe::jarm::Entry;
    ///
    /// let wire = ServerHello::new()
    ///     .with_cipher_suite(CipherSuite(0x1301))
    ///     .with_extension(Extension::selected_version(ProtocolVersion::TLS_1_3))
    ///     .to_records(ProtocolVersion::TLS_1_2, 16_384)?;
    /// assert_eq!(Entry::parse(&wire).to_string(), "1301|0303||002b");
    /// assert_eq!(Entry::parse(&[21, 3, 3, 0, 2, 2, 40]).to_string(), "|||");
    /// # Ok::<(), rune_tls_hello::Error>(())
    /// ```
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Self {
        let mut reader = ResponseReader::new();
        reader.feed(bytes).unwrap_or_else(|| reader.finish())
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAnswer => f.write_str("|||"),
            Self::Answered {
                cipher_suite,
                version,
                alpn,
                extensions,
            } => {
                write!(f, "{cipher_suite:04x}|{version:04x}|{alpn}|")?;
                for (i, ext) in extensions.iter().enumerate() {
                    if i > 0 {
                        f.write_str("-")?;
                    }
                    write!(f, "{ext:04x}")?;
                }
                Ok(())
            }
        }
    }
}

/// Reads the server's answer to one probe, sans-I/O, buffering at most
/// [`MAX_RESPONSE_BYTES`]. Anything but a well-formed `ServerHello` as the
/// first message is [`Entry::NoAnswer`], as in JARM.
///
/// ```
/// use rune_tls_probe::jarm::{Entry, ResponseReader};
///
/// let mut reader = ResponseReader::new();
/// assert_eq!(reader.feed(&[22, 3, 3]), None); // needs more bytes
/// assert_eq!(reader.finish(), Entry::NoAnswer); // connection closed
/// ```
#[derive(Debug, Clone)]
pub struct ResponseReader {
    reader: MessageReader,
    fed: usize,
}

impl Default for ResponseReader {
    fn default() -> Self {
        Self {
            reader: MessageReader::new().with_max_handshake_len(MAX_HELLO_LEN),
            fed: 0,
        }
    }
}

impl ResponseReader {
    /// A reader that has seen nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds bytes; returns the entry once it is known.
    pub fn feed(&mut self, bytes: &[u8]) -> Option<Entry> {
        if bytes.is_empty() {
            return None;
        }
        let room = MAX_RESPONSE_BYTES.saturating_sub(self.fed);
        let take = bytes.get(..room).unwrap_or(bytes);
        self.fed += take.len();
        self.reader.feed(take);
        match self.reader.next_message() {
            Ok(None) if self.fed < MAX_RESPONSE_BYTES => None,
            Ok(Some(Message::Handshake(HandshakeMessage::ServerHello(hello)))) => {
                let extensions = hello.extensions();
                let alpn = match extensions
                    .iter()
                    .find(|e| e.extension_type == ExtensionType::ALPN)
                {
                    // JARM gives up on an empty ALPN extension.
                    Some(ext) if ext.data.is_empty() => return Some(Entry::NoAnswer),
                    // The value after the list and name lengths, as text.
                    Some(ext) => match std::str::from_utf8(ext.data.get(3..).unwrap_or_default()) {
                        Ok(text) => text.to_owned(),
                        Err(_) => return Some(Entry::NoAnswer),
                    },
                    None => String::new(),
                };
                Some(Entry::Answered {
                    cipher_suite: hello.cipher_suite.0,
                    version: hello.legacy_version.0,
                    alpn,
                    extensions: extensions.iter().map(|e| e.extension_type.0).collect(),
                })
            }
            _ => Some(Entry::NoAnswer),
        }
    }

    /// The entry when the connection ended before [`ResponseReader::feed`]
    /// returned one.
    #[must_use]
    pub const fn finish(&self) -> Entry {
        Entry::NoAnswer
    }
}

/// The ten answers of a JARM run, in [`PROBES`] order.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub struct Fingerprint {
    /// One entry per probe.
    pub entries: [Entry; 10],
}

impl Fingerprint {
    /// A fingerprint from its ten entries.
    #[must_use]
    pub const fn new(entries: [Entry; 10]) -> Self {
        Self { entries }
    }

    /// The raw form: the ten entries joined by `,`.
    #[must_use]
    pub fn raw(&self) -> String {
        self.entries
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The 62-character fingerprint: [`hash`] of [`Fingerprint::raw`],
    /// worked out entry by entry. The two only differ when a server's ALPN
    /// answer contains `,` or `|`, which would otherwise shift the other
    /// entries in the raw form; no real protocol name does.
    #[must_use]
    pub fn hash(&self) -> String {
        if self.is_empty() {
            return "0".repeat(HASH_LEN);
        }
        let fields: Vec<[String; 4]> = self
            .entries
            .iter()
            .map(|entry| match entry {
                Entry::NoAnswer => Default::default(),
                Entry::Answered {
                    cipher_suite,
                    version,
                    alpn,
                    extensions,
                } => [
                    format!("{cipher_suite:04x}"),
                    format!("{version:04x}"),
                    alpn.clone(),
                    extensions
                        .iter()
                        .map(|ext| format!("{ext:04x}"))
                        .collect::<Vec<_>>()
                        .join("-"),
                ],
            })
            .collect();
        fuzzy_hash(fields.iter().map(|[a, b, c, d]| [&**a, &**b, &**c, &**d]))
    }

    /// Whether no probe got an answer (the hash is all zeros).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.iter().all(|e| *e == Entry::NoAnswer)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hash())
    }
}

/// Hashes a raw JARM string (ten `cipher|version|alpn|extensions` entries
/// joined by `,`) into the 62-character fingerprint.
///
/// Any input is accepted: missing entries or fields count as empty, entries
/// past the tenth are ignored, and a version whose last hex digit is not
/// 0-5 hashes like an empty one.
///
/// ```
/// let empty = "|||,|||,|||,|||,|||,|||,|||,|||,|||,|||";
/// assert_eq!(rune_tls_probe::jarm::hash(empty), "0".repeat(62));
/// ```
#[must_use]
pub fn hash(raw: &str) -> String {
    let entries: Vec<&str> = raw.split(',').collect();
    if entries.len() == PROBES.len() && entries.iter().all(|e| *e == "|||") {
        return "0".repeat(HASH_LEN);
    }
    fuzzy_hash(entries.into_iter().map(|entry| {
        let mut fields = entry.split('|');
        let mut next = || fields.next().unwrap_or("");
        [next(), next(), next(), next()]
    }))
}

/// The fuzzy hash of exactly ten `[cipher, version, alpn, extensions]`
/// entries: missing ones count as empty, extra ones are ignored.
fn fuzzy_hash<'a>(entries: impl Iterator<Item = [&'a str; 4]>) -> String {
    let order = hash_order();
    let mut out = String::with_capacity(HASH_LEN);
    let mut tail = String::new();
    let mut entries = entries.chain(std::iter::repeat([""; 4])).take(PROBES.len());
    for [cipher, version, alpn, extensions] in &mut entries {
        tail.push_str(alpn);
        tail.push_str(extensions);
        if cipher.is_empty() {
            out.push_str("00");
        } else {
            let index = order
                .iter()
                .position(|code| format!("{code:04x}") == cipher)
                .unwrap_or(order.len());
            let _ = write!(out, "{:02x}", index + 1);
        }
        out.push(version_letter(version));
    }
    let digest = rune_sha256::hash_bytes(tail.as_bytes());
    out.push_str(digest.get(..32).unwrap_or(&digest));
    out
}

fn version_letter(version: &str) -> char {
    version
        .chars()
        .nth(3)
        .and_then(|c| c.to_digit(10))
        .and_then(|d| "abcdef".chars().nth(d as usize))
        .unwrap_or('0')
}

/// What a fingerprint says about one probe's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Answer {
    /// The suite the server picked; `None` for a suite outside JARM's list.
    pub cipher_suite: Option<CipherSuite>,
    /// The `ServerHello` `legacy_version`, when it was SSL 3.0 to TLS 1.3.
    pub version: Option<ProtocolVersion>,
}

/// A fingerprint read back into its parts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Decoded {
    /// One answer per probe, `None` where the server did not answer.
    pub answers: [Option<Answer>; 10],
    /// The truncated SHA-256 of the ALPN and extension fields, 32 hex
    /// digits. Only equality means anything.
    pub extensions_hash: String,
}

/// Reads the cipher and version answers out of a fingerprint. `None` for
/// anything that is not 62 lowercase hex digits and version letters.
///
/// ```
/// use rune_tls_hello::{CipherSuite, ProtocolVersion};
///
/// // A published example fingerprint, from the JARM README.
/// let d = rune_tls_probe::jarm::decode("27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d").unwrap();
/// let first = d.answers[0].unwrap();
/// assert_eq!(first.cipher_suite, Some(CipherSuite(0xc02b))); // ECDHE_ECDSA AES-128-GCM
/// assert_eq!(first.version, Some(ProtocolVersion::TLS_1_2));
/// assert!(d.answers[8].is_none()); // the TLS 1.3 hello without TLS 1.3 suites
/// ```
#[must_use]
pub fn decode(fingerprint: &str) -> Option<Decoded> {
    let bytes = fingerprint.as_bytes();
    if bytes.len() != HASH_LEN
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return None;
    }
    let order = hash_order();
    let mut answers = [None; 10];
    for (slot, chunk) in answers.iter_mut().zip(bytes.chunks(3)) {
        let index = std::str::from_utf8(chunk.get(..2)?).ok()?;
        let index = usize::from_str_radix(index, 16).ok()?;
        let letter = *chunk.get(2)?;
        if index == 0 {
            if letter != b'0' {
                return None;
            }
            continue;
        }
        let version = match letter {
            b'a'..=b'f' => Some(ProtocolVersion(0x0300 + u16::from(letter - b'a'))),
            b'0' => None,
            _ => return None,
        };
        *slot = Some(Answer {
            cipher_suite: order.get(index - 1).map(|&code| CipherSuite(code)),
            version,
        });
    }
    Some(Decoded {
        answers,
        extensions_hash: fingerprint.get(30..)?.to_owned(),
    })
}

/// Runs the ten probes against `target`, one connection each, in order,
/// and returns the [`Fingerprint`].
///
/// Each connection is bounded by the runner's [`Options`](rune_service_probe::Options):
/// connect, I/O and total timeouts, and its read budget; on top of that
/// the reader stops at [`MAX_RESPONSE_BYTES`]. The target's host name is
/// sent as SNI (an IP literal too, as JARM does). Read-only: each
/// connection sends one hello and closes after the server's first answer.
///
/// ```no_run
/// use rune_service_probe::{Options, Runner, Target};
///
/// # async fn demo() -> Result<(), rune_tls_probe::Error> {
/// let runner = Runner::new(Options::default());
/// let fp = rune_tls_probe::jarm::fingerprint(&runner, &Target::new("app.example", 443)).await?;
/// println!("{fp}");
/// # Ok(()) }
/// ```
///
/// # Errors
///
/// [`Error::Probe`](crate::Error::Probe) when the first connection fails
/// (the target is unreachable). Later failures are [`Entry::NoAnswer`].
#[cfg(feature = "tokio")]
pub async fn fingerprint(
    runner: &rune_service_probe::Runner,
    target: &rune_service_probe::Target,
) -> Result<Fingerprint, crate::Error> {
    use std::sync::{Arc, Mutex, PoisonError};

    let mut entries: [Entry; 10] = Default::default();
    for (i, (spec, slot)) in PROBES.iter().zip(entries.iter_mut()).enumerate() {
        let sink = Arc::new(Mutex::new(None));
        let probe = HelloProbe {
            spec: *spec,
            seed: crate::probe::client_random(),
            sink: Arc::clone(&sink),
        };
        match runner.probe(&probe, target).await {
            Err(error) if i == 0 && error.is_unreachable() => {
                return Err(crate::Error::Probe(error));
            }
            _ => {}
        }
        *slot = sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .unwrap_or_default();
    }
    Ok(Fingerprint::new(entries))
}

/// One JARM hello as a `rune-service-probe` probe, so the runner's
/// timeouts and budgets apply.
#[cfg(feature = "tokio")]
struct HelloProbe {
    spec: ProbeSpec,
    seed: [u8; 32],
    sink: std::sync::Arc<std::sync::Mutex<Option<Entry>>>,
}

#[cfg(feature = "tokio")]
impl rune_service_probe::ServiceProbe for HelloProbe {
    fn id(&self) -> &'static str {
        "tls.jarm"
    }

    fn session(
        &self,
        target: &rune_service_probe::Target,
    ) -> Box<dyn rune_service_probe::ProbeSession> {
        Box::new(HelloSession {
            hello: self.spec.client_hello(&target.host, &self.seed).ok(),
            reader: ResponseReader::new(),
            entry: None,
            sink: std::sync::Arc::clone(&self.sink),
        })
    }
}

#[cfg(feature = "tokio")]
struct HelloSession {
    hello: Option<Vec<u8>>,
    reader: ResponseReader,
    entry: Option<Entry>,
    sink: std::sync::Arc<std::sync::Mutex<Option<Entry>>>,
}

#[cfg(feature = "tokio")]
impl rune_service_probe::ProbeSession for HelloSession {
    fn start(&mut self) -> rune_service_probe::Action {
        self.hello.take().map_or(
            rune_service_probe::Action::Done,
            rune_service_probe::Action::Send,
        )
    }

    fn on_data(&mut self, data: &[u8]) -> rune_service_probe::Action {
        match self.reader.feed(data) {
            Some(entry) => {
                self.entry = Some(entry);
                rune_service_probe::Action::Done
            }
            None => rune_service_probe::Action::Receive,
        }
    }

    fn finish(
        &mut self,
        _end: rune_service_probe::End,
    ) -> Result<rune_service_probe::ServiceInfo, rune_service_probe::Error> {
        let entry = self.entry.take().unwrap_or_else(|| self.reader.finish());
        let info = rune_service_probe::ServiceInfo::new("tls")
            .with_detail("tls.jarm_entry", entry.to_string());
        *self
            .sink
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(entry);
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_order_is_sorted_with_tls13_last() {
        let order = hash_order();
        assert_eq!(order.len(), 69);
        assert_eq!(order.first(), Some(&0x0004));
        assert_eq!(order.get(63), Some(&0xcca9));
        assert_eq!(
            order.get(64..),
            Some(&[0x1301, 0x1302, 0x1303, 0x1304, 0x1305][..])
        );
    }

    #[test]
    fn grease_values() {
        assert_eq!(grease(0), 0x0a0a);
        assert_eq!(grease(1), 0x1a1a);
        assert_eq!(grease(15), 0xfafa);
        assert!((0..=255).all(|i| rune_tls_hello::is_grease(grease(i))));
    }

    #[test]
    fn letters() {
        assert_eq!(version_letter("0300"), 'a');
        assert_eq!(version_letter("0304"), 'e');
        assert_eq!(version_letter("0306"), '0');
        assert_eq!(version_letter(""), '0');
        assert_eq!(version_letter("03"), '0');
    }
}
