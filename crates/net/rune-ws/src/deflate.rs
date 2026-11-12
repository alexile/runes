//! permessage-deflate (RFC 7692): extension negotiation and per-message
//! compression with a raw DEFLATE stream.
//!
//! The pure-Rust flate2 backend always compresses with a 32 KiB window, so
//! offers that require a smaller window for *our* compressor are declined
//! (server) or rejected (client). Smaller windows from the peer are always
//! fine to decompress.

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

use crate::error::{Error, Result};

const TAIL: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];
const NAME: &str = "permessage-deflate";

/// Local permessage-deflate preferences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeflateConfig {
    /// Ask for (client) or impose (server) `server_no_context_takeover`.
    pub server_no_context_takeover: bool,
    /// Ask for (client) or impose (server) `client_no_context_takeover`.
    pub client_no_context_takeover: bool,
    /// Compression level, 0–9. Default 6.
    pub level: u32,
    /// Messages shorter than this are sent uncompressed. Default 0.
    pub threshold: usize,
}

impl Default for DeflateConfig {
    fn default() -> Self {
        Self {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            level: 6,
            threshold: 0,
        }
    }
}

impl DeflateConfig {
    /// Sets [`server_no_context_takeover`](Self::server_no_context_takeover).
    #[must_use]
    pub const fn with_server_no_context_takeover(mut self, on: bool) -> Self {
        self.server_no_context_takeover = on;
        self
    }

    /// Sets [`client_no_context_takeover`](Self::client_no_context_takeover).
    #[must_use]
    pub const fn with_client_no_context_takeover(mut self, on: bool) -> Self {
        self.client_no_context_takeover = on;
        self
    }

    /// Sets [`level`](Self::level) (clamped to 9).
    #[must_use]
    pub fn with_level(mut self, level: u32) -> Self {
        self.level = level.min(9);
        self
    }

    /// Sets [`threshold`](Self::threshold).
    #[must_use]
    pub const fn with_threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold;
        self
    }

    /// The `Sec-WebSocket-Extensions` offer a client sends.
    #[must_use]
    pub fn offer(&self) -> String {
        let mut out = NAME.to_owned();
        if self.server_no_context_takeover {
            out.push_str("; server_no_context_takeover");
        }
        if self.client_no_context_takeover {
            out.push_str("; client_no_context_takeover");
        }
        out
    }
}

/// Parameters both sides agreed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DeflateParams {
    /// The server resets its compressor after every message.
    pub server_no_context_takeover: bool,
    /// The client resets its compressor after every message.
    pub client_no_context_takeover: bool,
    /// Local compression level.
    pub level: u32,
    /// Local minimum message size to compress.
    pub threshold: usize,
}

/// One element of a `Sec-WebSocket-Extensions` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// The extension token.
    pub name: String,
    /// Parameters, with their values (quotes removed) if any.
    pub params: Vec<(String, Option<String>)>,
}

/// Parses a `Sec-WebSocket-Extensions` header value (RFC 6455 §9.1).
///
/// # Errors
///
/// [`Error::Extension`] for an empty extension name or parameter name.
pub fn parse_extensions(value: &str) -> Result<Vec<Extension>> {
    let mut out = Vec::new();
    for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let mut parts = item.split(';').map(str::trim);
        let name = parts.next().unwrap_or_default();
        if name.is_empty() {
            return Err(Error::Extension("empty extension name".into()));
        }
        let mut params = Vec::new();
        for param in parts {
            let (key, value) = match param.split_once('=') {
                Some((k, v)) => (k.trim(), Some(v.trim().trim_matches('"').to_owned())),
                None => (param, None),
            };
            if key.is_empty() {
                return Err(Error::Extension("empty parameter name".into()));
            }
            params.push((key.to_ascii_lowercase(), value));
        }
        out.push(Extension {
            name: name.to_ascii_lowercase(),
            params,
        });
    }
    Ok(out)
}

fn window_bits(value: Option<&str>, required: bool) -> Result<Option<u8>> {
    match value {
        None if required => Err(Error::Extension("window bits value required".into())),
        None => Ok(None),
        Some(v) => match v.parse::<u8>() {
            Ok(bits @ 8..=15) if v.len() <= 2 && !v.starts_with('0') => Ok(Some(bits)),
            _ => Err(Error::Extension(format!("invalid window bits {v:?}"))),
        },
    }
}

/// The parameters of one permessage-deflate element, validated.
#[derive(Default)]
struct Offer {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: Option<u8>,
    /// `None`: absent; `Some(None)`: present without a value (offer only).
    #[allow(
        clippy::option_option,
        reason = "absent, bare and valued are all distinct on the wire"
    )]
    client_max_window_bits: Option<Option<u8>>,
}

fn parse_offer(ext: &Extension, is_response: bool) -> Result<Offer> {
    let mut offer = Offer::default();
    let mut seen = Vec::new();
    for (key, value) in &ext.params {
        if seen.contains(&key) {
            return Err(Error::Extension(format!("duplicate parameter {key}")));
        }
        seen.push(key);
        let flag_ok = value.is_none();
        match key.as_str() {
            "server_no_context_takeover" if flag_ok => offer.server_no_context_takeover = true,
            "client_no_context_takeover" if flag_ok => offer.client_no_context_takeover = true,
            "server_max_window_bits" => {
                offer.server_max_window_bits = window_bits(value.as_deref(), true)?;
            }
            "client_max_window_bits" => {
                offer.client_max_window_bits = Some(window_bits(value.as_deref(), is_response)?);
            }
            _ => return Err(Error::Extension(format!("unsupported parameter {key}"))),
        }
    }
    Ok(offer)
}

/// Server: picks the first acceptable permessage-deflate offer and returns
/// the agreed parameters and the response header value.
pub fn server_negotiate(
    config: &DeflateConfig,
    headers: &[&str],
) -> Result<Option<(DeflateParams, String)>> {
    for value in headers {
        for ext in parse_extensions(value)? {
            if ext.name != NAME {
                continue;
            }
            let Ok(offer) = parse_offer(&ext, false) else {
                continue;
            };
            // We cannot shrink our own (server) compression window.
            if offer.server_max_window_bits.is_some_and(|bits| bits < 15) {
                continue;
            }
            let params = DeflateParams {
                server_no_context_takeover: offer.server_no_context_takeover
                    || config.server_no_context_takeover,
                client_no_context_takeover: offer.client_no_context_takeover
                    || config.client_no_context_takeover,
                level: config.level,
                threshold: config.threshold,
            };
            let mut header = NAME.to_owned();
            if params.server_no_context_takeover {
                header.push_str("; server_no_context_takeover");
            }
            if params.client_no_context_takeover {
                header.push_str("; client_no_context_takeover");
            }
            return Ok(Some((params, header)));
        }
    }
    Ok(None)
}

/// Client: validates the server's extension response against our offer.
pub fn client_verify(
    config: Option<&DeflateConfig>,
    headers: &[&str],
) -> Result<Option<DeflateParams>> {
    let mut chosen = None;
    for value in headers {
        for ext in parse_extensions(value)? {
            let Some(config) = config.filter(|_| ext.name == NAME) else {
                return Err(Error::Extension(format!(
                    "extension {} was not offered",
                    ext.name
                )));
            };
            if chosen.is_some() {
                return Err(Error::Extension("permessage-deflate selected twice".into()));
            }
            let offer = parse_offer(&ext, true)?;
            // We did not offer client_max_window_bits, so the server may not
            // limit our window.
            if offer.client_max_window_bits.is_some() {
                return Err(Error::Extension(
                    "client_max_window_bits was not offered".into(),
                ));
            }
            if config.server_no_context_takeover && !offer.server_no_context_takeover {
                return Err(Error::Extension(
                    "server_no_context_takeover was required".into(),
                ));
            }
            chosen = Some(DeflateParams {
                server_no_context_takeover: offer.server_no_context_takeover,
                client_no_context_takeover: offer.client_no_context_takeover
                    || config.client_no_context_takeover,
                level: config.level,
                threshold: config.threshold,
            });
        }
    }
    Ok(chosen)
}

fn ext_error(err: impl std::fmt::Display) -> Error {
    Error::Extension(format!("deflate: {err}"))
}

fn delta(after: u64, before: u64) -> usize {
    usize::try_from(after - before).unwrap_or(usize::MAX)
}

/// Compresses outgoing messages.
pub struct Compressor {
    inner: Compress,
    reset: bool,
}

impl std::fmt::Debug for Compressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Compressor")
            .field("reset", &self.reset)
            .finish_non_exhaustive()
    }
}

impl Compressor {
    pub fn new(level: u32, no_context_takeover: bool) -> Self {
        Self {
            inner: Compress::new(Compression::new(level), false),
            reset: no_context_takeover,
        }
    }

    /// Compresses one message and strips the trailing empty block
    /// (RFC 7692 §7.2.1).
    pub fn compress(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(data.len() / 2 + 64);
        let start = self.inner.total_in();
        loop {
            if out.len() == out.capacity() {
                out.reserve(out.capacity().max(64));
            }
            let consumed = delta(self.inner.total_in(), start);
            self.inner
                .compress_vec(&data[consumed..], &mut out, FlushCompress::Sync)
                .map_err(ext_error)?;
            if delta(self.inner.total_in(), start) == data.len() && out.len() < out.capacity() {
                break;
            }
        }
        if out.ends_with(&TAIL) {
            out.truncate(out.len() - TAIL.len());
        }
        if self.reset {
            self.inner.reset();
        }
        Ok(out)
    }
}

/// Decompresses incoming messages, bounded by a size limit.
pub struct Decompressor {
    inner: Decompress,
    reset: bool,
}

impl std::fmt::Debug for Decompressor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decompressor")
            .field("reset", &self.reset)
            .finish_non_exhaustive()
    }
}

impl Decompressor {
    pub fn new(no_context_takeover: bool) -> Self {
        Self {
            inner: Decompress::new(false),
            reset: no_context_takeover,
        }
    }

    /// Decompresses one message (RFC 7692 §7.2.2), failing once the output
    /// would exceed `max` bytes.
    pub fn decompress(&mut self, data: &[u8], max: usize) -> Result<Vec<u8>> {
        let mut input = Vec::with_capacity(data.len() + TAIL.len());
        input.extend_from_slice(data);
        input.extend_from_slice(&TAIL);
        let mut out = Vec::with_capacity(input.len().saturating_mul(3).min(max.saturating_add(1)));
        let start = self.inner.total_in();
        let mut ended = false;
        loop {
            if out.len() == out.capacity() {
                if out.len() > max {
                    return Err(Error::MessageTooLarge { max });
                }
                out.reserve(
                    out.capacity()
                        .max(256)
                        .min(max.saturating_add(1).saturating_sub(out.len())),
                );
            }
            let consumed = delta(self.inner.total_in(), start);
            let before = (consumed, out.len());
            let status = self
                .inner
                .decompress_vec(&input[consumed..], &mut out, FlushDecompress::Sync)
                .map_err(ext_error)?;
            let consumed = delta(self.inner.total_in(), start);
            if status == Status::StreamEnd {
                ended = true;
                break;
            }
            if consumed == input.len() && out.len() < out.capacity() {
                break;
            }
            if (consumed, out.len()) == before && out.len() < out.capacity() {
                return Err(ext_error("stalled on truncated input"));
            }
        }
        if out.len() > max {
            return Err(Error::MessageTooLarge { max });
        }
        // A final block ends the DEFLATE stream; the next message starts a
        // fresh one.
        if self.reset || ended {
            self.inner.reset(false);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7692_hello_known_answer() {
        // RFC 7692 §7.2.3.1: "Hello" compressed with no context takeover.
        let mut d = Decompressor::new(false);
        assert_eq!(
            d.decompress(&[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], 100)
                .unwrap(),
            b"Hello"
        );
        // §7.2.3.2: the second "Hello" sharing the sliding window.
        assert_eq!(
            d.decompress(&[0xf2, 0x00, 0x11, 0x00, 0x00], 100).unwrap(),
            b"Hello"
        );
        // §7.2.3.3: an uncompressed (stored) block.
        let mut d = Decompressor::new(true);
        assert_eq!(
            d.decompress(
                &[
                    0x00, 0x05, 0x00, 0xfa, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00
                ],
                100
            )
            .unwrap(),
            b"Hello"
        );
        // §7.2.3.5: BFINAL set.
        let mut d = Decompressor::new(false);
        assert_eq!(
            d.decompress(&[0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], 100)
                .unwrap(),
            b"Hello"
        );
        assert_eq!(
            d.decompress(&[0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], 100)
                .unwrap(),
            b"Hello"
        );
    }

    #[test]
    fn compress_round_trip_with_and_without_takeover() {
        for reset in [false, true] {
            let mut c = Compressor::new(6, reset);
            let mut d = Decompressor::new(reset);
            let large = vec![42; 100_000];
            for msg in [&b""[..], b"Hello", b"Hello", &large] {
                let packed = c.compress(msg).unwrap();
                assert_eq!(d.decompress(&packed, 1 << 20).unwrap(), msg);
            }
        }
    }

    #[test]
    fn decompression_is_bounded() {
        let packed = Compressor::new(9, true)
            .compress(&vec![0; 1 << 20])
            .unwrap();
        assert!(packed.len() < 2048);
        assert!(matches!(
            Decompressor::new(true).decompress(&packed, 1000),
            Err(Error::MessageTooLarge { max: 1000 })
        ));
    }

    #[test]
    fn negotiation() {
        let config = DeflateConfig::default();
        let (params, header) = server_negotiate(
            &config,
            &["x-foo, permessage-deflate; server_max_window_bits=10, permessage-deflate; client_max_window_bits; client_no_context_takeover"],
        )
        .unwrap()
        .unwrap();
        assert!(params.client_no_context_takeover && !params.server_no_context_takeover);
        assert_eq!(header, "permessage-deflate; client_no_context_takeover");
        assert!(
            server_negotiate(&config, &["permessage-deflate; bogus"])
                .unwrap()
                .is_none()
        );

        let ok = client_verify(
            Some(&config),
            &["permessage-deflate; server_no_context_takeover"],
        )
        .unwrap();
        assert!(ok.unwrap().server_no_context_takeover);
        assert!(
            client_verify(
                Some(&config),
                &["permessage-deflate; client_max_window_bits=10"]
            )
            .is_err()
        );
        assert!(client_verify(None, &["permessage-deflate"]).is_err());
        assert!(client_verify(Some(&config), &["x-other"]).is_err());
        assert!(client_verify(Some(&config), &[]).unwrap().is_none());
        assert!(parse_extensions("a; =1").is_err());
    }
}
