//! Content codings and `Accept-Encoding` negotiation (RFC 9110 §12.5.3).

use std::fmt;

/// A content coding this middleware can apply to a response body.
///
/// Every variant exists in every build so the API does not change with the
/// cargo features; [`Encoding::is_enabled`] says whether the coding was
/// compiled in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Encoding {
    /// No transformation (`identity`).
    Identity,
    /// `gzip` (RFC 1952). Needs the `gzip` feature.
    Gzip,
    /// `deflate`: a zlib stream (RFC 1950) as RFC 9110 defines it. Needs the
    /// `deflate` feature.
    Deflate,
    /// `br`: Brotli (RFC 7932). Needs the `br` feature.
    Brotli,
    /// `zstd`: Zstandard (RFC 8878). Needs the `zstd` feature.
    Zstd,
}

impl Encoding {
    /// Every compressing coding, in the default server preference order:
    /// best ratio first.
    pub const PREFERENCE: [Self; 4] = [Self::Zstd, Self::Brotli, Self::Gzip, Self::Deflate];

    /// The token used in `Content-Encoding` and `Accept-Encoding`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Brotli => "br",
            Self::Zstd => "zstd",
        }
    }

    /// Parses a coding token, ignoring ASCII case. `x-gzip` is accepted as
    /// an alias of `gzip` (RFC 9110 §8.4.1.3).
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        let token = token.trim();
        [
            ("identity", Self::Identity),
            ("gzip", Self::Gzip),
            ("x-gzip", Self::Gzip),
            ("deflate", Self::Deflate),
            ("br", Self::Brotli),
            ("zstd", Self::Zstd),
        ]
        .into_iter()
        .find_map(|(name, enc)| token.eq_ignore_ascii_case(name).then_some(enc))
    }

    /// Whether this build can produce the coding. `identity` always can.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        match self {
            Self::Identity => true,
            Self::Gzip => cfg!(feature = "gzip"),
            Self::Deflate => cfg!(feature = "deflate"),
            Self::Brotli => cfg!(feature = "br"),
            Self::Zstd => cfg!(feature = "zstd"),
        }
    }
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Quality value in thousandths (`q=0.5` is 500), as RFC 9110 §12.4.2 allows
/// at most three decimals.
type Quality = u16;

const Q_MAX: Quality = 1000;

/// Parses a `qvalue`: `0`, `1`, `0.xyz` or `1.000`. Returns `None` when
/// malformed.
fn parse_q(raw: &str) -> Option<Quality> {
    let raw = raw.trim();
    let (int, frac) = raw.split_once('.').unwrap_or((raw, ""));
    if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut thousandths: Quality = 0;
    for (i, b) in frac.bytes().enumerate() {
        let scale: Quality = match i {
            0 => 100,
            1 => 10,
            _ => 1,
        };
        thousandths += Quality::from(b - b'0') * scale;
    }
    match int {
        "0" => Some(thousandths),
        "1" if thousandths == 0 => Some(Q_MAX),
        _ => None,
    }
}

/// What one `Accept-Encoding` header says about each coding.
#[derive(Debug, Default)]
struct Accepted {
    identity: Option<Quality>,
    gzip: Option<Quality>,
    deflate: Option<Quality>,
    brotli: Option<Quality>,
    zstd: Option<Quality>,
    any: Option<Quality>,
}

impl Accepted {
    fn parse(header: &str) -> Self {
        let mut out = Self::default();
        for item in header.split(',') {
            let mut parts = item.split(';');
            let token = parts.next().unwrap_or_default().trim();
            if token.is_empty() {
                continue;
            }
            let mut q = Some(Q_MAX);
            for param in parts {
                if let Some((name, value)) = param.split_once('=')
                    && name.trim().eq_ignore_ascii_case("q")
                {
                    q = parse_q(value);
                }
            }
            // A malformed weight makes the whole member unusable.
            let Some(q) = q else { continue };
            let slot = if token == "*" {
                &mut out.any
            } else {
                match Encoding::from_token(token) {
                    Some(Encoding::Identity) => &mut out.identity,
                    Some(Encoding::Gzip) => &mut out.gzip,
                    Some(Encoding::Deflate) => &mut out.deflate,
                    Some(Encoding::Brotli) => &mut out.brotli,
                    Some(Encoding::Zstd) => &mut out.zstd,
                    None => continue,
                }
            };
            // If a coding is listed twice, the most favourable weight wins.
            *slot = Some(slot.map_or(q, |old| old.max(q)));
        }
        out
    }

    fn quality(&self, encoding: Encoding) -> Quality {
        let explicit = match encoding {
            Encoding::Identity => self.identity,
            Encoding::Gzip => self.gzip,
            Encoding::Deflate => self.deflate,
            Encoding::Brotli => self.brotli,
            Encoding::Zstd => self.zstd,
        };
        match (explicit, encoding) {
            (Some(q), _) => q,
            // An unlisted `identity` stays acceptable (RFC 9110 §12.5.3) but
            // carries no weight against a listed coding.
            (None, Encoding::Identity) => 0,
            (None, _) => self.any.unwrap_or(0),
        }
    }
}

/// Picks the content coding for a response from an `Accept-Encoding` header
/// value.
///
/// `offered` lists the codings the server is willing to use, most preferred
/// first; codings that are not [enabled](Encoding::is_enabled) in this build
/// are skipped. The coding with the highest client weight wins, ties go to
/// the server's preference, and [`Encoding::Identity`] is returned when the
/// client lists `identity` with a higher weight or accepts none of the
/// offered codings.
///
/// Malformed members (for example `gzip;q=2`) are ignored. The function never
/// fails: `identity` is the answer of last resort, even when the client
/// excluded it, because refusing with `406` is not this middleware's call.
///
/// # Examples
///
/// ```rust
/// use rune_axum_compression::{negotiate, Encoding};
///
/// let offered = [Encoding::Gzip, Encoding::Deflate];
/// assert_eq!(negotiate("deflate, gzip", &offered), Encoding::Gzip);
/// assert_eq!(negotiate("gzip;q=0.2, deflate", &offered), Encoding::Deflate);
/// assert_eq!(negotiate("gzip;q=0", &offered), Encoding::Identity);
/// assert_eq!(negotiate("identity", &offered), Encoding::Identity);
/// ```
#[must_use]
pub fn negotiate(accept_encoding: &str, offered: &[Encoding]) -> Encoding {
    let accepted = Accepted::parse(accept_encoding);
    let mut best: Option<(Encoding, Quality)> = None;
    for &enc in offered {
        if enc == Encoding::Identity || !enc.is_enabled() {
            continue;
        }
        let q = accepted.quality(enc);
        if q > 0 && best.is_none_or(|(_, best_q)| q > best_q) {
            best = Some((enc, q));
        }
    }
    match best {
        Some((enc, q)) if q >= accepted.quality(Encoding::Identity) => enc,
        _ => Encoding::Identity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Encoding; 4] = Encoding::PREFERENCE;

    #[test]
    fn tokens_round_trip() {
        for enc in std::iter::once(Encoding::Identity).chain(ALL) {
            assert_eq!(Encoding::from_token(enc.as_str()), Some(enc));
            assert_eq!(enc.to_string(), enc.as_str());
        }
        assert_eq!(Encoding::from_token(" X-GZIP "), Some(Encoding::Gzip));
        assert_eq!(Encoding::from_token("compress"), None);
    }

    #[test]
    fn qvalues() {
        assert_eq!(parse_q("1"), Some(1000));
        assert_eq!(parse_q("1.000"), Some(1000));
        assert_eq!(parse_q("0"), Some(0));
        assert_eq!(parse_q("0.5"), Some(500));
        assert_eq!(parse_q("0.05"), Some(50));
        assert_eq!(parse_q("0.001"), Some(1));
        assert_eq!(parse_q(" 0.25 "), Some(250));
        assert_eq!(parse_q("1.5"), None);
        assert_eq!(parse_q("2"), None);
        assert_eq!(parse_q("0.0001"), None);
        assert_eq!(parse_q("-0"), None);
        assert_eq!(parse_q("0.x"), None);
        assert_eq!(parse_q(""), None);
    }

    #[test]
    fn gzip_is_negotiated() {
        assert_eq!(negotiate("gzip", &ALL), Encoding::Gzip);
        assert_eq!(negotiate("GZip", &ALL), Encoding::Gzip);
        assert_eq!(negotiate("x-gzip", &ALL), Encoding::Gzip);
        assert_eq!(negotiate("deflate", &ALL), Encoding::Deflate);
    }

    #[test]
    fn ties_follow_server_preference() {
        assert_eq!(
            negotiate("deflate, gzip", &[Encoding::Gzip, Encoding::Deflate]),
            Encoding::Gzip
        );
        assert_eq!(
            negotiate("gzip, deflate", &[Encoding::Deflate, Encoding::Gzip]),
            Encoding::Deflate
        );
    }

    #[test]
    fn client_weights_win_over_preference() {
        assert_eq!(
            negotiate("gzip;q=0.5, deflate;q=0.9", &ALL),
            Encoding::Deflate
        );
        assert_eq!(
            negotiate("gzip; Q=0.5, deflate;q=0.4", &ALL),
            Encoding::Gzip
        );
    }

    #[test]
    fn zero_weight_excludes() {
        assert_eq!(negotiate("gzip;q=0", &ALL), Encoding::Identity);
        assert_eq!(negotiate("*;q=0, deflate;q=0", &ALL), Encoding::Identity);
    }

    #[test]
    fn wildcard_covers_unlisted() {
        let offered = [Encoding::Gzip, Encoding::Deflate];
        assert_eq!(negotiate("*", &offered), Encoding::Gzip);
        assert_eq!(negotiate("gzip;q=0, *", &offered), Encoding::Deflate);
        assert_eq!(
            negotiate("*;q=0.1, deflate;q=0.2", &offered),
            Encoding::Deflate
        );
    }

    #[test]
    fn identity_preferred_when_heavier() {
        assert_eq!(negotiate("gzip;q=0.5, identity", &ALL), Encoding::Identity);
        // Equal weight: compress.
        assert_eq!(negotiate("gzip, identity", &ALL), Encoding::Gzip);
        // identity excluded: any acceptable coding goes.
        assert_eq!(negotiate("gzip;q=0.1, identity;q=0", &ALL), Encoding::Gzip);
    }

    #[test]
    fn empty_and_garbage() {
        assert_eq!(negotiate("", &ALL), Encoding::Identity);
        assert_eq!(negotiate(",,, ;q=1", &ALL), Encoding::Identity);
        assert_eq!(negotiate("gzip;q=2", &ALL), Encoding::Identity);
        assert_eq!(negotiate("compress, sdch", &ALL), Encoding::Identity);
        assert_eq!(negotiate("gzip;level=9", &ALL), Encoding::Gzip);
    }

    #[test]
    fn duplicates_keep_best_weight() {
        assert_eq!(negotiate("gzip;q=0, gzip;q=0.3", &ALL), Encoding::Gzip);
    }

    #[test]
    fn nothing_offered() {
        assert_eq!(negotiate("gzip", &[]), Encoding::Identity);
        assert_eq!(negotiate("gzip", &[Encoding::Identity]), Encoding::Identity);
    }

    #[cfg(not(feature = "br"))]
    #[test]
    fn disabled_codings_are_skipped() {
        assert!(!Encoding::Brotli.is_enabled());
        assert_eq!(negotiate("br", &ALL), Encoding::Identity);
    }

    #[cfg(feature = "br")]
    #[test]
    fn brotli_preferred_over_gzip_by_default() {
        assert_eq!(negotiate("gzip, deflate, br", &ALL), Encoding::Brotli);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn zstd_preferred_first_by_default() {
        assert_eq!(negotiate("gzip, deflate, br, zstd", &ALL), Encoding::Zstd);
    }
}
