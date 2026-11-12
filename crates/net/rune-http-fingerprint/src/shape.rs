//! Per-response features and the stack fingerprint built from them.

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};

use rune_http_model::{HttpResponse, HttpVersion};

use crate::raw::{Quirk, analyze_raw_head};
use crate::{Observations, ProbeKind};

/// How a set of header names is capitalised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Casing {
    /// No headers.
    None,
    /// `content-type` (HTTP/2 and HTTP/3 always, some proxies on HTTP/1).
    Lower,
    /// `CONTENT-TYPE`.
    Upper,
    /// `Content-Type`, `Etag`, `Www-Authenticate`: every dash-separated
    /// token capitalised, the rest lowercase (Go's canonical form).
    Title,
    /// Every token starts uppercase, some with more capitals
    /// (`ETag`, `WWW-Authenticate`, `X-XSS-Protection`).
    Capitalized,
    /// Anything else, or a mix of the above.
    Mixed,
}

impl Casing {
    /// The one-letter code used in fingerprints: `n`, `l`, `u`, `t`, `c`, `m`.
    #[must_use]
    pub const fn code(self) -> char {
        match self {
            Self::None => 'n',
            Self::Lower => 'l',
            Self::Upper => 'u',
            Self::Title => 't',
            Self::Capitalized => 'c',
            Self::Mixed => 'm',
        }
    }

    /// The casing of a whole list of names.
    #[must_use]
    pub fn of<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        let mut overall = Self::None;
        for name in names {
            let casing = Self::of_name(name);
            overall = match (overall, casing) {
                (Self::None, casing) => casing,
                (a, b) if a == b => a,
                (Self::Title | Self::Capitalized, Self::Title | Self::Capitalized) => {
                    Self::Capitalized
                }
                _ => Self::Mixed,
            };
        }
        overall
    }

    fn of_name(name: &str) -> Self {
        if !name.bytes().any(|byte| byte.is_ascii_alphabetic()) {
            // `1`, `-`: neutral, counts as lowercase.
            return Self::Lower;
        }
        if !name.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Self::Lower;
        }
        if !name.bytes().any(|byte| byte.is_ascii_lowercase()) {
            return Self::Upper;
        }
        let tokens = || name.split('-').filter(|token| !token.is_empty());
        let starts_upper = |token: &str| !token.as_bytes()[0].is_ascii_lowercase();
        if !tokens().all(starts_upper) {
            return Self::Mixed;
        }
        if tokens().all(|token| !token.bytes().skip(1).any(|byte| byte.is_ascii_uppercase())) {
            Self::Title
        } else {
            Self::Capitalized
        }
    }
}

/// How a response's reason phrase compares with the registered one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ReasonForm {
    /// No reason phrase (always so on HTTP/2 and HTTP/3).
    Missing,
    /// Exactly the registered phrase (`404 Not Found`).
    Standard,
    /// Anything else (`200 Ok`, `200 Fine`, or a phrase for an
    /// unregistered code).
    NonStandard,
}

impl ReasonForm {
    /// The one-letter code used in fingerprints: `x`, `s`, `n`.
    #[must_use]
    pub const fn code(self) -> char {
        match self {
            Self::Missing => 'x',
            Self::Standard => 's',
            Self::NonStandard => 'n',
        }
    }
}

/// The registered reason phrase of a status code ([RFC 9110 §15] and the
/// IANA registry), for the codes servers commonly send.
///
/// [RFC 9110 §15]: https://www.rfc-editor.org/rfc/rfc9110#section-15
#[must_use]
pub const fn standard_reason(status: u16) -> Option<&'static str> {
    Some(match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        203 => "Non-Authoritative Information",
        204 => "No Content",
        205 => "Reset Content",
        206 => "Partial Content",
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        305 => "Use Proxy",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        426 => "Upgrade Required",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        451 => "Unavailable For Legal Reasons",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        511 => "Network Authentication Required",
        _ => return None,
    })
}

/// Older registered phrases that are still common and count as standard.
const fn legacy_reason(status: u16) -> Option<&'static str> {
    match status {
        413 => Some("Request Entity Too Large"),
        414 => Some("Request-URI Too Long"),
        416 => Some("Requested Range Not Satisfiable"),
        422 => Some("Unprocessable Entity"),
        _ => None,
    }
}

/// The shape of one response: everything but header values and the body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ResponseShape {
    /// Protocol version.
    pub version: HttpVersion,
    /// Status code.
    pub status: u16,
    /// Reason phrase form.
    pub reason: ReasonForm,
    /// Lowercase header names in wire order, each listed once (at its
    /// first position).
    pub header_order: Vec<String>,
    /// Casing of the header names as received.
    pub casing: Casing,
    /// Quirks of the status line and headers (wire-level ones only when
    /// the response has `raw` bytes).
    pub quirks: BTreeSet<Quirk>,
}

impl ResponseShape {
    /// Extracts the shape of `response`. When `response.raw` holds the
    /// captured bytes, header names and the reason phrase are taken from
    /// the wire and wire-level [`Quirk`]s are added.
    #[must_use]
    pub fn of(response: &HttpResponse) -> Self {
        let raw = response
            .raw
            .as_ref()
            .and_then(|raw| analyze_raw_head(raw.as_bytes()));
        let names: Vec<&str> = raw.as_ref().map_or_else(
            || {
                response
                    .headers
                    .iter()
                    .map(|header| header.name.as_str())
                    .collect()
            },
            |head| head.header_names.iter().map(String::as_str).collect(),
        );
        let mut quirks = raw
            .as_ref()
            .map(|head| head.quirks.clone())
            .unwrap_or_default();
        let mut header_order: Vec<String> = Vec::new();
        for name in &names {
            let lower = name.to_ascii_lowercase();
            if header_order.contains(&lower) {
                if lower != "set-cookie" {
                    quirks.insert(Quirk::DuplicateHeader);
                }
            } else {
                header_order.push(lower);
            }
        }
        let reason_text = raw
            .as_ref()
            .map_or(response.reason.as_deref(), |head| {
                Some(head.reason.as_str())
            })
            .filter(|reason| !reason.is_empty());
        let reason = match reason_text {
            None => ReasonForm::Missing,
            Some(text)
                if standard_reason(response.status) == Some(text)
                    || legacy_reason(response.status) == Some(text) =>
            {
                ReasonForm::Standard
            }
            Some(_) => ReasonForm::NonStandard,
        };
        if reason == ReasonForm::NonStandard {
            quirks.insert(Quirk::NonStandardReason);
        }
        Self {
            version: response.http_version,
            status: response.status,
            reason,
            header_order,
            casing: Casing::of(names.iter().copied()),
            quirks,
        }
    }
}

/// The methods a response says the resource allows: the `Allow` header,
/// or IIS's `Public` header when there is no `Allow`. Upper-cased, sorted
/// and deduplicated.
#[must_use]
pub fn allowed_methods(response: &HttpResponse) -> Vec<String> {
    let name = if response.has_header("allow") {
        "allow"
    } else {
        "public"
    };
    let methods: BTreeSet<String> = response
        .header_values(name)
        .flat_map(|value| value.split(','))
        .map(|method| method.trim().to_ascii_uppercase())
        .filter(|method| !method.is_empty())
        .collect();
    methods.into_iter().collect()
}

/// Everything the fingerprint is computed from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct StackFeatures {
    /// The shape of each observed probe response, in [`ProbeKind::ALL`] order.
    pub shapes: Vec<(ProbeKind, ResponseShape)>,
    /// Methods allowed according to the [`ProbeKind::Options`] response.
    pub methods: Vec<String>,
}

impl StackFeatures {
    /// Extracts the features of every observed probe.
    #[must_use]
    pub fn of(observations: &Observations) -> Self {
        let shapes = ProbeKind::ALL
            .into_iter()
            .filter_map(|probe| {
                observations
                    .response(probe)
                    .map(|response| (probe, ResponseShape::of(response)))
            })
            .collect();
        let methods = observations
            .response(ProbeKind::Options)
            .map(allowed_methods)
            .unwrap_or_default();
        Self { shapes, methods }
    }

    /// The shape of `probe`, when observed.
    #[must_use]
    pub fn shape(&self, probe: ProbeKind) -> Option<&ResponseShape> {
        self.shapes
            .iter()
            .find(|(kind, _)| *kind == probe)
            .map(|(_, shape)| shape)
    }
}

/// A server/stack fingerprint.
///
/// The hashed form is `a_b_c` (for example `11c06s_3f9a0c7d21e4_9b1e60a2d4c8`):
///
/// - `a`, readable: the primary response's version (`09`, `10`, `11`, `20`,
///   `30`), [`Casing::code`], header count (two digits, capped at 99) and
///   [`ReasonForm::code`]. The primary response is the
///   [`ProbeKind::Baseline`] one, else the first observed probe.
/// - `b`: the first 12 hex digits of the SHA-256 of the primary response's
///   lowercase header order (comma-joined).
/// - `c`: the same of the behaviour string: for every probe in
///   [`ProbeKind::ALL`] order, `name=status:reason:casing:quirks` (or
///   `name=-` when not observed), then `methods=` and the allowed methods.
///
/// `raw` is `a_b_c` with the unhashed strings. Fingerprints only compare
/// meaningfully between observations of the same probe set. Header values
/// and bodies are deliberately left out so that the fingerprint does not
/// change with dates, lengths, cookies or content; [`Database`](crate::Database)
/// signatures look at those.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct StackFingerprint {
    /// The hashed form.
    pub hash: String,
    /// The readable, unhashed form.
    pub raw: String,
}

impl fmt::Display for StackFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hash)
    }
}

const fn version_code(version: HttpVersion) -> &'static str {
    match version {
        HttpVersion::Http09 => "09",
        HttpVersion::Http10 => "10",
        HttpVersion::Http2 => "20",
        HttpVersion::Http3 => "30",
        // Http11 and any later addition.
        _ => "11",
    }
}

/// The first 12 lowercase hex characters of the SHA-256 of `text`, or
/// twelve zeros when it is empty.
fn hash12(text: &str) -> String {
    if text.is_empty() {
        return "0".repeat(12);
    }
    let mut out = String::with_capacity(12);
    for byte in rune_sha256::hash_raw(text.as_bytes()).iter().take(6) {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Computes the stack fingerprint of `observations`. See
/// [`StackFingerprint`] for the format.
#[must_use]
pub fn fingerprint(observations: &Observations) -> StackFingerprint {
    fingerprint_features(&StackFeatures::of(observations))
}

/// Computes the stack fingerprint from already extracted features.
#[must_use]
pub fn fingerprint_features(features: &StackFeatures) -> StackFingerprint {
    let primary = features
        .shape(ProbeKind::Baseline)
        .or_else(|| features.shapes.first().map(|(_, shape)| shape));
    let (a, order) = primary.map_or_else(
        || ("00n00x".to_owned(), String::new()),
        |shape| {
            (
                format!(
                    "{}{}{:02}{}",
                    version_code(shape.version),
                    shape.casing.code(),
                    shape.header_order.len().min(99),
                    shape.reason.code()
                ),
                shape.header_order.join(","),
            )
        },
    );
    let mut behaviour = String::new();
    for probe in ProbeKind::ALL {
        let _ = write!(behaviour, "{probe}=");
        match features.shape(probe) {
            Some(shape) => {
                let quirks: Vec<&str> = shape.quirks.iter().map(|quirk| quirk.code()).collect();
                let _ = write!(
                    behaviour,
                    "{}:{}:{}:{}",
                    shape.status,
                    shape.reason.code(),
                    shape.casing.code(),
                    quirks.join("+")
                );
            }
            None => behaviour.push('-'),
        }
        behaviour.push(';');
    }
    let _ = write!(behaviour, "methods={}", features.methods.join(","));
    StackFingerprint {
        hash: format!("{a}_{}_{}", hash12(&order), hash12(&behaviour)),
        raw: format!("{a}_{order}_{behaviour}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn casing_classes() {
        let of = |names: &[&str]| Casing::of(names.iter().copied());
        assert_eq!(of(&[]), Casing::None);
        assert_eq!(of(&["content-type", "x-1"]), Casing::Lower);
        assert_eq!(of(&["SERVER"]), Casing::Upper);
        assert_eq!(of(&["Content-Type", "Etag"]), Casing::Title);
        assert_eq!(of(&["Content-Type", "ETag"]), Casing::Capitalized);
        assert_eq!(of(&["ETag"]), Casing::Capitalized);
        assert_eq!(of(&["Content-Type", "date"]), Casing::Mixed);
        assert_eq!(of(&["content-Type"]), Casing::Mixed);
        assert_eq!(of(&["-"]), Casing::Lower);
    }

    #[test]
    fn reason_forms() {
        let form = |status, reason: Option<&str>| {
            let mut response = HttpResponse::new(status);
            response.reason = reason.map(str::to_owned);
            ResponseShape::of(&response).reason
        };
        assert_eq!(form(200, Some("OK")), ReasonForm::Standard);
        assert_eq!(
            form(413, Some("Request Entity Too Large")),
            ReasonForm::Standard
        );
        assert_eq!(form(200, Some("Ok")), ReasonForm::NonStandard);
        assert_eq!(form(299, Some("Custom")), ReasonForm::NonStandard);
        assert_eq!(form(200, None), ReasonForm::Missing);
        assert_eq!(form(200, Some("")), ReasonForm::Missing);
        assert_eq!(standard_reason(299), None);
    }

    #[test]
    fn shape_collapses_duplicates_and_reads_raw() {
        let response = HttpResponse::new(200)
            .with_reason("OK")
            .with_header("Set-Cookie", "a=1")
            .with_header("set-cookie", "b=2")
            .with_header("Vary", "a")
            .with_header("Vary", "b");
        let shape = ResponseShape::of(&response);
        assert_eq!(shape.header_order, ["set-cookie", "vary"]);
        assert_eq!(
            shape.quirks.iter().copied().collect::<Vec<_>>(),
            [Quirk::DuplicateHeader]
        );
        assert_eq!(shape.casing, Casing::Mixed);

        // Raw bytes win over the parsed (possibly normalised) headers.
        let response = HttpResponse::new(200)
            .with_header("server", "x")
            .with_raw(b"HTTP/1.1 200 Fine\r\nSERVER: x\r\n\r\n".to_vec());
        let shape = ResponseShape::of(&response);
        assert_eq!(shape.casing, Casing::Upper);
        assert_eq!(shape.reason, ReasonForm::NonStandard);
        assert!(shape.quirks.contains(&Quirk::NonStandardReason));
    }

    #[test]
    fn methods_from_allow_or_public() {
        let response = HttpResponse::new(200).with_header("Allow", "get, HEAD,,OPTIONS, GET");
        assert_eq!(allowed_methods(&response), ["GET", "HEAD", "OPTIONS"]);
        let response = HttpResponse::new(200).with_header("Public", "OPTIONS, TRACE");
        assert_eq!(allowed_methods(&response), ["OPTIONS", "TRACE"]);
        assert_eq!(
            allowed_methods(&HttpResponse::new(200)),
            Vec::<String>::new()
        );
    }

    #[test]
    fn empty_observations_fingerprint() {
        let fp = fingerprint(&Observations::new());
        assert_eq!(fp.hash, "00n00x_000000000000_c63e0caa0e8c");
        assert_eq!(fp.raw, "00n00x__base=-;nf=-;opt=-;um=-;h10=-;methods=");
        assert_eq!(fp.to_string(), fp.hash);
    }
}
