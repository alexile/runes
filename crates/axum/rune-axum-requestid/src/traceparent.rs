use std::fmt;

use http::HeaderValue;
use rand::RngCore;

use crate::Error;
use crate::id::push_hex;

/// Length of a version `00` `traceparent` value.
const V00_LEN: usize = 55;

/// The sampled bit of the trace flags.
pub const FLAG_SAMPLED: u8 = 0x01;

/// A W3C Trace Context `traceparent` value.
///
/// Implements the header defined in
/// [W3C Trace Context §3.2](https://www.w3.org/TR/trace-context/#traceparent-header):
///
/// ```text
/// 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
/// ^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^ ^^
/// |  trace-id (16 bytes)              parent-id (8)    flags
/// version
/// ```
///
/// Parsing follows the specification's rules: fields are lowercase hex,
/// version `ff` is invalid, all-zero trace and parent ids are invalid, and a
/// value with a higher version is parsed by its version `00` prefix (the
/// forward-compatibility rule). [`Display`](fmt::Display) always writes
/// version `00`.
///
/// # Examples
///
/// ```
/// use rune_axum_requestid::TraceParent;
///
/// let tp = TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")?;
/// assert_eq!(tp.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
/// assert!(tp.sampled());
///
/// // The server's own span keeps the trace id and gets a new parent id.
/// let child = tp.child([1, 2, 3, 4, 5, 6, 7, 8]);
/// assert_eq!(child.to_string(), "00-4bf92f3577b34da6a3ce929d0e0e4736-0102030405060708-01");
/// # Ok::<(), rune_axum_requestid::Error>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceParent {
    trace_id: [u8; 16],
    parent_id: [u8; 8],
    flags: u8,
}

impl TraceParent {
    /// Builds a value from its parts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroTraceId`] or [`Error::ZeroParentId`] for the
    /// all-zero ids the specification forbids.
    pub fn from_parts(trace_id: [u8; 16], parent_id: [u8; 8], flags: u8) -> Result<Self, Error> {
        if trace_id == [0; 16] {
            return Err(Error::ZeroTraceId);
        }
        if parent_id == [0; 8] {
            return Err(Error::ZeroParentId);
        }
        Ok(Self {
            trace_id,
            parent_id,
            flags,
        })
    }

    /// Parses a `traceparent` header value.
    ///
    /// Surrounding spaces and tabs (HTTP optional whitespace) are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedTraceParent`], [`Error::InvalidVersion`],
    /// [`Error::ZeroTraceId`] or [`Error::ZeroParentId`].
    pub fn parse(value: &str) -> Result<Self, Error> {
        Self::parse_bytes(value.as_bytes())
    }

    /// Parses a `traceparent` header value given as raw bytes.
    ///
    /// # Errors
    ///
    /// As [`TraceParent::parse`].
    pub fn parse_bytes(value: &[u8]) -> Result<Self, Error> {
        let v = value.trim_ascii();
        if v.len() < V00_LEN {
            return Err(Error::MalformedTraceParent("too short"));
        }
        if v[2] != b'-' || v[35] != b'-' || v[52] != b'-' {
            return Err(Error::MalformedTraceParent("missing field separator"));
        }
        let mut version = [0u8; 1];
        decode_hex(&v[0..2], &mut version)?;
        match version[0] {
            0xff => return Err(Error::InvalidVersion),
            0x00 if v.len() != V00_LEN => {
                return Err(Error::MalformedTraceParent(
                    "trailing data after version 00",
                ));
            }
            // A future version may append fields, separated by a dash.
            _ if v.len() > V00_LEN && v[V00_LEN] != b'-' => {
                return Err(Error::MalformedTraceParent("missing field separator"));
            }
            _ => {}
        }
        let mut trace_id = [0u8; 16];
        decode_hex(&v[3..35], &mut trace_id)?;
        let mut parent_id = [0u8; 8];
        decode_hex(&v[36..52], &mut parent_id)?;
        let mut flags = [0u8; 1];
        decode_hex(&v[53..55], &mut flags)?;
        Self::from_parts(trace_id, parent_id, flags[0])
    }

    /// Starts a new trace with random trace and parent ids.
    #[must_use]
    pub fn random(flags: u8) -> Self {
        let mut rng = rand::rng();
        let mut trace_id = [0u8; 16];
        rng.fill_bytes(&mut trace_id);
        Self {
            trace_id: non_zero(trace_id),
            parent_id: random_span_id(),
            flags,
        }
    }

    /// The value for a child span: same trace id and flags, `parent_id`
    /// replaced by the child's own span id.
    ///
    /// An all-zero `span_id` is invalid on the wire, so it is replaced by
    /// `00…01`.
    #[must_use]
    pub fn child(&self, span_id: [u8; 8]) -> Self {
        Self {
            parent_id: non_zero(span_id),
            ..*self
        }
    }

    /// A child span with a random span id.
    #[must_use]
    pub fn random_child(&self) -> Self {
        self.child(random_span_id())
    }

    /// The 16-byte trace id.
    #[must_use]
    pub const fn trace_id(&self) -> [u8; 16] {
        self.trace_id
    }

    /// The 8-byte parent (span) id.
    #[must_use]
    pub const fn parent_id(&self) -> [u8; 8] {
        self.parent_id
    }

    /// The trace flags byte.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Whether the sampled flag is set.
    #[must_use]
    pub const fn sampled(&self) -> bool {
        self.flags & FLAG_SAMPLED != 0
    }

    /// The trace id as 32 lowercase hex digits.
    #[must_use]
    pub fn trace_id_hex(&self) -> String {
        hex(&self.trace_id)
    }

    /// The parent id as 16 lowercase hex digits.
    #[must_use]
    pub fn parent_id_hex(&self) -> String {
        hex(&self.parent_id)
    }

    /// The value as a header value.
    #[must_use]
    pub fn to_header_value(&self) -> HeaderValue {
        HeaderValue::from_str(&self.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("invalid-traceparent"))
    }
}

impl fmt::Display for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::with_capacity(V00_LEN);
        out.push_str("00-");
        out.push_str(&self.trace_id_hex());
        out.push('-');
        out.push_str(&self.parent_id_hex());
        out.push('-');
        push_hex(&mut out, self.flags);
        f.write_str(&out)
    }
}

impl fmt::Debug for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TraceParent({self})")
    }
}

impl std::str::FromStr for TraceParent {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        push_hex(&mut out, *b);
    }
    out
}

/// Decodes lowercase hex; `out.len() * 2 == src.len()` is the caller's job.
fn decode_hex(src: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let (pairs, _) = src.as_chunks::<2>();
    for (dst, [hi, lo]) in out.iter_mut().zip(pairs) {
        *dst = (nibble(*hi)? << 4) | nibble(*lo)?;
    }
    Ok(())
}

const fn nibble(c: u8) -> Result<u8, Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(Error::MalformedTraceParent("field is not lowercase hex")),
    }
}

fn random_span_id() -> [u8; 8] {
    let mut id = [0u8; 8];
    rand::rng().fill_bytes(&mut id);
    non_zero(id)
}

fn non_zero<const N: usize>(mut id: [u8; N]) -> [u8; N] {
    if id.iter().all(|b| *b == 0)
        && let Some(last) = id.last_mut()
    {
        *last = 1;
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    // Example from W3C Trace Context §3.2.2.5 (and §3.2.4).
    const SPEC: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const SPEC_UNSAMPLED: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00";

    #[test]
    fn parses_spec_example() {
        let tp = TraceParent::parse(SPEC).unwrap();
        assert_eq!(
            tp.trace_id(),
            [
                0x4b, 0xf9, 0x2f, 0x35, 0x77, 0xb3, 0x4d, 0xa6, 0xa3, 0xce, 0x92, 0x9d, 0x0e, 0x0e,
                0x47, 0x36
            ]
        );
        assert_eq!(tp.parent_id_hex(), "00f067aa0ba902b7");
        assert_eq!(tp.flags(), 1);
        assert!(tp.sampled());
        assert_eq!(tp.to_string(), SPEC);
        assert_eq!(tp.to_header_value(), SPEC);

        let unsampled = TraceParent::parse(SPEC_UNSAMPLED).unwrap();
        assert!(!unsampled.sampled());
        assert_eq!(unsampled.to_string(), SPEC_UNSAMPLED);
    }

    #[test]
    fn trims_optional_whitespace() {
        assert!(TraceParent::parse(&format!(" \t{SPEC} ")).is_ok());
    }

    #[test]
    fn rejects_uppercase_hex() {
        let upper = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01";
        assert!(matches!(
            TraceParent::parse(upper),
            Err(Error::MalformedTraceParent(_))
        ));
    }

    #[test]
    fn rejects_version_ff() {
        let v = "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert_eq!(TraceParent::parse(v), Err(Error::InvalidVersion));
    }

    #[test]
    fn rejects_zero_ids() {
        let zero_trace = "00-00000000000000000000000000000000-00f067aa0ba902b7-01";
        assert_eq!(TraceParent::parse(zero_trace), Err(Error::ZeroTraceId));
        let zero_parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01";
        assert_eq!(TraceParent::parse(zero_parent), Err(Error::ZeroParentId));
    }

    #[test]
    fn rejects_bad_shape() {
        for bad in [
            "",
            "00",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-011",
            "00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e473-600f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902bz-01",
            "0g-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0x",
        ] {
            assert!(TraceParent::parse(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn future_version_parses_prefix() {
        let v = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-what-the-future-will-be";
        let tp = TraceParent::parse(v).unwrap();
        assert_eq!(tp.to_string(), SPEC);
        let exact = "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        assert!(TraceParent::parse(exact).is_ok());
        let no_dash = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01x";
        assert!(TraceParent::parse(no_dash).is_err());
    }

    #[test]
    fn child_keeps_trace_and_flags() {
        let tp = TraceParent::parse(SPEC).unwrap();
        let child = tp.random_child();
        assert_eq!(child.trace_id(), tp.trace_id());
        assert_eq!(child.flags(), tp.flags());
        assert_ne!(child.parent_id(), [0; 8]);
        assert_eq!(tp.child([0; 8]).parent_id(), [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn random_is_valid() {
        let tp = TraceParent::random(FLAG_SAMPLED);
        assert!(tp.sampled());
        assert_eq!(TraceParent::parse(&tp.to_string()).unwrap(), tp);
        assert!(!TraceParent::random(0).sampled());
    }

    #[test]
    fn from_parts_validates() {
        assert_eq!(
            TraceParent::from_parts([0; 16], [1; 8], 0),
            Err(Error::ZeroTraceId)
        );
        assert_eq!(
            TraceParent::from_parts([1; 16], [0; 8], 0),
            Err(Error::ZeroParentId)
        );
    }
}
