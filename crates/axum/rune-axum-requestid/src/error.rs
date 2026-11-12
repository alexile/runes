/// Errors returned when a request id or a `traceparent` value is rejected.
///
/// The middleware never surfaces these to clients: an invalid incoming value
/// is replaced by a freshly generated one. They are returned by the parsing
/// functions ([`RequestId::new`](crate::RequestId::new),
/// [`TraceParent::parse`](crate::TraceParent::parse)) for callers that use
/// the sans-I/O core directly.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The request id is empty.
    #[error("request id is empty")]
    EmptyId,
    /// The request id is longer than the configured limit.
    #[error("request id is {len} bytes, more than the limit of {max} bytes")]
    IdTooLong {
        /// Length of the rejected id in bytes.
        len: usize,
        /// The configured limit.
        max: usize,
    },
    /// The request id contains a byte outside visible ASCII (`0x21..=0x7e`).
    #[error("request id has a byte outside visible ASCII at offset {index}")]
    InvalidIdByte {
        /// Byte offset of the first offending byte.
        index: usize,
    },
    /// The `traceparent` value does not have the W3C shape
    /// `version-traceid-parentid-flags` with lowercase hex fields.
    #[error("malformed traceparent: {0}")]
    MalformedTraceParent(&'static str),
    /// The `traceparent` version is `ff`, which the specification forbids.
    #[error("traceparent version ff is invalid")]
    InvalidVersion,
    /// The trace id is all zeroes.
    #[error("traceparent trace-id is all zeroes")]
    ZeroTraceId,
    /// The parent id is all zeroes.
    #[error("traceparent parent-id is all zeroes")]
    ZeroParentId,
}
