//! MIME for HTTP tooling: `Content-Type` and `Content-Disposition` parsing
//! and formatting, charset detection and decoding, and a bounded multipart
//! parser and encoder.
//!
//! - [`MediaType`] parses and formats media types ([RFC 9110 §8.3.1],
//!   [RFC 2045 §5.1]) with quoted strings and [RFC 8187] extended
//!   parameters.
//! - [`ContentDisposition`] does the same for `Content-Disposition`
//!   ([RFC 6266], [RFC 7578 §4.2]).
//! - [`detect_charset`] picks a charset from a BOM, the declared charset,
//!   an in-document declaration or the bytes themselves; [`Charset::decode`]
//!   decodes UTF-8, UTF-16, US-ASCII, ISO-8859-1 and Windows-1252.
//! - [`parse_multipart`] parses `multipart/form-data` ([RFC 7578]),
//!   `multipart/mixed` and the other `multipart/*` types ([RFC 2046 §5.1])
//!   into borrowed [`Part`]s with byte ranges, within the limits of
//!   [`MultipartOptions`]; [`encode_multipart`] writes them back.
//! - The [`rune_http_model`] glue reads these from an
//!   [`HttpRequest`](rune_http_model::HttpRequest) or
//!   [`HttpResponse`](rune_http_model::HttpResponse).
//!
//! The crate is sans-I/O, and no input makes it panic.
//!
//! # Example
//!
//! ```
//! use rune_mime::{MediaType, MultipartOptions, Part, encode_multipart, parse_multipart_body};
//!
//! let content_type: MediaType = "multipart/form-data; boundary=\"--rune\"".parse().unwrap();
//! assert!(content_type.is_form_data());
//!
//! let body = encode_multipart(
//!     content_type.boundary().unwrap(),
//!     &[Part::form_field("q", b"caf\xc3\xa9").unwrap()],
//! )
//! .unwrap();
//! let form = parse_multipart_body(&content_type, &body, &MultipartOptions::default()).unwrap();
//! let q = form.field("q").unwrap();
//! assert_eq!(q.body, "café".as_bytes());
//! assert_eq!(&body[q.body_range.clone()], q.body);
//! ```
//!
//! [RFC 9110 §8.3.1]: https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1
//! [RFC 2045 §5.1]: https://www.rfc-editor.org/rfc/rfc2045#section-5.1
//! [RFC 2046 §5.1]: https://www.rfc-editor.org/rfc/rfc2046#section-5.1
//! [RFC 6266]: https://www.rfc-editor.org/rfc/rfc6266
//! [RFC 7578]: https://www.rfc-editor.org/rfc/rfc7578
//! [RFC 7578 §4.2]: https://www.rfc-editor.org/rfc/rfc7578#section-4.2
//! [RFC 8187]: https://www.rfc-editor.org/rfc/rfc8187

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod charset;
mod disposition;
mod error;
mod http;
mod media_type;
mod multipart;
mod params;

pub use charset::{Charset, CharsetMatch, CharsetSource, bom, detect_charset};
pub use disposition::ContentDisposition;
pub use error::MimeError;
pub use http::{
    parse_request_multipart, parse_response_multipart, request_media_type, response_charset,
    response_media_type, set_multipart_form,
};
pub use media_type::MediaType;
pub use multipart::{
    MAX_PARSE_BOUNDARY, Multipart, MultipartOptions, Part, encode_multipart, parse_multipart,
    parse_multipart_body, validate_boundary,
};
pub use params::Param;
