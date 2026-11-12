//! Glue for the shared HTTP model of `rune-http-model`.
//!
//! Bodies are used as stored: if [`HttpBody::content_encoding`] is set
//! (gzip, br, …) the caller must decode the bytes first.
//!
//! [`HttpBody::content_encoding`]: rune_http_model::HttpBody::content_encoding

use rune_http_model::{HttpBody, HttpRequest, HttpResponse};

use crate::{
    CharsetMatch, MediaType, MimeError, Multipart, MultipartOptions, Part, detect_charset,
    encode_multipart, parse_multipart_body,
};

/// The request's parsed `Content-Type`, if it has one.
#[must_use]
pub fn request_media_type(request: &HttpRequest) -> Option<Result<MediaType, MimeError>> {
    request.content_type().map(MediaType::parse)
}

/// The response's parsed `Content-Type`, if it has one.
#[must_use]
pub fn response_media_type(response: &HttpResponse) -> Option<Result<MediaType, MimeError>> {
    response.content_type().map(MediaType::parse)
}

/// Parses a `multipart/*` request body (normally `multipart/form-data`).
///
/// ```
/// use rune_http_model::HttpRequest;
/// use rune_mime::{MultipartOptions, parse_request_multipart};
///
/// let request = HttpRequest::post("https://app.example.test/upload")
///     .with_header("Content-Type", "multipart/form-data; boundary=x")
///     .with_body("--x\r\nContent-Disposition: form-data; name=q\r\n\r\n1' OR '1\r\n--x--\r\n");
/// let form = parse_request_multipart(&request, &MultipartOptions::default()).unwrap();
/// assert_eq!(form.field("q").unwrap().body, b"1' OR '1");
/// ```
///
/// # Errors
///
/// [`MimeError::Empty`] without a `Content-Type`, a parse error of the
/// header, or any error of [`parse_multipart_body`].
pub fn parse_request_multipart<'a>(
    request: &'a HttpRequest,
    options: &MultipartOptions,
) -> Result<Multipart<'a>, MimeError> {
    let media_type = request_media_type(request).ok_or(MimeError::Empty)??;
    parse_multipart_body(&media_type, request.body.as_bytes(), options)
}

/// Parses a `multipart/*` response body (`multipart/byteranges`,
/// `multipart/mixed`).
///
/// # Errors
///
/// As [`parse_request_multipart`].
pub fn parse_response_multipart<'a>(
    response: &'a HttpResponse,
    options: &MultipartOptions,
) -> Result<Multipart<'a>, MimeError> {
    let media_type = response_media_type(response).ok_or(MimeError::Empty)??;
    parse_multipart_body(&media_type, response.body.as_bytes(), options)
}

/// Detects the charset of a response body, using the `Content-Type`
/// `charset` parameter as the declared charset.
///
/// ```
/// use rune_http_model::HttpResponse;
/// use rune_mime::{Charset, CharsetSource, response_charset};
///
/// let response = HttpResponse::new(200)
///     .with_header("Content-Type", "text/html; charset=ISO-8859-1")
///     .with_body(&b"caf\xe9"[..]);
/// let found = response_charset(&response);
/// assert_eq!((found.charset, found.source), (Charset::Iso8859_1, CharsetSource::Declared));
/// ```
#[must_use]
pub fn response_charset(response: &HttpResponse) -> CharsetMatch {
    let declared = response_media_type(response)
        .and_then(Result::ok)
        .and_then(|mt| mt.param("charset").map(str::to_owned));
    detect_charset(response.body.as_bytes(), declared.as_deref())
}

/// Sets `request`'s body to the encoded parts and its `Content-Type` to
/// `multipart/form-data; boundary=…`.
///
/// ```
/// use rune_http_model::HttpRequest;
/// use rune_mime::{MultipartOptions, Part, parse_request_multipart, set_multipart_form};
///
/// let mut request = HttpRequest::post("https://app.example.test/upload");
/// set_multipart_form(&mut request, "----rune", &[Part::form_field("a", b"1").unwrap()]).unwrap();
/// let form = parse_request_multipart(&request, &MultipartOptions::default()).unwrap();
/// assert_eq!(form.parts.len(), 1);
/// ```
///
/// # Errors
///
/// Any error of [`encode_multipart`]; the request is unchanged then.
pub fn set_multipart_form(
    request: &mut HttpRequest,
    boundary: &str,
    parts: &[Part<'_>],
) -> Result<(), MimeError> {
    let body = encode_multipart(boundary, parts)?;
    let media_type = MediaType::new("multipart", "form-data")?.with_param("boundary", boundary)?;
    request.set_header("Content-Type", media_type.to_string());
    request.body = HttpBody::new(body);
    Ok(())
}
