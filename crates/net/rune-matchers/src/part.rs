//! Selection of the bytes a matcher or extractor inspects.

use std::borrow::Cow;

use rune_http_model::{HeaderEntry, HttpExchange};

use crate::ResponsePart;

/// Renders headers as `Name: Value\n` lines.
fn header_blob(headers: &[HeaderEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    for header in headers {
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value.as_bytes());
        out.push(b'\n');
    }
    out
}

/// Whether reading `part` requires a response.
pub const fn needs_response(part: &ResponsePart) -> bool {
    !matches!(
        part,
        ResponsePart::RequestBody
            | ResponsePart::RequestHeaders
            | ResponsePart::Url
            | ResponsePart::Time
    )
}

/// The bytes of `part`, or `None` when it needs a missing response.
/// The body parts borrow; rendered parts allocate.
pub fn part_bytes<'a>(part: &ResponsePart, exchange: &'a HttpExchange) -> Option<Cow<'a, [u8]>> {
    let request = &exchange.request;
    match part {
        ResponsePart::RequestBody => return Some(Cow::Borrowed(request.body.as_bytes())),
        ResponsePart::RequestHeaders => return Some(Cow::Owned(header_blob(&request.headers))),
        ResponsePart::Url => return Some(Cow::Borrowed(request.url.as_bytes())),
        ResponsePart::Time => {
            return Some(Cow::Owned(
                exchange.timings.total_milliseconds.to_string().into_bytes(),
            ));
        }
        _ => {}
    }
    let response = exchange.response.as_ref()?;
    Some(match part {
        ResponsePart::Body => Cow::Borrowed(response.body.as_bytes()),
        ResponsePart::Headers => Cow::Owned(header_blob(&response.headers)),
        ResponsePart::Header(name) => {
            let values: Vec<&str> = response
                .headers
                .iter()
                .filter(|header| header.name.eq_ignore_ascii_case(name))
                .map(|header| header.value.as_str())
                .collect();
            Cow::Owned(values.join("\n").into_bytes())
        }
        ResponsePart::Status => Cow::Owned(response.status.to_string().into_bytes()),
        ResponsePart::All => {
            let mut out = header_blob(&response.headers);
            out.push(b'\n');
            out.extend_from_slice(response.body.as_bytes());
            Cow::Owned(out)
        }
        ResponsePart::Raw => response.raw.as_ref().map_or_else(
            || {
                let mut out = format!(
                    "{} {} {}\n",
                    response.http_version.as_str(),
                    response.status,
                    response.reason.as_deref().unwrap_or_default()
                )
                .into_bytes();
                out.extend_from_slice(&header_blob(&response.headers));
                out.push(b'\n');
                out.extend_from_slice(response.body.as_bytes());
                Cow::Owned(out)
            },
            |raw| Cow::Borrowed(raw.as_bytes()),
        ),
        ResponsePart::RequestBody
        | ResponsePart::RequestHeaders
        | ResponsePart::Url
        | ResponsePart::Time => return None,
    })
}
