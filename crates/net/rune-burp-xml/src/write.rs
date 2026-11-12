//! Writing: [`HttpExchange`]s to a Burp items export.

use std::fmt::Write as _;

use rune_http_model::{HttpExchange, HttpRequest, HttpResponse};

use crate::{message, time};

/// The document type Burp writes at the top of an items export.
const DOCTYPE: &str = r#"<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
<!ATTLIST items exportTime CDATA "">
<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>
<!ELEMENT time (#PCDATA)>
<!ELEMENT url (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
<!ELEMENT port (#PCDATA)>
<!ELEMENT protocol (#PCDATA)>
<!ELEMENT method (#PCDATA)>
<!ELEMENT path (#PCDATA)>
<!ELEMENT extension (#PCDATA)>
<!ELEMENT request (#PCDATA)>
<!ATTLIST request base64 (true|false) "false">
<!ELEMENT status (#PCDATA)>
<!ELEMENT responselength (#PCDATA)>
<!ELEMENT mimetype (#PCDATA)>
<!ELEMENT response (#PCDATA)>
<!ATTLIST response base64 (true|false) "false">
<!ELEMENT comment (#PCDATA)>
]>"#;

/// Settings for writing an export.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriteOptions {
    /// The `burpVersion` attribute.
    pub burp_version: String,
    /// The `exportTime` attribute, in milliseconds since the Unix epoch;
    /// left empty when `None`.
    pub export_time: Option<u64>,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            burp_version: concat!("rune-burp-xml ", env!("CARGO_PKG_VERSION")).to_owned(),
            export_time: None,
        }
    }
}

impl WriteOptions {
    /// Sets [`WriteOptions::burp_version`].
    #[must_use]
    pub fn with_burp_version(mut self, version: impl Into<String>) -> Self {
        self.burp_version = version.into();
        self
    }

    /// Sets [`WriteOptions::export_time`].
    #[must_use]
    pub const fn with_export_time(mut self, unix_milliseconds: u64) -> Self {
        self.export_time = Some(unix_milliseconds);
        self
    }
}

/// Escapes text for element content or a double-quoted attribute.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

/// Escapes an attribute value: as [`escape`], plus character references
/// for tabs and line breaks, which attribute normalization would turn into
/// spaces.
fn escape_attribute(text: &str) -> String {
    escape(text)
        .replace('\t', "&#9;")
        .replace('\n', "&#10;")
        .replace('\r', "&#13;")
}

/// Wraps text in CDATA, splitting any `]]>` across two sections.
fn cdata(text: &str) -> String {
    format!("<![CDATA[{}]]>", text.replace("]]>", "]]]]><![CDATA[>"))
}

/// Burp's coarse MIME type column, from a `Content-Type`.
fn mime_type(response: &HttpResponse) -> &'static str {
    let Some(content_type) = response.content_type() else {
        return "";
    };
    let content_type = content_type.to_ascii_lowercase();
    [
        ("html", "HTML"),
        ("json", "JSON"),
        ("javascript", "script"),
        ("ecmascript", "script"),
        ("css", "CSS"),
        ("xml", "XML"),
        ("image/", "image"),
        ("text/", "text"),
    ]
    .into_iter()
    .find(|(needle, _)| content_type.contains(needle))
    .map_or("", |(_, name)| name)
}

/// The URL's parts as Burp lists them: host, port, protocol, path with
/// query, extension and the origin-form request target.
struct UrlParts {
    host: String,
    port: String,
    protocol: String,
    path: String,
    extension: String,
}

/// A request target safe on a request line: whitespace and control
/// characters percent-encoded.
fn safe_target(target: &str) -> String {
    let mut out = String::with_capacity(target.len());
    for c in target.chars() {
        if c.is_whitespace() || c.is_control() {
            let mut buffer = [0; 4];
            for byte in c.encode_utf8(&mut buffer).bytes() {
                let _ = write!(out, "%{byte:02X}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn url_parts(request: &HttpRequest) -> UrlParts {
    let Ok(url) = request.parsed_url() else {
        return UrlParts {
            host: String::new(),
            port: String::new(),
            protocol: String::new(),
            path: safe_target(&request.url),
            extension: "null".to_owned(),
        };
    };
    let mut path = url.path().to_owned();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let extension = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .and_then(|last| last.rsplit_once('.'))
        .map(|(_, extension)| extension)
        .filter(|extension| !extension.is_empty())
        .unwrap_or("null")
        .to_owned();
    UrlParts {
        host: url.host_str().unwrap_or_default().to_owned(),
        port: url
            .port_or_known_default()
            .map(|port| port.to_string())
            .unwrap_or_default(),
        protocol: url.scheme().to_owned(),
        // Origin form needs a leading `/` (opaque URLs have no path).
        path: if path.starts_with('/') {
            safe_target(&path)
        } else {
            format!("/{}", safe_target(&path))
        },
        extension,
    }
}

/// Writes one `<item>`.
fn item(out: &mut String, exchange: &HttpExchange) {
    let request = &exchange.request;
    let parts = url_parts(request);
    let request_bytes = request.raw.as_ref().map_or_else(
        || message::write_request(request, &parts.path),
        |raw| raw.as_bytes().to_vec(),
    );
    let response = exchange.response.as_ref();
    let response_bytes = response.map(|response| {
        response.raw.as_ref().map_or_else(
            || message::write_response(response),
            |raw| raw.as_bytes().to_vec(),
        )
    });
    // A truncated body states its full length, as Burp's
    // `responselength` does.
    let response_length = response_bytes
        .as_ref()
        .zip(response)
        .map(|(bytes, response)| {
            let captured = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            let body = &response.body;
            let missing = match body.total_len {
                Some(total) if body.truncated => {
                    total.saturating_sub(u64::try_from(body.len()).unwrap_or(u64::MAX))
                }
                _ => 0,
            };
            captured.saturating_add(missing)
        });

    let _ = writeln!(out, "  <item>");
    let _ = writeln!(
        out,
        "    <time>{}</time>",
        time::format(exchange.started_at_unix_milliseconds)
    );
    let _ = writeln!(out, "    <url>{}</url>", cdata(&request.url));
    let _ = writeln!(
        out,
        "    <host ip=\"{}\">{}</host>",
        escape_attribute(exchange.remote_address.as_deref().unwrap_or_default()),
        escape(&parts.host)
    );
    let _ = writeln!(out, "    <port>{}</port>", parts.port);
    let _ = writeln!(out, "    <protocol>{}</protocol>", escape(&parts.protocol));
    let _ = writeln!(out, "    <method>{}</method>", cdata(&request.method));
    let _ = writeln!(out, "    <path>{}</path>", cdata(&parts.path));
    let _ = writeln!(
        out,
        "    <extension>{}</extension>",
        escape(&parts.extension)
    );
    let _ = writeln!(
        out,
        "    <request base64=\"true\">{}</request>",
        cdata(&rune_base64::encode(&request_bytes))
    );
    let _ = writeln!(
        out,
        "    <status>{}</status>",
        response
            .map(|response| response.status.to_string())
            .unwrap_or_default()
    );
    let _ = writeln!(
        out,
        "    <responselength>{}</responselength>",
        response_length
            .map(|length| length.to_string())
            .unwrap_or_default()
    );
    let _ = writeln!(
        out,
        "    <mimetype>{}</mimetype>",
        response.map(mime_type).unwrap_or_default()
    );
    let _ = writeln!(
        out,
        "    <response base64=\"true\">{}</response>",
        response_bytes
            .map(|bytes| cdata(&rune_base64::encode(&bytes)))
            .unwrap_or_default()
    );
    let _ = writeln!(
        out,
        "    <comment>{}</comment>",
        escape(exchange.notes.as_deref().unwrap_or_default())
    );
    let _ = writeln!(out, "  </item>");
}

/// Writes exchanges as a Burp items export, the format of Burp's "Save
/// items", which Burp and this crate's [`read`](crate::read) both load.
///
/// Requests and responses are written from their `raw` bytes when they
/// have them, and serialized otherwise (with a `chunked` body re-framed as
/// one chunk). Payloads are always base64.
///
/// ```
/// use rune_http_model::{ExchangeId, HttpExchange, HttpRequest, HttpResponse};
///
/// let exchange = HttpExchange::new(ExchangeId(0), "burp", HttpRequest::get("https://h.test/a?b=1"))
///     .with_response(HttpResponse::new(200).with_reason("OK").with_body("hi"));
/// let xml = rune_burp_xml::write([&exchange], &Default::default());
/// assert!(xml.contains("<path><![CDATA[/a?b=1]]></path>"));
///
/// let options = rune_burp_xml::ReadOptions::default().with_raw(false);
/// let report = rune_burp_xml::read(xml.as_bytes(), &options)?;
/// assert_eq!(report.exchanges, [exchange]);
/// # Ok::<(), rune_burp_xml::BurpError>(())
/// ```
#[must_use]
pub fn write<'a>(
    exchanges: impl IntoIterator<Item = &'a HttpExchange>,
    options: &WriteOptions,
) -> String {
    let mut out = String::from("<?xml version=\"1.0\"?>\n");
    out.push_str(DOCTYPE);
    out.push('\n');
    let _ = writeln!(
        out,
        "<items burpVersion=\"{}\" exportTime=\"{}\">",
        escape_attribute(&options.burp_version),
        options.export_time.map(time::format).unwrap_or_default()
    );
    for exchange in exchanges {
        item(&mut out, exchange);
    }
    out.push_str("</items>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression: an unparsable URL with line
    // breaks was written as the request target, splitting the request line
    // and losing the version on re-read.
    #[test]
    fn unparsable_urls_make_safe_targets() {
        let request = HttpRequest::get("https://h\n  <x> é");
        assert_eq!(url_parts(&request).path, "https://h%0A%20%20<x>%20é");
    }

    // Regression: line breaks in the host IP
    // attribute were normalized to spaces on re-read.
    #[test]
    fn attribute_line_breaks_survive() {
        let exchange = rune_http_model::HttpExchange::new(
            rune_http_model::ExchangeId(0),
            "burp",
            HttpRequest::get("http://h.test/"),
        )
        .with_remote_address("a\nb\tc\rd");
        let xml = write([&exchange], &WriteOptions::default());
        assert!(xml.contains("ip=\"a&#10;b&#9;c&#13;d\""));
        let report = crate::read(xml.as_bytes(), &crate::ReadOptions::default()).unwrap();
        assert_eq!(
            report.exchanges[0].remote_address.as_deref(),
            Some("a\nb\tc\rd")
        );
    }

    // Regression: a URL with a non-special
    // scheme and no path gave an empty request target.
    #[test]
    fn pathless_urls_get_a_root_target() {
        assert_eq!(url_parts(&HttpRequest::get("x://h")).path, "/");
        assert_eq!(url_parts(&HttpRequest::get("x:opaque")).path, "/opaque");
    }
}
