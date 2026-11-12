# rune-burp-xml

> Burp Suite items and issues XML export reader and writer over rune-http-model, base64 request/response to HttpExchange

[![crates.io](https://img.shields.io/crates/v/rune-burp-xml)](https://crates.io/crates/rune-burp-xml)
[![docs.rs](https://img.shields.io/docsrs/rune-burp-xml)](https://docs.rs/rune-burp-xml)
[![license](https://img.shields.io/crates/l/rune-burp-xml)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Reads the XML that Burp Suite writes when you "Save items" from the proxy
history or site map, and its scanner issues reports, into
`rune-http-model` `HttpExchange`s. Writes exchanges back out as an items
export that Burp and this crate load. It has no I/O of its own: it works
on bytes and strings, and the caller opens the files.

- **Streaming**: the document is walked one item at a time, so memory
  stays bounded by one item beyond the input.
- **Faithful**: base64 (or plain CDATA) payloads are decoded to the exact
  bytes Burp captured and kept as `raw`; requests and responses are parsed
  from them, with the URL, host IP, time and comment alongside. Chunked
  bodies are de-chunked; a `responselength` beyond the captured bytes marks
  the body truncated.
- **Tolerant**: bare `\n` line ends, folded headers, HTTP/2 in Burp's text
  form, odd request targets, unknown time zones and invalid UTF-8 are
  accepted. An item that cannot be read is skipped with a `Warning`, and a
  truncated export keeps the items before the cut.

## Installation

```toml
[dependencies]
rune-burp-xml = "0.1"
rune-http-model = "0.1"
```

## Usage

```rust
use rune_burp_xml::{ReadOptions, WriteOptions};
use rune_http_model::{ExchangeId, HttpExchange, HttpRequest, HttpResponse};

let input = br#"<items burpVersion="2024.1.1">
  <item>
    <time>Tue Jan 02 03:04:05 UTC 2024</time>
    <url><![CDATA[https://h.test/login]]></url>
    <host ip="192.0.2.1">h.test</host>
    <request base64="true"><![CDATA[UE9TVCAvbG9naW4gSFRUUC8xLjENCkhvc3Q6IGgudGVzdA0KDQp1c2VyPWE=]]></request>
    <response base64="false"><![CDATA[HTTP/1.1 302 Found
Location: /home

]]></response>
    <comment>login</comment>
  </item>
</items>"#;

let report = rune_burp_xml::read(input, &ReadOptions::default())?;
let login = &report.exchanges[0];
assert_eq!(login.request.method, "POST");
assert_eq!(login.request.body.as_utf8(), Some("user=a"));
assert_eq!(login.status(), Some(302));
assert_eq!(login.remote_address.as_deref(), Some("192.0.2.1"));

let exchange = HttpExchange::new(ExchangeId(0), "burp", HttpRequest::get("http://h.test/"))
    .with_response(HttpResponse::new(204));
let xml = rune_burp_xml::write([&exchange], &WriteOptions::default());
let again = rune_burp_xml::read(xml.as_bytes(), &ReadOptions::default().with_raw(false))?;
assert_eq!(again.exchanges, [exchange]);
# Ok::<(), rune_burp_xml::BurpError>(())
```

The crate documentation has the full field mapping and lists what an
items export cannot carry (`error`, `timings`, `redirect_chain`, `tags`,
sub-second start times). Burp's binary project files are not read; export
the items as XML first.

## Testing

The tests read and round-trip a proxy history saved with base64 payloads,
a site map saved as plain text and a scanner issues report
(`tests/fixtures/`), covering HTTP/2, gzip, chunked, binary, truncated and
missing responses. Property tests write arbitrary exchanges and read them
back, check that read → write → read is a fixpoint for arbitrary item
text, and that reading never panics.

## License

MIT
