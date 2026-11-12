//! The page a ruleset runs over, extracted from an HTTP exchange.

use std::collections::BTreeMap;

use rune_http_model::HttpExchange;

/// At most this many bytes of the body are treated as HTML.
pub const MAX_HTML_LEN: usize = 4 * 1024 * 1024;
/// At most this many tags are scanned for `<script src>` and `<meta>`.
pub const MAX_TAGS: usize = 20_000;

/// Everything rules are matched against.
///
/// Build it from an exchange with [`Page::from_exchange`], or field by
/// field for data from other sources.
///
/// ```
/// use rune_tech_detect::Page;
///
/// let page = Page::new("https://shop.example.test/")
///     .with_header("Server", "nginx")
///     .with_html(r#"<meta name="Generator" content="Example 1.0"><script src="/js/app.js"></script>"#);
/// assert_eq!(page.meta["generator"], ["Example 1.0"]);
/// assert_eq!(page.script_src, ["/js/app.js"]);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Page {
    /// The page URL.
    pub url: String,
    /// Response header values by lowercase name, in order.
    pub headers: BTreeMap<String, Vec<String>>,
    /// Cookie values by lowercase name, from `Set-Cookie`.
    pub cookies: BTreeMap<String, Vec<String>>,
    /// The HTML body (lossy UTF-8, at most [`MAX_HTML_LEN`] bytes).
    pub html: String,
    /// `<meta>` `content` values by lowercase `name`, `property` or
    /// `http-equiv`.
    pub meta: BTreeMap<String, Vec<String>>,
    /// `<script src>` URLs in document order.
    pub script_src: Vec<String>,
    /// Shodan-style favicon hash of the site's icon, when fetched.
    pub favicon_hash: Option<i32>,
}

impl Page {
    /// An empty page at `url`.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Self::default()
        }
    }

    /// The page of an exchange: request URL, response headers, cookies and
    /// body. The body must already be decoded (no content coding).
    #[must_use]
    pub fn from_exchange(exchange: &HttpExchange) -> Self {
        let mut page = Self::new(exchange.request.url.clone());
        if let Some(response) = &exchange.response {
            for header in &response.headers {
                page = page.with_header(&header.name, &header.value);
            }
            let body = response.body.as_bytes();
            let body = body.get(..MAX_HTML_LEN).unwrap_or(body);
            page = page.with_html(String::from_utf8_lossy(body));
        }
        page
    }

    /// Adds a response header (and its cookie, for `Set-Cookie`).
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        let name = name.to_ascii_lowercase();
        if name == "set-cookie" {
            let pair = value.split(';').next().unwrap_or_default();
            if let Some((cookie, cookie_value)) = pair.split_once('=') {
                let cookie = cookie.trim();
                if !cookie.is_empty() {
                    self.cookies
                        .entry(cookie.to_ascii_lowercase())
                        .or_default()
                        .push(cookie_value.trim().to_owned());
                }
            }
        }
        self.headers.entry(name).or_default().push(value.to_owned());
        self
    }

    /// Sets the HTML body and extracts its `<meta>` and `<script src>` tags.
    #[must_use]
    pub fn with_html(mut self, html: impl Into<String>) -> Self {
        let mut html = html.into();
        if html.len() > MAX_HTML_LEN {
            let mut end = MAX_HTML_LEN;
            while !html.is_char_boundary(end) {
                end -= 1;
            }
            html.truncate(end);
        }
        self.meta.clear();
        self.script_src.clear();
        for tag in Tags::new(&html).take(MAX_TAGS) {
            match tag.name.as_str() {
                "script" => {
                    if let Some(src) = tag.attribute("src") {
                        self.script_src.push(src.to_owned());
                    }
                }
                "meta" => {
                    let key = tag
                        .attribute("name")
                        .or_else(|| tag.attribute("property"))
                        .or_else(|| tag.attribute("http-equiv"));
                    if let (Some(key), Some(content)) = (key, tag.attribute("content")) {
                        self.meta
                            .entry(key.to_ascii_lowercase())
                            .or_default()
                            .push(content.to_owned());
                    }
                }
                _ => {}
            }
        }
        self.html = html;
        self
    }

    /// Sets the favicon hash from the icon bytes
    /// ([`rune_favicon_hash::favicon_hash`]).
    #[must_use]
    pub fn with_favicon(self, icon: &[u8]) -> Self {
        self.with_favicon_hash(rune_favicon_hash::favicon_hash(icon))
    }

    /// Sets an already computed favicon hash.
    #[must_use]
    pub const fn with_favicon_hash(mut self, hash: i32) -> Self {
        self.favicon_hash = Some(hash);
        self
    }
}

/// A start tag: lowercase name and attributes (lowercase names, raw values).
struct Tag {
    name: String,
    attributes: Vec<(String, String)>,
}

impl Tag {
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A forgiving scanner over the start tags of an HTML document. It skips
/// comments, and the content of `<script>` and `<style>` elements, and
/// never fails: malformed markup just yields fewer tags.
struct Tags<'a> {
    html: &'a str,
    position: usize,
}

impl<'a> Tags<'a> {
    const fn new(html: &'a str) -> Self {
        Self { html, position: 0 }
    }

    /// Moves past the closing tag of a raw-text element.
    fn skip_raw_text(&mut self, name: &str) {
        let rest = self.html.get(self.position..).unwrap_or_default();
        let closing = format!("</{name}");
        let found = rest
            .as_bytes()
            .windows(closing.len())
            .position(|window| window.eq_ignore_ascii_case(closing.as_bytes()));
        self.position = found.map_or(self.html.len(), |offset| self.position + offset);
    }
}

impl Iterator for Tags<'_> {
    type Item = Tag;

    fn next(&mut self) -> Option<Tag> {
        loop {
            let rest = self.html.get(self.position..)?;
            let start = rest.find('<')?;
            let after = &rest[start + 1..];
            self.position += start + 1;
            if after.starts_with("!--") {
                let end = after
                    .find("-->")
                    .map_or(self.html.len(), |end| self.position + end + 3);
                self.position = end;
                continue;
            }
            let name_len = after
                .bytes()
                .take_while(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
                .count();
            if name_len == 0 || !after.as_bytes()[0].is_ascii_alphabetic() {
                continue;
            }
            let name = after[..name_len].to_ascii_lowercase();
            let (attributes, consumed) = attributes(&after[name_len..]);
            self.position += name_len + consumed;
            if matches!(name.as_str(), "script" | "style") {
                self.skip_raw_text(&name);
            }
            return Some(Tag { name, attributes });
        }
    }
}

/// Parses attributes up to the closing `>`; returns them and the bytes used.
fn attributes(text: &str) -> (Vec<(String, String)>, usize) {
    let bytes = text.as_bytes();
    let mut attributes = Vec::new();
    let mut i = 0;
    loop {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        if i >= bytes.len() {
            return (attributes, i);
        }
        if bytes[i] == b'>' {
            return (attributes, i + 1);
        }
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && !matches!(bytes[i], b'=' | b'>' | b'/')
        {
            i += 1;
        }
        let name = text[name_start..i].to_ascii_lowercase();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value = String::new();
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && matches!(bytes[i], b'"' | b'\'') {
                let quote = bytes[i];
                let value_start = i + 1;
                let end = bytes[value_start..]
                    .iter()
                    .position(|byte| *byte == quote)
                    .map_or(bytes.len(), |offset| value_start + offset);
                text[value_start..end].clone_into(&mut value);
                i = (end + 1).min(bytes.len());
            } else {
                let value_start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
                    i += 1;
                }
                text[value_start..i].clone_into(&mut value);
            }
        }
        if !name.is_empty() && attributes.len() < 64 {
            attributes.push((name, value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_http_model::{ExchangeId, HttpRequest, HttpResponse};

    #[test]
    fn scans_meta_and_scripts() {
        let page = Page::new("u").with_html(
            "<!doctype html><!-- <script src=commented.js> --><HTML><head>\
             <META Property='og:site_name' CONTENT=\"Shop\">\
             <meta http-equiv=X-UA-Compatible content=IE=edge>\
             <meta name=empty>\
             <script>var s = '<script src=inline.js>';</script>\
             <SCRIPT type=module SRC=/a.js defer></SCRIPT>\
             <style>.x{background:url('<script src=x.js>')}</style>\
             <script src=\"/b.js?v=1\"/></head>< not a tag <1>",
        );
        assert_eq!(page.script_src, ["/a.js", "/b.js?v=1"]);
        assert_eq!(page.meta["og:site_name"], ["Shop"]);
        assert_eq!(page.meta["x-ua-compatible"], ["IE=edge"]);
        assert!(!page.meta.contains_key("empty"));
    }

    #[test]
    fn tolerates_truncated_markup() {
        for html in [
            "<", "<a", "<a b", "<a b=", "<a b='x", "<script", "<!--", "<é>", "<a é=1>",
        ] {
            let _ = Page::new("u").with_html(html);
        }
        let page = Page::new("u").with_html("<script src='x.js'");
        assert_eq!(page.script_src, ["x.js"]);
    }

    #[test]
    fn from_exchange_collects_headers_and_cookies() {
        let exchange = HttpExchange::new(ExchangeId(1), "t", HttpRequest::get("https://h.test/"))
            .with_response(
                HttpResponse::new(200)
                    .with_header("Server", "nginx")
                    .with_header("Set-Cookie", "PHPSESSID=abc; path=/")
                    .with_header("set-cookie", "theme=dark")
                    .with_header("Set-Cookie", "=bad")
                    .with_body("<script src=/x.js></script>"),
            );
        let page = Page::from_exchange(&exchange).with_favicon(b"hello");
        assert_eq!(page.url, "https://h.test/");
        assert_eq!(page.headers["server"], ["nginx"]);
        assert_eq!(page.headers["set-cookie"].len(), 3);
        assert_eq!(page.cookies["phpsessid"], ["abc"]);
        assert_eq!(page.cookies.len(), 2);
        assert_eq!(page.script_src, ["/x.js"]);
        assert_eq!(page.favicon_hash, Some(1_155_597_304));
    }

    #[test]
    fn html_is_capped_on_a_char_boundary() {
        let html = format!("{}é", "a".repeat(MAX_HTML_LEN - 1));
        let page = Page::new("u").with_html(html);
        assert_eq!(page.html.len(), MAX_HTML_LEN - 1);
    }
}
